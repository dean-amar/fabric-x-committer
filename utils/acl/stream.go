/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// authorizedStream wraps a server stream whose authorization is renewed from its bound token. No message
// crosses it while the decision is stale, and a valid decision is reused until it lapses - a per-message
// check would put AuthService latency on the data path of every block and batch.
//
// Renewal re-presents the token rather than the identity alone: the AuthService resolves the token to
// its record before evaluating policy, which is what makes token expiry and configuration changes
// observable to a stream that was established long ago.
type authorizedStream struct {
	grpc.ServerStream
	//nolint:containedctx // the wrapped stream must return this (cancelable) context from Context().
	ctx context.Context
	// cancel tears the stream down when a re-check reaches a definitive denial.
	cancel   context.CancelFunc
	enforcer *Enforcer
	resource string
	token    string

	// mu guards the cached decision. Recv and Send run on separate goroutines for a bidirectional
	// stream, and the refresh is held under the lock deliberately: letting a message through while the
	// decision is being renewed would defeat the check.
	mu sync.Mutex
	// tokenExpiresAt is the hard limit: past it the stream is denied locally, with no round trip.
	tokenExpiresAt time.Time
	// validUntil is when the cached decision must be renewed.
	validUntil time.Time
	// denied is the terminal error once a re-check has definitively failed.
	denied error
}

func (s *authorizedStream) Context() context.Context {
	return s.ctx
}

// RecvMsg authorizes the stream, receives the message, and re-checks the token's expiry before handing
// it to the handler. The second check is not redundant: a receive on an idle stream can block for longer
// than the token's remaining life, so the decision that admitted it may be dead by the time it returns.
// Only the local bound is re-checked - it costs no round trip, and the next message pays for a full
// re-authorization anyway.
func (s *authorizedStream) RecvMsg(m any) error {
	if err := s.authorizeIfLapsed(); err != nil {
		return err
	}
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkBoundTokenLocked(time.Now())
}

func (s *authorizedStream) SendMsg(m any) error {
	if err := s.authorizeIfLapsed(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

// authorizeIfLapsed renews the decision when it has lapsed, and terminates the stream on a definitive
// denial. A transient failure leaves the stream serving and is retried on the next message, bounded by
// the bound token's expiry - so an outage cannot extend a stream past that token's lifetime.
func (s *authorizedStream) authorizeIfLapsed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if err := s.checkBoundTokenLocked(now); err != nil {
		return err
	}
	if now.Before(s.validUntil) {
		return nil
	}

	resp, err := s.enforcer.authorize(s.ctx, s.token, s.resource)
	if err != nil {
		if grpcerror.FilterUnavailableErrorCode(err) == nil {
			// Transient (Unavailable / DeadlineExceeded): keep serving, and hold off before trying
			// again. Without the backoff every subsequent message would re-attempt the call and wait
			// out its timeout while holding mu, so a brief outage would stall the stream it is meant
			// to keep alive. The token-expiry guard above still bounds how long this can continue.
			//
			// Measured from after the failed call, not from `now`: the call may have burned its whole
			// timeout, which would leave the deadline already in the past and the backoff useless.
			s.validUntil = time.Now().Add(transientRetryInterval)
			logger.Warnf("ACL re-check for [%s] failed transiently; retrying in %s: %v",
				s.resource, transientRetryInterval, err)
			return nil
		}
		logger.Warnf("ACL re-check for [%s] denied; terminating the stream: %v", s.resource, err)
		s.terminate(err)
		return s.denied
	}

	s.validUntil = s.enforcer.decisionValidUntil(resp, now)
	return nil
}

// checkBoundTokenLocked returns the terminal error when the stream has already been denied or its bound
// token has expired, terminating the stream in the latter case. Both outcomes are decided locally, so an
// outage can never extend a stream past the life of the token that established it. Caller must hold mu.
func (s *authorizedStream) checkBoundTokenLocked(now time.Time) error {
	if s.denied != nil {
		return s.denied
	}
	if !s.tokenExpiresAt.IsZero() && now.After(s.tokenExpiresAt) {
		s.terminate(grpcerror.WrapUnauthenticated(
			errors.Newf("the token bound to stream [%s] has expired", s.resource),
		))
		return s.denied
	}
	return nil
}

// terminate records the terminal error and cancels the stream context. The caller must hold mu.
func (s *authorizedStream) terminate(err error) {
	s.denied = err
	s.cancel()
}
