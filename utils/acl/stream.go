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

// authorizedStream renews a stream's authorization from its bound token, so expiry and policy changes stay
// observable. A decision is reused until it lapses: a per-message check would add latency to every block.
type authorizedStream struct {
	grpc.ServerStream
	//nolint:containedctx // the wrapped stream must return this (cancelable) context from Context().
	ctx context.Context
	// cancel tears the stream down when a re-check reaches a definitive denial.
	cancel   context.CancelFunc
	enforcer *Enforcer
	resource string
	token    string

	// mu guards the cached decision: Recv and Send run on separate goroutines for a bidirectional stream.
	// The renewal is held under the lock deliberately - passing a message mid-renewal defeats the check.
	mu sync.Mutex
	// tokenExpiresAt is the hard limit: past it the stream is denied locally, with no round trip.
	tokenExpiresAt time.Time
	// nextAuthorizeAt is when the decision must be re-authorized against the AuthService.
	nextAuthorizeAt time.Time
	// denied is the terminal error once a re-check has definitively failed.
	denied error
}

func (s *authorizedStream) Context() context.Context {
	return s.ctx
}

// RecvMsg authorizes, receives, then re-checks the token's expiry before the handler sees the message: an
// idle receive can block past the token's life, so the decision that admitted it may already be dead.
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

// authorizeIfLapsed applies the two bounds a stream has. The token's expiry is checked on every message and
// costs nothing; a full re-authorization happens only once per interval, and is what makes a policy change
// observable. A transient failure keeps the stream serving, still bounded by the expiry.
func (s *authorizedStream) authorizeIfLapsed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if err := s.checkBoundTokenLocked(now); err != nil {
		return err
	}
	if now.Before(s.nextAuthorizeAt) {
		return nil
	}

	if _, err := s.enforcer.authorize(s.ctx, s.token, s.resource); err != nil {
		if grpcerror.FilterUnavailableErrorCode(err) == nil {
			s.nextAuthorizeAt = time.Now().Add(s.enforcer.TransientRetryInterval)
			logger.Warnf("ACL re-check for [%s] failed transiently; retrying in %s: %v",
				s.resource, s.enforcer.TransientRetryInterval, err)
			return nil
		}
		logger.Warnf("ACL re-check for [%s] denied; terminating the stream: %v", s.resource, err)
		s.terminate(err)
		return s.denied
	}

	// Re-authorization cannot extend the stream: tokenExpiresAt is fixed at establishment and is checked on
	// every message, so only the interval moves here.
	s.nextAuthorizeAt = now.Add(s.enforcer.ReAuthorizeInterval)
	return nil
}

// checkBoundTokenLocked returns the terminal error when the stream was denied or its bound token expired,
// both decided locally so an outage cannot extend a stream. Caller must hold mu.
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
