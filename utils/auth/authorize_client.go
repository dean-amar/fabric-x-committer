/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/retry"
)

// DefaultAuthorizeRetryProfile bounds how long AuthorizeConnection retries while the server is
// still bootstrapping its ACL bundle (codes.Unavailable). ACL-enforced services build their
// bundle asynchronously from the first configuration block, so a client that connects during
// that window must wait a bounded time rather than fail outright.
var DefaultAuthorizeRetryProfile = retry.Profile{MaxElapsedTime: new(30 * time.Second)}

// AuthorizeParameters describes how to authorize a gRPC connection to an ACL-enforced
// service (query or sidecar) before issuing any business RPC on it.
type AuthorizeParameters struct {
	// Signer is the client's MSP signing identity. Its serialized form is carried in the
	// envelope's SignatureHeader.Creator and the envelope payload is signed with its key.
	Signer msp.SigningIdentity
	// ChannelID is the channel the client is authorizing against.
	ChannelID string
	// TLSCertHash is the SHA-256 hash of the client's TLS certificate (DER). It binds the
	// envelope to this connection under mTLS. It must be empty when the connection is not
	// mutually authenticated (there is no client certificate to bind to).
	TLSCertHash []byte
}

// AuthorizeConnection authorizes a gRPC connection by calling the AuthService.Authorize RPC
// with a freshly-signed, cert-bound envelope. On success the server binds the resolved MSP
// identity to the connection, so every subsequent unary or streaming RPC on the same
// connection reuses that identity. This must be called once per connection before any other
// RPC.
//
// It is a no-op (returns nil) when params.Signer is nil, which lets callers that have no MSP
// identity — for example internal deployments without ACL enforcement — share the same code
// path. The server side independently decides whether to enforce ACL.
//
// While the server is still bootstrapping its bundle it returns codes.Unavailable; this call
// retries such responses within DefaultAuthorizeRetryProfile. Genuine denials (bad identity,
// cert mismatch, stale timestamp) are permanent and returned immediately.
func AuthorizeConnection(ctx context.Context, conn grpc.ClientConnInterface, params AuthorizeParameters) error {
	return authorizeConnection(ctx, conn, params, DefaultAuthorizeRetryProfile)
}

// authorizeConnection is the implementation behind AuthorizeConnection, parameterized by the retry
// profile so tests can drive the bootstrap-retry behavior with a fast profile without mutating
// package state.
func authorizeConnection(
	ctx context.Context, conn grpc.ClientConnInterface, params AuthorizeParameters, profile retry.Profile,
) error {
	if params.Signer == nil {
		return nil
	}

	client := committerpb.NewAuthServiceClient(conn)

	// The server returns codes.Unavailable while it is still bootstrapping its bundle. We retry
	// only that case within a bounded window; success and genuine denials return immediately.
	retryCtx, cancel := context.WithTimeout(ctx, *profile.MaxElapsedTime)
	defer cancel()
	backoff := profile.NewBackoff()

	for {
		err := authorizeOnce(ctx, client, params)
		if err == nil || !errors.Is(err, errAuthUnavailable) {
			return err
		}
		select {
		case <-retryCtx.Done():
			return errors.Wrap(err, "authorization did not succeed before timeout")
		case <-time.After(backoff.NextBackOff()):
		}
	}
}

// errAuthUnavailable marks an Authorize attempt that failed because the server is still
// bootstrapping its bundle; AuthorizeConnection retries such attempts.
var errAuthUnavailable = errors.New("authorization unavailable: server bootstrapping")

// authorizeOnce performs a single Authorize attempt. It returns nil on success, an error
// wrapping errAuthUnavailable when the server is still bootstrapping (retry), or any other
// error for permanent failures (stop).
func authorizeOnce(ctx context.Context, client committerpb.AuthServiceClient, params AuthorizeParameters) error {
	// Rebuild the envelope on each attempt so its timestamp stays within the freshness
	// window even if earlier attempts were spent waiting for the bundle to load.
	envelope, err := buildAuthorizeEnvelope(params)
	if err != nil {
		return err
	}

	resp, err := client.Authorize(ctx, &committerpb.AuthorizeRequest{SignedEnvelope: envelope})
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			return errors.Join(errAuthUnavailable, errors.Wrap(err, "authorize RPC unavailable"))
		}
		return errors.Wrap(err, "authorize RPC failed")
	}
	if !resp.GetSuccess() {
		return errors.Newf("authorization denied: %s", resp.GetMessage())
	}
	return nil
}

// buildAuthorizeEnvelope creates the signed, cert-bound envelope used by the Authorize RPC.
// The envelope's ChannelHeader carries a fresh timestamp (set by protoutil) and the TLS cert
// hash, which the server validates for replay prevention.
func buildAuthorizeEnvelope(params AuthorizeParameters) (*cb.Envelope, error) {
	// The Authorize envelope needs no business payload; the identity travels in the
	// signature header and the freshness/binding data in the channel header.
	envelope, err := protoutil.CreateSignedEnvelopeWithTLSBinding(
		cb.HeaderType_MESSAGE,
		params.ChannelID,
		params.Signer,
		&cb.Envelope{}, // empty, non-nil payload message
		0,
		0,
		params.TLSCertHash,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signed authorize envelope")
	}
	return envelope, nil
}

// ClientTLSCertHash returns the SHA-256 hash of the client certificate configured in the
// given TLS config, or nil when the config is not mutual TLS (no client certificate). The
// hash matches the value the server computes from the presented certificate.
func ClientTLSCertHash(tlsConfig connection.TLSConfig) ([]byte, error) {
	creds, err := connection.NewClientTLSCredentials(tlsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client TLS credentials")
	}
	if creds.Mode != connection.MutualTLSMode || len(creds.Cert) == 0 {
		return nil, nil
	}
	hash, err := protoutil.HashTLSCertificate(creds.Cert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash client TLS certificate")
	}
	return hash, nil
}
