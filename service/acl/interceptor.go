/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"encoding/base64"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// Metadata keys for ACL information
	metadataChannelID = "channel-id"
	metadataCreator   = "creator"
	metadataNonce     = "nonce"
	metadataSignature = "signature"
)

// Interceptor provides gRPC interceptors for ACL enforcement.
type Interceptor struct {
	provider Provider
}

// NewInterceptor creates a new ACL interceptor with the given provider.
func NewInterceptor(provider Provider) *Interceptor {
	return &Interceptor{
		provider: provider,
	}
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that validates ACL for each request.
func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip ACL check if provider is nil (ACL disabled)
		if i.provider == nil {
			return handler(ctx, req)
		}

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "missing metadata")
		}

		// Validate ACL
		if err := i.validateACL(md, req); err != nil {
			return nil, err
		}

		// Call actual handler
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that validates ACL for each message.
func (i *Interceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip ACL check if provider is nil (ACL disabled)
		if i.provider == nil {
			return handler(srv, ss)
		}

		// Wrap stream to intercept each message
		wrapped := &aclServerStream{
			ServerStream: ss,
			interceptor:  i,
		}

		return handler(srv, wrapped)
	}
}

// validateACL performs the ACL check using the metadata and request.
func (i *Interceptor) validateACL(md metadata.MD, req interface{}) error {
	// Extract metadata fields
	channelID := getMetadataValue(md, metadataChannelID)
	creatorB64 := getMetadataValue(md, metadataCreator)
	signatureB64 := getMetadataValue(md, metadataSignature)

	if channelID == "" {
		return status.Error(codes.InvalidArgument, "missing channel-id in metadata")
	}
	if creatorB64 == "" {
		return status.Error(codes.InvalidArgument, "missing creator in metadata")
	}
	if signatureB64 == "" {
		return status.Error(codes.InvalidArgument, "missing signature in metadata")
	}

	// Decode metadata
	creatorBytes, err := base64.StdEncoding.DecodeString(creatorB64)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid creator encoding")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid signature encoding")
	}

	// Unmarshal creator into Identity protobuf
	identity := &msppb.Identity{}
	if err := proto.Unmarshal(creatorBytes, identity); err != nil {
		return status.Error(codes.InvalidArgument, "invalid creator identity")
	}

	// Marshal request for signature verification
	requestData, err := proto.Marshal(req.(proto.Message))
	if err != nil {
		return status.Error(codes.Internal, "failed to marshal request")
	}

	// Create SignedData for policy evaluation
	signedData := []*protoutil.SignedData{{
		Data:      requestData,
		Identity:  identity,
		Signature: signature,
	}}

	// Get channel bundle
	bundle, err := i.provider.GetBundle(channelID)
	if err != nil {
		logger.Warnw("Failed to get bundle for channel", "channelID", channelID, "error", err)
		return status.Errorf(codes.FailedPrecondition, "channel not configured: %s", channelID)
	}

	// Get the Readers policy
	policy, ok := bundle.PolicyManager().GetPolicy(ReadersPolicy)
	if !ok {
		logger.Errorw("Readers policy not found", "channelID", channelID, "policy", ReadersPolicy)
		return status.Error(codes.Internal, "readers policy not found")
	}

	// Evaluate policy
	if err := policy.EvaluateSignedData(signedData); err != nil {
		logger.Warnw("ACL check failed",
			"channelID", channelID,
			"policy", ReadersPolicy,
			"error", err)
		return status.Error(codes.PermissionDenied, "access denied")
	}

	logger.Debugf("ACL check passed for channel %s", channelID)
	return nil
}

// aclServerStream wraps a grpc.ServerStream to intercept RecvMsg calls for ACL validation.
type aclServerStream struct {
	grpc.ServerStream
	interceptor *Interceptor
}

// RecvMsg intercepts incoming messages and validates ACL before passing to the handler.
func (s *aclServerStream) RecvMsg(m interface{}) error {
	// Receive the message first
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}

	// Validate ACL for the message
	md, ok := metadata.FromIncomingContext(s.Context())
	if !ok {
		return status.Error(codes.InvalidArgument, "missing metadata")
	}

	return s.interceptor.validateACL(md, m)
}

// getMetadataValue extracts a single value from metadata.
// Returns empty string if the key is not found or has no values.
func getMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// CheckACLFromMetadata is a helper function that can be called directly by services
// that need to perform ACL checks outside of the interceptor flow.
func (i *Interceptor) CheckACLFromMetadata(ctx context.Context, req proto.Message) error {
	if i.provider == nil {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("missing metadata")
	}

	return i.validateACL(md, req)
}

// Made with Bob
