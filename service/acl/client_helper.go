/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"encoding/base64"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// AddSignedMetadata adds ACL metadata to the context for a gRPC request.
// This function signs the request data and adds the signature along with
// the identity to the gRPC metadata.
//
// Parameters:
//   - ctx: The context to which metadata will be added
//   - channelID: The channel ID for which access is being requested
//   - identity: The signing identity (MSP identity with private key)
//   - request: The protobuf request message to be signed
//
// Returns a new context with the signed metadata attached.
func AddSignedMetadata(ctx context.Context, channelID string, identity msp.SigningIdentity, request proto.Message) (context.Context, error) {
	// Marshal the request for signing
	requestData, err := proto.Marshal(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal request")
	}

	// Serialize the identity
	creator, err := identity.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize identity")
	}

	// Sign the request data
	signature, err := identity.Sign(requestData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign request")
	}

	// Encode to base64 for metadata transmission
	creatorB64 := base64.StdEncoding.EncodeToString(creator)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Create metadata
	md := metadata.Pairs(
		metadataChannelID, channelID,
		metadataCreator, creatorB64,
		metadataSignature, signatureB64,
	)

	// Add metadata to context
	return metadata.NewOutgoingContext(ctx, md), nil
}

// AddSignedMetadataWithNonce adds ACL metadata with a nonce to the context.
// The nonce can be used for replay protection if needed.
func AddSignedMetadataWithNonce(ctx context.Context, channelID string, identity msp.SigningIdentity, request proto.Message, nonce []byte) (context.Context, error) {
	// Marshal the request for signing
	requestData, err := proto.Marshal(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal request")
	}

	// Serialize the identity
	creator, err := identity.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize identity")
	}

	// Sign the request data
	signature, err := identity.Sign(requestData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign request")
	}

	// Encode to base64 for metadata transmission
	creatorB64 := base64.StdEncoding.EncodeToString(creator)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Create metadata
	md := metadata.Pairs(
		metadataChannelID, channelID,
		metadataCreator, creatorB64,
		metadataNonce, nonceB64,
		metadataSignature, signatureB64,
	)

	// Add metadata to context
	return metadata.NewOutgoingContext(ctx, md), nil
}

// Made with Bob
