/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// envelopeToOutgoingContext marshals the envelope and attaches it to the outgoing gRPC
// metadata under MetadataEnvelopeKey (a "-bin" key, so gRPC base64-encodes it on the wire).
func envelopeToOutgoingContext(ctx context.Context, env *cb.Envelope) (context.Context, error) {
	raw, err := proto.Marshal(env)
	if err != nil {
		return ctx, errors.Wrap(err, "failed to marshal auth envelope")
	}
	return metadata.AppendToOutgoingContext(ctx, MetadataEnvelopeKey, string(raw)), nil
}

// envelopeFromIncomingContext reads and unmarshals the envelope from the incoming gRPC
// metadata. It returns an error when the metadata or the key is absent.
func envelopeFromIncomingContext(ctx context.Context) (*cb.Envelope, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("no incoming metadata")
	}
	vals := md.Get(MetadataEnvelopeKey)
	if len(vals) == 0 {
		return nil, errors.New("no auth envelope in metadata")
	}
	env := &cb.Envelope{}
	if err := proto.Unmarshal([]byte(vals[0]), env); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal auth envelope from metadata")
	}
	return env, nil
}
