/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func TestEnvelopeMetadataRoundTrip(t *testing.T) {
	t.Parallel()
	env := &cb.Envelope{Payload: []byte("p"), Signature: []byte("s")}

	outCtx, err := envelopeToOutgoingContext(context.Background(), env)
	require.NoError(t, err)
	md, ok := metadata.FromOutgoingContext(outCtx)
	require.True(t, ok)

	inCtx := metadata.NewIncomingContext(context.Background(), md)
	got, err := envelopeFromIncomingContext(inCtx)
	require.NoError(t, err)
	require.True(t, proto.Equal(env, got))
}

func TestEnvelopeFromIncomingContext_Missing(t *testing.T) {
	t.Parallel()
	_, err := envelopeFromIncomingContext(context.Background())
	require.Error(t, err)
}
