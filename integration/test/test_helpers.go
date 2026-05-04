/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// wrapInEnvelope wraps a proto message in a common.Envelope for testing.
// This is a simplified version that doesn't include signatures since ACL is disabled in tests (nil aclProvider).
func wrapInEnvelope(t *testing.T, channelID string, request proto.Message) *common.Envelope {
	t.Helper()

	// Marshal the request
	requestBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	// Create channel header
	channelHeader := &common.ChannelHeader{
		Type:      int32(common.HeaderType_MESSAGE),
		ChannelId: channelID,
	}
	channelHeaderBytes, err := proto.Marshal(channelHeader)
	require.NoError(t, err)

	// Create payload
	payload := &common.Payload{
		Header: &common.Header{
			ChannelHeader: channelHeaderBytes,
		},
		Data: requestBytes,
	}
	payloadBytes, err := proto.Marshal(payload)
	require.NoError(t, err)

	// Create envelope (unsigned for test simplicity since ACL is disabled)
	return &common.Envelope{
		Payload: payloadBytes,
	}
}
