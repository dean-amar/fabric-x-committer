/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// wrapNotificationInEnvelope wraps a NotificationRequest in an envelope for testing.
// ACL is disabled in tests (nil provider), so we use unsigned envelopes.
func wrapNotificationInEnvelope(t *testing.T, request *committerpb.NotificationRequest) *common.Envelope {
	t.Helper()

	requestBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	channelHeader := &common.ChannelHeader{
		Type:      int32(common.HeaderType_ENDORSER_TRANSACTION),
		ChannelId: "testchannel",
	}
	channelHeaderBytes, err := proto.Marshal(channelHeader)
	require.NoError(t, err)

	payload := &common.Payload{
		Header: &common.Header{
			ChannelHeader: channelHeaderBytes,
		},
		Data: requestBytes,
	}
	payloadBytes, err := proto.Marshal(payload)
	require.NoError(t, err)

	return &common.Envelope{
		Payload: payloadBytes,
	}
}

// Made with Bob
