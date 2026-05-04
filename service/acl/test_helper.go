/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
)

// CreateSignedEnvelope creates a signed envelope for testing ACL enforcement.
// The envelope is signed by the provided identity and includes the channel ID in the header.
func CreateSignedEnvelope(t *testing.T, channelID string, signer msp.SigningIdentity, payload []byte) *common.Envelope {
	t.Helper()

	env, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_MESSAGE,
		channelID,
		signer,
		&common.Payload{Data: payload},
		0, // msgVersion
		0, // epoch
	)
	require.NoError(t, err, "failed to create signed envelope")
	return env
}

// CreateUnsignedEnvelope creates an unsigned envelope for testing ACL rejection.
// This envelope will fail ACL checks because it has no valid signature.
func CreateUnsignedEnvelope(t *testing.T, channelID string) *common.Envelope {
	t.Helper()

	env, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_MESSAGE,
		channelID,
		nil, // no signer
		&common.Payload{Data: []byte("test payload")},
		0, // msgVersion
		0, // epoch
	)
	require.NoError(t, err, "failed to create unsigned envelope")
	return env
}

// Made with Bob
