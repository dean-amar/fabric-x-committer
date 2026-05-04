/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
)

// extractChannelID extracts the channel ID from the envelope's channel header.
func extractChannelID(envelope *common.Envelope) (string, error) {
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal payload")
	}

	channelHeader, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal channel header")
	}

	if channelHeader.ChannelId == "" {
		return "", errors.New("channel ID is empty in envelope")
	}

	return channelHeader.ChannelId, nil
}

// extractSignedData extracts SignedData from envelope for policy evaluation.
// This is used by the policy framework to verify signatures and evaluate policies.
func extractSignedData(envelope *common.Envelope) ([]*protoutil.SignedData, error) {
	signedData, err := protoutil.EnvelopeAsSignedData(envelope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract signed data from envelope")
	}
	return signedData, nil
}
