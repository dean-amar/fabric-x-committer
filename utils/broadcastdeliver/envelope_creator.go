/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/serialization"
)

type (
	// EnvelopedStream implements broadcast, with the addition of automatically signing the envelope.
	EnvelopedStream struct {
		BroadcastStream
		channelID string
		signer    protoutil.Signer
	}

	// BroadcastStream can be either CFT or BFT broadcast.
	BroadcastStream interface {
		Send(*common.Envelope) error
	}
)

// SendWithEnv wraps a payload with an envelope, signs it and send it to the stream.
func (s *EnvelopedStream) SendWithEnv(dataMsg proto.Message) (string, error) {
	env, txID, err := serialization.CreateEnvelope(s.channelID, s.signer, dataMsg)
	if err != nil {
		return txID, errors.Wrap(err, "error serializing envelope")
	}
	err = s.Send(env)
	return txID, errors.Wrap(err, "error submitting envelope")
}
