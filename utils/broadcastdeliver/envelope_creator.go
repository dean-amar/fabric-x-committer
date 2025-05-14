/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
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
		Submit(*common.Envelope) (*ab.BroadcastResponse, error)
	}
)

// SubmitWithEnv wraps a payload with an envelope, signs it and submit it to the stream.
func (s *EnvelopedStream) SubmitWithEnv(dataMsg proto.Message) (string, *ab.BroadcastResponse, error) {
	env, txID, err := serialization.CreateEnvelope(s.channelID, s.signer, dataMsg)
	if err != nil {
		return txID, nil, errors.Wrap(err, "error serializing envelope")
	}
	resp, err := s.Submit(env)
	return txID, resp, errors.Wrap(err, "error submitting envelope")
}
