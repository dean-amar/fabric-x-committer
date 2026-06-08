/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"crypto/sha256"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	msppb "github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/proto"
)

// ExtractIdentityFromEnvelope extracts and validates the MSP identity from a signed envelope.
// It returns the deserialized identity, MSPID, and TLS cert hash from the envelope.
func ExtractIdentityFromEnvelope(
	envelope *cb.Envelope,
	bundle *channelconfig.Bundle,
) (identity msp.Identity, mspID string, tlsCertHash []byte, err error) {
	// 1. Unmarshal payload using protoutil helper
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, "", nil, errors.Wrap(err, "failed to unmarshal payload")
	}

	if payload.Header == nil {
		return nil, "", nil, errors.New("missing payload header")
	}

	// 2. Extract channel header to get TLS cert hash
	channelHeader, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, "", nil, errors.Wrap(err, "failed to unmarshal channel header")
	}
	tlsCertHash = channelHeader.TlsCertHash

	// 3. Extract signature header using protoutil helper
	signatureHeader, err := protoutil.UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return nil, "", nil, errors.Wrap(err, "failed to unmarshal signature header")
	}

	if len(signatureHeader.Creator) == 0 {
		return nil, "", nil, errors.New("missing creator in signature header")
	}

	// 4. Unmarshal the identity protobuf from Creator
	// This is the msppb.Identity type from fabric-x-common/api/msppb
	identityProto := &msppb.Identity{}
	if err := proto.Unmarshal(signatureHeader.Creator, identityProto); err != nil {
		return nil, "", nil, errors.Wrap(err, "failed to unmarshal creator identity")
	}

	mspID = identityProto.GetMspId()

	// 5. Get the MSP manager from bundle (it implements IdentityDeserializer)
	idDeserializer := bundle.MSPManager()

	// 6. Deserialize the identity using the MSP manager
	// DeserializeIdentity takes *msppb.Identity and returns msp.Identity
	identity, err = idDeserializer.DeserializeIdentity(identityProto)
	if err != nil {
		return nil, "", nil, errors.Wrap(err, "failed to deserialize identity")
	}

	// 7. Validate the identity
	if err := identity.Validate(); err != nil {
		return nil, "", nil, errors.Wrap(err, "identity validation failed")
	}

	// 8. Verify the signature
	if err := identity.Verify(envelope.Payload, envelope.Signature); err != nil {
		return nil, "", nil, errors.Wrap(err, "signature verification failed")
	}

	return identity, mspID, tlsCertHash, nil
}

// VerifyTLSCertBinding verifies that the TLS cert hash in the envelope matches
// the actual TLS certificate hash from the connection.
func VerifyTLSCertBinding(envelopeTLSCertHash []byte, connectionTLSCertHash []byte) error {
	if len(envelopeTLSCertHash) == 0 {
		return errors.New("envelope does not contain TLS cert hash")
	}

	if len(connectionTLSCertHash) == 0 {
		return errors.New("connection does not have TLS certificate")
	}

	if !bytes.Equal(envelopeTLSCertHash, connectionTLSCertHash) {
		return errors.Newf("TLS cert hash mismatch: envelope=%x, connection=%x",
			envelopeTLSCertHash, connectionTLSCertHash)
	}

	return nil
}

// ComputeTLSCertHash computes the SHA256 hash of a certificate's raw bytes.
func ComputeTLSCertHash(certRaw []byte) []byte {
	hash := sha256.Sum256(certRaw)
	return hash[:]
}
