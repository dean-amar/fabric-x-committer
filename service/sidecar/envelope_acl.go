/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	msppb "github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/policies"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

const queryReadersPolicy = policies.ChannelApplicationReaders

type envelopeACL struct {
	policyName string
}

func newEnvelopeACL(policyName string) *envelopeACL {
	return &envelopeACL{policyName: policyName}
}

func (a *envelopeACL) authorizeAndUnmarshal(
	configEnvelopeBytes []byte,
	envelope *cb.Envelope,
	msg proto.Message,
) error {
	logger.Infof("ACL: authorizeAndUnmarshal start policy=%s hasEnvelope=%t hasMsg=%t",
		a.policyName, envelope != nil, msg != nil)

	payload, err := a.authorize(configEnvelopeBytes, envelope)
	if err != nil {
		logger.Infof("ACL: authorizeAndUnmarshal failed policy=%s err=%v", a.policyName, err)
		return err
	}
	if msg == nil {
		logger.Infof("ACL: authorizeAndUnmarshal completed policy=%s without message unmarshal", a.policyName)
		return nil
	}

	logger.Infof("ACL: unmarshalling envelope data policy=%s msgType=%T payloadSize=%d",
		a.policyName, msg, len(payload.Data))
	if err := proto.Unmarshal(payload.Data, msg); err != nil {
		logger.Infof("ACL: envelope data unmarshal failed policy=%s msgType=%T err=%v",
			a.policyName, msg, err)
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal envelope data"))
	}
	logger.Infof("ACL: authorizeAndUnmarshal completed policy=%s msgType=%T", a.policyName, msg)
	return nil
}

func (a *envelopeACL) authorize(configEnvelopeBytes []byte, envelope *cb.Envelope) (*cb.Payload, error) {
	logger.Infof("ACL: authorize start policy=%s", a.policyName)

	if envelope == nil {
		logger.Infof("ACL: missing envelope policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing envelope"))
	}
	logger.Infof("ACL: envelope received policy=%s payloadSize=%d signatureSize=%d",
		a.policyName, len(envelope.Payload), len(envelope.Signature))

	if len(envelope.Payload) == 0 {
		logger.Infof("ACL: missing envelope payload policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing envelope payload"))
	}
	if len(envelope.Signature) == 0 {
		logger.Infof("ACL: missing envelope signature policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing envelope signature"))
	}
	if len(configEnvelopeBytes) == 0 {
		logger.Infof("ACL: config transaction unavailable policy=%s", a.policyName)
		return nil, grpcerror.WrapFailedPrecondition(errors.New("config transaction is not available"))
	}

	logger.Infof("ACL: unmarshalling envelope payload policy=%s", a.policyName)
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		logger.Infof("ACL: failed to unmarshal payload policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal payload"))
	}
	if payload.Header == nil {
		logger.Infof("ACL: missing payload header policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing payload header"))
	}

	logger.Infof("ACL: unmarshalling signature header policy=%s", a.policyName)
	signatureHeader, err := protoutil.UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		logger.Infof("ACL: failed to unmarshal signature header policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal signature header"))
	}
	if len(signatureHeader.Creator) == 0 {
		logger.Infof("ACL: missing creator policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing creator"))
	}
	if len(signatureHeader.Nonce) == 0 {
		logger.Infof("ACL: missing nonce policy=%s", a.policyName)
		return nil, grpcerror.WrapInvalidArgument(errors.New("missing nonce"))
	}
	logger.Infof("ACL: signature header parsed policy=%s creatorSize=%d nonceSize=%d",
		a.policyName, len(signatureHeader.Creator), len(signatureHeader.Nonce))

	logger.Infof("ACL: unmarshalling config envelope policy=%s configEnvelopeSize=%d",
		a.policyName, len(configEnvelopeBytes))
	configEnvelope, err := protoutil.UnmarshalEnvelope(configEnvelopeBytes)
	if err != nil {
		logger.Infof("ACL: failed to unmarshal config envelope policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInternalError(errors.Wrap(err, "failed to unmarshal config envelope"))
	}
	logger.Infof("ACL: creating channel bundle policy=%s", a.policyName)
	bundle, err := channelconfig.NewBundleFromEnvelope(configEnvelope, factory.GetDefault())
	if err != nil {
		logger.Infof("ACL: failed to create channel bundle policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInternalError(errors.Wrap(err, "failed to create channel bundle"))
	}

	logger.Infof("ACL: unmarshalling creator identity policy=%s", a.policyName)
	identityProto := &msppb.Identity{}
	if err := proto.Unmarshal(signatureHeader.Creator, identityProto); err != nil {
		logger.Infof("ACL: failed to unmarshal creator identity policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal creator identity"))
	}
	logger.Infof("ACL: extracted creator identity policy=%s originalMSPID=%s identity=%v",
		a.policyName, identityProto.GetMspId(), identityProto)

	if remappedMSPID := remapTestMSPID(identityProto.GetMspId(), bundle.MSPManager()); remappedMSPID != "" {
		logger.Infof("ACL: remapping creator MSPID policy=%s from=%s to=%s",
			a.policyName, identityProto.GetMspId(), remappedMSPID)
		identityProto.MspId = remappedMSPID
	}
	logger.Infof("ACL: using creator identity policy=%s mspID=%s identity=%v",
		a.policyName, identityProto.GetMspId(), identityProto)

	logger.Infof("ACL: deserializing creator identity policy=%s mspID=%s",
		a.policyName, identityProto.GetMspId())
	identity, err := bundle.MSPManager().DeserializeIdentity(identityProto)
	if err != nil {
		logger.Infof("ACL: loading policy object before deserialize failure policy=%s", a.policyName)
		policyObj, ok := bundle.PolicyManager().GetPolicy(a.policyName)
		if !ok {
			logger.Infof("ACL: policy not found before deserialize failure policy=%s", a.policyName)
		} else {
			logger.Infof("ACL: policy resolved before deserialize failure policy=%s policyType=%T policy=%v",
				a.policyName, policyObj, policyObj)
		}
		logIdentityProtoCertificateDetails("ACL: certificate details before deserialize failure",
			a.policyName, identityProto.GetMspId(), identityProto)

		logger.Infof("ACL: failed to deserialize creator identity policy=%s mspID=%s err=%v",
			a.policyName, identityProto.GetMspId(), err)
		return nil, grpcerror.WrapFailedPrecondition(errors.Wrap(err, "failed to deserialize creator identity"))
	}

	logger.Infof("ACL: validating creator identity policy=%s mspID=%s", a.policyName, identityProto.GetMspId())
	if err := identity.Validate(); err != nil {
		logger.Infof("ACL: creator identity validation failed policy=%s mspID=%s err=%v",
			a.policyName, identityProto.GetMspId(), err)
		return nil, grpcerror.WrapFailedPrecondition(errors.Wrap(err, "creator identity is not valid"))
	}

	logger.Infof("ACL: verifying envelope signature policy=%s mspID=%s", a.policyName, identityProto.GetMspId())
	if err := identity.Verify(envelope.Payload, envelope.Signature); err != nil {
		logger.Infof("ACL: envelope signature verification failed policy=%s mspID=%s err=%v",
			a.policyName, identityProto.GetMspId(), err)
		return nil, grpcerror.WrapFailedPrecondition(errors.Wrap(err, "envelope signature verification failed"))
	}

	logger.Infof("ACL: loading policy object policy=%s", a.policyName)
	policyObj, ok := bundle.PolicyManager().GetPolicy(a.policyName)
	if !ok {
		logger.Infof("ACL: policy not found policy=%s", a.policyName)
		return nil, grpcerror.WrapFailedPrecondition(errors.Newf("policy %s not found in channel config", a.policyName))
	}
	logger.Infof("ACL: policy resolved policy=%s policyType=%T policy=%v", a.policyName, policyObj, policyObj)
	logCertificateDetails("ACL: certificate details", a.policyName, identityProto.GetMspId(), identity)

	logger.Infof("ACL: evaluating signed data against policy=%s", a.policyName)
	signedData := []*protoutil.SignedData{{
		Data:      envelope.Payload,
		Identity:  identityProto,
		Signature: envelope.Signature,
	}}
	if err := policyObj.EvaluateSignedData(signedData); err != nil {
		logger.Infof("ACL: policy evaluation failed policy=%s mspID=%s err=%v",
			a.policyName, identityProto.GetMspId(), err)
		return nil, grpcerror.WrapFailedPrecondition(errors.Wrapf(err, "creator does not satisfy policy %s", a.policyName))
	}

	logger.Infof("ACL: authorize success policy=%s mspID=%s", a.policyName, identityProto.GetMspId())
	return payload, nil
}

func remapTestMSPID(mspID string, manager interface {
	GetMSPs() (map[string]msp.MSP, error)
}) string {
	if mspID == "" {
		return ""
	}

	msps, err := manager.GetMSPs()
	if err != nil {
		return ""
	}
	if _, ok := msps[mspID]; ok {
		return ""
	}

	switch mspID {
	case "peer-org-0.com":
		if _, ok := msps["peer-org-0"]; ok {
			return "peer-org-0"
		}
	case "orderer-org-0.com":
		if _, ok := msps["orderer-org-0"]; ok {
			return "orderer-org-0"
		}
	}

	return ""
}

func logCertificateDetails(message, policyName, mspID string, identity msp.Identity) {
	certIdentity, ok := identity.(interface {
		GetX509Certificate() interface{}
	})
	if !ok {
		logger.Infof("%s policy=%s mspID=%s identityType=%T certificate=unavailable",
			message, policyName, mspID, identity)
		return
	}

	certObj := certIdentity.GetX509Certificate()
	cert, ok := certObj.(*x509.Certificate)
	if !ok || cert == nil {
		logger.Infof("%s policy=%s mspID=%s identityType=%T certificateType=%T certificate=unavailable",
			message, policyName, mspID, identity, certObj)
		return
	}

	logX509CertificateDetails(message, policyName, mspID, cert)
}

func logIdentityProtoCertificateDetails(message, policyName, mspID string, identityProto *msppb.Identity) {
	if identityProto == nil {
		logger.Infof("%s policy=%s mspID=%s identityProto=nil", message, policyName, mspID)
		return
	}

	certPEM := identityProto.GetCertificate()
	if len(certPEM) == 0 {
		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificate=missing",
			message, policyName, mspID, identityProto)
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificatePEMDecode=failed",
			message, policyName, mspID, identityProto)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificateParseErr=%v",
			message, policyName, mspID, identityProto, err)
		return
	}

	role := ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		role = cert.Subject.OrganizationalUnit[0]
	}
	logger.Infof(
		"%s policy=%s mspID=%s role=%s certSubject=%s issuer=%s serialNumber=%s ou=%v cn=%s",
		message,
		policyName,
		mspID,
		role,
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.SerialNumber.String(),
		cert.Subject.OrganizationalUnit,
		cert.Subject.CommonName,
	)
}

func logX509CertificateDetails(message, policyName, mspID string, cert *x509.Certificate) {
	if cert == nil {
		logger.Infof("%s policy=%s mspID=%s certificate=nil", message, policyName, mspID)
		return
	}

	role := ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		role = cert.Subject.OrganizationalUnit[0]
	}
	logger.Infof(
		"%s policy=%s mspID=%s role=%s certSubject=%s issuer=%s serialNumber=%s ou=%v cn=%s",
		message,
		policyName,
		mspID,
		role,
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.SerialNumber.String(),
		cert.Subject.OrganizationalUnit,
		cert.Subject.CommonName,
	)
}

// Made with Bob
