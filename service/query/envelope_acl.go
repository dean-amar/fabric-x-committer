/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	msppb "github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/policies"
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

func (q *Service) authorizeAndUnmarshal(ctx context.Context, envelope *cb.Envelope, msg proto.Message) error {
	logger.Infof("ACL: authorizeAndUnmarshal start policy=%s hasEnvelope=%t hasMsg=%t",
		q.acl.policyName, envelope != nil, msg != nil)

	payload, err := q.acl.authorize(ctx, q.batcher.pool, envelope)
	if err != nil {
		logger.Infof("ACL: authorizeAndUnmarshal failed policy=%s err=%v", q.acl.policyName, err)
		return err
	}
	if msg == nil {
		logger.Infof("ACL: authorizeAndUnmarshal completed policy=%s without message unmarshal", q.acl.policyName)
		return nil
	}

	logger.Infof("ACL: unmarshalling envelope data policy=%s msgType=%T payloadSize=%d",
		q.acl.policyName, msg, len(payload.Data))
	if err := proto.Unmarshal(payload.Data, msg); err != nil {
		logger.Infof("ACL: envelope data unmarshal failed policy=%s msgType=%T err=%v",
			q.acl.policyName, msg, err)
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal envelope data"))
	}
	logger.Infof("ACL: authorizeAndUnmarshal completed policy=%s msgType=%T", q.acl.policyName, msg)
	return nil
}

func (a *envelopeACL) authorize(
	ctx context.Context,
	queryObj querier,
	envelope *cb.Envelope,
) (*cb.Payload, error) {
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

	logger.Infof("ACL: loading config transaction policy=%s", a.policyName)
	configTx, err := queryConfig(ctx, queryObj)
	if err != nil {
		logger.Infof("ACL: failed to load config transaction policy=%s err=%v", a.policyName, err)
		return nil, grpcerror.WrapInternalError(err)
	}
	if len(configTx.Envelope) == 0 {
		logger.Infof("ACL: config transaction unavailable policy=%s", a.policyName)
		return nil, grpcerror.WrapFailedPrecondition(errors.New("config transaction is not available"))
	}

	logger.Infof("ACL: unmarshalling config envelope policy=%s configEnvelopeSize=%d",
		a.policyName, len(configTx.Envelope))
	configEnvelope, err := protoutil.UnmarshalEnvelope(configTx.Envelope)
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
	logIdentityProtoCertificateDetails("ACL: identity from signature (proto)", a.policyName, identityProto.GetMspId(), identityProto)

	logger.Infof("ACL: extracted creator identity policy=%s mspID=%s identity=%v",
		a.policyName, identityProto.GetMspId(), identityProto)

	logger.Infof("ACL: deserializing creator identity policy=%s mspID=%s",
		a.policyName, identityProto.GetMspId())
	identity, err := bundle.MSPManager().DeserializeIdentity(identityProto)
	if err != nil {
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

func logCertificateDetails(message, policyName, mspID string, identity interface{}) {
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

	// ⭐ EXTRACT OU FIELD ⭐
	role := "unknown"
	ouFields := cert.Subject.OrganizationalUnit // This is the OU field array
	if len(ouFields) > 0 {
		role = ouFields[0] // First OU is typically the role
	}

	// ⭐ LOG WITH OU FIELD PROMINENTLY ⭐
	logger.Infof(
		"%s policy=%s mspID=%s OU=%s role=%s cn=%s allOUs=%v serialNumber=%s subject=%s issuer=%s",
		message,
		policyName,
		mspID,
		role, // ⭐ PRIMARY OU (role)
		role, // Same as OU for clarity
		cert.Subject.CommonName,
		cert.Subject.OrganizationalUnit, // ⭐ ALL OU FIELDS
		cert.SerialNumber.String(),
		cert.Subject.String(),
		cert.Issuer.String(),
	)
}

func logIdentityProtoCertificateDetails(message, policyName, mspID string, identityProto *msppb.Identity) {
	if identityProto == nil {
		logger.Infof("%s policy=%s mspID=%s identityProto=nil", message, policyName, mspID)
		return
	}

	certPEM := identityProto.GetCertificate()
	if len(certPEM) == 0 {
		logger.Infof("%s policy=%s mspID=%s certificate=missing",
			message, policyName, mspID)
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		logger.Infof("%s policy=%s mspID=%s certificatePEMDecode=failed certPEMLength=%d",
			message, policyName, mspID, len(certPEM))
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Infof("%s policy=%s mspID=%s certificateParseErr=%v",
			message, policyName, mspID, err)
		return
	}

	// ⭐ EXTRACT OU FIELD ⭐
	role := "unknown"
	ouFields := cert.Subject.OrganizationalUnit // This is the OU field array
	if len(ouFields) > 0 {
		role = ouFields[0] // First OU is typically the role
	}

	// ⭐ LOG WITH OU FIELD PROMINENTLY ⭐
	logger.Infof(
		"%s policy=%s mspID=%s OU=%s role=%s cn=%s allOUs=%v serialNumber=%s subject=%s issuer=%s",
		message,
		policyName,
		mspID,
		role, // ⭐ PRIMARY OU (role)
		role, // Same as OU for clarity
		cert.Subject.CommonName,
		cert.Subject.OrganizationalUnit, // ⭐ ALL OU FIELDS
		cert.SerialNumber.String(),
		cert.Subject.String(),
		cert.Issuer.String(),
	)
}

//func logCertificateDetails(message, policyName, mspID string, identity interface{}) {
//	certIdentity, ok := identity.(interface {
//		GetX509Certificate() interface{}
//	})
//	if !ok {
//		logger.Infof("%s policy=%s mspID=%s identityType=%T certificate=unavailable",
//			message, policyName, mspID, identity)
//		return
//	}
//
//	certObj := certIdentity.GetX509Certificate()
//	cert, ok := certObj.(*x509.Certificate)
//	if !ok || cert == nil {
//		logger.Infof("%s policy=%s mspID=%s identityType=%T certificateType=%T certificate=unavailable",
//			message, policyName, mspID, identity, certObj)
//		return
//	}
//
//	role := ""
//	if len(cert.Subject.OrganizationalUnit) > 0 {
//		role = cert.Subject.OrganizationalUnit[0]
//	}
//	logger.Infof(
//		"%s policy=%s mspID=%s role=%s certSubject=%s issuer=%s serialNumber=%s ou=%v cn=%s",
//		message,
//		policyName,
//		mspID,
//		role,
//		cert.Subject.String(),
//		cert.Issuer.String(),
//		cert.SerialNumber.String(),
//		cert.Subject.OrganizationalUnit,
//		cert.Subject.CommonName,
//	)
//}
//
//func logIdentityProtoCertificateDetails(message, policyName, mspID string, identityProto *msppb.Identity) {
//	if identityProto == nil {
//		logger.Infof("%s policy=%s mspID=%s identityProto=nil", message, policyName, mspID)
//		return
//	}
//
//	certPEM := identityProto.GetCertificate()
//	if len(certPEM) == 0 {
//		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificate=missing",
//			message, policyName, mspID, identityProto)
//		return
//	}
//
//	block, _ := pem.Decode(certPEM)
//	if block == nil {
//		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificatePEMDecode=failed",
//			message, policyName, mspID, identityProto)
//		return
//	}
//
//	cert, err := x509.ParseCertificate(block.Bytes)
//	if err != nil {
//		logger.Infof("%s policy=%s mspID=%s identityProto=%v certificateParseErr=%v",
//			message, policyName, mspID, identityProto, err)
//		return
//	}
//
//	role := ""
//	if len(cert.Subject.OrganizationalUnit) > 0 {
//		role = cert.Subject.OrganizationalUnit[0]
//	}
//	logger.Infof(
//		"%s policy=%s mspID=%s role=%s certSubject=%s issuer=%s serialNumber=%s ou=%v cn=%s",
//		message,
//		policyName,
//		mspID,
//		role,
//		cert.Subject.String(),
//		cert.Issuer.String(),
//		cert.SerialNumber.String(),
//		cert.Subject.OrganizationalUnit,
//		cert.Subject.CommonName,
//	)
//}
//
//// Made with Bob
