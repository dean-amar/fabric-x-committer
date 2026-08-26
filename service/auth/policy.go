/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/protobuf/proto"
)

// policyReaders is the Application Readers policy every exposed resource maps to by default.
const policyReaders = "/Channel/Application/Readers"

// ErrNoPolicyForResource is returned when neither the channel configuration's ACLs section nor the
// built-in default map defines a policy for a resource.
var ErrNoPolicyForResource = errors.New("no policy defined for resource")

// defaultResourcePolicy is the hard-coded fallback resource-to-policy map, consulted when the
// channel configuration does not define an ACL for a resource. Every exposed method - the query
// service, the sidecar's block query and block delivery, and the notification streams - defaults to
// the Application Readers policy.
var defaultResourcePolicy = map[string]string{
	committerpb.QueryService_GetRows_FullMethodName:              policyReaders,
	committerpb.QueryService_BeginView_FullMethodName:            policyReaders,
	committerpb.QueryService_EndView_FullMethodName:              policyReaders,
	committerpb.QueryService_GetNamespacePolicies_FullMethodName: policyReaders,
	committerpb.QueryService_GetConfigTransaction_FullMethodName: policyReaders,
	committerpb.QueryService_GetTransactionStatus_FullMethodName: policyReaders,

	committerpb.BlockQueryService_GetBlockchainInfo_FullMethodName: policyReaders,
	committerpb.BlockQueryService_GetBlockByNumber_FullMethodName:  policyReaders,
	committerpb.BlockQueryService_GetBlockByTxID_FullMethodName:    policyReaders,
	committerpb.BlockQueryService_GetTxByID_FullMethodName:         policyReaders,

	committerpb.Notifier_OpenNotificationStream_FullMethodName: policyReaders,
	committerpb.Notifier_StreamAllTransactions_FullMethodName:  policyReaders,

	peer.Deliver_Deliver_FullMethodName:                policyReaders,
	peer.Deliver_DeliverFiltered_FullMethodName:        policyReaders,
	peer.Deliver_DeliverWithPrivateData_FullMethodName: policyReaders,
}

// resolvePolicyRef returns the channel-policy reference governing a resource. The channel
// configuration's ACLs mapping takes precedence; the built-in default map is the fallback. It
// returns "" when neither defines the resource.
func resolvePolicyRef(bundle *channelconfig.Bundle, resource string) string {
	if app, ok := bundle.ApplicationConfig(); ok {
		if ref := app.APIPolicyMapper().PolicyRefForAPI(resource); ref != "" {
			return ref
		}
	}
	return defaultResourcePolicy[resource]
}

// evaluateResourcePolicy re-resolves a token record's serialized identity against the latest bundle
// and evaluates it against the resource's policy. Re-resolving on every call is what lets a
// configuration change (a removed organization, a rotated MSP) take effect immediately. It returns
// ErrNoPolicyForResource when no policy governs the resource, or the policy evaluation error when
// the identity is not authorized.
func evaluateResourcePolicy(bundle *channelconfig.Bundle, resource string, serializedIdentity []byte) error {
	serialized := &msppb.Identity{}
	if err := proto.Unmarshal(serializedIdentity, serialized); err != nil {
		return errors.Wrap(err, "failed to unmarshal serialized identity")
	}
	identity, err := bundle.MSPManager().DeserializeIdentity(serialized)
	if err != nil {
		return errors.Wrap(err, "identity is no longer valid under the current configuration")
	}

	ref := resolvePolicyRef(bundle, resource)
	if ref == "" {
		return errors.Wrapf(ErrNoPolicyForResource, "resource %s", resource)
	}
	policy, ok := bundle.PolicyManager().GetPolicy(ref)
	if !ok {
		return errors.Wrapf(ErrNoPolicyForResource, "policy %s for resource %s is absent from the channel config",
			ref, resource)
	}
	if err = policy.EvaluateIdentities([]msp.Identity{identity}); err != nil {
		// Return the bare reason; the resource-server interceptor prefixes it with the resource
		// name so the "ACL check failed for [resource]:" context appears exactly once.
		return errors.Wrap(err, "identity is not authorized by the resource policy")
	}
	return nil
}
