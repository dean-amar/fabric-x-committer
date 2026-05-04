/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/policies"
	"github.com/hyperledger/fabric-x-common/protoutil"
)

// provider implements the ACL Provider interface.
type provider struct {
	bundleManager *BundleManager
}

// NewProvider creates a new ACL provider.
func NewProvider(bundleManager *BundleManager) Provider {
	return &provider{
		bundleManager: bundleManager,
	}
}

// CheckReadAccess verifies read access for the envelope.
// This is the main ACL enforcement point for all read operations in fabric-x-committer.
func (p *provider) CheckReadAccess(envelope *common.Envelope) error {
	// Step 1: Extract channel ID from envelope
	channelID, err := extractChannelID(envelope)
	if err != nil {
		return errors.Wrap(err, "failed to extract channel ID from envelope")
	}

	logger.Debugf("Checking read access for channel %s", channelID)

	// Step 2: Get channel config bundle
	bundle := p.bundleManager.GetChannelConfig(channelID)
	if bundle == nil {
		return errors.Errorf("channel config not found for channel %s", channelID)
	}

	// Step 3: Extract signed data from envelope
	signedData, err := extractSignedData(envelope)
	if err != nil {
		return errors.Wrap(err, "failed to extract signed data from envelope")
	}

	// Step 4: Get Readers policy from channel config
	// Use /Channel/Application/Readers as the standard read policy for all operations
	policyName := policies.ChannelApplicationReaders
	policy, ok := bundle.PolicyManager().GetPolicy(policyName)
	if !ok {
		return errors.Errorf("policy %s not found in channel config", policyName)
	}

	// Step 5: Evaluate policy
	err = policy.EvaluateSignedData(signedData)
	if err != nil {
		logger.Warnw("Read access denied",
			"channelID", channelID,
			"policy", policyName,
			"error", err)
		return errors.Wrapf(err, "access denied for channel %s", channelID)
	}

	logger.Debugf("Read access granted for channel %s", channelID)
	return nil
}

// UpdateFromConfigBlock updates the channel configuration bundle from a config block.
func (p *provider) UpdateFromConfigBlock(configBlock *common.Block) error {
	// Extract channel ID from the config block
	if len(configBlock.Data.Data) == 0 {
		return errors.New("config block has no data")
	}

	envelope, err := protoutil.UnmarshalEnvelope(configBlock.Data.Data[0])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal envelope from config block")
	}

	channelID, err := extractChannelID(envelope)
	if err != nil {
		return errors.Wrap(err, "failed to extract channel ID from config block")
	}

	return p.bundleManager.UpdateFromConfigBlock(channelID, configBlock)
}

// UpdateFromConfigEnvelope updates the channel configuration bundle from a config envelope.
func (p *provider) UpdateFromConfigEnvelope(envelopeBytes []byte) error {
	envelope, err := protoutil.UnmarshalEnvelope(envelopeBytes)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal config envelope")
	}

	channelID, err := extractChannelID(envelope)
	if err != nil {
		return errors.Wrap(err, "failed to extract channel ID from config envelope")
	}

	// Create a minimal block structure containing just the envelope
	// This is sufficient for LoadConfigBlockMaterial which only needs the envelope data
	configBlock := &common.Block{
		Data: &common.BlockData{
			Data: [][]byte{envelopeBytes},
		},
	}

	return p.bundleManager.UpdateFromConfigBlock(channelID, configBlock)
}
