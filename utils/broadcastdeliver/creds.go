/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	cryptotls "crypto/tls"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric/msp"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	"gopkg.in/yaml.v3"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/tls"
)

// NewIdentitySigner instantiate a signer for the given identity.
func NewIdentitySigner(config *IdentityConfig) (msp.SigningIdentity, error) { //nolint:ireturn,nolintlint // bug.
	if config == nil {
		logger.Infof("No identity configuration. Skipping signer initialization")
		return nil, nil
	}
	if configBytes, err := yaml.Marshal(config); err == nil {
		logger.Infof("Initialize signer:\n%s", string(configBytes))
	} else {
		logger.Debugf("Cannot marshal identity config: %s", err)
	}

	if !config.SignedEnvelopes || config.MspID == "" || config.MSPDir == "" {
		logger.Infof("Skipping signer initialization")
		return nil, nil
	}

	mspConfig, err := msp.GetLocalMspConfig(config.MSPDir, config.BCCSP, config.MspID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load MSP config")
	}
	err = mspmgmt.GetLocalMSP(factory.GetDefault()).Setup(mspConfig)
	if err != nil { // Handle errors reading the config file
		return nil, errors.Wrap(err, "failed to initialize local MSP")
	}

	signer, err := mspmgmt.GetLocalMSP(factory.GetDefault()).GetDefaultSigningIdentity()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load local signing identity")
	}
	return signer, nil
}

// LoadTLSConfig returns TLS configuration for connections.
func LoadTLSConfig(config *ConnectionConfig) (*cryptotls.Config, error) {
	var conf *cryptotls.Config
	var err error
	switch {
	case len(config.RootCA) > 0:
		conf, err = tls.LoadTLSCredentialsRaw(config.RootCA)
	case len(config.RootCAPaths) > 0:
		conf, err = tls.LoadTLSCredentials(config.RootCAPaths)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to load TLS config")
	}
	return conf, nil
}

// IsTLSConfigEqual returns true of the two configurations are equal.
func IsTLSConfigEqual(c1, c2 *cryptotls.Config) bool {
	if c1 == nil && c2 == nil {
		return true
	}
	if c1 == nil || c2 == nil {
		return false
	}
	return c1.RootCAs.Equal(c2.RootCAs)
}
