/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ordererconn

import (
	"os"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// Config defines the static configuration of the orderer client as loaded from YAML file.
	// It supports connectivity to multiple organization's orderer.
	Config struct {
		ConsensusType string                      `mapstructure:"consensus-type"`
		ChannelID     string                      `mapstructure:"channel-id"`
		Identity      *IdentityConfig             `mapstructure:"identity"`
		Retry         *connection.RetryProfile    `mapstructure:"reconnect"`
		TLS           connection.OrdererTLSConfig `mapstructure:"tls"`
		Organizations []*OrganizationConfig       `mapstructure:"connection"`
	}
	// IdentityConfig defines the orderer's MSP.
	IdentityConfig struct {
		// MspID indicates to which MSP this client belongs to.
		MspID  string               `mapstructure:"msp-id" yaml:"msp-id"`
		MSPDir string               `mapstructure:"msp-dir" yaml:"msp-dir"`
		BCCSP  *factory.FactoryOpts `mapstructure:"bccsp" yaml:"bccsp"`
	}
	// OrganizationConfig contains the MspID (Organization ID), orderer endpoints, and their root CA paths.
	OrganizationConfig struct {
		MspID     string                         `mapstructure:"msp-id" yaml:"msp-id"`
		Endpoints []*commontypes.OrdererEndpoint `mapstructure:"endpoints"`
		CACerts   []string                       `mapstructure:"ca-cert-paths"`
	}
	// OrganizationParameters contains the MspID (Organization ID), orderer endpoints, and their root CAs in bytes.
	OrganizationParameters struct {
		MspID        string
		Endpoints    []*commontypes.OrdererEndpoint
		CACertsBytes [][]byte
	}
	// OrdererConnectionParameters is the orderer client config with tls parameters already loaded bytes.
	OrdererConnectionParameters struct {
		Endpoints []*connection.Endpoint
		TLS       *connection.TLSParameters
		Retry     *connection.RetryProfile
	}
)

const (
	// Cft client support for crash fault tolerance.
	Cft = "CFT"
	// Bft client support for byzantine fault tolerance.
	Bft = "BFT"
	// DefaultConsensus default fault tolerance.
	DefaultConsensus = Cft

	// Broadcast support by endpoint.
	Broadcast = "broadcast"
	// Deliver support by endpoint.
	Deliver = "deliver"
)

// Errors that may be returned when updating a configuration.
var (
	ErrEmptyConnectionConfig = errors.New("empty connection config")
	ErrEmptyEndpoint         = errors.New("empty endpoint")
	ErrNoEndpoints           = errors.New("no endpoints")
)

// OrganizationConfigToParameters converts list of OrganizationConfig to OrganizationParameters.
func (c *Config) OrganizationConfigToParameters() ([]*OrganizationParameters, error) {
	orgParams := make([]*OrganizationParameters, 0, len(c.Organizations))
	for _, orgConfig := range c.Organizations {
		orgParam, err := orgConfig.ToParams(c.TLS.Mode)
		if err != nil {
			return nil, errors.Wrapf(err, "could not convert organization config into parameters")
		}
		orgParams = append(orgParams, orgParam)
	}
	return orgParams, nil
}

// ToParams converts the Organization Config into a parameter struct.
func (o *OrganizationConfig) ToParams(tlsMode string) (*OrganizationParameters, error) {
	orgParams := &OrganizationParameters{
		MspID:        o.MspID,
		Endpoints:    o.Endpoints,
		CACertsBytes: make([][]byte, 0),
	}
	if tlsMode == connection.NoneTLSMode || tlsMode == connection.UnmentionedTLSMode {
		return orgParams, nil
	}
	for _, caPath := range o.CACerts {
		caBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load CA certificate from %s", caBytes)
		}
		orgParams.CACertsBytes = append(orgParams.CACertsBytes, caBytes)
	}
	return orgParams, nil
}

// ReadOnlyEndpointsFromOrgParameters is a temp function that will be removed once we support
// having root CAs in the config block.
// For now, it is reading the config-block organization information but uses it all but the root CAs.
func ReadOnlyEndpointsFromOrgParameters(
	organizationConfig []*OrganizationConfig, organizationParameters []*OrganizationParameters,
) {
	if len(organizationConfig) != len(organizationParameters) {
		return
	}
	// we are only changing the endpoints and MSP IDs, leaving the rootCAs as they are.
	for i := range organizationConfig {
		organizationConfig[i].MspID = organizationParameters[i].MspID
		organizationConfig[i].Endpoints = organizationParameters[i].Endpoints
	}
}

// ValidateConfig validate the configuration.
func ValidateConfig(c *Config) error {
	if c.ConsensusType == "" {
		c.ConsensusType = DefaultConsensus
	}
	if c.ConsensusType != Bft && c.ConsensusType != Cft {
		return errors.Newf("unsupported orderer type %s", c.ConsensusType)
	}
	return ValidateOrganizationConfig(c.Organizations...)
}

// ValidateOrganizationConfig validate the configuration.
func ValidateOrganizationConfig(organizations ...*OrganizationConfig) error {
	for _, org := range organizations {
		if org == nil {
			return ErrEmptyConnectionConfig
		}
		if len(org.Endpoints) == 0 {
			return ErrNoEndpoints
		}
		uniqueEndpoints := make(map[string]string)
		for _, e := range org.Endpoints {
			if e.Host == "" || e.Port == 0 {
				return ErrEmptyEndpoint
			}
			target := e.Address()
			if other, ok := uniqueEndpoints[target]; ok {
				return errors.Newf("endpoint [%s] specified multiple times: %s, %s", target, other, e.String())
			}
			uniqueEndpoints[target] = e.String()
		}
	}
	return nil
}

// ValidateOrganizationParameters validate the configuration.
func ValidateOrganizationParameters(organizations ...*OrganizationParameters) error {
	for _, org := range organizations {
		if org == nil {
			return ErrEmptyConnectionConfig
		}
		if len(org.Endpoints) == 0 {
			return ErrNoEndpoints
		}
		uniqueEndpoints := make(map[string]string)
		for _, e := range org.Endpoints {
			if e.Host == "" || e.Port == 0 {
				return ErrEmptyEndpoint
			}
			target := e.Address()
			if other, ok := uniqueEndpoints[target]; ok {
				return errors.Newf("endpoint [%s] specified multiple times: %s, %s", target, other, e.String())
			}
			uniqueEndpoints[target] = e.String()
		}
	}
	return nil
}
