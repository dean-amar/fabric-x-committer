/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ordererconn

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// Config defines the static configuration of the orderer client as loaded from YAML file.
	// It supports connectivity to multiple organization's orderer.
	Config struct {
		CommonConfig  `mapstructure:",squash"`
		Organizations []*OrganizationConfig `mapstructure:"connection"`
	}
	// Parameters define the fully resolved runtime configuration of the orderer
	// client.
	Parameters struct {
		CommonConfig
		Organizations []*OrganizationParameters
	}
	// CommonConfig contains configuration fields shared between Config and
	// Parameters.
	// These settings define the orderer client, including consensus and channel identity, client MSP configuration,
	// retry behavior, and TLS settings.
	CommonConfig struct {
		ConsensusType string                      `mapstructure:"consensus-type"`
		ChannelID     string                      `mapstructure:"channel-id"`
		Identity      *IdentityConfig             `mapstructure:"identity"`
		Retry         *connection.RetryProfile    `mapstructure:"reconnect"`
		TLS           connection.OrdererTLSConfig `mapstructure:"tls"`
	}
	// IdentityConfig defines the orderer's MSP.
	IdentityConfig struct {
		// MspID indicates to which MSP this client belongs to.
		MspID  string               `mapstructure:"msp-id" yaml:"msp-id"`
		MSPDir string               `mapstructure:"msp-dir" yaml:"msp-dir"`
		BCCSP  *factory.FactoryOpts `mapstructure:"bccsp" yaml:"bccsp"`
	}
	// OrganizationConfig contains the MspID (Organization ID), orderer endpoints, and their TLS config.
	OrganizationConfig struct {
		MspID     string                         `mapstructure:"msp-id" yaml:"msp-id"`
		Endpoints []*commontypes.OrdererEndpoint `mapstructure:"endpoints"`
		CACerts   []string                       `mapstructure:"ca-cert-paths"`
	}
	// OrganizationParameters contains the MspID (Organization ID), orderer endpoints, and their TLS config.
	OrganizationParameters struct {
		OrganizationConfig
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

// ToParams converts the orderer's config into a parameter struct that holds the Root CAs certificates in bytes.
func (c *Config) ToParams() *Parameters {
	orgParams := make([]*OrganizationParameters, 0, len(c.Organizations))
	for _, org := range c.Organizations {
		orgParams = append(orgParams, org.ToParams())
	}
	sc := c.CommonConfig
	return &Parameters{
		CommonConfig:  sc,
		Organizations: orgParams,
	}
}

// ToParams converts the Organization Config into a parameter struct.
// @TODO: convert the organizationConfig into OrganizationParameters with the bytes. split the implementations.
func (o OrganizationConfig) ToParams() *OrganizationParameters {
	return &OrganizationParameters{
		OrganizationConfig: o,
	}
}

// CreateOrdererConnectionParameters comment will be added.
func (c *Parameters) CreateOrdererConnectionParameters(
	organizationParams *OrganizationParameters, endpoints []*connection.Endpoint,
) (*OrdererConnectionParameters, error) {
	tlsConfig := c.TLS.ToTLSConfig()
	tlsConfig.CACertPaths = append(tlsConfig.CACertPaths, organizationParams.CACerts...)

	tlsParams, err := tlsConfig.ToParams()
	if err != nil {
		return nil, errors.Wrap(err, "could not convert to TLS parameters")
	}
	tlsParams.CACerts = append(tlsParams.CACerts, organizationParams.CACertsBytes...)

	return &OrdererConnectionParameters{
		Endpoints: endpoints,
		TLS:       tlsParams,
		Retry:     c.Retry,
	}, nil
}

// ValidateConfig validate the configuration.
func ValidateConfig(c *Parameters) error {
	if c.ConsensusType == "" {
		c.ConsensusType = DefaultConsensus
	}
	if c.ConsensusType != Bft && c.ConsensusType != Cft {
		return errors.Newf("unsupported orderer type %s", c.ConsensusType)
	}
	return ValidateOrganizationParametersConfig(c.Organizations...)
}

// ValidateOrganizationParametersConfig validate the configuration.
func ValidateOrganizationParametersConfig(organizations ...*OrganizationParameters) error {
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
