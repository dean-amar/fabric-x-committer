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
		Organizations []*OrganizationConfig       `mapstructure:"organizations"`
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

// UpdateConfigFromParameters is a temporary workaround.
// Once the config-block-with-crypto tool is added, we will remove this function.
// For now, it's saving the initialized root CAs we got from the config
// and uses them for the updated orderer endpoints that arrived from the config block.
func (c *Config) UpdateConfigFromParameters(parameters []*OrganizationParameters) {
	if len(parameters) == 0 {
		return
	}

	var caCerts []string
	if len(c.Organizations) > 0 {
		caCerts = c.Organizations[0].CACerts
	}

	c.Organizations = make([]*OrganizationConfig, 0, len(parameters))
	for _, p := range parameters {
		org := &OrganizationConfig{
			MspID:   p.MspID,
			CACerts: caCerts,
		}
		if len(p.Endpoints) > 0 {
			org.Endpoints = append([]*commontypes.OrdererEndpoint(nil), p.Endpoints...)
		}
		c.Organizations = append(c.Organizations, org)
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

// ValidateOrganizationConfig validate the organization configuration.
func ValidateOrganizationConfig(organizations ...*OrganizationConfig) error {
	for _, org := range organizations {
		if org == nil {
			return ErrEmptyConnectionConfig
		}
		if err := validateEndpoints(org.Endpoints); err != nil {
			return err
		}
	}
	return nil
}

// ValidateOrganizationParameters validate the organization parameters.
func ValidateOrganizationParameters(organizations ...*OrganizationParameters) error {
	for _, org := range organizations {
		if org == nil {
			return ErrEmptyConnectionConfig
		}
		if err := validateEndpoints(org.Endpoints); err != nil {
			return err
		}
	}
	return nil
}

func validateEndpoints(endpoints []*commontypes.OrdererEndpoint) error {
	if len(endpoints) == 0 {
		return ErrNoEndpoints
	}
	uniqueEndpoints := make(map[string]string, len(endpoints))
	for _, e := range endpoints {
		if e == nil || e.Host == "" || e.Port == 0 {
			return ErrEmptyEndpoint
		}
		target := e.Address()
		if other, ok := uniqueEndpoints[target]; ok {
			return errors.Newf("endpoint [%s] specified multiple times: %s, %s", target, other, e.String())
		}
		uniqueEndpoints[target] = e.String()
	}
	return nil
}
