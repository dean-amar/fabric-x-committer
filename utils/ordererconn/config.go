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
	// Config for the orderer-client.
	// It supports multi-organization connectivity with the same ledger and consensus type.
	Config struct {
		SharedOrdererConfig `mapstructure:",squash"`
		Connection          []*OrganizationConfig `mapstructure:"connection"`
	}

	Parameters struct {
		SharedOrdererConfig
		Connection []*OrganizationParameters
	}

	SharedOrdererConfig struct {
		ConsensusType string                      `mapstructure:"consensus-type"`
		ChannelID     string                      `mapstructure:"channel-id"`
		Identity      *IdentityConfig             `mapstructure:"identity"`
		Retry         *connection.RetryProfile    `mapstructure:"reconnect"`
		TLS           connection.OrdererTLSConfig `mapstructure:"tls"`
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

	// GateConfig acts as the full configuration after reading information from the config block.
	GateConfig struct {
		OrganizationParameters
		TLS   *connection.TLSParameters
		Retry *connection.RetryProfile
	}

	// IdentityConfig defines the orderer's MSP.
	IdentityConfig struct {
		// MspID indicates to which MSP this client belongs to.
		MspID  string               `mapstructure:"msp-id" yaml:"msp-id"`
		MSPDir string               `mapstructure:"msp-dir" yaml:"msp-dir"`
		BCCSP  *factory.FactoryOpts `mapstructure:"bccsp" yaml:"bccsp"`
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

func (c *Config) ToParams() *Parameters {
	orgParams := make([]*OrganizationParameters, 0, len(c.Connection))
	for _, org := range c.Connection {
		orgParams = append(orgParams, org.ToParams())
	}
	sc := c.SharedOrdererConfig
	return &Parameters{
		SharedOrdererConfig: sc,
		Connection:          orgParams,
	}
}

func (o OrganizationConfig) ToParams() *OrganizationParameters {
	return &OrganizationParameters{
		OrganizationConfig: o,
	}
}

// CreateConfigWithRequiredParams comment will be added.
func (c *Parameters) CreateConfigWithRequiredParams(ogp *OrganizationParameters) (*GateConfig, error) {
	tlsConfig := c.TLS.ConvertToTLSConfig()
	for _, caPath := range ogp.CACerts {
		tlsConfig.CACertPaths = append(tlsConfig.CACertPaths, caPath)
	}
	tlsParams, err := tlsConfig.ConvertToTLSParams()
	if err != nil {
		return nil, errors.Wrap(err, "could not convert to TLS params")
	}
	for _, caCertByte := range ogp.CACertsBytes {
		tlsParams.CACerts = append(tlsParams.CACerts, caCertByte)
	}
	return &GateConfig{
		OrganizationParameters: *ogp,
		TLS:                    tlsParams,
		Retry:                  c.Retry,
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
	for _, org := range c.Connection {
		if err := ValidateConnectionConfig(org); err != nil {
			return err
		}
	}
	return nil
}

// ValidateConnectionConfig validate the configuration.
func ValidateConnectionConfig(c *OrganizationParameters) error {
	if c == nil {
		return ErrEmptyConnectionConfig
	}
	if len(c.Endpoints) == 0 {
		return ErrNoEndpoints
	}
	uniqueEndpoints := make(map[string]string)
	for _, e := range c.Endpoints {
		if e.Host == "" || e.Port == 0 {
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
