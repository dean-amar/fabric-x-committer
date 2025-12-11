/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/internaltools/configtxgen"
	"github.com/hyperledger/fabric-x-common/protoutil"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
)

type (
	// Config holds the configuration of the sidecar service. This includes
	// sidecar endpoint, committer endpoint to which the sidecar pushes the block and pulls statuses,
	// and the config of ledger service, and the orderer setup.
	// It may contain the orderer endpoint from which the sidecar pulls blocks.
	Config struct {
		Server                        *connection.ServerConfig  `mapstructure:"server"`
		Monitoring                    monitoring.Config         `mapstructure:"monitoring"`
		Committer                     *connection.ClientConfig  `mapstructure:"committer"`
		Orderer                       ordererconn.Config        `mapstructure:"orderer"`
		Ledger                        LedgerConfig              `mapstructure:"ledger"`
		Notification                  NotificationServiceConfig `mapstructure:"notification"`
		LastCommittedBlockSetInterval time.Duration             `mapstructure:"last-committed-block-set-interval"`
		WaitingTxsLimit               int                       `mapstructure:"waiting-txs-limit"`
		// ChannelBufferSize is the buffer size that will be used to queue blocks, requests, and statuses.
		ChannelBufferSize int       `mapstructure:"channel-buffer-size"`
		Bootstrap         Bootstrap `mapstructure:"bootstrap"`
	}
	// Bootstrap configures how to obtain the bootstrap configuration.
	Bootstrap struct {
		// GenesisBlockFilePath is the path for the genesis block.
		// If omitted, the local configuration will be used.
		GenesisBlockFilePath string `mapstructure:"genesis-block-file-path" yaml:"genesis-block-file-path,omitempty"`
	}

	// LedgerConfig holds the ledger path.
	LedgerConfig struct {
		Path string `mapstructure:"path"`
	}

	// NotificationServiceConfig holds the parameters for notifications.
	NotificationServiceConfig struct {
		// MaxTimeout is an upper limit on the request's timeout to prevent resource exhaustion.
		// If a request doesn't specify a timeout, this value will be used.
		MaxTimeout time.Duration `mapstructure:"max-timeout"`
	}

	ConfigParameters struct {
		Server                        *connection.ServerConfig
		Monitoring                    monitoring.Config
		Committer                     *connection.ClientConfig
		Orderer                       ordererconn.ConfigParameters
		Ledger                        LedgerConfig
		Notification                  NotificationServiceConfig
		LastCommittedBlockSetInterval time.Duration
		WaitingTxsLimit               int
		// ChannelBufferSize is the buffer size that will be used to queue blocks, requests, and statuses.
		ChannelBufferSize int
		Bootstrap         Bootstrap
	}
)

const (
	defaultNotificationMaxTimeout = time.Minute
	defaultBufferSize             = 100
)

func (c *Config) ConvertToConfigPrameters() *ConfigParameters {
	return &ConfigParameters{
		Server:                        c.Server,
		Monitoring:                    c.Monitoring,
		Committer:                     c.Committer,
		Orderer:                       *c.Orderer.ConvertToOrdererConfigParameters(),
		Ledger:                        c.Ledger,
		Notification:                  c.Notification,
		LastCommittedBlockSetInterval: c.LastCommittedBlockSetInterval,
		WaitingTxsLimit:               c.WaitingTxsLimit,
		ChannelBufferSize:             c.ChannelBufferSize,
		Bootstrap:                     c.Bootstrap,
	}
}

// LoadBootstrapConfig loads the bootstrap config according to the bootstrap method.
func LoadBootstrapConfig(conf *ConfigParameters) error {
	if conf.Bootstrap.GenesisBlockFilePath == "" {
		return nil
	}
	return OverwriteConfigFromBlockFile(conf)
}

// OverwriteConfigFromBlockFile overwrites the orderer connection with fields from the bootstrap config block.
func OverwriteConfigFromBlockFile(conf *ConfigParameters) error {
	configBlock, err := configtxgen.ReadBlock(conf.Bootstrap.GenesisBlockFilePath)
	if err != nil {
		return errors.Wrap(err, "read config block")
	}
	return OverwriteConfigFromBlock(conf, configBlock)
}

// OverwriteConfigFromBlock overwrites the orderer connection with fields from a config block.
func OverwriteConfigFromBlock(conf *ConfigParameters, configBlock *common.Block) error {
	envelope, err := protoutil.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return errors.Wrap(err, "failed to extract envelope")
	}
	return OverwriteConfigFromEnvelope(conf, envelope)
}

// OverwriteConfigFromEnvelope overwrites the orderer connection config with fields from a config transaction.
// For now, it fetches the following:
// - Orderer endpoints.
// - RootCAs per organization.
// TODO: Fetch Root CAs.
func OverwriteConfigFromEnvelope(conf *ConfigParameters, envelope *common.Envelope) error {
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		return errors.Wrap(err, "failed to create config bundle")
	}

	orgParams, err := getDeliveryEndpointsFromConfig(bundle)
	if err != nil {
		return err
	}
	for i := range conf.Orderer.Connection {
		conf.Orderer.Connection[i].Endpoints = orgParams[i].Endpoints
	}
	return nil
	//conf.Orderer.Connection, err = getDeliveryEndpointsFromConfig(bundle)
	//if err != nil {
	//	return err
	//}
	//return nil
}

func getDeliveryEndpointsFromConfig(bundle *channelconfig.Bundle) ([]*ordererconn.OrganizationParametersWithCaCertBytes, error) {
	oc, ok := bundle.OrdererConfig()
	if !ok {
		return nil, errors.New("could not find orderer config")
	}
	totalCAs := 0
	var orgParams []*ordererconn.OrganizationParametersWithCaCertBytes
	for orgID, org := range oc.Organizations() {
		var endpoints []*commontypes.OrdererEndpoint
		endpointsStr := org.Endpoints()
		for _, eStr := range endpointsStr {
			e, err := commontypes.ParseOrdererEndpoint(eStr)
			if err != nil {
				return nil, err
			}
			e.MspID = orgID
			endpoints = append(endpoints, e)
		}
		RootCAs := org.MSP().GetTLSRootCerts()
		totalCAs += len(RootCAs)
		orgParams = append(orgParams, &ordererconn.OrganizationParametersWithCaCertBytes{
			Endpoints:    endpoints,
			MspID:        orgID,
			CACertsBytes: RootCAs,
		})
	}
	logger.Infof("TOTAL_CAs: %v", totalCAs)
	return orgParams, nil
}
