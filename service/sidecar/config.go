/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/tools/configtxgen"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
)

type (
	// Config defines the static configuration of the sidecar service as loaded from the YAML file.
	// This includes sidecar endpoint, committer endpoint to which the sidecar pushes the block and pulls statuses,
	// and the config of ledger service, and the orderer parameters setup.
	// It may contain the orderer endpoint from which the sidecar pulls blocks.
	Config struct {
		CommonConfig `mapstructure:",squash"`
		Orderer      ordererconn.Config `mapstructure:"orderer"`
	}

	// Parameters defines the fully resolved runtime configuration of the sidecar service.
	// In addition to the common sidecar settings, it contains orderer parameters
	// and is used by the sidecar during execution.
	Parameters struct {
		CommonConfig
		Orderer ordererconn.Parameters
	}

	// CommonConfig contains configuration fields shared between Config and
	// Parameters.
	//
	// These settings define the core behavior of the sidecar service, including
	// server and monitoring configuration, committer connectivity, ledger and
	// notification services, internal limits, buffering behavior, and bootstrap
	// settings.
	CommonConfig struct {
		Server                        *connection.ServerConfig  `mapstructure:"server"`
		Monitoring                    monitoring.Config         `mapstructure:"monitoring"`
		Committer                     *connection.ClientConfig  `mapstructure:"committer"`
		Ledger                        LedgerConfig              `mapstructure:"ledger"`
		Notification                  NotificationServiceConfig `mapstructure:"notification"`
		LastCommittedBlockSetInterval time.Duration             `mapstructure:"last-committed-block-set-interval"`
		WaitingTxsLimit               int                       `mapstructure:"waiting-txs-limit"`
		// ChannelBufferSize is the buffer size that will be used to queue blocks, requests, and statuses.
		ChannelBufferSize int       `mapstructure:"channel-buffer-size"`
		Bootstrap         Bootstrap `mapstructure:"bootstrap"`
	}

	// NotificationServiceConfig holds the parameters for notifications.
	NotificationServiceConfig struct {
		// MaxTimeout is an upper limit on the request's timeout to prevent resource exhaustion.
		// If a request doesn't specify a timeout, this value will be used.
		MaxTimeout time.Duration `mapstructure:"max-timeout"`
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
)

const (
	defaultNotificationMaxTimeout = time.Minute
	defaultBufferSize             = 100
)

// ToParams converts a config struct into parameters struct.
// specifically, it converts the Orderer field from config to parameters.
func (c *Config) ToParams() *Parameters {
	sc := c.CommonConfig
	return &Parameters{
		CommonConfig: sc,
		Orderer:      *c.Orderer.ToParams(),
	}
}

// LoadBootstrapConfig loads the bootstrap config according to the bootstrap method.
func LoadBootstrapConfig(conf *Parameters) error {
	if conf.Bootstrap.GenesisBlockFilePath == "" {
		return nil
	}
	return OverwriteConfigFromBlockFile(conf)
}

// OverwriteConfigFromBlockFile overwrites the orderer connection with fields from the bootstrap config block.
func OverwriteConfigFromBlockFile(conf *Parameters) error {
	configBlock, err := configtxgen.ReadBlock(conf.Bootstrap.GenesisBlockFilePath)
	if err != nil {
		return errors.Wrap(err, "read config block")
	}
	return OverwriteConfigFromBlock(conf, configBlock)
}

// OverwriteConfigFromBlock overwrites the orderer connection with fields from a config block.
func OverwriteConfigFromBlock(conf *Parameters, configBlock *common.Block) error {
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
func OverwriteConfigFromEnvelope(conf *Parameters, envelope *common.Envelope) error {
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		return errors.Wrap(err, "failed to create config bundle")
	}

	orgParams, err := getDeliveryEndpointsFromConfig(bundle)
	if err != nil {
		return err
	}
	for i := range conf.Orderer.Organizations {
		conf.Orderer.Organizations[i].Endpoints = orgParams[i].Endpoints
	}
	return nil
	//conf.Orderer.Organizations, err = getDeliveryEndpointsFromConfig(bundle)
	//if err != nil {
	//	return err
	//}
	//return nil
}

func getDeliveryEndpointsFromConfig(bundle *channelconfig.Bundle) ([]*ordererconn.OrganizationParameters, error) {
	ordererCfg, ok := bundle.OrdererConfig()
	if !ok {
		return nil, errors.New("could not find orderer config")
	}
	totalCAs := 0
	orgParams := make([]*ordererconn.OrganizationParameters, 0, len(ordererCfg.Organizations()))
	for orgID, org := range ordererCfg.Organizations() {
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
		rootCAs := org.MSP().GetTLSRootCerts()
		totalCAs += len(rootCAs)
		orgParams = append(orgParams, &ordererconn.OrganizationParameters{
			OrganizationConfig: ordererconn.OrganizationConfig{
				Endpoints: endpoints,
				MspID:     orgID,
			},
			CACertsBytes: rootCAs,
		})
	}
	logger.Infof("TOTAL_CAs: %v", totalCAs)
	return orgParams, nil
}
