package adapters

import (
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/broadcastdeliver"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

type (
	// AdapterConfig contains all adapters configurations.
	AdapterConfig struct {
		OrdererClient     *OrdererClientConfig     `mapstructure:"orderer-client"`
		SidecarClient     *SidecarClientConfig     `mapstructure:"sidecar-client"`
		CoordinatorClient *CoordinatorClientConfig `mapstructure:"coordinator-client"`
		VCClient          *VCClientConfig          `mapstructure:"vc-client"`
		SigVerifierClient *SVClientConfig          `mapstructure:"sig-verifier-client"`
	}

	// OrdererClientConfig is a struct that contains the configuration for the orderer client.
	OrdererClientConfig struct {
		Orderer broadcastdeliver.Config `mapstructure:"orderer"`
		// @TODO: change to connection.ServerConfig
		SidecarEndpoint      *connection.Endpoint `mapstructure:"sidecar-endpoint"`
		SidecarTLSConfig     connection.ConfigTLS `mapstructure:"sidecar-tls-config"`
		BroadcastParallelism int                  `mapstructure:"broadcast-parallelism"`
	}

	// SidecarClientConfig is a struct that contains the configuration for the sidecar client.
	SidecarClientConfig struct {
		ChannelID string `mapstructure:"channel-id"`
		// @TODO: change to connection.ServerConfig
		SidecarEndpoint  *connection.Endpoint       `mapstructure:"sidecar-endpoint"`
		SidecarTLSConfig connection.ConfigTLS       `mapstructure:"sidecar-tls-config"`
		OrdererServers   []*connection.ServerConfig `mapstructure:"orderer-servers"`
	}

	// CoordinatorClientConfig is a struct that contains the configuration for the coordinator client.
	CoordinatorClientConfig struct {
		Endpoint *connection.Endpoint `mapstructure:"endpoint"`
	}

	// VCClientConfig is a struct that contains the configuration for the VC client.
	VCClientConfig struct {
		Endpoints []*connection.Endpoint `mapstructure:"endpoints"`
	}

	// SVClientConfig is a struct that contains the configuration for the signature verifier client.
	SVClientConfig struct {
		Endpoints []*connection.Endpoint `mapstructure:"endpoints"`
	}
)
