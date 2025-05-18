/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"net"
	"time"
)

type (
	// ClientConfig contains the endpoints, CAs, and retry profile.
	ClientConfig struct {
		Endpoints []*Endpoint   `mapstructure:"endpoints"`
		Retry     *RetryProfile `mapstructure:"reconnect"`
		RootCA    [][]byte      `mapstructure:"root-ca"`
		// RootCAPaths The path to the root CAs (alternative to the raw data).
		RootCAPaths []string `mapstructure:"root-ca-paths"`
	}

	// ServerConfig describes the connection parameter for a server.
	ServerConfig struct {
		Endpoint  Endpoint               `mapstructure:"endpoint"`
		Creds     *ServerCredsConfig     `mapstructure:"creds"`
		KeepAlive *ServerKeepAliveConfig `mapstructure:"keep-alive"`

		preAllocatedListener net.Listener
	}

	// ServerKeepAliveConfig describes the keep alive parameters.
	ServerKeepAliveConfig struct {
		Params            *ServerKeepAliveParamsConfig            `mapstructure:"params"`
		EnforcementPolicy *ServerKeepAliveEnforcementPolicyConfig `mapstructure:"enforcement-policy"`
	}

	// ServerKeepAliveParamsConfig describes the keep alive policy.
	ServerKeepAliveParamsConfig struct {
		MaxConnectionIdle     time.Duration `mapstructure:"max-connection-idle"`
		MaxConnectionAge      time.Duration `mapstructure:"max-connection-age"`
		MaxConnectionAgeGrace time.Duration `mapstructure:"max-connection-age-grace"`
		Time                  time.Duration `mapstructure:"time"`
		Timeout               time.Duration `mapstructure:"timeout"`
	}

	// ServerKeepAliveEnforcementPolicyConfig describes the keep alive enforcement policy.
	ServerKeepAliveEnforcementPolicyConfig struct {
		MinTime             time.Duration `mapstructure:"min-time"`
		PermitWithoutStream bool          `mapstructure:"permit-without-stream"`
	}

	// ServerCredsConfig describes the server's credentials configuration.
	ServerCredsConfig struct {
		CertPath string `mapstructure:"cert-path"`
		KeyPath  string `mapstructure:"key-path"`
	}
)
