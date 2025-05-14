/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/sidecar"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	serviceName    = "sidecar"
	serviceVersion = "0.0.1"
)

func main() {
	cmd := sidecarCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func sidecarCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   serviceName,
		Short: fmt.Sprintf("%v is the linkage between the system services.", serviceName),
	}

	cmd.AddCommand(config.VersionCmd(serviceName, serviceVersion))
	cmd.AddCommand(startCmd())
	return cmd
}

func startCmd() *cobra.Command {
	v := config.NewViperWithSidecarDefaults()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Starts a %v service.", serviceName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadSidecarYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v service\n", serviceName)

			service, err := sidecar.New(conf)
			if err != nil {
				return errors.Wrap(err, "failed to create sidecar service")
			}
			defer service.Close()

			// enable health check server
			healthcheck := health.NewServer()
			healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)

			return connection.StartService(cmd.Context(), service, conf.Server, func(server *grpc.Server) {
				peer.RegisterDeliverServer(server, service.GetLedgerService())
				healthgrpc.RegisterHealthServer(server, healthcheck)
			})
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	utils.Must(config.CobraInt(v, cmd, config.CobraFlag{
		Name:  "committer-endpoint",
		Usage: "sets the endpoint of the committer in the config file",
		Key:   "committer.endpoint",
	}))
	utils.Must(config.CobraString(v, cmd, config.CobraFlag{
		Name:  "ledger-path",
		Usage: "sets the path of the ledger",
		Key:   "ledger.path",
	}))
	return cmd
}
