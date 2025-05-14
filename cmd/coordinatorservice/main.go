/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/coordinator"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	serviceName    = "coordinator-service"
	serviceVersion = "0.0.2"
)

func main() {
	cmd := coordinatorserviceCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func coordinatorserviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   serviceName,
		Short: fmt.Sprintf("%v is a transaction flow coordinator within the committer", serviceName),
	}
	cmd.AddCommand(config.VersionCmd(serviceName, serviceVersion))
	cmd.AddCommand(startCmd())
	return cmd
}

func startCmd() *cobra.Command {
	v := config.NewViperWithCoordinatorDefaults()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Starts a %v", serviceName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadCoordinatorYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v service\n", serviceName)

			service := coordinator.NewCoordinatorService(conf)

			// As we do not have recovery mechanism for vcservice and sigverifier service, we stop the
			// coordinator service if any of them fails. In the future, we can add recovery mechanism
			// to restart the failed service and stop the coordinator service only if all the services
			// in vcservice fail or all the services in sigverifier fail.
			return connection.StartService(cmd.Context(), service, conf.Server, func(s *grpc.Server) {
				protocoordinatorservice.RegisterCoordinatorServer(s, service)
			})
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	return cmd
}
