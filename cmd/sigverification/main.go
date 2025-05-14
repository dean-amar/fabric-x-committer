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

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protosigverifierservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/verifier"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	serviceName    = "sig-verification"
	serviceVersion = "0.0.1"
)

func main() {
	cmd := sigverifierCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func sigverifierCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   serviceName,
		Short: fmt.Sprintf("%v is a service that verifies the transaction's signatures.", serviceName),
	}

	cmd.AddCommand(config.VersionCmd(serviceName, serviceVersion))
	cmd.AddCommand(startCmd())
	return cmd
}

func startCmd() *cobra.Command {
	v := config.NewViperWithVerifierDefaults()
	var configPath string

	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Starts a %v service.", serviceName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadVerifierYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v service\n", serviceName)
			defer cmd.Printf("%v service ended\n", serviceName)

			service := verifier.New(conf)
			return connection.StartService(cmd.Context(), service, conf.Server, func(server *grpc.Server) {
				protosigverifierservice.RegisterVerifierServer(server, service)
			})
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	utils.Must(config.CobraInt(v, cmd, config.CobraFlag{
		Name:  "parallelism",
		Usage: "sets the value of the parallelism in the config file",
		Key:   "parallel-executor.parallelism",
	}))
	utils.Must(config.CobraInt(v, cmd, config.CobraFlag{
		Name:  "batch-size-cutoff",
		Usage: "Batch time cutoff limit",
		Key:   "parallel-executor.batch-size-cutoff",
	}))
	utils.Must(config.CobraInt(v, cmd, config.CobraFlag{
		Name:  "channel-buffer-size",
		Usage: "Channel buffer size for the executor",
		Key:   "parallel-executor.channel-buffer-size",
	}))
	utils.Must(config.CobraDuration(v, cmd, config.CobraFlag{
		Name:  "batch-time-cutoff",
		Usage: "Batch time cutoff limit",
		Key:   "parallel-executor.batch-time-cutoff",
	}))
	return cmd
}
