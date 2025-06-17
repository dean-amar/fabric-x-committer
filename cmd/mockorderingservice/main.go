/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/cockroachdb/errors"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	serviceName = "mock-ordering-service"
)

func main() {
	cmd := mockorderingserviceCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func mockorderingserviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   serviceName,
		Short: fmt.Sprintf("%v is a mock ordering service.", serviceName),
	}

	cmd.AddCommand(config.VersionCmd())
	cmd.AddCommand(startCmd())
	return cmd
}

func startCmd() *cobra.Command {
	v := config.NewViperWithLoggingDefault()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Starts %v.", serviceName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadMockOrdererYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			service, err := mock.NewMockOrderer(conf)
			if err != nil {
				return errors.Wrap(err, "failed to create mock ordering service")
			}
			if len(conf.ServerConfigs) == 0 {
				return errors.New("missing server configuration")
			}

			cmd.Printf("Starting %v\n", serviceName)
			defer cmd.Printf("%v ended\n", serviceName)

			g, gCtx := errgroup.WithContext(cmd.Context())

			// We run the main worker, and start GRPC servers.
			g.Go(func() error {
				return connection.StartService(gCtx, service, nil, nil)
			})
			for _, subServer := range conf.ServerConfigs {
				subServer := subServer
				g.Go(func() error {
					return connection.RunGrpcServerMainWithError(gCtx, subServer, func(s *grpc.Server) {
						ab.RegisterAtomicBroadcastServer(s, service)
					})
				})
			}
			return g.Wait()
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	return cmd
}
