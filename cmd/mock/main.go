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

	"github.com/hyperledger/fabric-x-committer/api/protosigverifierservice"
	"github.com/hyperledger/fabric-x-committer/api/protovcservice"
	"github.com/hyperledger/fabric-x-committer/cmd/config"
	"github.com/hyperledger/fabric-x-committer/mock"
	"github.com/hyperledger/fabric-x-committer/utils"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

const (
	mockCmdName      = "mock"
	mockOrdererName  = "mock-ordering-service"
	mockVerifierName = "mock-verifier-service"
	mockVcName       = "mock-vc-service"
)

func main() {
	cmd := mockCMD()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func mockCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   mockCmdName,
		Short: "Fabric-X services mock.",
	}
	cmd.AddCommand(config.VersionCmd())
	cmd.AddCommand(mockOrdererCMD())
	cmd.AddCommand(mockVerifierCMD())
	cmd.AddCommand(mockVcCMD())
	return cmd
}

func mockOrdererCMD() *cobra.Command {
	v := config.NewViperWithLoggingDefault()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start-orderer",
		Short: fmt.Sprintf("Starts %v.", mockOrdererName),
		Long:  fmt.Sprintf("%v is a mock ordering service.", mockOrdererName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadMockOrdererYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v\n", mockOrdererName)
			defer cmd.Printf("%v ended\n", mockOrdererName)

			service, err := mock.NewMockOrderer(conf)
			if err != nil {
				return errors.Wrap(err, "failed to create mock ordering service")
			}

			g, gCtx := errgroup.WithContext(cmd.Context())

			// We run the main worker, and start GRPC servers.
			reg := func(s *grpc.Server) {
				ab.RegisterAtomicBroadcastServer(s, service)
			}
			g.Go(func() error {
				return connection.StartService(gCtx, service, conf.Server, reg)
			})
			for _, subServer := range conf.ServerConfigs {
				subServer := subServer
				g.Go(func() error {
					return connection.RunGrpcServerMainWithError(gCtx, subServer, reg)
				})
			}
			return g.Wait()
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	return cmd
}

//nolint:dupl // similar to mockVcCMD.
func mockVerifierCMD() *cobra.Command {
	v := config.NewViperWithVerifierDefaults()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start-verifier",
		Short: fmt.Sprintf("Starts %v", mockVerifierName),
		Long:  fmt.Sprintf("%v is a mock signature verification service.", mockVerifierName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadVerifierYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v\n", mockVerifierName)
			defer cmd.Printf("%v ended\n", mockVerifierName)

			sv := mock.NewMockSigVerifier()
			return connection.RunGrpcServerMainWithError(cmd.Context(), conf.Server, func(s *grpc.Server) {
				protosigverifierservice.RegisterVerifierServer(s, sv)
			})
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	return cmd
}

//nolint:dupl // similar to mockVerifierCMD.
func mockVcCMD() *cobra.Command {
	v := config.NewViperWithVCDefaults()
	var configPath string
	cmd := &cobra.Command{
		Use:   "start-vc",
		Short: fmt.Sprintf("Starts %v.", mockVcName),
		Long:  fmt.Sprintf("%v is a mock validator and committer service.", mockVcName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadVCYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v\n", mockVcName)
			defer cmd.Printf("%v ended\n", mockVcName)

			vcs := mock.NewMockVcService()
			return connection.RunGrpcServerMainWithError(cmd.Context(), conf.Server, func(server *grpc.Server) {
				protovcservice.RegisterValidationAndCommitServiceServer(server, vcs)
			})
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	return cmd
}
