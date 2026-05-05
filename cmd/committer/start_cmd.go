/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/cmd/cliutil"
	"github.com/hyperledger/fabric-x-committer/service/acl"
	"github.com/hyperledger/fabric-x-committer/service/coordinator"
	"github.com/hyperledger/fabric-x-committer/service/query"
	"github.com/hyperledger/fabric-x-committer/service/sidecar"
	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/service/verifier"
	"github.com/hyperledger/fabric-x-committer/utils/grpcservice"
)

func startCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a service.",
	}
	for _, name := range []string{sidecarService, coordinatorService, vcService, verifierService, queryService} {
		cmd.AddCommand(startServiceCommand(name))
	}
	return cmd
}

func startServiceCommand(name string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:          name,
		Short:        fmt.Sprintf("Starts %v.", serviceNames[name]),
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("Starting %v\n", serviceNames[name])
			defer cmd.Printf("%v ended\n", serviceNames[name])
			return startService(cmd.Context(), name, configPath)
		},
	}
	cliutil.SetDefaultFlags(cmd, &configPath)
	return cmd
}

func startService(ctx context.Context, name, configPath string) error {
	conf, err := readConfig(name, configPath)
	if err != nil {
		return err
	}

	// Create ACL components (shared by services that need ACL)
	bundleManager := acl.NewBundleManager()
	aclProvider := acl.NewProvider(bundleManager)
	aclInterceptor := acl.NewInterceptor(aclProvider)

	switch c := conf.(type) {
	case *sidecar.Config:
		tlsUpdater, tlsProvider, err := cliutil.NewDynamicTLS(c.Server)
		if err != nil {
			return err
		}
		service, err := sidecar.New(c, tlsUpdater, aclProvider)
		if err != nil {
			return errors.Wrap(err, "failed to create sidecar service")
		}
		defer service.Close()

		// Add ACL interceptors for sidecar
		unaryInterceptors := []grpc.UnaryServerInterceptor{aclInterceptor.UnaryServerInterceptor()}
		streamInterceptors := []grpc.StreamServerInterceptor{aclInterceptor.StreamServerInterceptor()}
		return grpcservice.StartAndServe(ctx, service, tlsProvider, unaryInterceptors, streamInterceptors, c.Server)

	case *coordinator.Config:
		// Coordinator doesn't need ACL
		return grpcservice.StartAndServe(ctx, coordinator.NewCoordinatorService(c), nil, nil, nil, c.Server)

	case *vc.Config:
		service, err := vc.NewValidatorCommitterService(ctx, c)
		if err != nil {
			return errors.Wrap(err, "failed to create validator committer service")
		}
		defer service.Close()
		// VC doesn't need ACL
		return grpcservice.StartAndServe(ctx, service, nil, nil, nil, c.Server)

	case *verifier.Config:
		// Verifier doesn't need ACL
		return grpcservice.StartAndServe(ctx, verifier.New(c), nil, nil, nil, c.Server)

	case *query.Config:
		tlsUpdater, tlsProvider, err := cliutil.NewDynamicTLS(c.Server)
		if err != nil {
			return err
		}

		// Add ACL interceptors for query service
		unaryInterceptors := []grpc.UnaryServerInterceptor{aclInterceptor.UnaryServerInterceptor()}
		streamInterceptors := []grpc.StreamServerInterceptor{aclInterceptor.StreamServerInterceptor()}
		return grpcservice.StartAndServe(ctx, query.NewQueryService(c, tlsUpdater, aclProvider), tlsProvider, unaryInterceptors, streamInterceptors, c.Server)

	default:
		return errors.Newf("unknown config type: %T", conf)
	}
}
