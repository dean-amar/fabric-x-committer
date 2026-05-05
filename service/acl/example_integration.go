/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
)

// This file provides examples of how to integrate the ACL interceptor with services.
// These examples are for documentation purposes and should not be used directly in production.

/*
Example 1: Server-Side Integration with Query Service

import (
	"context"

	"github.com/hyperledger/fabric-x-committer/service/acl"
	"google.golang.org/grpc"
)

func startQueryServiceWithACL(config *Config) error {
	// Create ACL provider
	bundleManager := acl.NewBundleManager()
	aclProvider := acl.NewProvider(bundleManager)

	// Create ACL interceptor
	aclInterceptor := acl.NewInterceptor(aclProvider)

	// Create gRPC server with interceptors
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(aclInterceptor.UnaryServerInterceptor()),
		grpc.StreamInterceptor(aclInterceptor.StreamServerInterceptor()),
	)

	// Register service - proto unchanged!
	queryService := query.NewQueryService(config, aclProvider, tlsUpdater)
	committerpb.RegisterQueryServiceServer(grpcServer, queryService)

	// Start server
	return grpcServer.Serve(listener)
}

Example 2: Client-Side Usage

import (
	"context"

	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-committer/service/acl"
)

func queryWithACL(client committerpb.QueryServiceClient, identity msp.SigningIdentity) error {
	// Create the query request
	query := &committerpb.Query{
		Namespace: "myapp",
		Keys: []string{"key1", "key2"},
	}

	// Add signed metadata to context
	ctx := context.Background()
	ctx, err := acl.AddSignedMetadata(ctx, "mychannel", identity, query)
	if err != nil {
		return err
	}

	// Make the gRPC call - proto unchanged!
	result, err := client.GetRows(ctx, query)
	if err != nil {
		return err
	}

	// Process result
	return nil
}

Example 3: Updating ACL Configuration from Config Block

import (
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-committer/service/acl"
)

func updateACLFromConfigBlock(provider acl.Provider, block *common.Block) error {
	// Update the ACL provider with new config
	if err := provider.UpdateFromConfigBlock(block); err != nil {
		return err
	}

	logger.Infof("Updated ACL configuration from block %d", block.Header.Number)
	return nil
}

Example 4: Service Handler (No Changes Needed!)

// With interceptor-based ACL, service handlers remain unchanged
func (s *Service) GetRows(ctx context.Context, query *committerpb.Query) (*committerpb.QueryResult, error) {
	// ACL check already performed by interceptor
	// Just implement business logic
	return s.processQuery(query)
}

Example 5: Streaming Service with ACL

func (s *Service) Notify(params *committerpb.NotifyParams, stream committerpb.SidecarService_NotifyServer) error {
	// ACL check performed automatically for each message by the interceptor
	for {
		block := <-s.blockChannel
		if err := stream.Send(block); err != nil {
			return err
		}
	}
}

Example 6: Disabling ACL (Backward Compatibility)

func startServiceWithoutACL(config *Config) error {
	// Pass nil as ACL provider to disable ACL checks
	aclInterceptor := acl.NewInterceptor(nil)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(aclInterceptor.UnaryServerInterceptor()),
		grpc.StreamInterceptor(aclInterceptor.StreamServerInterceptor()),
	)

	// ACL checks will be skipped
	return grpcServer.Serve(listener)
}
*/

// Made with Bob

func queryWithACL(client committerpb.QueryServiceClient, identity msp.SigningIdentity) error {
	// Create the query request
	query := &committerpb.Query{
		Namespace: "myapp",
		Keys:      []string{"key1", "key2"},
	}

	// Add signed metadata to context
	ctx := context.Background()
	ctx, err := acl.AddSignedMetadata(ctx, "mychannel", identity, query)
	if err != nil {
		return err
	}

	// Make the gRPC call - proto unchanged!
	result, err := client.GetRows(ctx, query)
	if err != nil {
		return err
	}

	// Process result
	return nil
}
