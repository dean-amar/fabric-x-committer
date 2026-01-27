/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// StartMockVerifierService starts a specified number of mock verifier service and register cancellation.
func StartMockVerifierService(t *testing.T, numService int) (
	*Verifier, *test.GrpcServers,
) {
	t.Helper()
	mockVerifier := NewMockSigVerifier()
	verifierGrpc := test.StartGrpcServersForTest(
		t.Context(), t, numService, mockVerifier.RegisterService, test.InsecureTLSConfig,
	)
	return mockVerifier, verifierGrpc
}

// StartMockVerifierServiceFromServerConfig starts a specified number of mock verifier service.
func StartMockVerifierServiceFromServerConfig(
	t *testing.T, verifier *Verifier, sc ...*connection.ServerConfig,
) *test.GrpcServers {
	t.Helper()
	return test.StartGrpcServersWithConfigForTest(t.Context(), t, verifier.RegisterService, sc...)
}

// StartMockVCService starts a specified number of mock VC service using the same shared instance.
// It is used for testing when multiple VC services are required to share the same state.
func StartMockVCService(t *testing.T, numService int) (*VcService, *test.GrpcServers) {
	t.Helper()
	sharedVC := NewMockVcService()
	vcGrpc := test.StartGrpcServersForTest(t.Context(), t, numService, sharedVC.RegisterService, test.InsecureTLSConfig)
	return sharedVC, vcGrpc
}

// StartMockVCServiceFromServerConfig starts a specified number of mock vc service.
func StartMockVCServiceFromServerConfig(
	t *testing.T, vc *VcService, sc ...*connection.ServerConfig,
) *test.GrpcServers {
	t.Helper()
	return test.StartGrpcServersWithConfigForTest(t.Context(), t, vc.RegisterService, sc...)
}

// StartMockCoordinatorService starts a mock coordinator service and registers cancellation.
func StartMockCoordinatorService(t *testing.T) (
	*Coordinator, *test.GrpcServers,
) {
	t.Helper()
	mockCoordinator := NewMockCoordinator()
	coordinatorGrpc := test.StartGrpcServersForTest(
		t.Context(), t, 1, mockCoordinator.RegisterService, test.InsecureTLSConfig,
	)
	return mockCoordinator, coordinatorGrpc
}

// StartMockCoordinatorServiceFromServerConfig starts a mock coordinator service using the given config.
func StartMockCoordinatorServiceFromServerConfig(
	t *testing.T,
	coordService *Coordinator,
	sc *connection.ServerConfig,
) *test.GrpcServers {
	t.Helper()
	return test.StartGrpcServersWithConfigForTest(t.Context(), t, coordService.RegisterService, sc)
}

// StartMockOrderingServices starts a specified number of mock ordering service and register cancellation.
func StartMockOrderingServices(t *testing.T, conf *OrdererConfig) (
	*Orderer, *test.GrpcServers, string, *workload.PolicyProfile,
) {
	t.Helper()
	service, err := NewMockOrderer(conf)
	require.NoError(t, err)

	// @TODO: read application details from config block

	// create orderer servers with pre-allocated ports.
	ordererServers := make([]*connection.ServerConfig, conf.NumService)
	for i := range ordererServers {
		ordererServers[i] = preAllocatePorts(t, conf.TLS)
	}

	if len(conf.ServerConfigs) == conf.NumService {
		ordererServers = conf.ServerConfigs
	}

	// create policy with these endpoints.
	policy := &workload.PolicyProfile{
		// we generate all the orderers for with the same msp-id.
		OrdererEndpoints:      test.NewOrdererEndpoints(0, ordererServers...),
		ChannelID:             "ch1",
		CryptoMaterialPath:    t.TempDir(),
		PeerOrganizationCount: 1,
	}

	//service.ConfigBlock, err = workload.CreateConfigBlock(policy)
	//require.NoError(t, err, "failed to create config block")
	//require.NotNil(t, service.ConfigBlock)

	// start the orderer service after updating the config-block.
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(service.Run(ctx))
	}, service.WaitForReady)

	//// updating the orderer sever-configs with the generated TLS credentials.
	//for i, ordererServer := range ordererServers {
	//
	//	certDir := filepath.Join(
	//		policy.CryptoMaterialPath,
	//		"ordererOrganizations", "orderer-org-0",
	//		"orderers", fmt.Sprintf("orderer-%d-org-0", i),
	//		"tls",
	//	)
	//
	//	// override cert and key paths.
	//	ordererServer.TLS.CertPath = filepath.Join(certDir, "server.crt")
	//	ordererServer.TLS.KeyPath = filepath.Join(certDir, "server.key")
	//}

	servers := test.StartGrpcServersWithConfigForTest(
		t.Context(),
		t, func(server *grpc.Server) {
			service.RegisterService(server)
		}, ordererServers...,
	)

	// change to the main orderer root CA - get it from walkDirectory.
	orderersCertsRootCA := filepath.Join(filepath.Join(
		policy.CryptoMaterialPath,
		"ordererOrganizations", "orderer-org-0",
		"orderers", fmt.Sprintf("orderer-%d-org-0", 0),
		"tls",
	), "ca.crt")

	return service, servers, orderersCertsRootCA, policy
}

// OrdererTestEnv allows starting fake and holder services in addition to the regular mock orderer services.
type OrdererTestEnv struct {
	Orderer         *Orderer
	Holder          *HoldingOrderer
	OrdererServers  *test.GrpcServers
	FakeServers     *test.GrpcServers
	HolderServers   *test.GrpcServers
	TestConfig      *OrdererTestConfig
	ConfigBlockPath string
	RootCA          string
	Policy          *workload.PolicyProfile
}

// OrdererTestConfig describes the configuration for OrdererTestEnv.
type OrdererTestConfig struct {
	ChanID                       string
	Config                       *OrdererConfig
	NumFake                      int
	NumHolders                   int
	MetaNamespaceVerificationKey []byte
}

// NewOrdererTestEnv creates and starts a new OrdererTestEnv.
func NewOrdererTestEnv(t *testing.T, conf *OrdererTestConfig) *OrdererTestEnv {
	t.Helper()
	orderer, ordererServers, newRootCA, policy := StartMockOrderingServices(t, conf.Config)
	holder := &HoldingOrderer{Orderer: orderer}
	holder.Release()
	return &OrdererTestEnv{
		TestConfig:     conf,
		Orderer:        orderer,
		Holder:         holder,
		OrdererServers: ordererServers,
		HolderServers: test.StartGrpcServersForTest(t.Context(), t, conf.NumHolders, func(s *grpc.Server) {
			holder.RegisterService(s)
		}, conf.Config.TLS),
		FakeServers: test.StartGrpcServersForTest(t.Context(), t, conf.NumFake, nil, test.InsecureTLSConfig),
		RootCA:      newRootCA,
		// maybe delete.
		Policy: policy,
	}
}

// SubmitConfigBlock creates and submits a config block.
func (e *OrdererTestEnv) SubmitConfigBlock(t *testing.T, conf *workload.ConfigBlock) *common.Block {
	t.Helper()
	if conf == nil {
		conf = &workload.ConfigBlock{}
	}
	if conf.ChannelID == "" {
		conf.ChannelID = e.TestConfig.ChanID
	}
	if len(conf.OrdererEndpoints) == 0 {
		conf.OrdererEndpoints = e.AllEndpoints()
	}
	if conf.MetaNamespaceVerificationKey == nil {
		conf.MetaNamespaceVerificationKey = e.TestConfig.MetaNamespaceVerificationKey
	}
	configBlock, err := workload.CreateDefaultConfigBlock(conf)
	require.NoError(t, err)
	err = e.Orderer.SubmitBlock(t.Context(), configBlock)
	require.NoError(t, err)
	return configBlock
}

// AllEndpoints returns a list of all the endpoints (real, fake, and holders).
func (e *OrdererTestEnv) AllEndpoints() []*commontypes.OrdererEndpoint {
	return slices.Concat(
		e.AllRealOrdererEndpoints(),
		e.AllHolderEndpoints(),
		e.AllFakeEndpoints(),
	)
}

// AllRealOrdererEndpoints returns a list of the real orderer endpoints.
func (e *OrdererTestEnv) AllRealOrdererEndpoints() []*commontypes.OrdererEndpoint {
	return test.NewOrdererEndpoints(0, e.OrdererServers.Configs...)
}

// AllFakeEndpoints returns a list of the fake orderer endpoints.
func (e *OrdererTestEnv) AllFakeEndpoints() []*commontypes.OrdererEndpoint {
	return test.NewOrdererEndpoints(0, e.FakeServers.Configs...)
}

// AllHolderEndpoints returns a list of the holder orderer endpoints.
func (e *OrdererTestEnv) AllHolderEndpoints() []*commontypes.OrdererEndpoint {
	return test.NewOrdererEndpoints(0, e.HolderServers.Configs...)
}

func preAllocatePorts(t *testing.T, tlsConfig connection.TLSConfig) *connection.ServerConfig {
	t.Helper()
	server := connection.NewLocalHostServer(tlsConfig)
	listener, err := server.PreAllocateListener()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
	})
	return server
}
