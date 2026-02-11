/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"context"
	"fmt"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// StartMockVerifierService starts a specified number of mock verifier service and register cancellation.
func StartMockVerifierService(t *testing.T, p test.StartServerParameters) (
	*Verifier, *test.GrpcServers,
) {
	t.Helper()
	mockVerifier := NewMockSigVerifier()
	verifierGrpc := test.StartGrpcServersForTest(t.Context(), t, p, mockVerifier.RegisterService)
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
func StartMockVCService(t *testing.T, p test.StartServerParameters) (*VcService, *test.GrpcServers) {
	t.Helper()
	sharedVC := NewMockVcService()
	vcGrpc := test.StartGrpcServersForTest(t.Context(), t, p, sharedVC.RegisterService)
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
func StartMockCoordinatorService(t *testing.T, p test.StartServerParameters) (
	*Coordinator, *test.GrpcServers,
) {
	t.Helper()
	p.NumService = 1
	mockCoordinator := NewMockCoordinator()
	coordinatorGrpc := test.StartGrpcServersForTest(
		t.Context(), t, p, mockCoordinator.RegisterService,
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
	*Orderer, *test.GrpcServers, *OrdererServers,
) {
	t.Helper()
	service, err := NewMockOrderer(conf)
	require.NoError(t, err)

	ordererSplit := AllocateOrdererServers(t, &OrdererServersParameters{
		NumIDs:          2,
		ServerPerID:     2,
		ServerTLSConfig: conf.TestServerParameters.TLSConfig,
	})

	policy := &workload.PolicyProfile{
		// create policy with these endpoints.
		// we generate all the orderers for with the same msp-id.
		OrdererEndpoints:      ordererSplit.AllEndpoints,
		ChannelID:             "ch1",
		CryptoMaterialPath:    t.TempDir(),
		PeerOrganizationCount: 1,
	}

	service.ConfigBlock, err = workload.CreateConfigBlock(policy)
	require.NoError(t, err, "failed to create config block")
	require.NotNil(t, service.ConfigBlock)

	// start the orderer service after updating the config-block.
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(service.Run(ctx))
	}, service.WaitForReady)
	// updating the orderer sever-configs with the generated TLS credentials.
	for mspID, serverConfigs := range ordererSplit.ServerConfigPerID {
		for i, ordererServer := range serverConfigs {

			certDir := filepath.Join(
				policy.CryptoMaterialPath,
				cryptogen.OrdererOrganizationsDir, fmt.Sprintf("orderer-org-%d", mspID),
				cryptogen.OrdererNodesDir, fmt.Sprintf("orderer-%d-org-%d", i, mspID),
				cryptogen.TLSDir,
			)

			// override cert and key paths.
			ordererServer.TLS.CertPath = filepath.Join(certDir, "server.crt")
			ordererServer.TLS.KeyPath = filepath.Join(certDir, "server.key")
		}
	}

	return service, test.StartGrpcServersWithConfigForTest(
		t.Context(), t, service.RegisterService, ordererSplit.GetAllOrdererServerConfigs(t)...,
	), ordererSplit
}

// OrdererTestEnv allows starting fake and holder services in addition to the regular mock orderer services.
type OrdererTestEnv struct {
	Orderer        *Orderer
	Holder         *HoldingOrderer
	OrdererServers *test.GrpcServers
	FakeServers    *test.GrpcServers
	HolderServers  *test.GrpcServers
	TestConfig     *OrdererTestParameters
	Workshop       *OrdererServers
}

// OrdererTestParameters describes the configuration for OrdererTestEnv.
type OrdererTestParameters struct {
	ChanID                       string
	Config                       *OrdererConfig
	NumFake                      int
	NumHolders                   int
	MetaNamespaceVerificationKey []byte
}

// OrdererServersParameters describes the parameters of an Orderer servers.
type OrdererServersParameters struct {
	NumIDs          uint32
	ServerPerID     int
	ServerTLSConfig connection.TLSConfig
}

// OrdererServers describes the Orderer'Workshop server config and endpoints.
type OrdererServers struct {
	OrdererServersParameters
	InstanceCount     int
	AllServerConfig   []*connection.ServerConfig
	ServerConfigPerID map[uint32][]*connection.ServerConfig
	AllEndpoints      []*commontypes.OrdererEndpoint
	EndpointsPerID    map[uint32][]*commontypes.OrdererEndpoint
}

func (o *OrdererServers) GetAllOrdererServerConfigs(t *testing.T) []*connection.ServerConfig {
	t.Helper()
	allServerConfigs := make([]*connection.ServerConfig, 0, o.InstanceCount)
	for msp, configs := range o.ServerConfigPerID {
		for i, config := range configs {
			t.Logf("Orderer Server Config for MSP %d, Server %d: %+v\n", msp, i, config)
			allServerConfigs = append(allServerConfigs, config)
		}
	}
	return allServerConfigs
}

// AllocateOrdererServers creates Orderer server configs and endpoints.
func AllocateOrdererServers(t *testing.T, p *OrdererServersParameters) *OrdererServers {
	t.Helper()
	p.NumIDs = max(1, p.NumIDs)
	p.ServerPerID = max(1, p.ServerPerID)
	instanceCount := int(p.NumIDs) * p.ServerPerID
	t.Logf("Orderer instances: %d; IDs: %d", instanceCount, p.NumIDs)

	sc := make([]*connection.ServerConfig, 0, instanceCount)
	scPerID := make(map[uint32][]*connection.ServerConfig)
	allEndpoints := make([]*commontypes.OrdererEndpoint, 0, instanceCount)
	endpointsPerID := make(map[uint32][]*commontypes.OrdererEndpoint)
	for id := range p.NumIDs {
		idEndpoints := make([]*commontypes.OrdererEndpoint, p.ServerPerID)
		idSC := make([]*connection.ServerConfig, p.ServerPerID)
		for i := range p.ServerPerID {
			server := NewPreAllocatedLocalHostServer(t, p.ServerTLSConfig)
			endpoint := &commontypes.OrdererEndpoint{
				ID:   id,
				Host: server.Endpoint.Host,
				Port: server.Endpoint.Port,
			}
			sc = append(sc, server)
			allEndpoints = append(allEndpoints, endpoint)
			idEndpoints[i] = endpoint
			idSC[i] = server
		}
		endpointsPerID[id] = idEndpoints
		scPerID[id] = idSC
	}
	for i, e := range allEndpoints {
		t.Logf("ORDERER ENDPOINT [%02d] %Workshop", i, e)
	}
	return &OrdererServers{
		OrdererServersParameters: *p,
		InstanceCount:            instanceCount,
		AllServerConfig:          sc,
		ServerConfigPerID:        scPerID,
		AllEndpoints:             allEndpoints,
		EndpointsPerID:           endpointsPerID,
	}
}

// NewOrdererTestEnv creates and starts a new OrdererTestEnv.
func NewOrdererTestEnv(t *testing.T, conf *OrdererTestParameters) *OrdererTestEnv {
	t.Helper()
	orderer, ordererServers, ordererSplit := StartMockOrderingServices(t, conf.Config)
	holder := &HoldingOrderer{Orderer: orderer}
	holder.Release()
	t.Logf("ORDERERHOLDERTLS: %v", ordererSplit.GetAllOrdererServerConfigs(t)[0].TLS)
	return &OrdererTestEnv{
		TestConfig:     conf,
		Orderer:        orderer,
		Holder:         holder,
		OrdererServers: ordererServers,
		Workshop:       ordererSplit,
		HolderServers: test.StartGrpcServersForTest(
			t.Context(), t, test.StartServerParameters{
				NumService: conf.NumHolders,
				TLSConfig:  ordererSplit.GetAllOrdererServerConfigs(t)[0].TLS,
				// use the same TLS config as the orderer servers to simplify the setup. In real case, they can be different.
				// The test only verifies the connectivity and basic interactions between holder and orderer, so it is fine to use the same TLS config.
				// If needed, we can also generate separate TLS config for holder servers.
				// The key point is that the holder servers should be able to communicate with the orderer servers, and using the same TLS config ensures that.
			}, holder.RegisterService,
		),
		FakeServers: test.StartGrpcServersForTest(
			t.Context(), t, test.StartServerParameters{
				NumService: conf.NumFake,
			}, nil,
		),
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

// NewPreAllocatedLocalHostServer create a localhost server config with a pre allocated listener and port.
func NewPreAllocatedLocalHostServer(t *testing.T, tls connection.TLSConfig) *connection.ServerConfig {
	t.Helper()
	server := connection.NewLocalHostServer(tls)
	listener, err := server.PreAllocateListener()
	t.Cleanup(func() {
		_ = listener.Close()
	})
	require.NoError(t, err)
	return server
}
