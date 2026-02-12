/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"context"
	"fmt"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"path/filepath"
	"slices"
	"strconv"
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

// StartMockOrderingServices starts a specified number of mock ordering service per given number of IDs,
// and register cancellation.
// We also generate the config block for the orderer service based on the provided endpoints and other parameters,
// and start the service with the generated config block.
func StartMockOrderingServices(t *testing.T, conf *OrdererConfig) (
	*Orderer, *test.GrpcServers, *OrdererBundle,
) {
	t.Helper()
	service, err := NewMockOrderer(conf)
	require.NoError(t, err)

	if conf.TestServerParameters.UseCryptoMaterial {
		// We allocate orderer servers before creating the config block,
		// so that we can include the servers endpoint in the config block.
		ordererBundle := AllocateOrdererServers(t, &conf.TestServerParameters)

		// We create the policy based on the orderer endpoints and other parameters,
		// which will be used to generate the config block.
		policy := &workload.PolicyProfile{
			// create policy with these endpoints.
			OrdererEndpoints:      ordererBundle.AllEndpoints,
			ChannelID:             "ch1",
			CryptoMaterialPath:    t.TempDir(),
			PeerOrganizationCount: 1,
		}

		// We generate the config block based on the policy, which includes the orderer endpoints.
		service.ConfigBlock, err = workload.CreateConfigBlock(policy)
		require.NoError(t, err, "failed to create config block")
		require.NotNil(t, service.ConfigBlock)

		// start the orderer service after updating the config-block.
		test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
			return connection.FilterStreamRPCError(service.Run(ctx))
		}, service.WaitForReady)

		// updating the orderer sever-configs with the generated TLS credentials.
		for mspID, serverConfigs := range ordererBundle.ServerConfigPerID {
			setRootCA := false
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

				if !setRootCA {
					// For each MSP ID, we add the root CA path to the orderer bundle.
					// We know that the root CA is the same for all orderer nodes under the same MSP ID,
					// so we can just add one of them.
					// We take the first one as we know that there is at least one server config for each MSP ID based on the way
					// we generate the orderer servers.
					ordererBundle.MspIDToRootCAsPaths[mspID] =
						append(ordererBundle.MspIDToRootCAsPaths[mspID], filepath.Join(certDir, "ca.crt"))
					setRootCA = true
				}
			}
		}

		//// We map the orderer servers to their respective MSP ID, so that we can easily access them in the tests.
		//mspToGrpcServers := make(map[uint32]*test.GrpcServers)
		//for id, serverConfigs := range ordererBundle.ServerConfigPerID {
		//	mspToGrpcServers[id] = test.StartGrpcServersWithConfigForTest(
		//		t.Context(), t, service.RegisterService, serverConfigs...,
		//	)
		//}

		// We map the orderer servers to their respective MSP ID, so that we can easily access them in the tests.
		return service, test.StartGrpcServersWithConfigForTest(
			t.Context(), t, service.RegisterService, ordererBundle.AllServerConfig...,
		), ordererBundle
	}

	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(service.Run(ctx))
	}, service.WaitForReady)

	if len(conf.ServerConfigs) > 0 {
		require.Zero(t, conf.TestServerParameters.NumService)
		return service, test.StartGrpcServersWithConfigForTest(t.Context(), t, service.RegisterService,
			conf.ServerConfigs...,
		), nil
	}
	return service, test.StartGrpcServersForTest(t.Context(), t, conf.TestServerParameters, service.RegisterService), nil
}

// OrdererTestEnv allows starting fake and holder services in addition to the regular mock orderer services.
type OrdererTestEnv struct {
	Orderer        *Orderer
	Holder         *HoldingOrderer
	OrdererServers *test.GrpcServers
	FakeServers    *test.GrpcServers
	HolderServers  *test.GrpcServers
	TestConfig     *OrdererTestParameters
	OrdererBundle  *OrdererBundle
}

// OrdererTestParameters describes the configuration for OrdererTestEnv.
type OrdererTestParameters struct {
	ChanID                       string
	Config                       *OrdererConfig
	NumFake                      int
	NumHolders                   int
	MetaNamespaceVerificationKey []byte
	StartFromCryptoMaterial      bool
}

// OrdererBundle describes the Orderer'OrdererBundle server config and endpoints.
type OrdererBundle struct {
	test.StartServerParameters
	InstanceCount       int
	AllServerConfig     []*connection.ServerConfig
	ServerConfigPerID   map[uint32][]*connection.ServerConfig
	AllEndpoints        []*commontypes.OrdererEndpoint
	EndpointsPerID      map[uint32][]*commontypes.OrdererEndpoint
	MspIDToRootCAsPaths map[uint32][]string
}

// CreateOrganizationConfig creates the orderer organizations config based on the
// orderer endpoints and TLS configuration.
// It extracts the endpoints and TLS certificate paths for each organization (ID)
// from the OrdererBundle and constructs the organization config accordingly.
func (o *OrdererBundle) CreateOrganizationConfig(
	t *testing.T, TLSConfig *connection.TLSConfig,
) map[string]*ordererconn.OrganizationConfig {
	orgConfig := make(map[string]*ordererconn.OrganizationConfig)
	for id, endpoints := range o.EndpointsPerID {
		t.Logf("Orderer organization %d has endpoints: %v", id, endpoints)
		orgConfig[strconv.Itoa(int(id))] = &ordererconn.OrganizationConfig{
			Endpoints: endpoints,
			CACerts:   append(TLSConfig.CACertPaths, o.MspIDToRootCAsPaths[id]...),
		}
	}
	return orgConfig
}

func (o *OrdererBundle) GetAllOrdererServerConfigs(t *testing.T) []*connection.ServerConfig {
	t.Helper()
	allServerConfigs := make([]*connection.ServerConfig, 0, o.InstanceCount)
	for _, configs := range o.ServerConfigPerID {
		allServerConfigs = append(allServerConfigs, configs...)
	}
	return allServerConfigs
}

// AllocateOrdererServers creates Orderer server configs and endpoints.
func AllocateOrdererServers(t *testing.T, p *test.StartServerParameters) *OrdererBundle {
	t.Helper()
	p.NumIDs = max(1, p.NumIDs)
	p.NumService = max(1, p.NumService)
	instanceCount := int(p.NumIDs) * p.NumService
	t.Logf("Orderer instances: %d; IDs: %d", instanceCount, p.NumIDs)

	sc := make([]*connection.ServerConfig, 0, instanceCount)
	scPerID := make(map[uint32][]*connection.ServerConfig)
	allEndpoints := make([]*commontypes.OrdererEndpoint, 0, instanceCount)
	endpointsPerID := make(map[uint32][]*commontypes.OrdererEndpoint)
	for id := range p.NumIDs {
		idEndpoints := make([]*commontypes.OrdererEndpoint, p.NumService)
		idSC := make([]*connection.ServerConfig, p.NumService)
		for i := range p.NumService {
			server := NewPreAllocatedLocalHostServer(t, p.TLSConfig)
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
		t.Logf("ORDERER ENDPOINT [%02d] %v", i, e)
	}
	return &OrdererBundle{
		StartServerParameters: *p,
		InstanceCount:         instanceCount,
		AllServerConfig:       sc,
		ServerConfigPerID:     scPerID,
		AllEndpoints:          allEndpoints,
		EndpointsPerID:        endpointsPerID,
		MspIDToRootCAsPaths:   make(map[uint32][]string),
	}
}

// NewOrdererTestEnv creates and starts a new OrdererTestEnv.
func NewOrdererTestEnv(t *testing.T, conf *OrdererTestParameters) *OrdererTestEnv {
	t.Helper()
	orderer, ordererServers, ordererBundle := StartMockOrderingServices(t, conf.Config)
	holder := &HoldingOrderer{Orderer: orderer}
	holder.Release()
	return &OrdererTestEnv{
		TestConfig:     conf,
		Orderer:        orderer,
		Holder:         holder,
		OrdererServers: ordererServers,
		OrdererBundle:  ordererBundle,
		HolderServers: test.StartGrpcServersForTest(
			t.Context(), t, test.StartServerParameters{
				NumService: conf.NumHolders,
				TLSConfig:  ordererBundle.GetAllOrdererServerConfigs(t)[0].TLS,
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
	return test.NewOrdererEndpoints(0, e.OrdererBundle.AllServerConfig...)
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
