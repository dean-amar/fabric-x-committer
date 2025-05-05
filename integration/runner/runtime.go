package runner

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoqueryservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/sidecar/sidecarclient"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc/dbtest"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/broadcastdeliver"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/serialization"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature/sigtest"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

type (
	// CommitterRuntime represents a test system of Coordinator, SigVerifier, VCService and Query processes.
	CommitterRuntime struct {
		SystemConfig config.SystemConfig

		MockOrderer  *ProcessWithConfig
		Sidecar      *ProcessWithConfig
		Coordinator  *ProcessWithConfig
		QueryService *ProcessWithConfig
		Verifier     []*ProcessWithConfig
		VcService    []*ProcessWithConfig

		dbEnv *vc.DatabaseTestEnv

		ordererEndpoints []*connection.OrdererEndpoint

		ordererClient      *broadcastdeliver.Client
		ordererStream      *broadcastdeliver.EnvelopedStream
		CoordinatorClient  protocoordinatorservice.CoordinatorClient
		QueryServiceClient protoqueryservice.QueryServiceClient
		sidecarClient      *sidecarclient.Client

		CommittedBlock chan *common.Block

		nsToCrypto     map[string]*Crypto
		nsToCryptoLock sync.Mutex

		config *Config

		seedForCryptoGen *rand.Rand

		LastReceivedBlockNumber uint64
	}

	// Crypto holds crypto material for a namespace.
	Crypto struct {
		Namespace  string
		Profile    *workload.Policy
		HashSigner *workload.HashSignerVerifier
		NsSigner   *sigtest.NsSigner
		PubKey     []byte
		PubKeyPath string
	}

	// Config represents the runtime configuration.
	Config struct {
		NumVerifiers      int
		NumVCService      int
		BlockSize         uint64
		BlockTimeout      time.Duration
		LoadgenBlockLimit uint64

		// DBCluster configures the cluster to operate in DB cluster mode.
		DBCluster *dbtest.Connection
	}
)

// Service flags.
const (
	Orderer = 1 << iota
	Sidecar
	Coordinator
	Verifier
	VC
	QueryService
	LoadGenForOrderer
	LoadGenForCommitter

	FullTxPath            = Orderer | Sidecar | Coordinator | Verifier | VC
	FullTxPathWithLoadGen = FullTxPath | LoadGenForOrderer
	FullTxPathWithQuery   = FullTxPath | QueryService

	CommitterTxPath            = Sidecar | Coordinator | Verifier | VC
	CommitterTxPathWithLoadGen = CommitterTxPath | LoadGenForCommitter
)

// NewRuntime creates a new test runtime.
func NewRuntime(t *testing.T, conf *Config) *CommitterRuntime {
	t.Helper()

	c := &CommitterRuntime{
		config: conf,
		SystemConfig: config.SystemConfig{
			ChannelID:         "channel1",
			BlockSize:         conf.BlockSize,
			BlockTimeout:      conf.BlockTimeout,
			LoadGenBlockLimit: conf.LoadgenBlockLimit,
			Logging:           &logging.DefaultConfig,
		},
		nsToCrypto:       make(map[string]*Crypto),
		CommittedBlock:   make(chan *common.Block, 100),
		seedForCryptoGen: rand.New(rand.NewSource(10)),
	}

	t.Log("Making DB env")
	if conf.DBCluster == nil {
		c.dbEnv = vc.NewDatabaseTestEnv(t)
	} else {
		c.dbEnv = vc.NewDatabaseTestEnvWithCluster(t, conf.DBCluster)
	}
	t.Log("Allocating ports")
	s := &c.SystemConfig
	s.Endpoints.Database = c.dbEnv.DBConf.Endpoints

	ports := portAllocator{}
	defer ports.close()
	s.Endpoints.Orderer = ports.allocatePorts(t, 1)
	s.Endpoints.Verifier = ports.allocatePorts(t, conf.NumVerifiers)
	s.Endpoints.VCService = ports.allocatePorts(t, conf.NumVCService)
	s.Endpoints.Query = ports.allocatePorts(t, 1)[0]
	s.Endpoints.Coordinator = ports.allocatePorts(t, 1)[0]
	s.Endpoints.Sidecar = ports.allocatePorts(t, 1)[0]
	s.Endpoints.LoadGen = ports.allocatePorts(t, 1)[0]
	s.DB.Name = c.dbEnv.DBConf.Database
	s.DB.LoadBalance = c.dbEnv.DBConf.LoadBalance
	s.LedgerPath = t.TempDir()

	t.Logf("Endpoints: %s", &utils.LazyJSON{O: s.Endpoints, Indent: "  "})

	t.Log("Creating config block")
	c.ordererEndpoints = make([]*connection.OrdererEndpoint, len(s.Endpoints.Orderer))
	for i, endpoint := range s.Endpoints.Orderer {
		c.ordererEndpoints[i] = &connection.OrdererEndpoint{MspID: "org", Endpoint: *endpoint}
	}
	metaCrypto := c.CreateCryptoForNs(t, types.MetaNamespaceID, signature.Ecdsa)
	s.ConfigBlockPath = config.CreateConfigBlock(t, &config.ConfigBlock{
		ChannelID:                    s.ChannelID,
		OrdererEndpoints:             c.ordererEndpoints,
		MetaNamespaceVerificationKey: metaCrypto.PubKey,
	})

	t.Log("Create processes")
	c.MockOrderer = newProcess(t, mockordererCMD, config.TemplateMockOrderer, s)
	for _, e := range s.Endpoints.Verifier {
		c.Verifier = append(c.Verifier, newProcess(t, verifierCMD, config.TemplateVerifier, s.WithEndpoint(e)))
	}
	for _, e := range s.Endpoints.VCService {
		c.VcService = append(c.VcService, newProcess(t, vcCMD, config.TemplateVC, s.WithEndpoint(e)))
	}
	c.Coordinator = newProcess(t, coordinatorCMD, config.TemplateCoordinator, s.WithEndpoint(s.Endpoints.Coordinator))
	c.QueryService = newProcess(t, queryexecutorCMD, config.TemplateQueryService, s.WithEndpoint(s.Endpoints.Query))
	c.Sidecar = newProcess(t, sidecarCMD, config.TemplateSidecar, s.WithEndpoint(s.Endpoints.Sidecar))

	t.Log("Create clients")
	c.CoordinatorClient = protocoordinatorservice.NewCoordinatorClient(clientConn(t, s.Endpoints.Coordinator))
	c.QueryServiceClient = protoqueryservice.NewQueryServiceClient(clientConn(t, s.Endpoints.Query))

	var err error
	c.ordererClient, err = broadcastdeliver.New(&broadcastdeliver.Config{
		Connection: broadcastdeliver.ConnectionConfig{
			Endpoints: c.ordererEndpoints,
		},
		ChannelID:     s.ChannelID,
		ConsensusType: broadcastdeliver.Bft,
	})
	require.NoError(t, err)

	c.ordererStream, err = c.ordererClient.Broadcast(t.Context())
	require.NoError(t, err)

	c.sidecarClient, err = sidecarclient.New(&sidecarclient.Config{
		ChannelID: s.ChannelID,
		Endpoint:  s.Endpoints.Sidecar,
	})
	require.NoError(t, err)
	return c
}

// Start runs all services and load generator as configured by the serviceFlags.
func (c *CommitterRuntime) Start(t *testing.T, serviceFlags int) {
	t.Helper()

	t.Log("Running services")
	if LoadGenForCommitter&serviceFlags != 0 {
		c.StartLoadGenCommitter(t)
	}
	if Orderer&serviceFlags != 0 {
		c.MockOrderer.Restart(t)
	}
	if Verifier&serviceFlags != 0 {
		for _, p := range c.Verifier {
			p.Restart(t)
		}
	}
	if VC&serviceFlags != 0 {
		for _, p := range c.VcService {
			p.Restart(t)
		}
	}
	if Coordinator&serviceFlags != 0 {
		c.Coordinator.Restart(t)
	}
	if Sidecar&serviceFlags != 0 {
		c.Sidecar.Restart(t)
	}
	if QueryService&serviceFlags != 0 {
		c.QueryService.Restart(t)
	}
	if LoadGenForOrderer&serviceFlags != 0 {
		c.StartLoadGenOrderer(t)
	}

	t.Log("Validate state")
	c.ensureAtLeastLastCommittedBlockNumber(t, 0)

	t.Log("Running delivery client")
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(c.sidecarClient.Deliver(ctx, &sidecarclient.DeliverConfig{
			EndBlkNum:   broadcastdeliver.MaxBlockNum,
			OutputBlock: c.CommittedBlock,
		}))
	}, func(ctx context.Context) bool {
		select {
		case <-ctx.Done():
			return false
		case b := <-c.CommittedBlock:
			require.NotNil(t, b)
			return true
		}
	})
}

// StartLoadGenOrderer applies load on the orderer.
// We need to run the load gen after initializing because it will re-initialize.
func (c *CommitterRuntime) StartLoadGenOrderer(t *testing.T) {
	t.Helper()
	c.startLoadGenWithTemplate(t, config.TemplateLoadGenOrderer)
}

// StartLoadGenCommitter applies load on the sidecar.
// We need to run the load gen after initializing because it will re-initialize.
func (c *CommitterRuntime) StartLoadGenCommitter(t *testing.T) {
	t.Helper()
	c.startLoadGenWithTemplate(t, config.TemplateLoadGenCommitter)
}

func (c *CommitterRuntime) startLoadGenWithTemplate(t *testing.T, template string) {
	t.Helper()
	s := c.SystemConfig
	s.Policy = &workload.PolicyProfile{
		NamespacePolicies: make(map[string]*workload.Policy),
	}
	// We create the crypto profile for the generated namespace to ensure consistency.
	c.CreateCryptoForNs(t, workload.GeneratedNamespaceID, signature.Ecdsa)
	for _, cr := range c.GetAllCrypto() {
		s.Policy.NamespacePolicies[cr.Namespace] = cr.Profile
	}
	newProcess(t, loadgenCMD, template, s.WithEndpoint(s.Endpoints.LoadGen)).Restart(t)
}

// clientConn creates a service connection using its given server endpoint.
func clientConn(t *testing.T, e *connection.Endpoint) *grpc.ClientConn {
	t.Helper()
	serviceConnection, err := connection.Connect(connection.NewDialConfig(e))
	require.NoError(t, err)
	return serviceConnection
}

// CreateNamespacesAndCommit creates namespaces in the committer.
func (c *CommitterRuntime) CreateNamespacesAndCommit(t *testing.T, namespaces ...string) {
	t.Helper()
	if len(namespaces) == 0 {
		return
	}

	t.Logf("Creating namespaces: %v", namespaces)
	metaTX := c.CreateMetaTX(t, namespaces...)
	c.SendTransactionsToOrderer(t, []*protoblocktx.Tx{metaTX})
	c.ValidateExpectedResultsInCommittedBlock(t, &ExpectedStatusInBlock{
		TxIDs:    []string{metaTX.Id},
		Statuses: []protoblocktx.Status{protoblocktx.Status_COMMITTED},
	})
}

// CreateMetaTX creates a meta transaction without submitting it.
func (c *CommitterRuntime) CreateMetaTX(t *testing.T, namespaces ...string) *protoblocktx.Tx {
	t.Helper()
	writeToMetaNs := &protoblocktx.TxNamespace{
		NsId:       types.MetaNamespaceID,
		NsVersion:  types.VersionNumber(0).Bytes(),
		ReadWrites: make([]*protoblocktx.ReadWrite, 0, len(namespaces)),
	}

	for _, nsID := range namespaces {
		nsCr := c.CreateCryptoForNs(t, nsID, signature.Ecdsa)
		nsPolicy := &protoblocktx.NamespacePolicy{
			Scheme:    signature.Ecdsa,
			PublicKey: nsCr.PubKey,
		}
		policyBytes, err := proto.Marshal(nsPolicy)
		require.NoError(t, err)

		writeToMetaNs.ReadWrites = append(writeToMetaNs.ReadWrites, &protoblocktx.ReadWrite{
			Key:   []byte(nsID),
			Value: policyBytes,
		})
	}

	tx := &protoblocktx.Tx{
		Id: uuid.New().String(),
		Namespaces: []*protoblocktx.TxNamespace{
			writeToMetaNs,
		},
	}
	c.AddSignatures(t, tx)
	return tx
}

// AddSignatures adds signature for each namespace in a given transaction.
func (c *CommitterRuntime) AddSignatures(t *testing.T, tx *protoblocktx.Tx) {
	t.Helper()
	tx.Signatures = make([][]byte, len(tx.Namespaces))
	for idx, ns := range tx.Namespaces {
		nsCr := c.GetCryptoForNs(t, ns.NsId)
		sig, err := nsCr.NsSigner.SignNs(tx, idx)
		require.NoError(t, err)
		tx.Signatures[idx] = sig
	}
}

// SendTransactionsToOrderer creates a block with given transactions and sent it to the committer.
func (c *CommitterRuntime) SendTransactionsToOrderer(t *testing.T, txs []*protoblocktx.Tx) {
	t.Helper()
	for _, tx := range txs {
		_, resp, err := c.ordererStream.SubmitWithEnv(tx)
		require.NoError(t, err)
		require.Equal(t, common.Status_SUCCESS, resp.Status)
	}
}

// CreateCryptoForNs creates Crypto materials for a namespace and stores it locally.
// It will fail the test if we create crypto material twice for the same namespace.
func (c *CommitterRuntime) CreateCryptoForNs(t *testing.T, nsID string, schema signature.Scheme) *Crypto {
	t.Helper()
	cr := c.createCrypto(t, nsID, schema)
	c.nsToCryptoLock.Lock()
	defer c.nsToCryptoLock.Unlock()
	require.Nil(t, c.nsToCrypto[nsID])
	c.nsToCrypto[nsID] = cr
	return cr
}

// createCrypto creates Crypto materials.
func (c *CommitterRuntime) createCrypto(t *testing.T, nsID string, schema signature.Scheme) *Crypto {
	t.Helper()
	policyMsg := &workload.Policy{
		Scheme: schema,
		Seed:   c.seedForCryptoGen.Int63(),
	}
	hashSigner := workload.NewHashSignerVerifier(policyMsg)
	pubKey, signer := hashSigner.GetVerificationKeyAndSigner()
	return &Crypto{
		Namespace:  nsID,
		Profile:    policyMsg,
		HashSigner: hashSigner,
		NsSigner:   signer,
		PubKey:     pubKey,
	}
}

// UpdateCryptoForNs creates Crypto materials for a namespace and stores it locally.
// It will fail the test if we create crypto material for the first time.
func (c *CommitterRuntime) UpdateCryptoForNs(t *testing.T, nsID string, schema signature.Scheme) *Crypto {
	t.Helper()
	cr := c.createCrypto(t, nsID, schema)
	c.nsToCryptoLock.Lock()
	defer c.nsToCryptoLock.Unlock()
	require.NotNil(t, c.nsToCrypto[nsID])
	c.nsToCrypto[nsID] = cr
	return cr
}

// GetCryptoForNs returns the Crypto material a namespace.
func (c *CommitterRuntime) GetCryptoForNs(t *testing.T, nsID string) *Crypto {
	t.Helper()
	c.nsToCryptoLock.Lock()
	defer c.nsToCryptoLock.Unlock()
	cr, ok := c.nsToCrypto[nsID]
	require.True(t, ok)
	return cr
}

// GetAllCrypto returns all the Crypto material.
func (c *CommitterRuntime) GetAllCrypto() []*Crypto {
	c.nsToCryptoLock.Lock()
	defer c.nsToCryptoLock.Unlock()
	ret := make([]*Crypto, 0, len(c.nsToCrypto))
	for _, cr := range c.nsToCrypto {
		ret = append(ret, cr)
	}
	return ret
}

// ExpectedStatusInBlock holds pairs of expected txID and the corresponding status in a block. The order of statuses
// is expected to be the same as in the committed block.
type ExpectedStatusInBlock struct {
	TxIDs    []string
	Statuses []protoblocktx.Status
}

// ValidateExpectedResultsInCommittedBlock validates the status of transactions in the committed block.
func (c *CommitterRuntime) ValidateExpectedResultsInCommittedBlock(t *testing.T, expected *ExpectedStatusInBlock) {
	t.Helper()
	var blk *common.Block
	var ok bool
	select {
	case blk, ok = <-c.CommittedBlock:
		if !ok {
			return
		}
	case <-time.After(2 * time.Minute):
		t.Fatalf("Timed out waiting for block #%d", c.LastReceivedBlockNumber+1)
	}
	c.LastReceivedBlockNumber = blk.Header.Number
	t.Logf("Got block #%d", blk.Header.Number)

	expectedStatuses := make([]byte, 0, len(expected.Statuses))
	for _, s := range expected.Statuses {
		expectedStatuses = append(expectedStatuses, byte(s))
	}

	for txNum, txEnv := range blk.Data.Data {
		txBytes, hdr, err := serialization.UnwrapEnvelope(txEnv)
		require.NoError(t, err)
		require.NotNil(t, hdr)
		if hdr.Type == int32(common.HeaderType_CONFIG) {
			continue
		}
		tx, err := serialization.UnmarshalTx(txBytes)
		require.NoError(t, err)
		require.Equal(t, expected.TxIDs[txNum], tx.GetId())
	}

	require.Equal(t, expectedStatuses, blk.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER])

	c.ensureLastCommittedBlockNumber(t, blk.Header.Number)

	nonDuplicateTxIDsStatus := make(map[string]*protoblocktx.StatusWithHeight)
	var nonDupTxIDs []string
	duplicateTxIDsStatus := make(map[string]*protoblocktx.StatusWithHeight)
	for i, tID := range expected.TxIDs {
		s := types.CreateStatusWithHeight(expected.Statuses[i], blk.Header.Number, i)
		if expected.Statuses[i] != protoblocktx.Status_ABORTED_DUPLICATE_TXID {
			nonDuplicateTxIDsStatus[tID] = s
			nonDupTxIDs = append(nonDupTxIDs, tID)
			continue
		}
		duplicateTxIDsStatus[tID] = s
	}

	c.dbEnv.StatusExistsForNonDuplicateTxID(t, nonDuplicateTxIDsStatus)
	// For the duplicate txID, neither the status nor the height would match the entry in the
	// transaction status table.
	c.dbEnv.StatusExistsWithDifferentHeightForDuplicateTxID(t, duplicateTxIDsStatus)

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()
	test.EnsurePersistedTxStatus(ctx, t, c.CoordinatorClient, nonDupTxIDs, nonDuplicateTxIDsStatus)
}

// CountStatus returns the number of transactions with a given tx status.
func (c *CommitterRuntime) CountStatus(t *testing.T, status protoblocktx.Status) int {
	t.Helper()
	return c.dbEnv.CountStatus(t, status)
}

// CountAlternateStatus returns the number of transactions not with a given tx status.
func (c *CommitterRuntime) CountAlternateStatus(t *testing.T, status protoblocktx.Status) int {
	t.Helper()
	return c.dbEnv.CountAlternateStatus(t, status)
}

func (c *CommitterRuntime) ensureLastCommittedBlockNumber(t *testing.T, blkNum uint64) {
	t.Helper()
	c.ensureAtLeastLastCommittedBlockNumber(t, blkNum)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	lastBlock, err := c.CoordinatorClient.GetLastCommittedBlockNumber(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, blkNum, lastBlock.Number)
}

func (c *CommitterRuntime) ensureAtLeastLastCommittedBlockNumber(t *testing.T, blkNum uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		lastBlock, err := c.CoordinatorClient.GetLastCommittedBlockNumber(ctx, nil)
		require.NoError(ct, err)
		require.GreaterOrEqual(ct, lastBlock.Number, blkNum)
	}, 2*time.Minute, 250*time.Millisecond)
}
