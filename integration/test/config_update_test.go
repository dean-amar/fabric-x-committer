/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/mock"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

const blockSize = 1

func TestConfigUpdate(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockSize:    100,
		BlockTimeout: 2 * time.Second,
		CrashTest:    true,
	})
	ordererServers := make([]*connection.ServerConfig, len(c.SystemConfig.Endpoints.Orderer))
	for i, e := range c.SystemConfig.Endpoints.Orderer {
		ordererServers[i] = &connection.ServerConfig{Endpoint: *e.Server, TLS: c.SystemConfig.ServiceTLS}
	}
	ordererEnv := mock.NewOrdererTestEnv(t, &mock.OrdererTestConfig{
		ChanID: "ch1",
		Policy: c.SystemConfig.Policy,
		Config: &mock.OrdererConfig{
			ServerConfigs: ordererServers,
			NumService:    len(ordererServers),
			BlockSize:     blockSize,
			// We want each block to contain exactly <blockSize> transactions.
			// Therefore, we set a higher block timeout so that we have enough time to send all the
			// transactions to the orderer and create a block.
			BlockTimeout:    5 * time.Minute,
			ConfigBlockPath: c.SystemConfig.ConfigBlockPath,
			SendConfigBlock: true,
		},
		NumHolders: 1,
	})
	t.Log(c.SystemConfig.Endpoints.Orderer)
	t.Log(ordererEnv.AllRealOrdererEndpoints())

	c.Start(t, runner.CommitterTxPath)

	c.CreateNamespacesAndCommit(t, "1")

	sendTXs := func() {
		txs := make([][]*applicationpb.TxNamespace, blockSize)
		expected := make([]committerpb.Status, blockSize)
		for i := range blockSize {
			txs[i] = []*applicationpb.TxNamespace{{
				NsId:        "1",
				NsVersion:   0,
				BlindWrites: []*applicationpb.Write{{Key: []byte(fmt.Sprintf("key-%d", i))}},
			}}
			expected[i] = committerpb.Status_COMMITTED
		}
		c.MakeAndSendTransactionsToOrderer(t, txs, expected)
	}

	t.Log("Sanity check")
	sendTXs()

	metaTx, err := workload.CreateNamespacesTX(c.SystemConfig.Policy, 1, "2", "3")
	require.NoError(t, err)

	// We sign the meta TX with the old signature.
	lgMetaTx := c.TxBuilder.MakeTx(metaTx)

	c.AddOrUpdateNamespaces(t, committerpb.MetaNamespaceID)
	//verPolicies := c.TxBuilder.TxEndorser.VerificationPolicies()
	//metaPolicy := verPolicies[committerpb.MetaNamespaceID]
	//submitConfigBlock := func(endpoints []*commontypes.OrdererEndpoint) {
	//	ordererEnv.SubmitConfigBlock(t, &workload.ConfigBlock{
	//		ChannelID:                    c.SystemConfig.Policy.ChannelID,
	//		OrdererEndpoints:             endpoints,
	//		MetaNamespaceVerificationKey: metaPolicy.GetThresholdRule().GetPublicKey(),
	//	})
	//}
	//submitConfigBlock := func(endpoints []*commontypes.OrdererEndpoint) {
	//	verPolicies := c.TxBuilder.TxEndorser.VerificationPolicies()
	//	metaPolicy := verPolicies[committerpb.MetaNamespaceID]
	//
	//	tmpl, err := workload.CreateDefaultConfigBlockWithCrypto(
	//		c.SystemConfig.Policy.CryptoMaterialPath,
	//		&workload.ConfigBlock{
	//			ChannelID:                    c.SystemConfig.Policy.ChannelID,
	//			OrdererEndpoints:             endpoints,
	//			MetaNamespaceVerificationKey: metaPolicy.GetThresholdRule().GetPublicKey(),
	//			PeerOrganizationCount:        1,
	//		},
	//	)
	//	require.NoError(t, err)
	//
	//	// Load PEM needle from the same file configtxgen reads (your logs show meta-namespace-cert.pem).
	//	pemNeedle, _ := os.ReadFile(path.Join(c.SystemConfig.Policy.CryptoMaterialPath, "meta-namespace-cert.pem"))
	//
	//	metaKey, metaBlob, err := discoverMetaNamespaceConfigValueFromTemplateBlockWithPEMNeedle(t, tmpl, pemNeedle)
	//	require.NoError(t, err)
	//
	//	patched, err := PatchConfigBlockForTest(
	//		ordererEnv.Orderer.ConfigBlock,
	//		"",
	//		test.EndpointsToStrings(endpoints),
	//		c.SystemConfig.Policy.ChannelID,
	//		metaKey,
	//		metaBlob,
	//	)
	//	require.NoError(t, err)
	//
	//	require.NoError(t, ordererEnv.Orderer.SubmitBlock(t.Context(), patched))
	//}

	//submitConfigBlock := func(endpoints []*commontypes.OrdererEndpoint) {
	//	t.Helper()
	//
	//	// Current meta namespace key from the runtime (this is what you’re rotating to).
	//	verPolicies := c.TxBuilder.TxEndorser.VerificationPolicies()
	//	metaPolicy := verPolicies[committerpb.MetaNamespaceID]
	//	metaNeedle := metaPolicy.GetThresholdRule().GetPublicKey()
	//	require.NotEmpty(t, metaNeedle, "meta policy public key is empty")
	//
	//	// --- helpers (local) ---
	//	parseConfigEnvelope := func(b *common.Block) (*common.ConfigEnvelope, error) {
	//		if b == nil || b.Data == nil || len(b.Data.Data) == 0 {
	//			return nil, fmt.Errorf("invalid block: empty data")
	//		}
	//		env := &common.Envelope{}
	//		if err := proto.Unmarshal(b.Data.Data[0], env); err != nil {
	//			return nil, fmt.Errorf("unmarshal envelope: %w", err)
	//		}
	//		pl := &common.Payload{}
	//		if err := proto.Unmarshal(env.Payload, pl); err != nil {
	//			return nil, fmt.Errorf("unmarshal payload: %w", err)
	//		}
	//		cfgEnv := &common.ConfigEnvelope{}
	//		if err := proto.Unmarshal(pl.Data, cfgEnv); err != nil {
	//			return nil, fmt.Errorf("unmarshal config envelope: %w", err)
	//		}
	//		if cfgEnv.Config == nil || cfgEnv.Config.ChannelGroup == nil {
	//			return nil, fmt.Errorf("missing config/channel group")
	//		}
	//		return cfgEnv, nil
	//	}
	//
	//	// 1) Build a TEMPLATE config block (fresh) so we can discover the *real* key name + encoding.
	//	// IMPORTANT: use the correct function signature you have.
	//	tmpl, err := workload.CreateDefaultConfigBlockWithCrypto(
	//		c.SystemConfig.Policy.CryptoMaterialPath,
	//		&workload.ConfigBlock{
	//			ChannelID:                    c.SystemConfig.Policy.ChannelID,
	//			OrdererEndpoints:             endpoints,
	//			PeerOrganizationCount:        1,
	//			MetaNamespaceVerificationKey: metaNeedle,
	//		},
	//	)
	//	require.NoError(t, err)
	//
	//	cfgEnv, err := parseConfigEnvelope(tmpl)
	//	require.NoError(t, err)
	//
	//	metaKeyName, metaBlob, ok := findConfigValueContaining(cfgEnv.Config.ChannelGroup, metaNeedle)
	//	require.True(t, ok, "could not find any config value that contains the meta public key bytes in the template block")
	//	require.NotEmpty(t, metaKeyName)
	//	require.NotEmpty(t, metaBlob)
	//
	//	// 2) Patch your EXISTING config block with:
	//	//    - updated /Channel/Orderer/<org>/Endpoints
	//	//    - updated meta key (using the discovered key name + full value bytes from template)
	//	patched, err := PatchConfigBlockForTest(
	//		ordererEnv.Orderer.ConfigBlock,
	//		"",                                 // orgID: auto-pick first orderer org group
	//		test.EndpointsToStrings(endpoints), // []string "host:port"
	//		c.SystemConfig.Policy.ChannelID,
	//		metaKeyName, // discovered key name in config tree
	//		metaBlob,    // correctly-encoded raw ConfigValue.Value bytes
	//	)
	//	require.NoError(t, err)
	//
	//	// 3) Submit patched block.
	//	require.NoError(t, ordererEnv.Orderer.SubmitBlock(t.Context(), patched))
	//}

	// submitConfigBlock creates a template config-block to discover the *real* meta key path,
	// patches the running orderer config-block, **bumps TxID/nonce** (fixes REJECTED_DUPLICATE_TX_ID),
	// and submits it.
	submitConfigBlock := func(endpoints []*commontypes.OrdererEndpoint) {
		t.Helper()

		// Current meta namespace key from the runtime (this is what you’re rotating to).
		verPolicies := c.TxBuilder.TxEndorser.VerificationPolicies()
		metaPolicy := verPolicies[committerpb.MetaNamespaceID]
		metaNeedle := metaPolicy.GetThresholdRule().GetPublicKey()
		require.NotEmpty(t, metaNeedle, "meta policy public key is empty")

		// --- helpers (local) ---
		parseConfigEnvelope := func(b *common.Block) (*common.ConfigEnvelope, error) {
			if b == nil || b.Data == nil || len(b.Data.Data) == 0 {
				return nil, fmt.Errorf("invalid block: empty data")
			}
			env := &common.Envelope{}
			if err := proto.Unmarshal(b.Data.Data[0], env); err != nil {
				return nil, fmt.Errorf("unmarshal envelope: %w", err)
			}
			pl := &common.Payload{}
			if err := proto.Unmarshal(env.Payload, pl); err != nil {
				return nil, fmt.Errorf("unmarshal payload: %w", err)
			}
			cfgEnv := &common.ConfigEnvelope{}
			if err := proto.Unmarshal(pl.Data, cfgEnv); err != nil {
				return nil, fmt.Errorf("unmarshal config envelope: %w", err)
			}
			if cfgEnv.Config == nil || cfgEnv.Config.ChannelGroup == nil {
				return nil, fmt.Errorf("missing config/channel group")
			}
			return cfgEnv, nil
		}

		// Find the config value key that contains the meta public key bytes (as substring).
		findConfigValueContaining := func(g *common.ConfigGroup, needle []byte) (string, []byte, bool) {
			if g == nil {
				return "", nil, false
			}
			for k, cv := range g.Values {
				if cv != nil && len(cv.Value) > 0 && bytes.Contains(cv.Value, needle) {
					return k, cv.Value, true
				}
			}
			for _, child := range g.Groups {
				if k, v, ok := findConfigValueContaining(child, needle); ok {
					return k, v, true
				}
			}
			return "", nil, false
		}

		// IMPORTANT: the committer rejects duplicate TxIDs. configtxgen tends to produce a repeated TxID/nonce.
		// This bumps SignatureHeader.Nonce and ChannelHeader.TxId (computed from nonce+creator).
		bumpBlockTxID := func(b *common.Block) error {
			if b == nil || b.Data == nil || len(b.Data.Data) == 0 {
				return fmt.Errorf("invalid block: empty data")
			}

			env := &common.Envelope{}
			if err := proto.Unmarshal(b.Data.Data[0], env); err != nil {
				return fmt.Errorf("unmarshal envelope: %w", err)
			}
			pl := &common.Payload{}
			if err := proto.Unmarshal(env.Payload, pl); err != nil {
				return fmt.Errorf("unmarshal payload: %w", err)
			}
			if pl.Header == nil {
				return fmt.Errorf("missing payload header")
			}

			sh := &common.SignatureHeader{}
			if err := proto.Unmarshal(pl.Header.SignatureHeader, sh); err != nil {
				return fmt.Errorf("unmarshal signature header: %w", err)
			}
			ch := &common.ChannelHeader{}
			if err := proto.Unmarshal(pl.Header.ChannelHeader, ch); err != nil {
				return fmt.Errorf("unmarshal channel header: %w", err)
			}

			nonce := make([]byte, 24)
			if _, err := rand.Read(nonce); err != nil {
				return fmt.Errorf("rand nonce: %w", err)
			}
			sh.Nonce = nonce

			newTxID := protoutil.ComputeTxID(nonce, sh.Creator)
			ch.TxId = newTxID

			var err error
			pl.Header.SignatureHeader, err = proto.Marshal(sh)
			if err != nil {
				return fmt.Errorf("marshal signature header: %w", err)
			}
			pl.Header.ChannelHeader, err = proto.Marshal(ch)
			if err != nil {
				return fmt.Errorf("marshal channel header: %w", err)
			}

			env.Payload, err = proto.Marshal(pl)
			if err != nil {
				return fmt.Errorf("marshal payload: %w", err)
			}
			b.Data.Data[0], err = proto.Marshal(env)
			if err != nil {
				return fmt.Errorf("marshal envelope: %w", err)
			}
			return nil
		}
		// --- end helpers ---

		// 1) Build a TEMPLATE config block (fresh) so we can discover the real key name + encoding.
		tmpl, err := workload.CreateDefaultConfigBlockWithCrypto(
			c.SystemConfig.Policy.CryptoMaterialPath,
			&workload.ConfigBlock{
				ChannelID:                    c.SystemConfig.Policy.ChannelID,
				OrdererEndpoints:             endpoints,
				PeerOrganizationCount:        1,
				MetaNamespaceVerificationKey: metaNeedle,
			},
		)
		require.NoError(t, err)

		cfgEnv, err := parseConfigEnvelope(tmpl)
		require.NoError(t, err)

		metaKeyName, metaBlob, ok := findConfigValueContaining(cfgEnv.Config.ChannelGroup, metaNeedle)
		require.True(t, ok, "could not find meta public key bytes inside template config block values")
		require.NotEmpty(t, metaKeyName)
		require.NotEmpty(t, metaBlob)

		// 2) Patch the EXISTING orderer config block:
		patched, err := PatchConfigBlockForTest(
			ordererEnv.Orderer.ConfigBlock,
			"",                                 // orgID: auto-pick first orderer org group
			test.EndpointsToStrings(endpoints), // []string "host:port"
			c.SystemConfig.Policy.ChannelID,
			metaKeyName, // discovered key
			metaBlob,    // correctly-encoded value bytes
		)
		require.NoError(t, err)

		// 3) Fix duplicate-txid rejection.
		require.NoError(t, bumpBlockTxID(patched))

		// 4) Submit.
		require.NoError(t, ordererEnv.Orderer.SubmitBlock(t.Context(), patched))
	}

	submitConfigBlock(ordererEnv.AllRealOrdererEndpoints())
	c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
		Statuses: []committerpb.Status{committerpb.Status_COMMITTED},
	})

	// We send the old version and it fails.
	c.SendTransactionsToOrderer(
		t,
		[]*servicepb.LoadGenTx{lgMetaTx},
		[]committerpb.Status{committerpb.Status_ABORTED_SIGNATURE_INVALID},
	)

	// We send with the updated key and it works.
	c.MakeAndSendTransactionsToOrderer(
		t,
		[][]*applicationpb.TxNamespace{metaTx.Namespaces},
		[]committerpb.Status{committerpb.Status_COMMITTED},
	)

	t.Log("Sanity check")
	sendTXs()

	t.Log("Update the sidecar to use a holder orderer group")
	submitConfigBlock(ordererEnv.AllHolderEndpoints())
	c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
		Statuses: []committerpb.Status{committerpb.Status_COMMITTED},
	})

	holdingBlock := c.LastReceivedBlockNumber + 2
	t.Logf("Holding block #%d", holdingBlock)
	ordererEnv.Holder.HoldFromBlock.Store(holdingBlock)

	t.Log("Restart sidecar to check that it restarts using the holding orderer")
	c.Sidecar.Restart(t)

	t.Log("Sanity check")
	sendTXs()

	t.Log("Submit new config block, and ensure it was not received")
	// We submit the config that returns to the non-holding orderer.
	// But it should not be processed as the sidecar should have switched to the holding
	// orderer.
	submitConfigBlock(ordererEnv.AllRealOrdererEndpoints())
	select {
	case <-c.CommittedBlock:
		t.Fatal("the sidecar cannot receive blocks since its orderer holds them")
	case <-time.After(30 * time.Second):
		t.Log("Fantastic")
	}

	t.Log("We expect the block to be held")
	nextBlock, err := c.CoordinatorClient.GetNextBlockNumberToCommit(t.Context(), nil)
	require.NoError(t, err)
	require.NotNil(t, nextBlock)
	require.Equal(t, holdingBlock, nextBlock.Number)

	t.Log("We advance the holder by one to allow the config block to pass through, but not other blocks")
	ordererEnv.Holder.HoldFromBlock.Add(1)
	c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
		Statuses: []committerpb.Status{committerpb.Status_COMMITTED},
	})

	t.Log("The sidecar should use the non-holding orderer, so the holding should not affect the processing")
	sendTXs()
}

type metaKeyHit struct {
	path  string // group path, e.g. /Channel/Application
	key   string // value map key, e.g. "MetaNamespaceVerificationKey"
	value []byte // raw ConfigValue.Value bytes
}

// discoverMetaNamespaceConfigValueFromTemplateBlock scans a *template* config block and tries to find
// which ConfigValue key is used to store the meta-namespace verification material.
// It returns the discovered map-key (e.g. "MetaNamespaceVerificationKey") and the raw Value bytes from the template.
//
// Why: your configtx profile might not use "MetaNamespacePolicyKey". This makes your test robust.
func discoverMetaNamespaceConfigValueFromTemplateBlock(t *testing.T, tmpl *common.Block) (string, []byte, error) {
	t.Helper()

	cfgEnv, err := unmarshalConfigEnvelopeFromBlock(tmpl)
	if err != nil {
		return "", nil, err
	}

	// 1) Try well-known candidates first (fast path).
	candidates := []string{
		"MetaNamespacePolicyKey",
		"MetaNamespaceKey",
		"MetaNamespaceVerificationKey",
		"MetaNamespaceVerificationKeyPath",
		"LifecycleEndorsementPolicy",
	}
	for _, k := range candidates {
		if cv := findConfigValueByKey(cfgEnv.Config.ChannelGroup, k); cv != nil && len(cv.Value) > 0 {
			return k, cv.Value, nil
		}
	}

	// 2) Heuristic scan: locate the config value whose bytes contain the PEM public key (or its DER form).
	// configtxgen logs show it reads a PUBLIC KEY from meta-namespace-cert.pem in your setup.
	// We load that PEM file and search for its content.
	//
	// NOTE: We don't have the path to the pem from here, so the caller should pass needle bytes if they want.
	// For convenience, we attempt to extract ANY embedded PEM block and search with it is not possible here.
	// Instead: return a good error indicating candidates weren't found.
	return "", nil, fmt.Errorf("none of the meta keys found in template block; tried: %v", candidates)
}

// discoverMetaNamespaceConfigValueFromTemplateBlockWithPEMNeedle does the same as above, but if no known
// key is found it scans for a config value containing the given PEM or DER bytes.
func discoverMetaNamespaceConfigValueFromTemplateBlockWithPEMNeedle(t *testing.T, tmpl *common.Block, pemBytes []byte) (string, []byte, error) {
	t.Helper()

	cfgEnv, err := unmarshalConfigEnvelopeFromBlock(tmpl)
	if err != nil {
		return "", nil, err
	}

	// 1) Try well-known candidates first (fast path).
	candidates := []string{
		"MetaNamespacePolicyKey",
		"MetaNamespaceKey",
		"MetaNamespaceVerificationKey",
		"MetaNamespaceVerificationKeyPath",
		"LifecycleEndorsementPolicy",
	}
	for _, k := range candidates {
		if cv := findConfigValueByKey(cfgEnv.Config.ChannelGroup, k); cv != nil && len(cv.Value) > 0 {
			return k, cv.Value, nil
		}
	}

	// 2) If PEM provided, search by PEM *and* DER.
	var hits []metaKeyHit
	if len(pemBytes) > 0 {
		pemNeedle := bytes.TrimSpace(pemBytes)
		hits = append(hits, findConfigValuesContaining(cfgEnv.Config.ChannelGroup, pemNeedle)...)

		// Extract DER from PEM (if pemBytes is PEM).
		if blk, _ := pem.Decode(pemBytes); blk != nil && len(blk.Bytes) > 0 {
			derNeedle := blk.Bytes
			hits = append(hits, findConfigValuesContaining(cfgEnv.Config.ChannelGroup, derNeedle)...)
		}
	}

	if len(hits) == 0 {
		return "", nil, fmt.Errorf("no suitable meta key found in template block (no candidate keys matched; scan produced 0 hits)")
	}

	// Pick best-scored hit.
	best := hits[0]
	bestScore := scoreMetaHit(best)
	for i := 1; i < len(hits); i++ {
		s := scoreMetaHit(hits[i])
		if s > bestScore {
			best = hits[i]
			bestScore = s
		}
	}

	t.Logf("Discovered meta namespace config value key via scan: key=%q path=%q len(value)=%d score=%d",
		best.key, best.path, len(best.value), bestScore)

	return best.key, best.value, nil
}

func scoreMetaHit(h metaKeyHit) int {
	s := 0
	lp := strings.ToLower(h.path)
	lk := strings.ToLower(h.key)

	if strings.Contains(lp, "application") {
		s += 10
	}
	if strings.Contains(lp, "meta") || strings.Contains(lp, "namespace") {
		s += 8
	}
	if strings.Contains(lk, "meta") || strings.Contains(lk, "namespace") || strings.Contains(lk, "verification") {
		s += 12
	}
	if len(h.value) > 10_000 {
		s -= 5
	}
	return s
}

// findConfigValuesContaining walks the config tree and returns hits where ConfigValue.Value contains needle bytes.
func findConfigValuesContaining(g *common.ConfigGroup, needle []byte) []metaKeyHit {
	var out []metaKeyHit
	var walk func(path string, cg *common.ConfigGroup)

	walk = func(path string, cg *common.ConfigGroup) {
		if cg == nil {
			return
		}
		for k, cv := range cg.Values {
			if cv == nil || len(cv.Value) == 0 {
				continue
			}
			if bytes.Contains(cv.Value, needle) {
				out = append(out, metaKeyHit{
					path:  path,
					key:   k,
					value: cv.Value,
				})
			}
		}
		for name, child := range cg.Groups {
			walk(path+"/"+name, child)
		}
	}

	walk("/Channel", g)
	return out
}

func unmarshalConfigEnvelopeFromBlock(b *common.Block) (*common.ConfigEnvelope, error) {
	if b == nil || b.Data == nil || len(b.Data.Data) == 0 {
		return nil, fmt.Errorf("invalid block")
	}
	env := &common.Envelope{}
	if err := proto.Unmarshal(b.Data.Data[0], env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	pl := &common.Payload{}
	if err := proto.Unmarshal(env.Payload, pl); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	cfgEnv := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(pl.Data, cfgEnv); err != nil {
		return nil, fmt.Errorf("unmarshal config envelope: %w", err)
	}
	if cfgEnv.Config == nil || cfgEnv.Config.ChannelGroup == nil {
		return nil, fmt.Errorf("missing config/channel group")
	}
	return cfgEnv, nil
}

// patchConfigValueByPathKey sets ConfigValue.Value at an exact group path + key.
// groupPath format: "/Channel/Orderer", "/Channel/Application", etc.
func patchConfigValueByPathKey(root *common.ConfigGroup, groupPath string, key string, newValue []byte) bool {
	if root == nil {
		return false
	}
	if groupPath == "" || groupPath == "/" {
		groupPath = "/Channel"
	}
	parts := strings.Split(strings.Trim(groupPath, "/"), "/")
	// parts should start with "Channel"
	cur := root
	for i := 1; i < len(parts); i++ { // skip "Channel"
		if cur.Groups == nil {
			return false
		}
		nxt := cur.Groups[parts[i]]
		if nxt == nil {
			return false
		}
		cur = nxt
	}
	if cur.Values == nil {
		return false
	}
	cv := cur.Values[key]
	if cv == nil {
		return false
	}
	cv.Value = newValue
	return true
}

// setConfigValueByKey searches the config tree and sets the first ConfigValue whose MAP KEY equals targetKey.
// Returns true if it was found and replaced.
func setConfigValueByKey(g *common.ConfigGroup, targetKey string, newValue []byte) bool {
	if g == nil {
		return false
	}
	if g.Values != nil {
		if cv := g.Values[targetKey]; cv != nil {
			cv.Value = newValue
			return true
		}
	}
	for _, child := range g.Groups {
		if setConfigValueByKey(child, targetKey, newValue) {
			return true
		}
	}
	return false
}

func findConfigValueByKey(g *common.ConfigGroup, key string) *common.ConfigValue {
	if g == nil {
		return nil
	}
	if g.Values != nil {
		if cv := g.Values[key]; cv != nil {
			return cv
		}
	}
	for _, child := range g.Groups {
		if cv := findConfigValueByKey(child, key); cv != nil {
			return cv
		}
	}
	return nil
}

// PatchConfigBlockForTest patches a config block in-place (clone) for testing:
//  1. /Channel/Orderer/<orgID>/Endpoints (as common.OrdererAddresses{Addresses: addresses})
//  2. ChannelID in the outer ChannelHeader (+ ConfigEnvelope.LastUpdate if exists)
//  3. MetaNamespace verification key blob stored under the discovered config value key
//
// metaNamespaceValue is the raw ConfigValue.Value bytes you want to set.
func PatchConfigBlockForTest(
	block *common.Block,
	orgID string,
	addresses []string,
	newChannelID string,
	metaNamespaceKey string,
	metaNamespaceValue []byte,
) (*common.Block, error) {
	if block == nil || block.Data == nil || len(block.Data.Data) == 0 {
		return nil, fmt.Errorf("invalid block: empty data")
	}
	if metaNamespaceKey == "" {
		metaNamespaceKey = "MetaNamespacePolicyKey"
	}

	out := proto.Clone(block).(*common.Block)

	// Envelope -> Payload
	env := &common.Envelope{}
	if err := proto.Unmarshal(out.Data.Data[0], env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	pl := &common.Payload{}
	if err := proto.Unmarshal(env.Payload, pl); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	// Patch outer ChannelHeader.ChannelId
	if newChannelID != "" && pl.Header != nil && len(pl.Header.ChannelHeader) > 0 {
		chHdr := &common.ChannelHeader{}
		if err := proto.Unmarshal(pl.Header.ChannelHeader, chHdr); err == nil {
			chHdr.ChannelId = newChannelID
			pl.Header.ChannelHeader, _ = proto.Marshal(chHdr)
		}
	}

	// Payload.Data -> ConfigEnvelope
	cfgEnv := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(pl.Data, cfgEnv); err != nil {
		return nil, fmt.Errorf("unmarshal config envelope: %w", err)
	}
	if cfgEnv.Config == nil || cfgEnv.Config.ChannelGroup == nil {
		return nil, fmt.Errorf("missing config/channel group")
	}

	// Patch LastUpdate.ChannelId too (optional but recommended for consistency)
	if newChannelID != "" && cfgEnv.LastUpdate != nil {
		luPayload := &common.Payload{}
		if err := proto.Unmarshal(cfgEnv.LastUpdate.Payload, luPayload); err == nil {
			if luPayload.Header != nil && len(luPayload.Header.ChannelHeader) > 0 {
				luChHdr := &common.ChannelHeader{}
				if err := proto.Unmarshal(luPayload.Header.ChannelHeader, luChHdr); err == nil {
					luChHdr.ChannelId = newChannelID
					luPayload.Header.ChannelHeader, _ = proto.Marshal(luChHdr)
					cfgEnv.LastUpdate.Payload, _ = proto.Marshal(luPayload)
				}
			}
		}
	}

	// 1) Patch endpoints in /Channel/Orderer/<orgID>/Endpoints
	ch := cfgEnv.Config.ChannelGroup
	ordererGrp, ok := ch.Groups["Orderer"]
	if !ok || ordererGrp == nil {
		return nil, fmt.Errorf(`missing group "/Channel/Orderer"`)
	}
	if ordererGrp.Groups == nil || len(ordererGrp.Groups) == 0 {
		return nil, fmt.Errorf(`"/Channel/Orderer" has no org groups`)
	}

	// Pick orgID if not provided (deterministic)
	if orgID == "" {
		keys := make([]string, 0, len(ordererGrp.Groups))
		for k := range ordererGrp.Groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		orgID = keys[0]
	}

	orgGrp, ok := ordererGrp.Groups[orgID]
	if !ok || orgGrp == nil {
		return nil, fmt.Errorf(`missing group "/Channel/Orderer/%s"`, orgID)
	}

	addrsBytes, err := proto.Marshal(&common.OrdererAddresses{Addresses: addresses})
	if err != nil {
		return nil, fmt.Errorf("marshal OrdererAddresses: %w", err)
	}

	if orgGrp.Values == nil {
		orgGrp.Values = map[string]*common.ConfigValue{}
	}
	cv := orgGrp.Values["Endpoints"]
	if cv == nil {
		cv = &common.ConfigValue{ModPolicy: "Admins"} // OK for tests
		orgGrp.Values["Endpoints"] = cv
	}
	cv.Value = addrsBytes

	// 2) Patch MetaNamespace value blob:
	// Prefer exact-path patch first (Application group is where this usually lives),
	// else fallback to first-match by key anywhere.
	if len(metaNamespaceValue) > 0 {
		patched := patchConfigValueByPathKey(cfgEnv.Config.ChannelGroup, "/Channel/Application", metaNamespaceKey, metaNamespaceValue)
		if !patched {
			patched = setConfigValueByKey(cfgEnv.Config.ChannelGroup, metaNamespaceKey, metaNamespaceValue)
		}
		if !patched {
			return nil, fmt.Errorf("could not find config value key %q in config tree", metaNamespaceKey)
		}
	}

	// Re-wrap ConfigEnvelope -> Payload -> Envelope -> Block
	newCfgEnvBytes, err := proto.Marshal(cfgEnv)
	if err != nil {
		return nil, fmt.Errorf("marshal config envelope: %w", err)
	}
	pl.Data = newCfgEnvBytes

	newPayloadBytes, err := proto.Marshal(pl)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	env.Payload = newPayloadBytes

	newEnvBytes, err := proto.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	out.Data.Data[0] = newEnvBytes

	return out, nil
}

func findConfigValueContaining(g *common.ConfigGroup, needle []byte) (string, []byte, bool) {
	if g == nil {
		return "", nil, false
	}
	for k, cv := range g.Values {
		if cv != nil && len(cv.Value) > 0 && bytes.Contains(cv.Value, needle) {
			return k, cv.Value, true
		}
	}
	for _, child := range g.Groups {
		if k, v, ok := findConfigValueContaining(child, needle); ok {
			return k, v, true
		}
	}
	return "", nil, false
}

// TestConfigBlockImmediateCommit verifies that config blocks are committed immediately,
// bypassing the normal batching delays configured for the verifier and VC services.
func TestConfigBlockImmediateCommit(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)

	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers:                        1,
		NumVCService:                        1,
		BlockSize:                           100,
		BlockTimeout:                        5 * time.Minute,
		CrashTest:                           true,
		VCMinTransactionBatchSize:           100,
		VCTimeoutForMinTransactionBatchSize: 1 * time.Hour,
		VerifierBatchSizeCutoff:             100,
		VerifierBatchTimeCutoff:             1 * time.Hour,
	})

	ordererServers := make([]*connection.ServerConfig, len(c.SystemConfig.Endpoints.Orderer))
	for i, e := range c.SystemConfig.Endpoints.Orderer {
		ordererServers[i] = &connection.ServerConfig{Endpoint: *e.Server}
	}
	ordererEnv := mock.NewOrdererTestEnv(t, &mock.OrdererTestConfig{
		ChanID: "ch1",
		Config: &mock.OrdererConfig{
			ServerConfigs:   ordererServers,
			NumService:      len(ordererServers),
			BlockSize:       1, // Each block contains exactly 1 transaction.
			BlockTimeout:    5 * time.Minute,
			ConfigBlockPath: c.SystemConfig.ConfigBlockPath,
			SendConfigBlock: true,
		},
		NumHolders: 0,
	})

	// The Start function internally calls ensureAtLeastLastCommittedBlockNumber(t, 0)
	// which waits 2 minutes for block 0 to be committed. If config blocks weren't processed
	// immediately, this would timeout due to the 1-hour batching delays.
	t.Log("Starting services - block 0 (config block) should be committed immediately")
	startTime := time.Now()
	c.Start(t, runner.CommitterTxPath)
	elapsed := time.Since(startTime)
	// this time would be higher due to the start of all services and connection establishment.
	t.Logf("Services started and block 0 committed in %v", elapsed)

	verPolicies := c.TxBuilder.TxEndorser.VerificationPolicies()
	metaPolicy := verPolicies[committerpb.MetaNamespaceID]
	submitConfigBlock := func() {
		ordererEnv.SubmitConfigBlock(t, &workload.ConfigBlock{
			ChannelID:                    c.SystemConfig.Policy.ChannelID,
			OrdererEndpoints:             ordererEnv.AllRealOrdererEndpoints(),
			MetaNamespaceVerificationKey: metaPolicy.GetThresholdRule().GetPublicKey(),
		})
	}

	t.Log("Submitting config block (block 1) - should be committed immediately")
	startTime = time.Now()

	submitConfigBlock()

	const maxWaitTime = 3 * time.Second
	select {
	case blk := <-c.CommittedBlock:
		elapsed = time.Since(startTime)
		t.Logf("Config block #%d committed in %v", blk.Header.Number, elapsed)
		require.Equal(t, uint64(1), blk.Header.Number)
		require.Less(t, elapsed, maxWaitTime)
	case <-time.After(maxWaitTime):
		t.Fatalf("Config block was not committed within %v", maxWaitTime)
	}

	t.Log("Config block was committed immediately, bypassing batching delays")
}
