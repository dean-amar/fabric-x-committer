/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"github.com/yugabyte/pgx/v5/pgxpool"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

const (
	testChannelID   = "test-channel"
	resourceGetRows = "/committerpb.QueryService/GetRows"
)

// authTestEnv is a shared test fixture: a real channel-configuration bundle built from a config block
// with crypto, the marshaled configuration envelope it was built from (for exercising the DB refresh
// path), and a peer signing identity that belongs to that bundle's MSP.
type authTestEnv struct {
	bundle         *channelconfig.Bundle
	configEnvelope []byte
	signer         msp.SigningIdentity
}

// newAuthTestEnv builds a two-organization config block with crypto, constructs a
// channelconfig.Bundle from it, and loads a peer client signing identity from the same crypto.
func newAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()
	cryptoPath := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
		ChannelID:             testChannelID,
		PeerOrganizationCount: 2,
	})
	require.NoError(t, err)

	envelope, err := protoutil.ExtractEnvelope(block, 0)
	require.NoError(t, err)
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	require.NoError(t, err)
	envelopeBytes, err := proto.Marshal(envelope)
	require.NoError(t, err)

	identities, err := testcrypto.GetPeersIdentities(cryptoPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	return &authTestEnv{bundle: bundle, configEnvelope: envelopeBytes, signer: identities[0]}
}

// envelopeParams describes an envelope to sign, so the builder stays within the argument limit while
// letting tests vary the header type, channel, payload, and certificate binding independently.
type envelopeParams struct {
	headerType  common.HeaderType
	channelID   string
	payload     proto.Message
	tlsCertHash []byte
}

// signedEnvelope builds a client-signed authentication envelope carrying the given TLS certificate
// hash, marshaled ready to place in an AuthenticateRequest.
func (e *authTestEnv) signedEnvelope(t *testing.T, tlsCertHash []byte) []byte {
	t.Helper()
	return e.signedEnvelopeFor(t, common.HeaderType_MESSAGE, testChannelID, tlsCertHash)
}

// signedEnvelopeFor builds a client-signed envelope with an explicit header type and channel id (and
// an empty payload, as a genuine authentication envelope has), for exercising the envelope-scope
// checks.
func (e *authTestEnv) signedEnvelopeFor(
	t *testing.T, headerType common.HeaderType, channelID string, tlsCertHash []byte,
) []byte {
	t.Helper()
	return e.signEnvelope(t, envelopeParams{
		headerType: headerType, channelID: channelID, payload: &emptypb.Empty{}, tlsCertHash: tlsCertHash,
	})
}

// signedEnvelopeWithPayload builds a client-signed envelope wrapping an explicit application payload,
// so a test can construct a transaction-shaped envelope (non-empty payload) and assert it cannot be
// replayed to mint a token.
func (e *authTestEnv) signedEnvelopeWithPayload(
	t *testing.T, headerType common.HeaderType, channelID string, payload proto.Message,
) []byte {
	t.Helper()
	return e.signEnvelope(t, envelopeParams{headerType: headerType, channelID: channelID, payload: payload})
}

// signEnvelope signs and marshals an envelope from the given parameters.
func (e *authTestEnv) signEnvelope(t *testing.T, p envelopeParams) []byte {
	t.Helper()
	env, err := protoutil.CreateSignedEnvelopeWithTLSBinding(
		p.headerType, p.channelID, e.signer, p.payload, 0, 0, p.tlsCertHash,
	)
	require.NoError(t, err)
	envBytes, err := proto.Marshal(env)
	require.NoError(t, err)
	return envBytes
}

// insertConfigTx writes a configuration transaction into the config namespace at the given version.
func insertConfigTx(t *testing.T, pool *pgxpool.Pool, envelope []byte, version uint64) {
	t.Helper()
	//nolint:gosec // G115: test version values are small and non-negative.
	_, err := pool.Exec(t.Context(),
		"INSERT INTO ns__config (key, value, version) VALUES ($1, $2, $3) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, version = EXCLUDED.version",
		[]byte(committerpb.ConfigKey), envelope, int64(version))
	require.NoError(t, err)
}

// peerContextWithCert returns a context carrying a TLS peer certificate, together with the SHA-256
// hash of that certificate (the value util.ExtractCertificateHashFromContext computes for it).
func peerContextWithCert(t *testing.T) (context.Context, []byte) {
	t.Helper()
	cert := selfSignedCert(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
	hash := sha256.Sum256(cert.Raw)
	return ctx, hash[:]
}

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "auth-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newTokenStoreForTest provisions a database and returns a token store whose table has been created.
func newTokenStoreForTest(t *testing.T) *tokenStore {
	t.Helper()
	dbEnv := vc.NewDatabaseTestEnv(t)
	pool, err := statedb.NewPool(t.Context(), dbEnv.DBConf)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	store := newTokenStore(pool)
	require.NoError(t, store.ensureTable(t.Context()))
	return store
}

// newAuthServiceForTest wires a fully operational Service - database-backed store, ephemeral signer,
// and the given environment's bundle already loaded into the config provider - without opening the
// gRPC servers. It returns the shared signer so tests can mint tokens the service will accept.
func newAuthServiceForTest(t *testing.T, env *authTestEnv) (*Service, *tokenSigner) {
	t.Helper()
	store := newTokenStoreForTest(t)
	signer, err := newTokenSigner("")
	require.NoError(t, err)

	cfg := &Config{TokenTTL: 5 * time.Minute, EnvelopeFreshnessWindow: time.Minute}
	svc := &Service{
		config:        cfg,
		metrics:       newAuthServiceMetrics(),
		store:         store,
		authenticator: newAuthenticator(signer, store, cfg.EnvelopeFreshnessWindow, cfg.TokenTTL),
		authorizer:    newAuthorizer(signer, store),
	}
	svc.provider = newConfigProvider(store.pool, svc.metrics)
	svc.provider.bundle.Store(env.bundle)
	return svc, signer
}

// testRecord builds a token record with the given id and expiry.
func testRecord(jti string, expiresAt time.Time) *servicepb.TokenRecord {
	return &servicepb.TokenRecord{
		Jti:                jti,
		SerializedIdentity: []byte("serialized-" + jti),
		MspId:              testMSPID,
		CertHashSha256:     []byte{0x01, 0x02, 0x03},
		Scope:              []string{resourceGetRows},
		IssuedSequence:     1,
		ExpiresAt:          expiresAt.Unix(),
	}
}
