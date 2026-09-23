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
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"github.com/yugabyte/pgx/v5/pgxpool"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

const (
	testChannelID   = "test-channel"
	resourceGetRows = "/committerpb.QueryService/GetRows"
)

// authTestEnv is a real channel-configuration bundle, the envelope it was built from (for the DB refresh
// path), and a peer signing identity belonging to that bundle's MSP.
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

// envelopeParams describes an envelope to sign, letting a test vary the header type, channel, payload and
// certificate binding independently. A nil payload signs an empty one, which is the authentication shape.
type envelopeParams struct {
	headerType  common.HeaderType
	channelID   string
	payload     proto.Message
	tlsCertHash []byte
	nonce       []byte
}

// signedEnvelope builds a client-signed envelope carrying the given certificate hash. It has no nonce, so
// only verifyEnvelope accepts it; a test going through Authenticate needs signedEnvelopeWithNonce.
func (e *authTestEnv) signedEnvelope(t *testing.T, tlsCertHash []byte) *common.Envelope {
	t.Helper()
	return e.signEnvelope(t, envelopeParams{
		headerType: common.HeaderType_MESSAGE, channelID: testChannelID, tlsCertHash: tlsCertHash,
	})
}

// signedEnvelopeWithNonce builds an authentication envelope carrying a server-issued nonce, as a real
// client does after its IssueNonce pre-step.
func (e *authTestEnv) signedEnvelopeWithNonce(t *testing.T, nonce, tlsCertHash []byte) *common.Envelope {
	t.Helper()
	return e.signEnvelope(t, envelopeParams{
		headerType: common.HeaderType_MESSAGE, channelID: testChannelID,
		tlsCertHash: tlsCertHash, nonce: nonce,
	})
}

// signEnvelope signs and marshals an envelope directly rather than via protoutil's helper, which always
// picks its own SignatureHeader nonce - a test needs to control it.
func (e *authTestEnv) signEnvelope(t *testing.T, p envelopeParams) *common.Envelope {
	t.Helper()
	creator, err := e.signer.Serialize()
	require.NoError(t, err)

	channelHeader := protoutil.MakeChannelHeader(p.headerType, 0, p.channelID, 0)
	channelHeader.TlsCertHash = p.tlsCertHash
	var data []byte
	if p.payload != nil {
		data, err = proto.Marshal(p.payload)
		require.NoError(t, err)
	}

	payloadBytes, err := proto.Marshal(&common.Payload{
		Header: protoutil.MakePayloadHeader(channelHeader, protoutil.MakeSignatureHeader(creator, p.nonce)),
		Data:   data,
	})
	require.NoError(t, err)

	signature, err := e.signer.Sign(payloadBytes)
	require.NoError(t, err)
	return &common.Envelope{Payload: payloadBytes, Signature: signature}
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

// newTokenStoreForTest returns a token store over a provisioned database. The auth tables come from the
// system schema NewDatabaseTestEnv applies, so tests exercise exactly what `init-db` creates.
func newTokenStoreForTest(t *testing.T) *tokenStore {
	t.Helper()
	dbEnv := vc.NewDatabaseTestEnv(t)
	pool, err := statedb.NewPool(t.Context(), dbEnv.DBConf)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &tokenStore{pool: pool}
}

// newAuthServiceForTest wires an operational Service - database store, ephemeral signer, bundle loaded -
// without opening the gRPC servers. It returns the signer so tests can mint tokens it will accept.
func newAuthServiceForTest(t *testing.T, env *authTestEnv) (*Service, *tokenSigner) {
	t.Helper()
	store := newTokenStoreForTest(t)
	signer, err := newTokenSigner("")
	require.NoError(t, err)

	cfg := &Config{TokenTTL: 5 * time.Minute, EnvelopeFreshnessWindow: time.Minute, NonceTTL: time.Minute}
	nonces := &nonceStore{pool: store.pool, ttl: cfg.NonceTTL}

	svc := &Service{
		config:  cfg,
		metrics: newAuthServiceMetrics(),
		tokens:  store,
		nonces:  nonces,
		authenticator: &authenticator{
			signer:                  signer,
			tokens:                  store,
			nonces:                  nonces,
			envelopeFreshnessWindow: cfg.EnvelopeFreshnessWindow,
			tokenTTL:                cfg.TokenTTL,
		},
		authorizer: &authorizer{signer: signer, tokens: store},
	}
	svc.configBlockProvider = &configProvider{pool: store.pool, metrics: svc.metrics}
	svc.configBlockProvider.bundle.Store(env.bundle)
	return svc, signer
}

// issueNonce obtains a nonce from the service, as a client's mandatory pre-authentication step.
func issueNonce(t *testing.T, svc *Service) []byte {
	t.Helper()
	resp, err := svc.IssueNonce(t.Context(), &servicepb.IssueNonceRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetNonce())
	return resp.GetNonce()
}

// testRecord builds a token record with the given id and expiry.
func testRecord(jti string, expiresAt time.Time) *servicepb.TokenRecord {
	return &servicepb.TokenRecord{
		Jti:            jti,
		Identity:       &msppb.Identity{MspId: testMSPID},
		MspId:          testMSPID,
		CertHashSha256: []byte{0x01, 0x02, 0x03},
		Scope:          []string{resourceGetRows},
		IssuedSequence: 1,
		ExpiresAt:      expiresAt.Unix(),
	}
}
