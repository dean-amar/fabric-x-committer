/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth_test

import (
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

const testChannelID = "testchannel"

func TestValidateAuthEnvelope_HappyPath(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t) // helper below (Step 3a)
	const method = "/committerpb.QueryService/GetRows"

	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)

	id, mspID, err := auth.ValidateAuthEnvelope(
		env, bundle, certHash, method, auth.DefaultEnvelopeFreshnessWindow, time.Now())
	require.NoError(t, err)
	require.NotNil(t, id)
	require.NotEmpty(t, mspID)
}

func TestValidateAuthEnvelope_WrongMethodRejected(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t)
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, "/committerpb.QueryService/GetRows", certHash)
	require.NoError(t, err)

	_, _, err = auth.ValidateAuthEnvelope(
		env, bundle, certHash, "/committerpb.QueryService/BeginView",
		auth.DefaultEnvelopeFreshnessWindow, time.Now())
	require.ErrorContains(t, err, "method")
}

func TestValidateAuthEnvelope_StaleRejected(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t)
	const method = "/committerpb.QueryService/GetRows"
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)

	future := time.Now().Add(10 * time.Minute)
	_, _, err = auth.ValidateAuthEnvelope(env, bundle, certHash, method, auth.DefaultEnvelopeFreshnessWindow, future)
	require.ErrorContains(t, err, "freshness")
}

func TestValidateAuthEnvelope_CertHashMismatchRejected(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t)
	const method = "/committerpb.QueryService/GetRows"
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)

	_, _, err = auth.ValidateAuthEnvelope(
		env, bundle, []byte("different-hash"), method, auth.DefaultEnvelopeFreshnessWindow, time.Now())
	require.ErrorContains(t, err, "cert")
}

func TestValidateAuthEnvelope_NoCertHashSkipsBinding(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t)
	const method = "/committerpb.QueryService/GetRows"
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)

	// connCertHash nil => non-mTLS => binding skipped, still valid.
	_, _, err = auth.ValidateAuthEnvelope(
		env, bundle, nil, method, auth.DefaultEnvelopeFreshnessWindow, time.Now())
	require.NoError(t, err)
}

func TestValidateAuthEnvelope_TamperedSignatureRejected(t *testing.T) {
	t.Parallel()
	bundle, signer, certHash := setupAuthFixture(t)
	const method = "/committerpb.QueryService/GetRows"
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)
	env.Signature = append([]byte(nil), env.Signature...)
	env.Signature[0] ^= 0xFF

	_, _, err = auth.ValidateAuthEnvelope(
		env, bundle, certHash, method, auth.DefaultEnvelopeFreshnessWindow, time.Now())
	require.Error(t, err)
	_ = cb.Envelope{}
}

// setupAuthFixture builds a channel-configuration bundle and a signing identity that is a
// member of that bundle's MSP, plus a fixed TLS cert hash for binding tests. The bundle and
// the signer MUST be derived from the same crypto material, otherwise DeserializeIdentity/
// Validate/Verify fail because the signer's certificate is not trusted by the bundle's MSP.
//
//nolint:ireturn // msp.SigningIdentity is an interface by design.
func setupAuthFixture(t *testing.T) (*channelconfig.Bundle, msp.SigningIdentity, []byte) {
	t.Helper()

	dir := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
		ChannelID:             testChannelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	bundle, err := serialization.ExtractAppBundle(block.Data.Data[0])
	require.NoError(t, err)

	signer := auth.CreateTestSigner(t, dir)

	certHash := auth.ComputeTLSCertHash([]byte("test-cert"))

	return bundle, signer, certHash
}
