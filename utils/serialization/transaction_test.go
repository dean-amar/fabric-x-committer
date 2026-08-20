/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serialization_test

import (
	"testing"

	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

func TestExtractAppBundle(t *testing.T) {
	t.Parallel()

	// Create a valid config block with crypto materials
	configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(t.TempDir(), &testcrypto.ConfigBlock{
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)
	envBytes := configBlock.Data.Data[0]

	// Test successful extraction
	bundle, err := serialization.ExtractAppBundle(envBytes)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	_, ok := bundle.ApplicationConfig()
	require.True(t, ok)

	// Test with invalid input
	_, err = serialization.ExtractAppBundle([]byte("not-an-envelope"))
	require.Error(t, err)
}
