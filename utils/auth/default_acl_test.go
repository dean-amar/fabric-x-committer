/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultACLCoversClientFacingMethods(t *testing.T) {
	t.Parallel()
	for _, m := range []string{
		"/committerpb.QueryService/GetRows",
		"/committerpb.BlockQueryService/GetBlockByNumber",
		"/committerpb.Notifier/OpenNotificationStream",
		"/protos.Deliver/Deliver",
	} {
		require.Equal(t, ReaderPolicy, DefaultACL[m], "method %s must map to a policy", m)
	}
}

func TestExemptMethods(t *testing.T) {
	t.Parallel()
	require.True(t, isExemptMethod("/grpc.health.v1.Health/Check"))
	require.True(t, isExemptMethod("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"))
	require.False(t, isExemptMethod("/committerpb.QueryService/GetRows"))
}

func TestMetadataKeyIsBinary(t *testing.T) {
	t.Parallel()
	// gRPC auto base64-encodes metadata whose key ends in "-bin".
	require.Equal(t, "-bin", MetadataEnvelopeKey[len(MetadataEnvelopeKey)-4:])
}
