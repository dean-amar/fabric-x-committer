/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

func TestWorkerPool(t *testing.T) {
	t.Parallel()
	workers := newWorkerPool(10, 5)
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(workers.run(ctx))
	}, nil)

	size := 100
	result := channel.Make[int](t.Context(), size)
	for i := range size {
		i := i
		workers.Submit(t.Context(), func() {
			result.Write(i)
		})
	}
	resultMap := make(map[int]any)
	for range size {
		i, ok := result.Read()
		require.True(t, ok, "context ended before worker finished")
		_, ok = resultMap[i]
		require.False(t, ok, "repeated result")
		resultMap[i] = nil
	}
}
