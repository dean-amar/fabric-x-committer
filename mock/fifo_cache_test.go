/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFifoCache(t *testing.T) {
	t.Parallel()
	c := newFifoCache[int](10)
	key := func(i int) string {
		return fmt.Sprintf("%d", i)
	}
	for i := range 10 {
		require.Truef(t, c.addIfNotExist(key(i), i), "insert %d", i)
	}
	for i := range 10 {
		v, ok := c.get(key(i))
		require.True(t, ok)
		require.Equalf(t, i, v, "get %d", i)
	}
	for i := range 10 {
		require.Falsef(t, c.addIfNotExist(key(i), i), "insert %d", i)
	}

	for i := range 3 {
		require.Truef(t, c.addIfNotExist(key(i+10), i), "insert %d", i)
	}
	for i := range 3 {
		_, ok := c.get(key(i))
		require.False(t, ok)
	}
	for i := range 3 {
		require.Truef(t, c.addIfNotExist(key(i), i), "insert %d", i)
	}
	for i := range 4 {
		require.Falsef(t, c.addIfNotExist(key(i+6), i), "insert %d", i)
	}
}
