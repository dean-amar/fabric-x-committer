/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

type testStruct struct {
	value int
}

func TestSyncMapInt(t *testing.T) {
	t.Parallel()
	var m SyncMap[string, int]
	_, ok := m.Load("a")
	require.False(t, ok)
	m.Store("a", 1)
	v, ok := m.Load("a")
	require.True(t, ok)
	require.Equal(t, 1, v)
}

func TestSyncMapPtr(t *testing.T) {
	t.Parallel()
	var m SyncMap[string, *testStruct]
	_, ok := m.Load("a")
	require.False(t, ok)
	m.Store("a", &testStruct{value: 1})
	v, ok := m.Load("a")
	require.True(t, ok)
	require.NotNil(t, v)
	require.Equal(t, 1, v.value)
}

func TestSyncMapMethods(t *testing.T) {
	t.Parallel()
	var sm SyncMap[string, testStruct]

	t.Run("Store, Load, and Delete", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k, testStruct{value: 1})
		value, ok := sm.Load(k)
		require.True(t, ok)
		require.Equal(t, 1, value.value)
		sm.Delete(k)
		_, ok = sm.Load(k)
		require.False(t, ok)
	})

	t.Run("Swap", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k, testStruct{value: 1})
		previous, loaded := sm.Swap(k, testStruct{value: 2})
		require.True(t, loaded)
		require.Equal(t, 1, previous.value)
		value, ok := sm.Load(k)
		require.True(t, ok)
		require.Equal(t, 2, value.value)
	})

	t.Run("LoadOrStore", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		_, loaded := sm.LoadOrStore(k, testStruct{value: 3})
		require.False(t, loaded)
		actual, loaded := sm.LoadOrStore(k, testStruct{value: 4})
		require.True(t, loaded)
		require.Equal(t, 3, actual.value)
	})

	t.Run("LoadAndDelete", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k, testStruct{value: 2})
		value, loaded := sm.LoadAndDelete(k)
		require.True(t, loaded)
		require.Equal(t, 2, value.value)
		_, ok := sm.Load(k)
		require.False(t, ok)
	})

	t.Run("CompareAndSwap", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k, testStruct{value: 5})
		swapped := sm.CompareAndSwap(k, testStruct{value: 5}, testStruct{value: 6})
		require.True(t, swapped)
		value, ok := sm.Load(k)
		require.True(t, ok)
		require.Equal(t, 6, value.value)
	})

	t.Run("CompareAndDelete", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k, testStruct{value: 6})
		deleted := sm.CompareAndDelete(k, testStruct{value: 6})
		require.True(t, deleted)
		_, ok := sm.Load(k)
		require.False(t, ok)
	})

	t.Run("Range", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		k7 := k + "7"
		k8 := k + "8"
		sm.Store(k7, testStruct{value: 7})
		sm.Store(k8, testStruct{value: 8})
		keyValues := make(map[any]int)
		sm.Range(func(key string, value testStruct) bool {
			keyValues[key] = value.value
			return true
		})
		require.GreaterOrEqualf(t, len(keyValues), 2, "items: %v", keyValues)
		require.Equal(t, 7, keyValues[k7])
		require.Equal(t, 8, keyValues[k8])
	})

	t.Run("Clear", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		k7 := k + "7"
		k8 := k + "8"
		sm.Store(k7, testStruct{value: 7})
		sm.Store(k8, testStruct{value: 8})
		sm.Clear()
		_, ok := sm.Load(k7)
		require.False(t, ok)
		_, ok = sm.Load(k8)
		require.False(t, ok)
	})

	t.Run("IterItems", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		k10 := k + "10"
		k20 := k + "20"
		sm.Store(k10, testStruct{value: 10})
		sm.Store(k20, testStruct{value: 20})
		items := maps.Collect(sm.IterItems())
		require.GreaterOrEqualf(t, len(items), 2, "items: %v", items)
		require.Equal(t, 10, items[k10].value)
		require.Equal(t, 20, items[k20].value)
	})

	t.Run("IterKeys", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		k30 := k + "30"
		k40 := k + "40"
		sm.Store(k30, testStruct{value: 30})
		sm.Store(k40, testStruct{value: 40})
		keys := slices.Collect(sm.IterKeys())
		require.GreaterOrEqualf(t, len(keys), 2, "keys: %v", keys)
		require.Contains(t, keys, k30)
		require.Contains(t, keys, k40)
	})

	t.Run("IterValues", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		k30 := k + "30"
		k40 := k + "40"
		sm.Store(k30, testStruct{value: 30})
		sm.Store(k40, testStruct{value: 40})
		values := slices.Collect(sm.IterValues())
		require.GreaterOrEqualf(t, len(values), 2, "values: %v", values)
		require.Contains(t, values, testStruct{value: 30})
		require.Contains(t, values, testStruct{value: 40})
	})

	t.Run("Count", func(t *testing.T) {
		t.Parallel()
		k := t.Name()
		sm.Store(k+"50", testStruct{value: 50})
		sm.Store(k+"60", testStruct{value: 60})
		count := sm.Count()
		require.GreaterOrEqual(t, count, 2)
	})
}
