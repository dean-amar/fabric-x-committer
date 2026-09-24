/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	resourceA = "/svc/A"
	resourceB = "/svc/B"
)

func TestNormalizeScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "nil stays nil", input: nil, expected: nil},
		{name: "empty slice normalizes to nil", input: []string{}, expected: nil},
		{name: "all-blank normalizes to nil", input: []string{"", "  ", "\t"}, expected: nil},
		{
			name:     "trims and preserves order",
			input:    []string{" " + resourceA + " ", resourceB},
			expected: []string{resourceA, resourceB},
		},
		{
			name:     "drops duplicates keeping first",
			input:    []string{resourceA, resourceB, resourceA},
			expected: []string{resourceA, resourceB},
		},
		{
			name:     "drops empties between entries",
			input:    []string{resourceA, "", resourceB},
			expected: []string{resourceA, resourceB},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, normalizeScope(tc.input))
		})
	}
}

func TestScopeAllows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		scope    []string
		resource string
		expected bool
	}{
		{name: "empty scope allows anything", scope: nil, resource: resourceA, expected: true},
		{
			name:     "resource in scope is allowed",
			scope:    []string{resourceA, resourceB},
			resource: resourceB,
			expected: true,
		},
		{
			name:     "resource outside scope is denied",
			scope:    []string{resourceA},
			resource: resourceB,
			expected: false,
		},
		{
			name:     "exact match only - no prefix matching",
			scope:    []string{resourceA},
			resource: resourceA + "B",
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, scopeAllows(tc.scope, tc.resource))
		})
	}
}
