/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// RequireProtoEqual verifies that two proto are equal.
func RequireProtoEqual(t *testing.T, expected, actual proto.Message) {
	t.Helper()
	require.Truef(
		t,
		proto.Equal(expected, actual),
		"EXPECTED: %v\nACTUAL: %v",
		protojson.Format(expected),
		protojson.Format(actual),
	)
}

// RequireProtoElementsMatch verifies that two arrays of proto have the same elements.
func RequireProtoElementsMatch[T proto.Message](
	t *testing.T, expected, actual []T, msgAndArgs ...any,
) {
	t.Helper()
	if expected == nil {
		require.Nil(t, actual, msgAndArgs...)
		return
	}
	require.Len(t, actual, len(expected), msgAndArgs...)
	if msg, haveDiff := protoElemDiff(expected, actual); haveDiff {
		require.Fail(t, msg, msgAndArgs...)
	}
}

func protoElemDiff[T proto.Message](expected, actual []T) (string, bool) { //nolint:gocognit // cognitive complexity 23
	expectedMatched := make([]bool, len(expected))
	actualMatched := make([]bool, len(actual))
	for aInd, aElem := range actual {
		for eInd, eElem := range expected {
			if expectedMatched[eInd] {
				continue
			}
			if proto.Equal(eElem, aElem) {
				expectedMatched[eInd] = true
				actualMatched[aInd] = true
				break
			}
		}
	}

	var missing []string
	for eInd, eElem := range expected {
		if !expectedMatched[eInd] {
			missing = append(missing, protojson.Format(eElem))
		}
	}
	var extra []string
	for aInd, aElem := range actual {
		if !actualMatched[aInd] {
			extra = append(extra, protojson.Format(aElem))
		}
	}

	if len(extra) == 0 && len(missing) == 0 {
		return "", false
	}

	var msg bytes.Buffer
	if len(extra) > 0 {
		msg.WriteString("\nextra elements:\n")
		for _, extraElem := range extra {
			msg.WriteString(extraElem)
			msg.WriteString("\n")
		}
	}
	if len(missing) > 0 {
		msg.WriteString("\nmissing elements:\n")
		for _, missingElem := range missing {
			msg.WriteString(missingElem)
			msg.WriteString("\n")
		}
	}
	return msg.String(), true
}
