/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/protoqueryservice"
)

func TestRequireProtoEqual(t *testing.T) {
	t.Parallel()
	a := &protoqueryservice.View{Id: "a"}
	RequireProtoEqual(t, a, a)
	b := proto.Clone(a)
	RequireProtoEqual(t, a, b)
	c := &protoqueryservice.View{Id: "a"}
	RequireProtoEqual(t, a, c)
}

func TestProtoDiff(t *testing.T) {
	t.Parallel()
	a := []*protoqueryservice.View{
		{Id: "a"}, {Id: "b"},
	}
	msg, haveDiff := protoElemDiff(a, a)
	require.False(t, haveDiff, msg)

	b := []*protoqueryservice.View{
		{Id: "b"}, {Id: "a"},
	}
	msg, haveDiff = protoElemDiff(a, b)
	require.False(t, haveDiff, msg)

	c := []*protoqueryservice.View{{Id: "b"}, {Id: "c"}}
	msg, haveDiff = protoElemDiff(a, c)
	require.True(t, haveDiff, msg)
	t.Log(msg)
}
