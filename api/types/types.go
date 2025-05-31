/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package types

import (
	"google.golang.org/protobuf/encoding/protowire"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
)

type (
	// VersionNumber represents a row's version.
	VersionNumber uint64
)

const (
	// MetaNamespaceID is the system's namespace ID that holds information about application's namespaces.
	MetaNamespaceID = "_meta"

	// ConfigNamespaceID is the system's namespace ID that holds the config transaction.
	ConfigNamespaceID = "_config"
	// ConfigKey is the key of the config transaction.
	ConfigKey = "_config"
)

// Bytes converts a version number representation to bytes representation.
func (v VersionNumber) Bytes() []byte {
	return protowire.AppendVarint(nil, uint64(v))
}

// VersionNumberFromBytes converts a version bytes representation to a number representation.
func VersionNumberFromBytes(version []byte) VersionNumber {
	v, _ := protowire.ConsumeVarint(version)
	return VersionNumber(v)
}

// CreateStatusWithHeight creates a protoblocktx.StatusWithHeight with the given values.
func CreateStatusWithHeight(s protoblocktx.Status, blkNum uint64, txNum int) *protoblocktx.StatusWithHeight {
	return &protoblocktx.StatusWithHeight{
		Code:        s,
		BlockNumber: blkNum,
		TxNumber:    uint32(txNum), //nolint:gosec
	}
}
