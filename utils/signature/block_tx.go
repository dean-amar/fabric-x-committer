/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/sha256"
	"encoding/asn1"

	"github.com/cockroachdb/errors"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
)

// DigestTxNamespace digests a transactions for a given namespace index.
func DigestTxNamespace(tx *protoblocktx.Tx, nsIndex int) ([]byte, error) {
	if nsIndex >= len(tx.Namespaces) {
		return nil, errors.New("namespace index out of range")
	}
	ns := tx.Namespaces[nsIndex]
	n := Namespace{
		Reads:      make([]Read, len(ns.ReadsOnly)),
		ReadWrites: make([]ReadWrite, len(ns.ReadWrites)),
		Writes:     make([]BlindWrite, len(ns.BlindWrites)),
	}

	for i, r := range ns.ReadsOnly {
		n.Reads[i] = Read{
			Key:     r.Key,
			Version: r.Version,
		}
	}

	for i, rw := range ns.ReadWrites {
		n.ReadWrites[i] = ReadWrite{
			Key:     rw.Key,
			Version: rw.Version,
			Value:   rw.Value,
		}
	}

	for i, bw := range ns.BlindWrites {
		n.Writes[i] = BlindWrite{
			Key:   bw.Key,
			Value: bw.Value,
		}
	}

	bytes, err := asn1.Marshal(Tx{
		TxID:      tx.Id,
		Namespace: n,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal tx")
	}

	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil), nil
}

type (
	// Tx is a stab for [protoblocktx.Tx].
	Tx struct {
		TxID      string
		Namespace Namespace
	}
	// Namespace is a stab for [protoblocktx.TxNamespace].
	Namespace struct {
		Reads      []Read
		ReadWrites []ReadWrite
		Writes     []BlindWrite
	}
	// Read is a stab for [protoblocktx.Read].
	Read struct {
		Key     []byte
		Version []byte
	}
	// BlindWrite is a stab for [protoblocktx.Write].
	BlindWrite struct {
		Key   []byte
		Value []byte
	}
	// ReadWrite is a stab for [protoblocktx.ReadWrite].
	ReadWrite struct {
		Key     []byte
		Version []byte
		Value   []byte
	}
)
