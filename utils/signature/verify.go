/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"strings"

	"github.com/cockroachdb/errors"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
)

// DigestVerifier verifies a digest.
type DigestVerifier interface {
	Verify(Digest, Signature) error
}

// NsVerifier verifies a given namespace.
type NsVerifier struct {
	DigestVerifier
}

// NewNsVerifier creates a new namespace verifier according to the implementation scheme.
func NewNsVerifier(scheme Scheme, key []byte) (*NsVerifier, error) {
	scheme = strings.ToUpper(scheme)
	var err error
	var v DigestVerifier
	switch scheme {
	case NoScheme, "":
		v = &DummyVerifier{}
	case Ecdsa:
		v, err = NewEcdsaVerifier(key)
	case Bls:
		v, err = NewBLSVerifier(key)
	case Eddsa:
		v = &EdDSAVerifier{PublicKey: key}
	default:
		return nil, errors.Newf("scheme '%v' not supported", scheme)
	}
	return &NsVerifier{DigestVerifier: v}, errors.Wrap(err, "failed creating verifier")
}

// VerifyNs verifies a transaction's namespace signature.
func (v *NsVerifier) VerifyNs(tx *protoblocktx.Tx, nsIndex int) error {
	if nsIndex < 0 || nsIndex >= len(tx.Namespaces) || nsIndex >= len(tx.Signatures) {
		return errors.New("namespace index out of range")
	}
	digest, err := DigestTxNamespace(tx, nsIndex)
	if err != nil {
		return err
	}
	return v.Verify(digest, tx.Signatures[nsIndex])
}
