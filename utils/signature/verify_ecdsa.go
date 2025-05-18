/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/cockroachdb/errors"
)

// EcdsaTxVerifier verifies using the ECDSA scheme.
type EcdsaTxVerifier struct {
	verificationKey *ecdsa.PublicKey
}

// NewEcdsaVerifier instantiate a new ECDSA scheme verifier.
func NewEcdsaVerifier(key []byte) (*EcdsaTxVerifier, error) {
	block, _ := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.Newf("failed to decode PEM block containing public key, got %v", block)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse public key")
	}

	ecdsaVerificationKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to assert public key type to ECDSA")
	}
	return &EcdsaTxVerifier{verificationKey: ecdsaVerificationKey}, nil
}

// Verify a digest given a signature.
func (v *EcdsaTxVerifier) Verify(digest Digest, signature Signature) error {
	valid := ecdsa.VerifyASN1(v.verificationKey, digest, signature)
	if !valid {
		return ErrSignatureMismatch
	}
	return nil
}
