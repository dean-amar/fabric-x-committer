/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto/ed25519"
	"errors"
)

// EdDSAVerifier verifies using the EdDSA scheme.
type EdDSAVerifier struct {
	PublicKey ed25519.PublicKey
}

var defaultOptions = ed25519.Options{
	Context: "Example_ed25519ctx",
}

// Verify a digest given a signature.
func (v *EdDSAVerifier) Verify(digest Digest, signature Signature) error {
	err := ed25519.VerifyWithOptions(v.PublicKey, digest, signature, &defaultOptions)
	if err != nil {
		return errors.Join(ErrSignatureMismatch, err)
	}
	return nil
}
