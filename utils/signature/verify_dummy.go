/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

// DummyVerifier always return success.
type DummyVerifier struct{}

// Verify a digest given a signature.
func (*DummyVerifier) Verify(Digest, Signature) error {
	return nil
}
