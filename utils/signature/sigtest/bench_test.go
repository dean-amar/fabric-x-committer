/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sigtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
)

var (
	r    []byte
	rerr error
	msg  = []byte("Hello World")
)

func BenchmarkSign(b *testing.B) {
	for _, scheme := range signature.AllSchemes {
		b.Run(scheme, func(b *testing.B) {
			f := NewSignatureFactory(scheme)
			sk, _ := f.NewKeys()
			s, err := f.NewSigner(sk)
			require.NoError(b, err)

			var sig []byte
			b.ResetTimer()
			for range b.N {
				sig, _ = s.Sign(msg)
			}
			r = sig
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, scheme := range signature.AllSchemes {
		b.Run(scheme, func(b *testing.B) {
			f := NewSignatureFactory(scheme)
			sk, pk := f.NewKeys()
			s, err := f.NewSigner(sk)
			require.NoError(b, err)
			v, err := f.NewVerifier(pk)
			require.NoError(b, err)
			sig, _ := s.Sign(msg)

			b.ResetTimer()
			for range b.N {
				err = v.Verify(msg, sig)
			}
			rerr = err
		})
	}
}
