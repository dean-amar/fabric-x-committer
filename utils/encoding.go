/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"encoding/binary"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/golang/protobuf/proto" //nolint:staticcheck // proto.EncodeVarint does not exist in the new version
)

// EncodeOrderPreservingVarUint64 returns a byte-representation for a uint64 number such that
// all zero-bits starting bytes are trimmed in order to reduce the length of the array
// For preserving the order in a default bytes-comparison, first byte contains the number of remaining bytes.
// The presence of first byte also allows to use the returned bytes as part of other larger byte array such as a
// composite-key representation in db.
func EncodeOrderPreservingVarUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, number)
	startingIndex := 0
	size := 0
	for i, b := range bytes {
		if b != 0x00 {
			startingIndex = i
			size = 8 - i
			break
		}
	}

	sizeBytes := proto.EncodeVarint(uint64(size)) //nolint:gosec // integer overflow conversion int -> uint64.
	if len(sizeBytes) > 1 {
		panic(fmt.Errorf(
			"[]sizeBytes should not be more than one byte because the max number it needs to hold is 8. size=%d",
			size,
		))
	}
	encodedBytes := make([]byte, size+1)
	encodedBytes[0] = sizeBytes[0]
	copy(encodedBytes[1:], bytes[startingIndex:])
	return encodedBytes
}

// DecodeOrderPreservingVarUint64 decodes the number from the bytes obtained from method
// 'EncodeOrderPreservingVarUint64'.
// It returns the decoded number, the number of bytes that are consumed in the process,
// and an error if the input bytes are invalid.
func DecodeOrderPreservingVarUint64(bytes []byte) (uint64, int, error) {
	s, numBytes := proto.DecodeVarint(bytes)

	switch {
	case numBytes != 1:
		return 0, 0, errors.Newf("number of consumed bytes from DecodeVarint is invalid, expected 1, but got %d",
			numBytes)
	case s > 8:
		return 0, 0, errors.Newf("decoded size from DecodeVarint is invalid, expected <=8, but got %d", s)
	case int(s) > len(bytes)-1:
		return 0, 0, errors.Newf("decoded size (%d) from DecodeVarint is more than available bytes (%d)",
			s, len(bytes)-1)
	default:
		// no error
		size := int(s)
		decodedBytes := make([]byte, 8)
		copy(decodedBytes[8-size:], bytes[1:size+1])
		numBytesConsumed := size + 1
		return binary.BigEndian.Uint64(decodedBytes), numBytesConsumed, nil
	}
}
