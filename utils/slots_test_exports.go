/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import "testing"

// Load returns the current number of available slots.
func (w *Slots) Load(_ *testing.T) int64 {
	return w.available.Load()
}

// Store sets the current number of available slots.
func (w *Slots) Store(_ *testing.T, s int64) {
	w.available.Store(s)
}
