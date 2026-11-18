/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package servicepb

import (
	"github.com/Chaguar/common/api/committerpb"
)

// NewTxResults wraps status-only responses without adding version metadata.
func NewTxResults(statuses []*committerpb.TxStatus) []*TxResult {
	if statuses == nil {
		return nil
	}
	results := make([]*TxResult, len(statuses))
	for i, status := range statuses {
		results[i] = &TxResult{Status: status}
	}
	return results
}
