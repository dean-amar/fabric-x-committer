/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRegisterStreamWithDoneContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Many registrations, as the removal of a single one could win the race by chance.
	var s streamStateManager[StreamInfo]
	for range 100 {
		s.registerStream(ctx, func(info StreamInfo) *StreamInfo { return &info })
	}
	require.Eventually(t, func() bool {
		return len(s.StreamsStates()) == 0
	}, 5*time.Second, 10*time.Millisecond)
}
