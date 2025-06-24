/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package workload

import (
	"golang.org/x/time/rate"
)

// NewLimiter instantiate a new rate limiter with optional remote control capabilities.
func NewLimiter(c *LimiterConfig, burst int) *rate.Limiter {
	if c == nil || c.InitialLimit < 1 {
		logger.Debugf("Setting to unlimited (input: %+v).", c)
		return rate.NewLimiter(rate.Inf, burst)
	}
	logger.Debugf("Setting limit to %.2f requests per second.", c.InitialLimit)
	return rate.NewLimiter(c.InitialLimit, burst)
}
