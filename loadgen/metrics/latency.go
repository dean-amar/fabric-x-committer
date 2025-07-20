/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"hash/maphash"
	"math"
	"sort"
	"time"

	"github.com/cockroachdb/errors"
)

type (
	// LatencyConfig describes the latency monitoring parameters.
	LatencyConfig struct {
		SamplerConfig SamplerConfig `mapstructure:"sampler"`
		BucketConfig  BucketConfig  `mapstructure:"buckets"`
	}

	// SamplerConfig describes the latency sampling parameters.
	SamplerConfig struct {
		// Prefix checks for TXs that have the given prefix.
		Prefix string `mapstructure:"prefix" json:"prefix,omitempty"`
		// Portion uses the simple and efficient hash of the key to sample the required portion of TXs.
		Portion float64 `mapstructure:"portion" json:"portion,omitempty"`
	}

	// BucketConfig describes the latency bucket distribution.
	BucketConfig struct {
		Distribution BucketDistribution `mapstructure:"distribution"`
		MaxLatency   time.Duration      `mapstructure:"max-latency"`
		BucketCount  int                `mapstructure:"bucket-count"`
		Values       []float64          `mapstructure:"values"`
	}

	// BucketDistribution can be empty, uniform, or fixed.
	BucketDistribution string
	// TraceSamplerType can be always, never, prefix, hash, or timer.
	TraceSamplerType string

	// KeyTracingSampler returns true to sample a given key.
	KeyTracingSampler = func(key string) bool
	// NumberTracingSampler returns true to sample a given number.
	NumberTracingSampler = func(blockNumber uint64) bool
)

// Sample and bucket constants.
const (
	BucketEmpty   BucketDistribution = "empty"
	BucketUniform BucketDistribution = "uniform"
	BucketFixed   BucketDistribution = "fixed"

	// portionEps is chosen to ensure 1 > (1-eps).
	portionEps float64 = 1e-16
)

// Buckets returns a list of buckets for latency monitoring.
func (c *BucketConfig) Buckets() []float64 {
	switch c.Distribution {
	case BucketUniform:
		required(c.BucketCount >= 0, "invalid bucket count")
		required(c.MaxLatency > 0, "invalid max latency")
		return uniformBuckets(c.BucketCount, 0, c.MaxLatency.Seconds())
	case BucketFixed:
		required(len(c.Values) > 0, "no fixed values provided")
		sort.Float64s(c.Values)
		return c.Values
	case BucketEmpty:
		return []float64{}
	case "":
		return []float64{}
	default:
		panic("undefined distribution: " + c.Distribution)
	}
}

// TxSampler returns a KeyTracingSampler for latency monitoring.
func (c *SamplerConfig) TxSampler() KeyTracingSampler {
	switch {
	case len(c.Prefix) > 0:
		prefixSize := len(c.Prefix)
		return func(key string) bool {
			return len(key) >= prefixSize && key[:prefixSize] == c.Prefix
		}
	case c.Portion < portionEps:
		return func(string) bool { return false }
	case c.Portion > (float64(1) - portionEps):
		return func(string) bool { return true }
	default:
		seed := maphash.MakeSeed()
		valueLimit := uint64(math.Round(c.Portion * math.MaxUint64))
		return func(key string) bool {
			return maphash.String(seed, key) < valueLimit
		}
	}
}

func uniformBuckets(count int, from, to float64) []float64 {
	if to < from {
		panic("invalid input")
	}
	result := make([]float64, 0, count)
	step := (to - from) / float64(count-1)
	for low := from; low < to; low += step {
		result = append(result, low)
	}
	return append(result, to)
}

//nolint:revive // flag-parameter: parameter 'condition' seems to be a control flag, avoid control coupling.
func required(condition bool, msg string) {
	if !condition {
		panic(errors.New(msg))
	}
}
