/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"encoding/binary"
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
		Type TraceSamplerType `mapstructure:"type"`
		// Prefix related.
		Prefix string `mapstructure:"prefix"`
		// SampleHash related.
		SamplePeriod uint64 `mapstructure:"sample-period"`
		SampleSize   uint64 `mapstructure:"sample-size"`
		Ratio        uint64 `mapstructure:"ratio"`
		// SampleTimer related.
		SamplingInterval time.Duration `mapstructure:"sampling-interval"`
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

	SampleAlways TraceSamplerType = "always"
	SampleNever  TraceSamplerType = "never"
	SamplePrefix TraceSamplerType = "prefix"
	SampleHash   TraceSamplerType = "hash"
	SampleTimer  TraceSamplerType = "timer"
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
	switch c.Type {
	case SampleAlways:
		return func(string) bool { return true }
	case SampleNever, "":
		return func(string) bool { return false }
	case SamplePrefix:
		return func(key string) bool {
			return len(key) >= len(c.Prefix) && key[:len(c.Prefix)] == c.Prefix
		}
	case SampleHash:
		return func(key string) bool {
			hash := binary.LittleEndian.Uint64([]byte(key))
			return hash%c.SamplePeriod < c.SampleSize && hash%c.Ratio == 0
		}
	case SampleTimer:
		ticker := time.NewTicker(c.SamplingInterval)
		return func(string) bool {
			select {
			case <-ticker.C:
				return true
			default:
				return false
			}
		}
	default:
		panic("type " + c.Type + " not defined")
	}
}

// BlockSampler returns a NumberTracingSampler for latency monitoring.
func (c *SamplerConfig) BlockSampler() NumberTracingSampler {
	switch c.Type {
	case SampleAlways:
		return func(uint64) bool { return true }
	case SampleNever, "":
		return func(uint64) bool { return false }
	case SampleHash:
		return func(hash uint64) bool {
			return hash%c.SamplePeriod < c.SampleSize && hash%c.Ratio == 0
		}
	case SampleTimer:
		ticker := time.NewTicker(c.SamplingInterval)
		return func(uint64) bool {
			select {
			case <-ticker.C:
				return true
			default:
				return false
			}
		}
	default:
		panic("type " + c.Type + " not supported")
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
