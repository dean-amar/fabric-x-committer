/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

func TestStartPrometheusServer_WithDefaultRetry(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Use an invalid endpoint to force an error
	serverConfig := &connection.ServerConfig{
		Endpoint: connection.Endpoint{
			Host: "invalid-host-that-does-not-exist",
			Port: 0,
		},
		TLS: connection.TLSConfig{
			Mode: connection.NoneTLSMode,
		},
	}

	// StartPrometheusServer now uses default retry, should retry multiple times before failing
	startTime := time.Now()
	err := p.StartPrometheusServer(ctx, serverConfig)
	elapsed := time.Since(startTime)

	// Should fail after retries
	require.Error(t, err)
	// Should have taken at least some time due to retries (default initial interval is 500ms)
	assert.Greater(t, elapsed, 400*time.Millisecond, "Should have retried at least once with default retry profile")
}

func TestStartPrometheusServerWithRetry_NoRetryProfile(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use an invalid endpoint to force an error
	serverConfig := &connection.ServerConfig{
		Endpoint: connection.Endpoint{
			Host: "invalid-host-that-does-not-exist",
			Port: 0,
		},
		TLS: connection.TLSConfig{
			Mode: connection.NoneTLSMode,
		},
	}

	// Without retry profile, should fail immediately
	startTime := time.Now()
	err := p.StartPrometheusServerWithRetry(ctx, serverConfig, nil)
	elapsed := time.Since(startTime)

	require.Error(t, err)
	// Should fail quickly without retries
	assert.Less(t, elapsed, 200*time.Millisecond, "Should fail immediately without retry profile")
}

func TestStartPrometheusServerWithRetry_CustomRetryProfile(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Use an invalid endpoint to force an error
	serverConfig := &connection.ServerConfig{
		Endpoint: connection.Endpoint{
			Host: "invalid-host-that-does-not-exist",
			Port: 0,
		},
		TLS: connection.TLSConfig{
			Mode: connection.NoneTLSMode,
		},
	}

	// With custom retry profile, should retry multiple times before failing
	retryProfile := &connection.RetryProfile{
		InitialInterval:     100 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         500 * time.Millisecond,
		MaxElapsedTime:      2 * time.Second,
	}

	startTime := time.Now()
	err := p.StartPrometheusServerWithRetry(ctx, serverConfig, retryProfile)
	elapsed := time.Since(startTime)

	// Should fail after retries
	require.Error(t, err)
	// Should have taken at least some time due to retries
	assert.Greater(t, elapsed, 100*time.Millisecond, "Should have retried at least once")
}

func TestStartPrometheusServer_SuccessfulStart(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	serverConfig := &connection.ServerConfig{
		Endpoint: connection.Endpoint{
			Host: "127.0.0.1",
			Port: 0, // Use port 0 to get a random available port
		},
		TLS: connection.TLSConfig{
			Mode: connection.NoneTLSMode,
		},
	}

	// Test that the server starts successfully with default retry
	go func() {
		_ = p.StartPrometheusServer(ctx, serverConfig)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Verify URL was set (indicates server started)
	assert.NotEmpty(t, p.URL())
}

// Made with Bob
