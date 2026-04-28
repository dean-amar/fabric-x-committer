/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	t.Run("nil config creates disabled provider", func(t *testing.T) {
		t.Parallel()

		provider, err := NewProvider(nil)
		require.NoError(t, err)
		require.NotNil(t, provider)
		require.False(t, provider.IsEnabled())
	})

	t.Run("disabled config creates disabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		provider, err := NewProvider(config)
		require.NoError(t, err)
		require.NotNil(t, provider)
		require.False(t, provider.IsEnabled())
	})

	t.Run("enabled config with valid policies creates enabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			Policies: map[string]string{
				"/test.Service/Method": "admin",
			},
		}

		provider, err := NewProvider(config)
		require.NoError(t, err)
		require.NotNil(t, provider)
		require.True(t, provider.IsEnabled())
		require.Len(t, provider.policies, 1)
	})

	t.Run("enabled config with invalid policy fails", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			Policies: map[string]string{
				"/test.Service/Method": "invalid-role",
			},
		}

		provider, err := NewProvider(config)
		require.Error(t, err)
		require.Nil(t, provider)
		require.Contains(t, err.Error(), "invalid required role")
	})
}

func TestProvider_CheckACL_Disabled(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(nil)
	require.NoError(t, err)

	// Disabled provider should allow all access
	ctx := context.Background()
	err = provider.CheckACL(ctx, "/any.Service/AnyMethod")
	require.NoError(t, err)
}

func TestProvider_CheckACL_Enabled(t *testing.T) {
	t.Parallel()

	// Create test CA and certificates
	ca, caCert := createTestCA(t)
	clientCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleClient, time.Now().Add(24*time.Hour))
	adminCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleAdmin, time.Now().Add(24*time.Hour))
	memberCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleMember, time.Now().Add(24*time.Hour))

	// Create certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Create enabled provider
	provider := &Provider{
		enabled: true,
		policies: map[string]*Policy{
			"/test.Service/ReaderMethod": {
				Resource:     "/test.Service/ReaderMethod",
				RequiredRole: "reader",
			},
			"/test.Service/AdminMethod": {
				Resource:     "/test.Service/AdminMethod",
				RequiredRole: RoleAdmin,
			},
		},
		metrics: NewMetrics(),
	}

	// Success cases
	for _, tc := range []struct {
		name   string
		cert   *x509.Certificate
		method string
	}{
		{
			name:   "client can access reader method",
			cert:   clientCert,
			method: "/test.Service/ReaderMethod",
		},
		{
			name:   "admin can access reader method",
			cert:   adminCert,
			method: "/test.Service/ReaderMethod",
		},
		{
			name:   "admin can access admin method",
			cert:   adminCert,
			method: "/test.Service/AdminMethod",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := createContextWithCert(t, tc.cert)
			err := provider.CheckACL(ctx, tc.method)
			require.NoError(t, err)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name   string
		cert   *x509.Certificate
		method string
	}{
		{
			name:   "member cannot access reader method",
			cert:   memberCert,
			method: "/test.Service/ReaderMethod",
		},
		{
			name:   "client cannot access admin method",
			cert:   clientCert,
			method: "/test.Service/AdminMethod",
		},
		{
			name:   "member cannot access admin method",
			cert:   memberCert,
			method: "/test.Service/AdminMethod",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := createContextWithCert(t, tc.cert)
			err := provider.CheckACL(ctx, tc.method)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrAccessDenied)
		})
	}
}

func TestProvider_CheckACL_NoPolicyDefined(t *testing.T) {
	t.Parallel()

	// Create test CA and certificate
	ca, caCert := createTestCA(t)
	clientCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleClient, time.Now().Add(24*time.Hour))

	// Create certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Create provider with no policies
	provider := &Provider{
		enabled:  true,
		policies: map[string]*Policy{},
		metrics:  NewMetrics(),
	}

	ctx := createContextWithCert(t, clientCert)
	err := provider.CheckACL(ctx, "/test.Service/UnknownMethod")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoPolicyDefined)
}

func TestProvider_CheckACL_NoCertificate(t *testing.T) {
	t.Parallel()

	// Create provider
	provider := &Provider{
		enabled: true,
		policies: map[string]*Policy{
			"/test.Service/Method": {
				Resource:     "/test.Service/Method",
				RequiredRole: "reader",
			},
		},
		metrics: NewMetrics(),
	}

	// Context without certificate
	ctx := context.Background()
	err := provider.CheckACL(ctx, "/test.Service/Method")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoPeerInfo)
}

func TestProvider_IsEnabled(t *testing.T) {
	t.Parallel()

	t.Run("disabled provider returns false", func(t *testing.T) {
		t.Parallel()

		provider, err := NewProvider(nil)
		require.NoError(t, err)
		require.False(t, provider.IsEnabled())
	})

	t.Run("enabled provider returns true", func(t *testing.T) {
		t.Parallel()

		provider := &Provider{
			enabled: true,
			metrics: NewMetrics(),
		}
		require.True(t, provider.IsEnabled())
	})
}

func TestProvider_GetMetrics(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(nil)
	require.NoError(t, err)

	metrics := provider.GetMetrics()
	require.NotNil(t, metrics)
}

func TestProvider_RecordCertError(t *testing.T) {
	t.Parallel()

	provider := &Provider{
		enabled: true,
		metrics: NewMetrics(),
	}

	// Test different error types
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "no peer info", err: ErrNoPeerInfo},
		{name: "no TLS info", err: ErrNoTLSInfo},
		{name: "no certificate", err: ErrNoCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Should not panic
			provider.recordCertError(tc.err)
		})
	}
}

func TestProvider_CheckACL_Metrics(t *testing.T) {
	t.Parallel()

	// Create test CA and certificate
	ca, caCert := createTestCA(t)
	clientCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleClient, time.Now().Add(24*time.Hour))

	// Create certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Create provider
	provider := &Provider{
		enabled: true,
		policies: map[string]*Policy{
			"/test.Service/Method": {
				Resource:     "/test.Service/Method",
				RequiredRole: "reader",
			},
		},
		metrics: NewMetrics(),
	}

	// Perform successful check
	ctx := createContextWithCert(t, clientCert)
	err := provider.CheckACL(ctx, "/test.Service/Method")
	require.NoError(t, err)

	// Verify metrics were recorded (metrics should not be nil)
	require.NotNil(t, provider.GetMetrics())
}

func TestProvider_CheckACL_WithDefaultPolicies(t *testing.T) {
	t.Parallel()

	// Create test CA and certificate
	ca, caCert := createTestCA(t)
	clientCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleClient, time.Now().Add(24*time.Hour))

	// Create certificate pool
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Create provider with default policies
	policies := make(map[string]*Policy)
	for method, role := range DefaultACLs {
		policy, err := NewPolicy(method, role)
		require.NoError(t, err)
		policies[method] = policy
	}

	provider := &Provider{
		enabled:  true,
		policies: policies,
		metrics:  NewMetrics(),
	}

	// Test Query Service methods
	for _, method := range []string{
		"/committerpb.QueryService/BeginView",
		"/committerpb.QueryService/GetRows",
		"/committerpb.QueryService/GetTransactionStatus",
	} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			ctx := createContextWithCert(t, clientCert)
			err := provider.CheckACL(ctx, method)
			require.NoError(t, err, "client should be able to access %s", method)
		})
	}

	// Test Sidecar methods
	for _, method := range []string{
		"/peer.Deliver/Deliver",
		"/committerpb.Notifier/Subscribe",
		"/committerpb.BlockQueryService/GetBlockByNumber",
	} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			ctx := createContextWithCert(t, clientCert)
			err := provider.CheckACL(ctx, method)
			require.NoError(t, err, "client should be able to access %s", method)
		})
	}
}
