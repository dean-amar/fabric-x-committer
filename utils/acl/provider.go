/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

// Provider coordinates ACL enforcement by managing policies and making access control decisions.
// It serves as the main entry point for ACL checks.
//
// Note: Certificate validation is performed by the TLS layer when mTLS is enabled.
// The Provider only extracts identity information and evaluates policies.
type Provider struct {
	// enabled controls whether ACL enforcement is active.
	// If false, all CheckACL calls return nil (access granted).
	enabled bool

	// policies maps gRPC method names to their access control policies.
	policies map[string]*Policy

	// metrics tracks ACL operations for observability.
	metrics *Metrics
}

var (
	// ErrACLDisabled is returned when attempting operations on a disabled provider.
	ErrACLDisabled = errors.New("ACL is disabled")

	// ErrNoPolicyDefined is returned when no policy exists for a method.
	ErrNoPolicyDefined = errors.New("no ACL policy defined for method")
)

// NewProvider creates a new ACL provider from the given configuration.
// If config is nil, returns a disabled provider (backward compatible mode).
// If config.Enabled is false, returns a disabled provider.
// Otherwise, returns an enabled provider with loaded policies.
//
// Note: This provider relies on mTLS being enabled on the server for certificate validation.
// The TLS layer validates certificates against trusted CAs before requests reach the ACL layer.
func NewProvider(config *Config) (*Provider, error) {
	// If no config provided, create disabled provider (backward compatible)
	if config == nil {
		logger.Info("Creating disabled ACL provider (no configuration provided)")
		return &Provider{
			enabled: false,
			metrics: NewMetrics(),
		}, nil
	}

	// If config explicitly disables ACL, create disabled provider
	if !config.Enabled {
		logger.Info("Creating disabled ACL provider (ACL disabled in configuration)")
		return &Provider{
			enabled: false,
			metrics: NewMetrics(),
		}, nil
	}

	// Build policy map from configuration
	policyMap := make(map[string]*Policy)
	policyConfig := config.GetPolicies()
	for method, requiredRole := range policyConfig {
		policy, err := NewPolicy(method, requiredRole)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create policy for method: %s", method)
		}
		policyMap[method] = policy
	}

	logger.Infof("Created enabled ACL provider with %d policies", len(policyMap))
	logger.Info("ACL requires mTLS to be enabled on the server for certificate-based authentication")

	return &Provider{
		enabled:  true,
		policies: policyMap,
		metrics:  NewMetrics(),
	}, nil
}

// CheckACL performs a complete access control check for a gRPC method.
// It extracts the client identity from the context, looks up the policy for the method,
// and evaluates whether the identity satisfies the policy.
//
// Returns nil if access is granted, or an error describing why access was denied.
// If the provider is disabled, always returns nil (access granted).
func (p *Provider) CheckACL(ctx context.Context, method string) error {
	// If ACL is disabled, allow all access (backward compatible)
	if !p.enabled {
		return nil
	}

	// Check if context is already cancelled (client disconnected)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Record start time for metrics
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		p.metrics.RecordCheckDuration(method, duration)
	}()

	// Extract client identity from context
	// Note: Certificate validation is already performed by the TLS layer
	identity, err := ExtractIdentityFromContext(ctx)
	if err != nil {
		// Record specific certificate extraction errors for metrics
		p.recordCertError(err)
		p.metrics.RecordCheckDenied(method)
		logger.Infof("ACL check failed for method %s: %v", method, err)
		return errors.Wrap(err, "failed to extract client identity")
	}

	// Look up policy for this method
	policy, exists := p.policies[method]
	if !exists {
		p.metrics.RecordPolicyLookupFailure(method)
		p.metrics.RecordCheckDenied(method)
		logger.Warnf("No ACL policy defined for method: %s", method)
		return errors.Wrapf(ErrNoPolicyDefined, "method: %s", method)
	}

	// Evaluate policy against identity
	if err := policy.Evaluate(identity); err != nil {
		p.metrics.RecordCheckDenied(method)
		logger.Infof("ACL denied: method=%s org=%s role=%s required_role=%s reason=%v",
			method, identity.Organization, identity.Role, policy.RequiredRole, err)
		return err
	}

	// Access granted
	p.metrics.RecordCheckAllowed(method)
	logger.Debugf("ACL allowed: method=%s org=%s role=%s",
		method, identity.Organization, identity.Role)

	return nil
}

// IsEnabled returns whether ACL enforcement is active.
func (p *Provider) IsEnabled() bool {
	return p.enabled
}

// GetMetrics returns the metrics instance for this provider.
// Useful for testing and monitoring.
func (p *Provider) GetMetrics() *Metrics {
	return p.metrics
}

// recordCertError records certificate validation errors in metrics.
// It categorizes errors by type for better observability.
func (p *Provider) recordCertError(err error) {
	switch {
	case errors.Is(err, ErrNoPeerInfo):
		p.metrics.RecordCertValidationError("no_peer_info")
	case errors.Is(err, ErrNoTLSInfo):
		p.metrics.RecordCertValidationError("no_tls_info")
	case errors.Is(err, ErrNoCertificate):
		p.metrics.RecordCertValidationError("missing_cert_mtls_required")
	default:
		// Check if error message contains role-related keywords
		errMsg := err.Error()
		if strings.Contains(errMsg, "role") || strings.Contains(errMsg, "OU") {
			p.metrics.RecordCertValidationError("invalid_role")
		} else {
			p.metrics.RecordCertValidationError("other")
		}
	}
}
