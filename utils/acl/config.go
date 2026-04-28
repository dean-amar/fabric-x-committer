/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"os"

	"github.com/cockroachdb/errors"
	"gopkg.in/yaml.v2"
)

// Config represents the complete ACL configuration loaded from YAML.
// It includes ACL policy mappings for role-based access control.
//
// Note: Certificate validation is handled by the TLS layer when mTLS is enabled.
// The ACL system only needs policy mappings (method -> required role).
type Config struct {
	// Enabled controls whether ACL enforcement is active.
	// If false, all ACL checks pass (backward compatible mode).
	Enabled bool `yaml:"enabled"`

	// Policies maps gRPC method names to required roles.
	// Format: "/service.Name/Method": "required_role"
	// Valid roles: "admin", "client", "member"
	// If empty, DefaultACLs are used.
	Policies map[string]string `yaml:"policies"`
}

// LoadConfig loads ACL configuration from a YAML file.
// Returns nil if the file doesn't exist (ACL will be disabled).
// Returns an error if the file exists but cannot be parsed or validated.
func LoadConfig(path string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Infof("ACL config file not found: %s (ACL will be disabled)", path)
		return nil, nil
	}

	// Read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read ACL config file: %s", path)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, errors.Wrapf(err, "failed to parse ACL config YAML: %s", path)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid ACL configuration in file: %s", path)
	}

	logger.Infof("Loaded ACL configuration from: %s (enabled=%v, policies=%d)",
		path, config.Enabled, len(config.Policies))

	return &config, nil
}

// Validate checks that the configuration is valid and complete.
// It verifies that all policy roles are valid.
func (c *Config) Validate() error {
	// If ACL is disabled, no further validation needed
	if !c.Enabled {
		return nil
	}

	// Validate each policy's required role
	for method, role := range c.Policies {
		if !isValidRole(role) {
			return errors.Newf("invalid role '%s' for method '%s'", role, method)
		}
	}

	return nil
}

// GetPolicies returns the policy mappings from the configuration.
// If no policies are configured, returns the default policies.
func (c *Config) GetPolicies() map[string]string {
	if len(c.Policies) > 0 {
		return c.Policies
	}
	return DefaultACLs
}
