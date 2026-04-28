/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("non-existent file returns nil", func(t *testing.T) {
		t.Parallel()

		config, err := LoadConfig("/non/existent/path.yaml")
		require.NoError(t, err)
		require.Nil(t, config)
	})

	t.Run("valid config file loads successfully", func(t *testing.T) {
		t.Parallel()

		// Create temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "acl-config.yaml")

		// Build YAML content with proper spacing (YAML requires spaces, not tabs)
		configContent := "enabled: true\n" +
			"policies:\n" +
			"  \"/test.Service/Method\": \"admin\"\n"
		err := os.WriteFile(configPath, []byte(configContent), 0600)
		require.NoError(t, err)

		config, err := LoadConfig(configPath)
		require.NoError(t, err)
		require.NotNil(t, config)
		require.True(t, config.Enabled)
		require.Len(t, config.Policies, 1)
	})

	t.Run("invalid YAML returns error", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")

		invalidContent := `
enabled: true
policies:
  - this is invalid yaml structure
`
		err := os.WriteFile(configPath, []byte(invalidContent), 0600)
		require.NoError(t, err)

		config, err := LoadConfig(configPath)
		require.Error(t, err)
		require.Nil(t, config)
		require.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("config with validation errors returns error", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid-config.yaml")

		// Config with invalid role
		invalidContent := `
enabled: true
policies:
		"/test.Service/Method": "invalid-role"
`
		err := os.WriteFile(configPath, []byte(invalidContent), 0600)
		require.NoError(t, err)

		config, err := LoadConfig(configPath)
		require.Error(t, err)
		require.Nil(t, config)
		require.Contains(t, err.Error(), "invalid")
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("disabled config is valid", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("enabled config with invalid policy role is invalid", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			Policies: map[string]string{
				"/test.Service/Method": "invalid-role",
			},
		}

		err := config.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid role")
	})

	t.Run("enabled config with valid policies is valid", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
			Policies: map[string]string{
				"/test.Service/Method": "admin",
			},
		}

		err := config.Validate()
		require.NoError(t, err)
	})
}

func TestConfig_GetPolicies(t *testing.T) {
	t.Parallel()

	t.Run("returns configured policies when present", func(t *testing.T) {
		t.Parallel()

		customPolicies := map[string]string{
			"/custom.Service/Method": "admin",
		}

		config := &Config{
			Policies: customPolicies,
		}

		policies := config.GetPolicies()
		require.Equal(t, customPolicies, policies)
	})

	t.Run("returns default policies when none configured", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Policies: map[string]string{},
		}

		policies := config.GetPolicies()
		require.Equal(t, DefaultACLs, policies)
	})

	t.Run("returns default policies when policies is nil", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Policies: nil,
		}

		policies := config.GetPolicies()
		require.Equal(t, DefaultACLs, policies)
	})
}
