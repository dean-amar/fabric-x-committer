/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"context"
	_ "embed"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

//go:embed test-config.yaml
var testConfig string

type TestConfig struct {
	BoolFlag     bool          `mapstructure:"bool-flag"`
	DurationFlag time.Duration `mapstructure:"duration-flag"`
	IntFlag      int           `mapstructure:"int-flag"`
	StringFlag   string        `mapstructure:"string-flag"`
	EnvFlag      string        `mapstructure:"env-flag"`
}

func TestReadConfig(t *testing.T) {
	t.Parallel()
	defaultYamlValuesConfig := &TestConfig{
		BoolFlag:     false,
		DurationFlag: 1 * time.Second,
		IntFlag:      1,
		StringFlag:   "default-value",
		EnvFlag:      "default",
	}
	testCmd := startCmd(t, defaultYamlValuesConfig)
	testCmd.SetArgs([]string{})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	_, err := testCmd.ExecuteContextC(ctx)
	require.NoError(t, err)
}

func TestCobraFlags(t *testing.T) {
	t.Parallel()
	expectedConfig := &TestConfig{
		BoolFlag:     true,
		DurationFlag: 99 * time.Millisecond,
		IntFlag:      99,
		StringFlag:   "test-string",
		EnvFlag:      "default",
	}
	testCmd := startCmd(t, expectedConfig)

	testCmd.SetArgs([]string{
		"--int-flag", strconv.Itoa(expectedConfig.IntFlag),
		"--string-flag", expectedConfig.StringFlag,
		"--bool-flag",
		"--duration-flag", expectedConfig.DurationFlag.String(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	_, err := testCmd.ExecuteContextC(ctx)
	require.NoError(t, err)
}

func TestReadConfigEnv(t *testing.T) {
	defaultYamlValuesConfig := &TestConfig{
		BoolFlag:     false,
		DurationFlag: 1 * time.Second,
		IntFlag:      1,
		StringFlag:   "from-env",
		EnvFlag:      "default",
	}
	t.Setenv("SC_TEST_STRING_FLAG", "from-env")
	testCmd := startCmd(t, defaultYamlValuesConfig)
	testCmd.SetArgs([]string{})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	_, err := testCmd.ExecuteContextC(ctx)
	require.NoError(t, err)
}

func TestReadConfigEnvUnset(t *testing.T) {
	defaultYamlValuesConfig := &TestConfig{
		BoolFlag:     false,
		DurationFlag: 1 * time.Second,
		IntFlag:      1,
		StringFlag:   "default-value",
		EnvFlag:      "from-env",
	}
	t.Setenv("SC_TEST_ENV_FLAG", "from-env")
	testCmd := startCmd(t, defaultYamlValuesConfig)
	testCmd.SetArgs([]string{})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	_, err := testCmd.ExecuteContextC(ctx)
	require.NoError(t, err)
}

func startCmd(t *testing.T, expectedConfig *TestConfig) *cobra.Command {
	t.Helper()
	v := viper.New()
	v.SetDefault("env-flag", "default")
	cmd := &cobra.Command{
		Use:   "Test-Cmd",
		Short: "Test command to check the binding between Cobra and Viper.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			require.NoError(t, readYamlConfigsFromIO(v, bytes.NewBufferString(testConfig)))
			setupEnv(v, "test")
			conf := &TestConfig{}
			require.NoError(t, unmarshal(v, conf))
			require.Equal(t, expectedConfig, conf)
			return nil
		},
	}
	require.NoError(t, CobraInt(v, cmd, CobraFlag{
		Name:  "int-flag",
		Usage: "Testing",
		Key:   "int-flag",
	}))
	require.NoError(t, CobraString(v, cmd, CobraFlag{
		Name:  "string-flag",
		Usage: "Testing",
		Key:   "string-flag",
	}))
	require.NoError(t, CobraBool(v, cmd, CobraFlag{
		Name:  "bool-flag",
		Usage: "Testing",
		Key:   "bool-flag",
	}))
	require.NoError(t, CobraDuration(v, cmd, CobraFlag{
		Name:  "duration-flag",
		Usage: "Testing",
		Key:   "duration-flag",
	}))
	return cmd
}
