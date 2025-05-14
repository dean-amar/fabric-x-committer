/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/spf13/viper"

	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/coordinator"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/query"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/sidecar"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/verifier"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

var logger = logging.New("config reader")

// ReadSidecarYamlAndSetupLogging reading the YAML config file of the sidecar.
func ReadSidecarYamlAndSetupLogging(v *viper.Viper, configPath string) (*sidecar.Config, error) {
	c := &sidecar.Config{}
	return c, ReadYamlAndSetupLogging(v, configPath, "SIDECAR", c)
}

// ReadCoordinatorYamlAndSetupLogging reading the YAML config file of the coordinator.
func ReadCoordinatorYamlAndSetupLogging(v *viper.Viper, configPath string) (*coordinator.Config, error) {
	c := &coordinator.Config{}
	return c, ReadYamlAndSetupLogging(v, configPath, "COORDINATOR", c)
}

// ReadVCYamlAndSetupLogging reading the YAML config file of the VC.
func ReadVCYamlAndSetupLogging(v *viper.Viper, configPath string) (*vc.Config, error) {
	c := &vc.Config{}
	return c, ReadYamlAndSetupLogging(v, configPath, "VC", c)
}

// ReadVerifierYamlAndSetupLogging reading the YAML config file of the verifier.
func ReadVerifierYamlAndSetupLogging(v *viper.Viper, configPath string) (*verifier.Config, error) {
	c := &verifier.Config{}
	return c, ReadYamlAndSetupLogging(v, configPath, "VERIFIER", c)
}

// ReadQueryYamlAndSetupLogging reading the YAML config file of the query service.
func ReadQueryYamlAndSetupLogging(v *viper.Viper, configPath string) (*query.Config, error) {
	c := &query.Config{}
	return c, ReadYamlAndSetupLogging(v, configPath, "QUERY", c)
}

// ReadMockOrdererYamlAndSetupLogging reading the YAML config file of the mock ordering service.
func ReadMockOrdererYamlAndSetupLogging(v *viper.Viper, configPath string) (*mock.OrdererConfig, error) {
	c := &mock.OrdererConfig{}
	return c, ReadYamlAndSetupLogging(v, configPath, "ORDERER", c)
}

// ReadLoadGenYamlAndSetupLogging reading the YAML config file of the load generator.
func ReadLoadGenYamlAndSetupLogging(v *viper.Viper, configPath string) (*loadgen.ClientConfig, error) {
	c := &loadgen.ClientConfig{}
	return c, ReadYamlAndSetupLogging(v, configPath, "LOADGEN", c)
}

// ReadYamlAndSetupLogging reading the YAML config file of a service.
func ReadYamlAndSetupLogging(v *viper.Viper, configPath, servicePrefix string, c any) error {
	if configPath == "" {
		return errors.New("--config flag must be set")
	}
	content, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return errors.Wrapf(err, "failed to read config file: %s", configPath)
	}
	if err = readYamlConfigsFromIO(v, bytes.NewReader(content)); err != nil {
		return err
	}
	setupEnv(v, servicePrefix)

	loggingWrapper := struct {
		Logging *logging.Config `mapstructure:"logging"`
	}{}
	if err = unmarshal(v, &loggingWrapper); err != nil {
		return err
	}
	logging.SetupWithConfig(loggingWrapper.Logging)
	return unmarshal(v, c)
}

// unmarshal populate a config object.
func unmarshal(v *viper.Viper, c any) error {
	defer logger.Debugf("Decoded config: %s", &utils.LazyJSON{O: c})
	return errors.Wrap(v.Unmarshal(c, decoderHook(decoders...)), "error decoding config")
}

// setupEnv enables setting configuration via environment variables.
// E.g. SC_LOGGING_ENABLED=false, but not SC_VERBOSE=false (does not work with aliases).
func setupEnv(v *viper.Viper, servicePrefix string) {
	v.SetEnvPrefix("SC_" + strings.ToUpper(servicePrefix))
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
}

// readYamlConfigsFromIO reads configurations from IO.
func readYamlConfigsFromIO(v *viper.Viper, in io.Reader) error {
	v.SetConfigType("yaml")
	return errors.Wrap(v.ReadConfig(in), "failed to read config")
}
