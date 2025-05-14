/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/adapters"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
)

const (
	serviceName    = "loadgen"
	serviceVersion = "0.0.2"
)

func main() {
	cmd := loadgenCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func loadgenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   serviceName,
		Short: fmt.Sprintf("%v is a load generator for FabricX committer services.", serviceName),
	}

	cmd.AddCommand(config.VersionCmd(serviceName, serviceVersion))
	cmd.AddCommand(startCmd())
	return cmd
}

func startCmd() *cobra.Command {
	v := config.NewViperWithLoadGenDefaults()
	var configPath string
	var onlyNamespace bool
	var onlyWorkload bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Starts a %v", serviceName),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			conf, err := config.ReadLoadGenYamlAndSetupLogging(v, configPath)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			cmd.Printf("Starting %v service\n", serviceName)

			if onlyNamespace {
				conf.Generate = adapters.Phases{Namespaces: true}
			}
			if onlyWorkload {
				conf.Generate = adapters.Phases{Load: true}
			}

			client, err := loadgen.NewLoadGenClient(conf)
			if err != nil {
				return errors.Wrap(err, "failed to create loadgen client")
			}
			return client.Run(cmd.Context())
		},
	}
	utils.Must(config.SetDefaultFlags(v, cmd, &configPath))
	p := cmd.PersistentFlags()
	p.BoolVar(&onlyNamespace, "only-namespace", false, "only run namespace generation")
	p.BoolVar(&onlyWorkload, "only-workload", false, "only run workload generation")
	return cmd
}
