/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CobraFlag parameters.
type CobraFlag struct {
	Name  string
	Usage string
	Key   string
}

// SetDefaultFlags setting useful Cobra flags for the cmd parameter.
func SetDefaultFlags(v *viper.Viper, cmd *cobra.Command, configPath *string) error {
	cmd.PersistentFlags().StringVarP(configPath, "config", "c", "", "set the config file path")
	err := make([]error, 3)
	err[0] = CobraString(v, cmd, CobraFlag{
		Name:  "endpoint",
		Usage: "Determine the endpoint of the server",
		Key:   "server.endpoint",
	})
	err[1] = CobraString(v, cmd, CobraFlag{
		Name:  "metrics-endpoint",
		Usage: "Where prometheus listens for incoming connections",
		Key:   "monitoring.server.endpoint",
	})
	err[2] = CobraBool(v, cmd, CobraFlag{
		Name:  "verbose",
		Usage: "Turn on verbose mode",
		Key:   "logging.enabled",
	})
	return errors.Join(err...)
}

// CobraInt creates a flag of type integer for the cmd parameter.
func CobraInt(v *viper.Viper, cmd *cobra.Command, c CobraFlag) error {
	cmd.PersistentFlags().Int(c.Name, v.GetInt(c.Key), c.Usage)
	return bindFlag(v, cmd, c)
}

// CobraString creates a flag of type string for the cmd parameter.
func CobraString(v *viper.Viper, cmd *cobra.Command, c CobraFlag) error {
	cmd.PersistentFlags().String(c.Name, v.GetString(c.Key), c.Usage)
	return bindFlag(v, cmd, c)
}

// CobraBool creates a flag of type boolean for the cmd parameter.
func CobraBool(v *viper.Viper, cmd *cobra.Command, c CobraFlag) error {
	cmd.PersistentFlags().Bool(c.Name, viper.GetBool(c.Key), c.Usage)
	return bindFlag(v, cmd, c)
}

// CobraDuration creates a flag of type Duration for the cmd parameter.
func CobraDuration(v *viper.Viper, cmd *cobra.Command, c CobraFlag) error {
	cmd.PersistentFlags().Duration(c.Name, viper.GetDuration(c.Key), c.Usage)
	return bindFlag(v, cmd, c)
}

func bindFlag(v *viper.Viper, cmd *cobra.Command, c CobraFlag) error {
	return errors.Wrap(v.BindPFlag(c.Key, cmd.PersistentFlags().Lookup(c.Name)), "failed to bind flag")
}
