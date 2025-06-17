/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
)

func main() {
	cmd := sigverifierCmd()

	// On failure, Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func sigverifierCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   config.VerifierName,
		Short: fmt.Sprintf("%v is a service that verifies the transaction's signatures.", config.VerifierName),
	}

	cmd.AddCommand(config.VersionCmd())
	cmd.AddCommand(config.VerifierCMD("start"))
	return cmd
}
