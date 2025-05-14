/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"testing"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
)

//nolint:paralleltest // Cannot parallelize due to logger.
func TestVCServiceCmd(t *testing.T) {
	s := config.StartDefaultSystem(t)
	commonTests := []config.CommandTest{
		{
			Name:              "start with endpoint",
			Args:              []string{"start", "--endpoint", "localhost:8000"},
			CmdLoggerOutputs:  []string{"Serving", "localhost:8000"},
			CmdStdOutput:      fmt.Sprintf("Starting %v service", serviceName),
			UseConfigTemplate: config.TemplateVC,
			System:            s,
		},
		{
			Name:              "start",
			Args:              []string{"start"},
			CmdLoggerOutputs:  []string{"Serving", s.ServiceEndpoints.Server.String()},
			CmdStdOutput:      fmt.Sprintf("Starting %v service", serviceName),
			UseConfigTemplate: config.TemplateVC,
			System:            s,
		},
		{
			Name:         "print version",
			Args:         []string{"version"},
			CmdStdOutput: fmt.Sprintf("%v %v", serviceName, serviceVersion),
		},
		{
			Name: "trailing flag args for version",
			Args: []string{"version", "--test"},
			Err:  errors.New("unknown flag: --test"),
		},
		{
			Name: "trailing command args for version",
			Args: []string{"version", "test"},
			Err:  fmt.Errorf(`unknown command "test" for "%v version"`, serviceName),
		},
	}

	for _, test := range commonTests {
		tc := test
		t.Run(tc.Name, func(t *testing.T) {
			config.UnitTestRunner(t, vcserviceCmd(), tc)
		})
	}
}
