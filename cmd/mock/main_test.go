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

	"github.com/hyperledger/fabric-x-committer/cmd/config"
)

//nolint:paralleltest // Cannot parallelize due to logger.
func TestMockCMD(t *testing.T) {
	s := config.StartDefaultSystem(t)
	s.Endpoints.Orderer[0] = s.ServiceEndpoints
	commonTests := []config.CommandTest{
		{
			Name:         "print version",
			Args:         []string{"version"},
			CmdStdOutput: config.FullCommitterVersion(),
		},
		{
			Name: "trailing flag args for version",
			Args: []string{"version", "--test"},
			Err:  errors.New("unknown flag: --test"),
		},
		{
			Name: "trailing command args for version",
			Args: []string{"version", "test"},
			Err:  fmt.Errorf(`unknown command "test" for "%v version"`, mockCmdName),
		},
	}
	for _, test := range commonTests {
		tc := test
		t.Run(test.Name, func(t *testing.T) {
			config.UnitTestRunner(t, mockCMD(), tc)
		})
	}

	for _, serviceCase := range []struct {
		Command  string
		Name     string
		Template string
	}{
		{Command: "start-vc", Name: mockVcName, Template: config.TemplateVC},
		{Command: "start-verifier", Name: mockVerifierName, Template: config.TemplateVerifier},
		{Command: "start-orderer", Name: mockOrdererName, Template: config.TemplateMockOrderer},
	} {
		t.Run(serviceCase.Name, func(t *testing.T) {
			cases := []config.CommandTest{
				{
					Name:              "start with endpoint",
					Args:              []string{serviceCase.Command, "--endpoint", "localhost:8004"},
					CmdLoggerOutputs:  []string{"Serving", "localhost:8004"},
					CmdStdOutput:      fmt.Sprintf("Starting %v", serviceCase.Name),
					UseConfigTemplate: serviceCase.Template,
					System:            s,
				},
				{
					Name:              "start",
					Args:              []string{serviceCase.Command},
					CmdLoggerOutputs:  []string{"Serving", s.ServiceEndpoints.Server.String()},
					CmdStdOutput:      fmt.Sprintf("Starting %v", serviceCase.Name),
					UseConfigTemplate: serviceCase.Template,
					System:            s,
				},
			}
			for _, test := range cases {
				tc := test
				t.Run(test.Name, func(t *testing.T) {
					config.UnitTestRunner(t, mockCMD(), tc)
				})
			}
		})
	}
}
