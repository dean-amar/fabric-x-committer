package main

import (
	_ "embed"
	"errors"
	"fmt"
	"testing"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
)

//nolint:paralleltest // Cannot parallelize due to logger.
func TestMockOrderingService(t *testing.T) {
	s := config.StartDefaultSystem(t)
	s.Endpoints.Orderer[0] = s.ServiceEndpoints
	commonTests := []config.CommandTest{
		{
			Name:              "start",
			Args:              []string{"start"},
			CmdLoggerOutputs:  []string{"Serving", s.ServiceEndpoints.Server.String()},
			CmdStdOutput:      fmt.Sprintf("Starting %v service", serviceName),
			UseConfigTemplate: config.TemplateMockOrderer,
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
		t.Run(test.Name, func(t *testing.T) {
			config.UnitTestRunner(t, mockorderingserviceCmd(), tc)
		})
	}
}
