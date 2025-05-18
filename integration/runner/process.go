/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
)

type (
	// ProcessWithConfig holds the ifrit process and the corresponding configuration.
	ProcessWithConfig struct {
		process        ifrit.Process
		cmdName        string
		configFilePath string
	}
)

const (
	mockordererCMD   = "mockorderingservice"
	queryexecutorCMD = "queryexecutor"
	verifierCMD      = "signatureverifier"
	vcCMD            = "validatorpersister"
	coordinatorCMD   = "coordinator"
	sidecarCMD       = "sidecar"
	loadgenCMD       = "loadgen"
)

func newProcess(
	t *testing.T,
	cmdName string,
	cmdTemplate string,
	conf *config.SystemConfig,
) *ProcessWithConfig {
	t.Helper()
	configFilePath := config.CreateTempConfigFromTemplate(t, cmdTemplate, conf)
	p := &ProcessWithConfig{
		cmdName:        cmdName,
		configFilePath: configFilePath,
	}
	t.Cleanup(func() {
		p.Stop(t)
	})
	return p
}

// Stop stops the running process.
func (p *ProcessWithConfig) Stop(t *testing.T) {
	t.Helper()
	if p.process == nil {
		return
	}
	p.process.Signal(os.Kill)
	select {
	case <-p.process.Wait():
	case <-time.After(30 * time.Second):
		t.Errorf("Process [%s] did not terminate after 30 seconds", p.cmdName)
	}
}

// Restart stops the process if it is running and then starts it.
func (p *ProcessWithConfig) Restart(t *testing.T) {
	t.Helper()
	p.Stop(t)
	cmdPath := path.Join("bin", p.cmdName)
	c := exec.Command(cmdPath, "start", "--config", p.configFilePath)
	dir, err := os.Getwd()
	require.NoError(t, err)
	c.Dir = path.Clean(path.Join(dir, "../.."))
	p.process = Run(c, p.cmdName, "")
}

// Run executes the specified command and returns the corresponding process.
// It is important to note that the underlying invocation function (Invoke)
// returns only when either process.Ready or process.Wait has been read.
// Consequently, the caller only needs to read process.Wait to wait for the
// process to complete and capture any errors that may have occurred during execution.
//
//nolint:ireturn
func Run(cmd *exec.Cmd, name, startCheck string) ifrit.Process {
	return ifrit.Invoke(ginkgomon.New(ginkgomon.Config{
		Command:           cmd,
		Name:              name,
		AnsiColorCode:     "",
		StartCheck:        startCheck,
		StartCheckTimeout: 0,
		Cleanup: func() {
		},
	}))
}
