/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	_ "embed"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	testNodeImage      = "icr.io/cbdc/committer-test-node:0.0.2"
	sidecarPort        = "4001"
	loadGenMetricsPort = "2118"
)

// TestStartTestNode spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNode(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	dockerClient := createDockerClient(t)
	stopAndRemoveContainersByName(ctx, t, dockerClient, "committer")
	startCommitter(ctx, t, dockerClient, "committer")

	t.Log("Try to fetch the first block")
	sidecarEndpoint, err := connection.NewEndpoint("localhost:" + sidecarPort)
	require.NoError(t, err)
	fetchFirstBlock(ctx, t, test.MakeInsecureClientConfig(sidecarEndpoint))
	monitorMetrics(t, loadGenMetricsPort)
}

func startCommitter(ctx context.Context, t *testing.T, dockerClient *client.Client, name string) {
	t.Helper()
	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", "db", "committer", "orderer", "loadgen"},
		ExposedPorts: nat.PortSet{
			nat.Port(sidecarPort + "/tcp"):        struct{}{},
			nat.Port(loadGenMetricsPort + "/tcp"): struct{}{},
		},
		Tty: true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: network.NetworkDefault,
		PortBindings: nat.PortMap{
			// sidecar port binding
			nat.Port(sidecarPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: sidecarPort,
			}},
			// loadgen service port bindings
			nat.Port(loadGenMetricsPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: loadGenMetricsPort,
			}},
		},
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}
