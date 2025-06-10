/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dbtest

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection/tlsgen"
)

const (
	defaultYugabyteImage            = "yugabytedb/yugabyte:2.20.7.0-b58"
	defaultPostgresImage            = "postgres:16.9-alpine3.21"
	defaultDBDeploymentTemplateName = "sc_%s_unit_tests"

	defaultHostIP  = "127.0.0.1"
	defaultPortMap = "7000/tcp"

	// defaultPathForYugabytePassword holds the path to the database credentials.
	// This work-around needed due to the fact yugabyte has a bug that doesn't allow the usage
	// of default passwords when running it in secure mode.
	// Instead, they create a random password.
	// Therefore, the password has to be manually extracted for later usage.
	defaultPathForYugabytePassword = "/root/var/data/yugabyted_credentials.txt"

	defaultSubnet                 = "172.28.0.0/16"
	defaultGateway                = "172.28.0.1"
	defaultYugabyteTLSContainerIP = "172.28.0.100"
	defaultNetworkName            = "yugabyte_with_tls_network"

	// YugabyteReadinessOutput is the output indicating that a Yugabyte node is ready.
	YugabyteReadinessOutput = "Data placement constraint successfully verified"
)

var (
	// YugabyteCMD starts yugabyte without SSL and fault tolerance (single server).
	YugabyteCMD = []string{
		"bin/yugabyted", "start",
		"--callhome", "false",
		"--background", "false",
		"--ui", "false",
		"--tserver_flags", "ysql_max_connections=5000",
		"--insecure",
	}

	enforcePostgresSSLScript = []string{
		"sh", "-c",
		`sed -i 's/^host all all all scram-sha-256$/hostssl all all 0.0.0.0\/0 scram-sha-256/' /var/lib/postgresql/data/pg_hba.conf`,
	}

	reloadPostgresConfigScript = []string{
		"psql", "-U", "yugabyte", "-c", "SELECT pg_reload_conf();",
	}
)

// DatabaseContainer manages the execution of an instance of a dockerized DB for tests.
type DatabaseContainer struct {
	Name         string
	Image        string
	HostIP       string
	Network      string
	DatabaseType string
	Tag          string
	Role         string
	Cmd          []string
	Env          []string
	Binds        []string
	HostPort     int
	DbPort       docker.Port
	PortMap      docker.Port
	PortBinds    map[docker.Port][]docker.PortBinding
	NetToIP      map[string]*docker.EndpointConfig
	AutoRm       bool
	Creds        *containerCreds
	UseTLS       bool

	client           *docker.Client
	networkingConfig *docker.NetworkingConfig
	containerID      string
}

type containerCreds struct {
	CredsPath  string
	CACertPath string
	ServerName string
}

// StartContainer runs a DB container, if no specific container details provided, default values will be set.
func (dc *DatabaseContainer) StartContainer(ctx context.Context, t *testing.T) {
	t.Helper()

	dc.initDefaults(t)

	dc.createContainer(ctx, t)

	// Starts the container
	err := dc.client.StartContainerWithContext(dc.containerID, nil, ctx)
	if _, ok := err.(*docker.ContainerAlreadyRunning); ok {
		t.Log("Container is already running")
		return
	}
	require.NoError(t, err)
}

func (dc *DatabaseContainer) initDefaults(t *testing.T) { //nolint:gocognit
	t.Helper()

	switch dc.DatabaseType {
	case YugaDBType:
		if dc.Image == "" {
			dc.Image = defaultYugabyteImage
		}

		if dc.Cmd == nil {
			dc.Cmd = YugabyteCMD
		}

		if dc.DbPort == "" {
			dc.DbPort = docker.Port(fmt.Sprintf("%s/tcp", yugaDBPort))
		}
	case PostgresDBType:
		if dc.Image == "" {
			dc.Image = defaultPostgresImage
		}

		if dc.Env == nil {
			dc.Env = []string{
				"POSTGRES_PASSWORD=yugabyte",
				"POSTGRES_USER=yugabyte",
				//"POSTGRES_INITDB_SKIP=true",
			}
		}

		if dc.DbPort == "" {
			dc.DbPort = docker.Port(fmt.Sprintf("%s/tcp", postgresDBPort))
		}
	default:
		t.Fatalf("Unsupported database type: %s", dc.DatabaseType)
	}

	if dc.Name == "" {
		dc.Name = fmt.Sprintf(defaultDBDeploymentTemplateName, dc.DatabaseType)
	}

	if dc.HostIP == "" {
		dc.HostIP = defaultHostIP
	}

	if dc.PortMap == "" {
		dc.PortMap = defaultPortMap
	}

	if dc.PortBinds == nil {
		dc.PortBinds = map[docker.Port][]docker.PortBinding{
			dc.PortMap: {{
				HostIP:   dc.HostIP,
				HostPort: strconv.Itoa(dc.HostPort),
			}},
		}
	}

	if dc.client == nil {
		dc.client = GetDockerClient(t)
	}

	dc.setTLSPropertiesForDatabase(t)
}

func (dc *DatabaseContainer) setTLSPropertiesForDatabase(t *testing.T) {
	t.Helper()
	if dc.UseTLS {
		t.Logf("using TLS: %v", dc.UseTLS)
		var credsPathDir, serverName string
		var paths map[string]string

		tlsManager := tlsgen.NewSecureCommunicationManager(t)

		switch dc.DatabaseType {
		case PostgresDBType:
			{
				serverName = "database"
				credsPathDir, paths = tlsManager.CreateDatabaseCreds(t, serverName)

				dc.Cmd = []string{
					"-c", "ssl=on",
					"-c", "ssl_cert_file=/creds/server.crt",
					"-c", "ssl_key_file=/creds/server.key",
				}
			}
		case YugaDBType:
			{
				CreateDockerNetwork(t, defaultNetworkName)
				t.Cleanup(func() {
					RemoveDockerNetwork(t, defaultNetworkName)
				})

				serverName = defaultYugabyteTLSContainerIP
				dc.Network = defaultNetworkName

				stopContainerByIP(t, serverName)

				credsPathDir, paths = tlsManager.CreateDatabaseCredsForYugabyte(t, serverName)

				dc.Cmd = append(
					utils.ReplacePattern(
						dc.Cmd, func(s string) bool { return s == "--insecure" }, "--secure"),
					"--certs_dir=/creds",
				)

				dc.networkingConfig = &docker.NetworkingConfig{
					EndpointsConfig: map[string]*docker.EndpointConfig{
						defaultNetworkName: {
							IPAMConfig: &docker.EndpointIPAMConfig{
								IPv4Address: defaultYugabyteTLSContainerIP,
							},
						},
					},
				}
			}
		default:
			t.Fatalf("Unsupported database type: %s", dc.DatabaseType)
		}

		// We can't re-use the container because of the certificates being created on runtime.
		// If we want to use docker secrets, we need to run the code in the same container, which we don't.
		// Therefore, we need to remove the container and start a new one.
		dc.Creds = &containerCreds{
			CredsPath:  credsPathDir,
			CACertPath: paths["ca-certificate"],
			ServerName: serverName,
		}

		dc.Binds = append(dc.Binds, dc.Creds.CredsPath+":/creds")
		dc.Name += "_with_tls"

		t.Cleanup(
			func() {
				dc.StopAndRemoveContainer(t)
			},
		)
	}
}

// createContainer attempts to create a container instance, or attach to an existing one.
func (dc *DatabaseContainer) createContainer(ctx context.Context, t *testing.T) {
	t.Helper()
	// If container exists, we don't have to create it.
	found := dc.findContainer(t)

	if found {
		return
	}

	// Pull the image if not exist
	require.NoError(t, dc.client.PullImage(docker.PullImageOptions{
		Context:      ctx,
		Repository:   dc.Image,
		Tag:          dc.Tag,
		OutputStream: os.Stdout,
	}, docker.AuthConfiguration{}))

	// Create the container instance
	container, err := dc.client.CreateContainer(
		docker.CreateContainerOptions{
			Context: ctx,
			Name:    dc.Name,
			Config: &docker.Config{
				Image: dc.Image,
				Cmd:   dc.Cmd,
				Env:   dc.Env,
			},
			HostConfig: &docker.HostConfig{
				AutoRemove:   dc.AutoRm,
				PortBindings: dc.PortBinds,
				NetworkMode:  dc.Network,
				Binds:        dc.Binds,
			},
			NetworkingConfig: dc.networkingConfig,
		},
	)

	// If container created successfully, finish.
	if err == nil {
		dc.containerID = container.ID
		return
	}
	require.ErrorIs(t, err, docker.ErrContainerAlreadyExists)

	// Try to find it again.
	require.True(t, dc.findContainer(t), "cannot create container (already exists), but cannot find it")
}

// findContainer looks up a container with the same name.
func (dc *DatabaseContainer) findContainer(t *testing.T) bool {
	t.Helper()
	allContainers, err := dc.client.ListContainers(docker.ListContainersOptions{All: true})
	require.NoError(t, err, "could not load containers.")

	for _, c := range allContainers {
		for _, n := range c.Names {
			if n == dc.Name || n == fmt.Sprintf("/%s", dc.Name) {
				dc.containerID = c.ID
				return true
			}
		}
	}

	return false
}

// getConnectionOptions inspect the container and fetches the available connection options.
func (dc *DatabaseContainer) getConnectionOptions(ctx context.Context, t *testing.T) *Connection {
	t.Helper()
	container, err := dc.client.InspectContainerWithOptions(docker.InspectContainerOptions{
		Context: ctx,
		ID:      dc.containerID,
	})
	require.NoError(t, err)

	endpoints := []*connection.Endpoint{
		dc.GetContainerConnectionDetails(ctx, t),
	}

	for _, p := range container.NetworkSettings.Ports[dc.DbPort] {
		endpoints = append(endpoints, connection.CreateEndpointHP(p.HostIP, p.HostPort))
	}

	dbConnection := NewConnection(endpoints...)

	if dc.UseTLS {
		dbConnection.Creds = connection.DatabaseCreds{
			CAPaths:    []string{dc.Creds.CACertPath},
			ServerName: dc.Creds.ServerName,
		}
		switch dc.DatabaseType {
		case YugaDBType:
			dc.WaitForNodeReadiness(t, YugabyteReadinessOutput)
			dbConnection.Password = dc.readPasswordFromContainer(t, defaultPathForYugabytePassword)
		case PostgresDBType:
			dc.enforceSSLForPostgres(t)
		default:
			t.Fatalf("Unsupported database type: %s", dc.DatabaseType)
		}
	}

	return dbConnection
}

// GetContainerConnectionDetails inspect the container and fetches its connection to an endpoint.
func (dc *DatabaseContainer) GetContainerConnectionDetails(
	ctx context.Context,
	t *testing.T,
) *connection.Endpoint {
	t.Helper()
	container, err := dc.client.InspectContainerWithOptions(docker.InspectContainerOptions{
		Context: ctx,
		ID:      dc.containerID,
	})
	require.NoError(t, err)

	ipAddress := container.NetworkSettings.IPAddress
	require.NotNil(t, ipAddress)
	if dc.Network != "" {
		net, ok := container.NetworkSettings.Networks[dc.Network]
		require.True(t, ok)
		ipAddress = net.IPAddress
	}
	return connection.CreateEndpointHP(ipAddress, dc.DbPort.Port())
}

// streamLogs streams the container output to the requested stream.
func (dc *DatabaseContainer) streamLogs(t *testing.T) {
	t.Helper()
	logOptions := docker.LogsOptions{
		//nolint:usetesting //t.Context finished after the function call, which is causing an unexpected crash.
		Context:      context.Background(),
		Container:    dc.containerID,
		Follow:       true,
		ErrorStream:  os.Stderr,
		OutputStream: os.Stdout,
		Stderr:       true,
		Stdout:       true,
	}

	assert.NoError(t, dc.client.Logs(logOptions))
}

// GetContainerLogs return the output of the DatabaseContainer.
func (dc *DatabaseContainer) GetContainerLogs(t *testing.T) string {
	t.Helper()
	var outputBuffer bytes.Buffer
	require.NoError(t, dc.client.Logs(docker.LogsOptions{
		Stdout:       true,
		Stderr:       true,
		Container:    dc.Name,
		OutputStream: &outputBuffer,
		ErrorStream:  &outputBuffer,
	}))

	return outputBuffer.String()
}

// StopAndRemoveContainer stops and removes the db container from the docker engine.
func (dc *DatabaseContainer) StopAndRemoveContainer(t *testing.T) {
	t.Helper()
	require.NoError(t, dc.client.StopContainer(dc.ContainerID(), 10))
	require.NoError(t, dc.client.RemoveContainer(docker.RemoveContainerOptions{
		ID:    dc.ContainerID(),
		Force: true,
	}))
	t.Logf("Container %s stopped and removed successfully", dc.ContainerID())
}

// ContainerID returns the container ID.
func (dc *DatabaseContainer) ContainerID() string {
	return dc.containerID
}

// readPasswordFromContainer reads a password from a file in the container.
// This function is required for the extraction of the random password
// created by YugabyteDB in secure mode.
// Default passwords cannot be used.
func (dc *DatabaseContainer) readPasswordFromContainer(t *testing.T, filePath string) string {
	t.Helper()
	output := dc.ExecuteCommand(t, []string{"cat", filePath})

	scanner := bufio.NewScanner(strings.NewReader(output))
	re := regexp.MustCompile(`(?i)^password:\s*(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if matches := re.FindStringSubmatch(line); len(matches) == 2 {
			return matches[1]
		}
	}

	require.NoError(t, scanner.Err(), "error scanning command output")
	t.Log("password not found in output, returning default password.")

	return defaultPassword
}

// ExecuteCommand execute a given command in the container.
func (dc *DatabaseContainer) ExecuteCommand(t *testing.T, cmd []string) string {
	t.Helper()

	var stdout bytes.Buffer
	t.Logf("executing %s", strings.Join(cmd, " "))
	exec, err := dc.client.CreateExec(docker.CreateExecOptions{
		Container:    dc.containerID,
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	})
	require.NoError(t, err, "failed to create exec for command: %v", cmd)

	err = dc.client.StartExec(exec.ID, docker.StartExecOptions{
		OutputStream: &stdout,
		RawTerminal:  false,
	})
	require.NoError(t, err, "failed to start exec for command: %v", cmd)

	return stdout.String()
}

// WaitForNodeReadiness checks the container's readiness by monitoring its logs.
func (dc *DatabaseContainer) WaitForNodeReadiness(t *testing.T, requiredOutput string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		output := dc.GetContainerLogs(t)
		require.Contains(ct, output, requiredOutput)
	}, 90*time.Second, 250*time.Millisecond, "Node %s readiness check failed", dc.Name)
}

func (dc *DatabaseContainer) enforceSSLForPostgres(t *testing.T) {
	t.Helper()
	dc.WaitForNodeReadiness(t, "database system is ready to accept connections")
	dc.ExecuteCommand(t, enforcePostgresSSLScript)
	dc.ExecuteCommand(t, reloadPostgresConfigScript)
}

func stopContainerByIP(t *testing.T, targetIP string) {
	t.Helper()
	client := GetDockerClient(t)
	containers, err := client.ListContainers(docker.ListContainersOptions{})
	require.NoError(t, err)

	for _, container := range containers {
		info, err := client.InspectContainerWithOptions(docker.InspectContainerOptions{
			ID: container.ID,
		})
		if err != nil {
			t.Logf("Failed to inspect container %s: %v", container.ID, err)
			continue
		}

		for netName, netSettings := range info.NetworkSettings.Networks {
			if netSettings.IPAddress == targetIP {
				t.Logf("Stopping container %s on network %s with ip %s",
					info.Name, netName, targetIP)
				cont := DatabaseContainer{containerID: info.ID, client: GetDockerClient(t)}
				cont.StopAndRemoveContainer(t)
			}
		}
	}
	t.Logf("no container found with the requested ip: %v", targetIP)
}

// CreateDockerNetwork creates a network if it doesn't exist.
func CreateDockerNetwork(t *testing.T, name string) {
	t.Helper()
	client := GetDockerClient(t)
	_, err := client.NetworkInfo(name)
	if err == nil {
		t.Logf("network '%s' already exists", name)
		return
	}

	opts := docker.CreateNetworkOptions{
		Name:   name,
		Driver: "bridge",
		IPAM: &docker.IPAMOptions{
			Config: []docker.IPAMConfig{
				{Subnet: defaultSubnet, Gateway: defaultGateway},
			},
		},
	}
	_, err = client.CreateNetwork(opts)
	require.NoError(t, err, "failed to create network '%s'", name)

	t.Logf("Docker network %s created", name)
}

// RemoveDockerNetwork removes a Docker network by name.
func RemoveDockerNetwork(t *testing.T, name string) {
	t.Helper()
	client := GetDockerClient(t)
	network, err := client.NetworkInfo(name)
	require.NoError(t, err, "failed to inspect network %s", name)

	err = client.RemoveNetwork(network.ID)
	require.NoError(t, err, "failed to remove network %s", name)

	t.Logf("network %s removed successfully", name)
}

// GetDockerClient instantiate a new docker client.
func GetDockerClient(t *testing.T) *docker.Client {
	t.Helper()
	client, err := docker.NewClientFromEnv()
	require.NoError(t, err)
	return client
}
