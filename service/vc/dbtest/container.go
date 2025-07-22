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

	"github.com/cockroachdb/errors"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/tlsgen"
)

const (
	defaultYugabyteImage            = "yugabytedb/yugabyte:2.20.7.0-b58"
	defaultPostgresImage            = "postgres:16.9-alpine3.21"
	defaultDBDeploymentTemplateName = "sc_%s_unit_tests"

	defaultHostIP  = "127.0.0.1"
	defaultPortMap = "7000/tcp"

	// container's Memory and CPU management.
	gb         = 1 << 30 // gb is the number of bytes needed to represent 1 GB.
	memorySwap = -1      // memorySwap disable memory swaps (don't store data on disk)

	// ContainerPathForYugabytePassword holds the path to the database credentials.
	// This work-around is needed due to a Yugabyte bug that prevents using default passwords in secure mode.
	// Instead, Yugabyte generates a random password, and this path points to the output file containing it.
	ContainerPathForYugabytePassword = "/root/var/data/yugabyted_credentials.txt" //nolint:gosec

	defaultSubnet                 = "172.28.0.0/16"
	defaultGateway                = "172.28.0.1"
	defaultYugabyteTLSContainerIP = "172.28.0.100"
	defaultNetworkName            = "yugabyte_with_tls_network"

	defaultPostgresServerName = "database"

	// YugabyteReadinessOutput is the output indicating that a Yugabyte node is ready.
	YugabyteReadinessOutput = "Data placement constraint successfully verified"
	// PostgresReadinessOutput is the output indicating that a Postgres node is ready.
	PostgresReadinessOutput = "database system is ready to accept connections"
)

var (
	// YugabyteCMD starts yugabyte without SSL and fault tolerance (single server).
	YugabyteCMD = []string{
		"bin/yugabyted", "start",
		"--callhome", "false",
		"--background", "false",
		"--ui", "false",
		"--tserver_flags",
		"ysql_max_connections=500," +
			"tablet_replicas_per_gib_limit=4000," +
			"yb_num_shards_per_tserver=1," +
			"minloglevel=3," +
			"yb_enable_read_committed_isolation=true",
		"--insecure",
	}

	// This script enforces SSL-only client connections to a PostgreSQL instance by updating pg_hba.conf.
	enforcePostgresSSLScript = []string{
		"sh", "-c",
		`sed -i 's/^host all all all scram-sha-256$/hostssl all all 0.0.0.0\/0 scram-sha-256/' ` +
			`/var/lib/postgresql/data/pg_hba.conf`,
	}

	// This script reloads the PostgreSQL server configuration without restarting the instance.
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
	Creds        containerCreds
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
	var containerAlreadyRunning *docker.ContainerAlreadyRunning
	if errors.As(err, &containerAlreadyRunning) {
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

	// Apply TLS configuration and credential binding if enabled.
	// This is done after all other defaults are set up.
	dc.setTLSPropertiesForDatabase(t)
}

func (dc *DatabaseContainer) setTLSPropertiesForDatabase(t *testing.T) {
	t.Helper()
	if !dc.UseTLS {
		return
	}

	tlsManager := tlsgen.NewSecureCommunicationManager(t)

	var (
		credsPathDir, serverName string
		paths                    map[string]string
	)

	switch dc.DatabaseType {
	case PostgresDBType:
		serverName = defaultPostgresServerName
		credsPathDir, paths = dc.configurePostgresTLS(t, tlsManager)
	case YugaDBType:
		serverName = defaultYugabyteTLSContainerIP
		credsPathDir, paths = dc.configureYugabyteTLS(t, tlsManager)

	default:
		t.Fatalf("Unsupported database type: %s", dc.DatabaseType)
	}

	dc.Creds = containerCreds{
		CredsPath:  credsPathDir,
		CACertPath: paths[tlsgen.KeyCACert],
		ServerName: serverName,
	}
	dc.Binds = append(dc.Binds, credsPathDir+":/creds")
	dc.Name += fmt.Sprintf("_with_tls_%s", uuid.New())
}

func (dc *DatabaseContainer) configurePostgresTLS(
	t *testing.T,
	tlsManager *tlsgen.SecureCommunicationManager,
) (string, map[string]string) {
	t.Helper()

	dc.Cmd = []string{
		"-c", "ssl=on",
		"-c", "ssl_cert_file=/creds/server.crt",
		"-c", "ssl_key_file=/creds/server.key",
	}

	return tlsManager.CreateServerCreds(t, defaultPostgresServerName, tlsgen.CertStylePostgres)
}

func (dc *DatabaseContainer) configureYugabyteTLS(
	t *testing.T,
	tlsManager *tlsgen.SecureCommunicationManager,
) (string, map[string]string) {
	t.Helper()
	dc.Network = CreateDockerNetwork(t, defaultNetworkName, defaultSubnet, defaultGateway).Name
	t.Cleanup(func() {
		RemoveDockerNetwork(t, defaultNetworkName)
	})

	stopContainerByIP(t, defaultYugabyteTLSContainerIP)

	dc.Cmd = append(
		utils.ReplacePattern(dc.Cmd, func(s string) bool { return s == "--insecure" }, "--secure"),
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

	return tlsManager.CreateServerCreds(t, defaultYugabyteTLSContainerIP, tlsgen.CertStyleYugabyte)
}

// createContainer attempts to create a container instance, or attach to an existing one.
func (dc *DatabaseContainer) createContainer(ctx context.Context, t *testing.T) {
	t.Helper()
	// If container exists, we don't have to create it.
	err := dc.findContainer(t)
	if err == nil {
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
				Memory:       4 * gb,
				MemorySwap:   memorySwap,
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
	require.NoError(t, dc.findContainer(t))
}

// findContainer looks up a container with the same name.
func (dc *DatabaseContainer) findContainer(t *testing.T) error {
	t.Helper()
	allContainers, err := dc.client.ListContainers(docker.ListContainersOptions{All: true})
	require.NoError(t, err, "could not load containers.")

	names := make([]string, 0, len(allContainers))
	for _, c := range allContainers {
		for _, n := range c.Names {
			names = append(names, n)
			if n == dc.Name || n == fmt.Sprintf("/%s", dc.Name) {
				dc.containerID = c.ID
				return nil
			}
		}
	}
	return errors.Errorf("cannot find container '%s'. Containers: %v", dc.Name, names)
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
	dc.StopContainer(t)
	require.NoError(t, dc.client.RemoveContainer(docker.RemoveContainerOptions{
		ID:    dc.ContainerID(),
		Force: true,
	}))
	t.Logf("Container %s stopped and removed successfully", dc.ContainerID())
}

// StopContainer stops db container.
func (dc *DatabaseContainer) StopContainer(t *testing.T) {
	t.Helper()
	require.NoError(t, dc.client.StopContainer(dc.ContainerID(), 10))
}

// ContainerID returns the container ID.
func (dc *DatabaseContainer) ContainerID() string {
	return dc.containerID
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
	require.NoError(t, err, "failed to create exec for command")

	err = dc.client.StartExec(exec.ID, docker.StartExecOptions{
		OutputStream: &stdout,
	})
	require.NoError(t, err, "failed to start exec for command")

	return stdout.String()
}

// readPasswordFromContainer extracts the randomly generated password from a file inside the container.
// This is required because YugabyteDB, when running in secure mode, doesn't allow default passwords
// and instead generates a random one at startup.
// If no password is found, the default one will be returned.
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

func stopContainerByIP(t *testing.T, targetIP string) {
	t.Helper()
	client := GetDockerClient(t)
	containers, err := client.ListContainers(docker.ListContainersOptions{})
	require.NoError(t, err)

	for _, container := range containers {
		cont, err := client.InspectContainerWithOptions(docker.InspectContainerOptions{
			ID: container.ID,
		})
		require.NoError(t, err)

		for netName, netSettings := range cont.NetworkSettings.Networks {
			if netSettings.IPAddress == targetIP {
				t.Logf("Stopping container %s on network %s with ip %s",
					cont.Name, netName, targetIP)
				contToRemove := DatabaseContainer{containerID: cont.ID, client: GetDockerClient(t)}
				contToRemove.StopAndRemoveContainer(t)
			}
		}
	}
	t.Logf("no container found with the requested ip: %v", targetIP)
}

// CreateDockerNetwork creates a network if it doesn't exist.
func CreateDockerNetwork(t *testing.T, name, subnet, gateway string) *docker.Network {
	t.Helper()
	client := GetDockerClient(t)
	network, err := client.NetworkInfo(name)
	if err == nil {
		t.Logf("network %s already exists", name)
		return network
	}

	network, err = client.CreateNetwork(docker.CreateNetworkOptions{
		Name:   name,
		Driver: "bridge",
		IPAM: &docker.IPAMOptions{
			Config: []docker.IPAMConfig{
				{Subnet: subnet, Gateway: gateway},
			},
		},
	})
	require.NoError(t, err, "failed to create network")

	t.Logf("network %s created", network.Name)
	return network
}

// RemoveDockerNetwork removes a Docker network by name.
func RemoveDockerNetwork(t *testing.T, name string) {
	t.Helper()
	client := GetDockerClient(t)
	network, err := client.NetworkInfo(name)
	require.NoError(t, err)

	err = client.RemoveNetwork(network.ID)
	require.NoError(t, err)

	t.Logf("network %s removed successfully", name)
}

// EnsureNodeReadiness checks the container's readiness by monitoring its logs and ensure its running correctly.
func (dc *DatabaseContainer) EnsureNodeReadiness(t *testing.T, requiredOutput string) error {
	t.Helper()
	var err error
	if ok := assert.Eventually(t, func() bool {
		output := dc.GetContainerLogs(t)
		if !strings.Contains(output, requiredOutput) {
			err = errors.Newf("Node %s readiness check failed", dc.Name)
			return false
		}
		return true
	}, 90*time.Second, 250*time.Millisecond); !ok {
		dc.StopContainer(t)
		return err
	}
	return nil
}

// fixCertificatePermissions fixes the ownership and permissions of SSL certificates inside the container.
func (dc *DatabaseContainer) fixCertificatePermissions(t *testing.T,
	user,
	containerPublicKeyPath,
	containerPrivateKeyPath string,
) {
	t.Helper()

	exec, err := dc.client.CreateExec(docker.CreateExecOptions{
		Container: dc.containerID,
		Cmd:       []string{"chown", user, containerPublicKeyPath, containerPrivateKeyPath},
		User:      "root", // Run as root to change ownership
	})
	require.NoError(t, err)
	require.NoError(t, dc.client.StartExec(exec.ID, docker.StartExecOptions{}))
}

// GetDockerClient instantiate a new docker client.
func GetDockerClient(t *testing.T) *docker.Client {
	t.Helper()
	client, err := docker.NewClientFromEnv()
	require.NoError(t, err)
	return client
}
