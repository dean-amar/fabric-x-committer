package runner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc/dbtest"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

// DBClusterController is a class that facilitates the manipulation of a DB cluster,
// with its nodes running in Docker containers.
//
// To create the cluster, we are using Yugabyte's preconfigured tool, which is set up as follows:
// 1. If the cluster size is greater than or equal to 3,
// the replication factor (RF) is set to 3; otherwise, RF is set to 1.
// 2. The cluster supports a maximum of 3 master nodes.
// Therefore, a cluster with more than 3 master nodes cannot be created.
// Any additional node will act as a tserver node.
//
// In addition, RF=3 supports the failure of one master node, while RF=1 does not provide resilience to node failures.
// There are some bugs in YugaDB that prevent the cluster behavior from functioning as expected:
// 1. After a master-node is deleted, a new master-node cannot be added to the cluster as a replacement.
// 2. If the leader node is failing, the whole db connectivity will stop functioning.
type DBClusterController struct {
	nodes []*dbtest.DatabaseContainer
	lock  sync.RWMutex
}

// StartYugaCluster creates a Yugabyte cluster in a Docker environment and returns the first node connection properties.
func StartYugaCluster(ctx context.Context, t *testing.T, clusterSize uint) (*DBClusterController, *dbtest.Connection) {
	t.Helper()
	cluster := &DBClusterController{}

	t.Logf("starting yuga cluster of size: %d", clusterSize)
	for range clusterSize {
		cluster.AddNode(ctx, t)
	}

	t.Cleanup(func() {
		cluster.stopAndRemoveYugaCluster(t)
	})

	return cluster, cluster.GetNodesConnections(ctx, t)
}

// AddNode creates, starts and add a YugabyteDB node to the cluster.
func (cc *DBClusterController) AddNode(ctx context.Context, t *testing.T) *dbtest.DatabaseContainer {
	t.Helper()
	cc.lock.Lock()
	defer cc.lock.Unlock()

	node := cc.createNode(ctx, t)
	cc.nodes = append(cc.nodes, node)

	node.StartContainer(ctx, t)
	cc.waitForNodeReadiness(t, node)

	return node
}

// waitForNodeReadiness checks the container's readiness by monitoring its logs.
func (*DBClusterController) waitForNodeReadiness(t *testing.T, node *dbtest.DatabaseContainer) {
	t.Helper()
	require.Eventually(
		t,
		func() bool {
			output := node.GetContainerLogs(t)
			return strings.Contains(output, "Data placement constraint successfully verified")
		},
		90*time.Second,
		250*time.Millisecond,
		"Node %s readiness check failed", node.Name,
	)
}

// RemoveLastNode stop and remove the last yugaDB node created, but not the first.
func (cc *DBClusterController) RemoveLastNode(t *testing.T) {
	t.Helper()
	cc.lock.Lock()
	defer cc.lock.Unlock()
	clusterSize := len(cc.nodes)
	switch clusterSize {
	case 0:
		t.Logf("no nodes to remove.")

	case 1:
		t.Logf("only one node is alive. no follower nodes to remove.")

	default:
		cc.nodes[clusterSize-1].StopAndRemoveContainer(t)
		cc.nodes = cc.nodes[:clusterSize-1]
	}
}

// GetClusterSize returns the amount of active nodes in the cluster.
func (cc *DBClusterController) GetClusterSize() int {
	cc.lock.RLock()
	defer cc.lock.RUnlock()
	return len(cc.nodes)
}

// GetNodesConnections return a slice with all the cluster nodes connections.
func (cc *DBClusterController) GetNodesConnections(ctx context.Context, t *testing.T) *dbtest.Connection {
	t.Helper()
	cc.lock.RLock()
	defer cc.lock.RUnlock()

	if len(cc.nodes) == 0 {
		return nil
	}

	endpoints := make([]*connection.Endpoint, len(cc.nodes))
	for i, node := range cc.nodes {
		endpoints[i] = node.GetContainerConnectionDetails(ctx, t)
	}

	return dbtest.NewConnection(endpoints...)
}

// createNode initializes a new node with appropriate configuration.
func (cc *DBClusterController) createNode(ctx context.Context, t *testing.T) *dbtest.DatabaseContainer {
	t.Helper()
	node := &dbtest.DatabaseContainer{
		Name:         fmt.Sprintf("yuga-%s", uuid.New()),
		DatabaseType: dbtest.YugaDBType,
		Cmd:          dbtest.YugabyteCMD,
	}

	if len(cc.nodes) != 0 {
		node.Cmd = append(node.Cmd, fmt.Sprintf("--join=%s", cc.getFirstNodeHost(ctx, t)))
	}

	return node
}

func (cc *DBClusterController) stopAndRemoveYugaCluster(t *testing.T) {
	t.Helper()
	cc.lock.Lock()
	defer cc.lock.Unlock()

	for _, node := range cc.nodes {
		t.Logf("stopping and removing node: %v", node.Name)
		node.StopAndRemoveContainer(t)
	}
	cc.nodes = nil
}

func (cc *DBClusterController) getFirstNodeHost(ctx context.Context, t *testing.T) string {
	t.Helper()
	require.NotEmpty(t, cc.nodes)
	nodeEndpoint := cc.nodes[0].GetContainerConnectionDetails(ctx, t)
	return nodeEndpoint.GetHost()
}
