package broadcastdeliver

import (
	"context"
	"crypto/tls"
	"iter"
	"maps"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

var logger = logging.New("broadcast-deliver")

type (
	// OrdererConnectionManager packs all the orderer connections.
	// Its connections can be updated via the Update() method.
	// This will increase the config version, allowing a OrdererConnectionResiliencyManager instance to identify
	// a connection update and fetch the new connections.
	OrdererConnectionManager struct {
		configVersion atomic.Uint64
		connections   []*OrdererConnection
		tlsConfig     *tls.Config
		retry         *connection.RetryProfile
		lock          sync.Mutex
	}
	// OrdererConnectionResiliencyManager packs a subset of the connections according to the given filter.
	// It supports resiliency by fetching the next connection to attempt.
	OrdererConnectionResiliencyManager struct {
		configVersion uint64
		connections   []*OrdererConnection
	}
	// OrdererConnection holds the connection information.
	OrdererConnection struct {
		*connection.OrdererEndpoint
		*grpc.ClientConn

		// These allow monitoring the connection's errors and backoff.
		expBackoff            *backoff.ExponentialBackOff
		nextConnectionAttempt time.Time
		stopped               bool

		// LastError is used to monitor connection errors.
		// The user should update this accordingly to inform the module
		// of issues with this connection.
		LastError error
	}

	// FilterFunc returns true to include a connection.
	FilterFunc func(*OrdererConnection) bool
)

// Errors that may be returned when trying to get the next connection.
var (
	ErrNoConnections      = errors.New("no connection found")
	ErrNoAliveConnections = errors.New("no alive connection is available")
)

// WithAPI filters for API.
func WithAPI(api string) FilterFunc {
	return func(conn *OrdererConnection) bool {
		return conn.SupportsAPI(api)
	}
}

// WithID filters for ID.
func WithID(id uint32) FilterFunc {
	return func(conn *OrdererConnection) bool {
		return conn.ID == id
	}
}

// Update updates the connection configs.
// This will close all obsolete connections, making the child packages reload.
// However, if a connection is still valid, the children connection will not be interrupted.
func (c *OrdererConnectionManager) Update(config *ConnectionConfig) error {
	if err := validateConnectionConfig(config); err != nil {
		return err
	}

	// We open all connections first, and later we might close some of them if we can reuse existing ones.
	newTLSConfig, newConnections, err := openConnections(config)
	if err != nil {
		return errors.Wrap(err, "failed to open connections")
	}

	// We lock once we read internal members.
	c.lock.Lock()
	defer c.lock.Unlock()

	// We increase the version early (before closing any connections, but after locking)
	// to ensure the recovery stage knows about an update.
	c.configVersion.Add(1)

	var connectionsToClose []*OrdererConnection
	reusedConnections := make([]bool, len(c.connections))
	if IsTLSConfigEqual(newTLSConfig, c.tlsConfig) {
		// If the CA was not updated, we can reuse existing connections that has the exact same endpoint.
		// This allows seamless operation for connections that were not changed.
		for i, newConn := range newConnections {
			if existingIndex := slices.IndexFunc(c.connections, newConn.EqualEndpoints); existingIndex >= 0 {
				connectionsToClose = append(connectionsToClose, newConn)
				newConnections[i] = c.connections[existingIndex]
				reusedConnections[existingIndex] = true
			}
		}
		for i, reuse := range reusedConnections {
			if !reuse {
				connectionsToClose = append(connectionsToClose, c.connections[i])
			}
		}
	} else {
		// If the CA was updated, then all the connections are obsolete.
		connectionsToClose = c.connections
	}

	connection.CloseConnectionsLog(connectionsToClose...)

	c.connections = newConnections
	c.tlsConfig = newTLSConfig
	c.retry = config.Retry
	return nil
}

func openConnections(config *ConnectionConfig) (*tls.Config, []*OrdererConnection, error) {
	tlsConfig, err := LoadTLSConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load TLS config")
	}
	var tlsCredentials credentials.TransportCredentials
	if tlsConfig != nil {
		tlsCredentials = credentials.NewTLS(tlsConfig)
	} else {
		tlsCredentials = insecure.NewCredentials()
	}

	grpcConnections, err := connection.OpenConnections(config.Endpoints, tlsCredentials)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open connections")
	}
	connections := make([]*OrdererConnection, len(grpcConnections))
	for i, conn := range grpcConnections {
		connections[i] = &OrdererConnection{
			ClientConn:      conn,
			OrdererEndpoint: config.Endpoints[i],
		}
	}
	return tlsConfig, connections, nil
}

// Close closes all the connections.
func (c *OrdererConnectionManager) Close() {
	c.lock.Lock()
	defer c.lock.Unlock()
	connection.CloseConnectionsLog(c.connections...)
}

// GetResiliencyManager instantiate a OrdererConnectionResiliencyManager with a given filter.
func (c *OrdererConnectionManager) GetResiliencyManager(filter ...FilterFunc) *OrdererConnectionResiliencyManager {
	c.lock.Lock()
	defer c.lock.Unlock()
	connections := make([]*OrdererConnection, len(c.connections))
	for i, conn := range c.connections {
		connections[i] = &OrdererConnection{
			OrdererEndpoint: conn.OrdererEndpoint,
			ClientConn:      conn.ClientConn,
			expBackoff:      c.retry.NewBackoff(),
		}
	}
	// We shuffle the nodes for load balancing.
	shuffle(connections)
	rm := &OrdererConnectionResiliencyManager{
		connections:   connections,
		configVersion: c.configVersion.Load(),
	}
	return rm.Filter(filter...)
}

// IsStale checks if the given OrdererConnectionResiliencyManager is stale.
// If nil is given, it returns true.
func (c *OrdererConnectionManager) IsStale(child *OrdererConnectionResiliencyManager) bool {
	return child == nil || c.configVersion.Load() != child.configVersion
}

// Filter returns a new instance with filtered connections.
func (c *OrdererConnectionResiliencyManager) Filter(filter ...FilterFunc) *OrdererConnectionResiliencyManager {
	connections := make([]*OrdererConnection, 0, len(c.connections))
	for _, conn := range c.connections {
		if allFilters(conn, filter) {
			connections = append(connections, conn)
		}
	}
	return &OrdererConnectionResiliencyManager{
		connections:   connections,
		configVersion: c.configVersion,
	}
}

// allFilters returns true if all given filters returns true for the given connection.
func allFilters(conn *OrdererConnection, filter []FilterFunc) bool {
	for _, f := range filter {
		if !f(conn) {
			return false
		}
	}
	return true
}

// IDs iterates over the connections' IDs.
func (c *OrdererConnectionResiliencyManager) IDs() iter.Seq[uint32] {
	ids := make(map[uint32]any)
	for _, conn := range c.connections {
		ids[conn.ID] = nil
	}
	return maps.Keys(ids)
}

// GetNextConnection returns the next connection for a new attempt.
// It checks if the previous attempt failed (LastError != nil), and extend its backoff.
func (c *OrdererConnectionResiliencyManager) GetNextConnection(ctx context.Context) (*OrdererConnection, error) {
	if len(c.connections) == 0 {
		return nil, ErrNoConnections
	}

	curNode := c.connections[0]
	if curNode.LastError != nil {
		curNode.backoff()
		sortConnections(c.connections)
		curNode = c.connections[0]
	}

	if curNode.stopped {
		// We exhausted all the connections.
		// We return the joint errors of all the connections.
		errs := make([]error, len(c.connections)+1)
		errs[0] = ErrNoAliveConnections
		for i, conn := range c.connections {
			errs[i+1] = errors.Wrapf(conn.LastError, "failed connection: %s", conn.String())
		}
		return nil, errors.Join(errs...)
	}

	waitDuration := time.Until(curNode.nextConnectionAttempt)
	if waitDuration > 0 {
		select {
		case <-ctx.Done():
			return nil, errors.Wrap(ctx.Err(), "context ended")
		case <-time.After(waitDuration):
		}
	}
	return curNode, nil
}

// ResetBackoff resets the backoff values for all connections.
func (c *OrdererConnectionResiliencyManager) ResetBackoff() {
	for _, conn := range c.connections {
		conn.ResetBackoff()
	}
}

func shuffle[T any](nodes []T) {
	rand.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
}

func sortConnections(nodes []*OrdererConnection) {
	slices.SortStableFunc(nodes, func(e1, e2 *OrdererConnection) int {
		if e1.stopped == e2.stopped {
			return e1.nextConnectionAttempt.Compare(e2.nextConnectionAttempt)
		}
		if e1.stopped {
			return 1
		}
		return -1
	})
}

// EqualEndpoints returns true if the connections' endpoints are identical.
func (e *OrdererConnection) EqualEndpoints(e2 *OrdererConnection) bool {
	if e == nil || e.OrdererEndpoint == nil || e2 == nil || e2.OrdererEndpoint == nil {
		return false
	}
	//nolint: staticcheck // could remove embedded field "OrdererEndpoint" from selector, but here explicit call helps.
	return e.OrdererEndpoint.String() == e2.OrdererEndpoint.String()
}

// ResetBackoff resets the connection's backoff.
func (e *OrdererConnection) ResetBackoff() {
	e.expBackoff.Reset()
	e.stopped = false
	e.nextConnectionAttempt = time.Time{}
	e.LastError = nil
}

func (e *OrdererConnection) backoff() {
	backoffTime := e.expBackoff.NextBackOff()
	if backoffTime == e.expBackoff.Stop {
		backoffTime = e.expBackoff.MaxInterval
		e.stopped = true
	}
	e.nextConnectionAttempt = time.Now().Add(backoffTime)
}
