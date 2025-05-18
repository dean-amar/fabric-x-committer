/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

type portAllocator struct {
	listeners []net.Listener
}

// allocatePorts finds a range of available ports.
func (p *portAllocator) allocatePorts(t *testing.T, count int) []config.ServiceEndpoints {
	t.Helper()
	endpoints := make([]config.ServiceEndpoints, count)
	for i := range endpoints {
		endpoints[i].Server = p.allocate(t)
		endpoints[i].Metrics = p.allocate(t)
	}
	return endpoints
}

func (p *portAllocator) allocate(t *testing.T) *connection.Endpoint {
	t.Helper()
	s := connection.NewLocalHostServer()
	listener, err := s.Listener()
	require.NoError(t, err)
	p.listeners = append(p.listeners, listener)
	return &s.Endpoint
}

// close releases the ports to be used for their intended purpose.
func (p *portAllocator) close() {
	connection.CloseConnectionsLog(p.listeners...)
	p.listeners = nil
}
