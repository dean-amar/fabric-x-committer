/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"

	"github.com/hyperledger/fabric-x-common/common/channelconfig"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// ACLProvider holds the dynamically updatable channel-configuration state that the gRPC
	// server reads on each connection: the TLS client-CA pool (for mutual TLS) and the channel
	// configuration bundle (for ACL enforcement). Both derive from the same configuration
	// blocks and are refreshed together via the ACLUpdater.
	//
	// The design separates writers (services) from readers (server), ensuring a linear dependency flow:
	//
	//	Service -> ACLUpdater <- ACLProvider <- Server
	ACLProvider struct {
		serverConfig        *tls.Config
		clientConfig        *tls.Config
		clientConfigVersion uint64
		staticCertPool      *x509.CertPool
		updater             *ACLUpdater
		mu                  sync.Mutex
	}

	// ACLUpdater is the write side of an ACLProvider. A service pushes the latest TLS client-CA
	// certificates and channel-configuration bundle here as new configuration blocks arrive.
	// requiresACL marks whether the owning service enforces ACL (sidecar, query) or only needs
	// dynamic TLS CA refresh (orderer).
	ACLUpdater struct {
		certs              atomic.Pointer[[][]byte]
		certsUpdateVersion atomic.Uint64
		bundle             atomic.Pointer[channelconfig.Bundle]
		requiresACL        bool
	}
)

// RegisterACLUpdater registers an ACLUpdater with an ACLProvider.
// It uses a signature similar to gRPC server registration to allow common
// language for all server<->service interfaces.
// The requiresACL parameter indicates whether this service requires ACL enforcement.
// Services that need ACL enforcement (sidecar, query) should set this to true.
// Services that only need dynamic TLS CAs (orderer) should set this to false.
func RegisterACLUpdater(d *ACLProvider, updater *ACLUpdater, requiresACL bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	updater.requiresACL = requiresACL
	d.updater = updater
}

// NewACLProvider loads TLS credentials from a TLSConfig.
func NewACLProvider(tlsConfig connection.TLSConfig) (*ACLProvider, error) {
	creds, err := connection.NewServerTLSCredentials(tlsConfig)
	if err != nil {
		return nil, err
	}

	d := &ACLProvider{}
	d.clientConfig, err = creds.CreateServerTLSConfig()
	if err != nil {
		return nil, err
	}

	d.serverConfig = d.clientConfig
	if creds.Mode == connection.MutualTLSMode && d.clientConfig != nil {
		d.staticCertPool = d.clientConfig.ClientCAs
		d.serverConfig = &tls.Config{
			// tls.VersionTLS12 is the minimum version required to achieve secure connections.
			MinVersion:         tls.VersionTLS12,
			GetConfigForClient: d.GetConfigForClient,
		}
	}

	return d, nil
}

// GetBundle returns the latest channel-configuration bundle for ACL evaluation.
// It returns auth.ErrNoUpdater when no updater is registered (internal service), or
// auth.ErrNoBundle when a bundle has not been loaded yet (still bootstrapping).
func (d *ACLProvider) GetBundle() (*channelconfig.Bundle, error) {
	if d.updater == nil {
		return nil, auth.ErrNoUpdater
	}
	bundle := d.updater.bundle.Load()
	if bundle == nil {
		return nil, auth.ErrNoBundle
	}
	return bundle, nil
}

// RequiresACL returns whether this service requires ACL enforcement.
func (d *ACLProvider) RequiresACL() bool {
	if d.updater == nil {
		return false
	}
	return d.updater.requiresACL
}

// GetServerTLSCredentials returns the TLS credentials for the server.
func (d *ACLProvider) GetServerTLSCredentials() *tls.Config {
	return d.serverConfig
}

// GetConfigForClient returns the current TLS config for a new client connection.
// This is a single atomic pointer load with no allocations, making it safe and
// efficient to call on every TLS handshake.
func (d *ACLProvider) GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.updateNoLock()
	return d.clientConfig, nil
}

func (d *ACLProvider) updateNoLock() bool {
	if d.updater == nil || d.clientConfig == nil || d.staticCertPool == nil {
		return false
	}

	// Loading the version before the certs ensures the loaded certificates are of version equal or higher
	// than the loaded version.
	// If the version is higher, we may update again on the next handshake.
	version := d.updater.certsUpdateVersion.Load()
	if version <= d.clientConfigVersion {
		return false
	}

	mergedPool := d.staticCertPool.Clone()
	// We ignore failed certificates here, and process the rest.
	// This ensures we allow partial updates to succeed even if some certs are invalid.
	// Otherwise, a single bad certificate could block access to the system to new clients,
	// or allow access to invalid clients.
	connection.ExtendCertPool(mergedPool, d.updater.Load()...)
	newConfig := d.clientConfig.Clone()
	newConfig.ClientCAs = mergedPool
	d.clientConfig = newConfig
	d.clientConfigVersion = version
	return true
}

// UpdateClientRootCAs updates the client root CAs with the given certificates.
func (d *ACLUpdater) UpdateClientRootCAs(certs [][]byte) {
	d.certs.Store(&certs)
	d.certsUpdateVersion.Add(1)
}

// UpdateBundle stores the latest channel-configuration bundle for ACL evaluation.
func (d *ACLUpdater) UpdateBundle(bund *channelconfig.Bundle) {
	d.bundle.Store(bund)
}

// Load loads the dynamic certificates.
func (d *ACLUpdater) Load() [][]byte {
	certs := d.certs.Load()
	if certs == nil {
		return nil
	}
	return *certs
}
