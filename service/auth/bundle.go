/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/yugabyte/pgx/v5"
	"github.com/yugabyte/pgx/v5/pgxpool"

	"github.com/hyperledger/fabric-x-committer/utils/monitoring/promutil"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

// ErrConfigUnavailable is returned when no channel-configuration bundle has been loaded yet, so the
// service cannot authenticate or authorize. This is expected during bootstrap, before the first
// configuration block has been committed and observed.
var ErrConfigUnavailable = errors.New("channel configuration not available")

// sqlSelectConfig reads the committed configuration transaction from the config system namespace,
// exactly as the query service does.
var sqlSelectConfig = fmt.Sprintf(
	"SELECT value, version FROM %s WHERE key = $1", statedb.TableName(committerpb.ConfigNamespaceID),
)

// configProvider reads the latest committed channel configuration from the state database and
// exposes it as a channelconfig.Bundle. The auth service does not own or mutate configuration; it
// only reads what the sidecar and coordinator have committed, mirroring how the query service reads
// the config transaction to refresh its TLS roots. The current bundle is swapped atomically; the
// last-seen version and warm-up flag are touched only by the single refresh goroutine.
type configProvider struct {
	pool    *pgxpool.Pool
	metrics *perfMetrics

	bundle      atomic.Pointer[channelconfig.Bundle]
	lastVersion uint64
	seen        bool
}

func newConfigProvider(pool *pgxpool.Pool, metrics *perfMetrics) *configProvider {
	return &configProvider{pool: pool, metrics: metrics}
}

// run reads the latest configuration immediately, then re-reads it every interval until the context
// is done. It runs as a standalone goroutine (not in an errgroup) so a transient database error does
// not stop the service; the service simply keeps serving Unavailable until a bundle is available.
func (p *configProvider) run(ctx context.Context, interval time.Duration) {
	if err := p.refresh(ctx); err != nil {
		logger.Warnf("Initial channel-configuration load failed (will retry): %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.refresh(ctx); err != nil {
				logger.Errorf("Channel-configuration refresh failed: %v", err)
			}
		}
	}
}

// refresh reads the committed configuration and, only when its version has advanced, rebuilds and
// atomically installs a new bundle. The version guard uses a strict "not newer" test so a stale read
// can never roll the configuration - and thus the ACL policy set - backward.
func (p *configProvider) refresh(ctx context.Context) error {
	configTX, err := readConfigTransaction(ctx, p.pool)
	if err != nil {
		return err
	}
	if len(configTX.GetEnvelope()) == 0 {
		return nil // No configuration committed yet.
	}
	if p.seen && configTX.GetVersion() <= p.lastVersion {
		return nil // Not newer than what we already hold.
	}

	bundle, err := buildBundle(configTX.GetEnvelope())
	if err != nil {
		return err
	}

	sequence := bundle.ConfigtxValidator().Sequence()
	p.bundle.Store(bundle)
	p.lastVersion = configTX.GetVersion()
	p.seen = true
	//nolint:gosec // G115: a channel configuration sequence never approaches int overflow.
	promutil.SetGauge(p.metrics.configSequence, int(sequence))
	logger.Infof("Loaded channel configuration version %d (sequence %d)", configTX.GetVersion(), sequence)
	return nil
}

// current returns the latest loaded bundle, or ErrConfigUnavailable if none has been loaded yet.
func (p *configProvider) current() (*channelconfig.Bundle, error) {
	bundle := p.bundle.Load()
	if bundle == nil {
		return nil, ErrConfigUnavailable
	}
	return bundle, nil
}

// readConfigTransaction reads the committed configuration transaction from the config namespace. It
// returns an empty transaction (nil envelope) when no configuration has been committed yet.
func readConfigTransaction(ctx context.Context, pool *pgxpool.Pool) (*applicationpb.ConfigTransaction, error) {
	tx := &applicationpb.ConfigTransaction{}
	err := pool.QueryRow(ctx, sqlSelectConfig, []byte(committerpb.ConfigKey)).Scan(&tx.Envelope, &tx.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to read config transaction")
	}
	return tx, nil
}

// buildBundle constructs a channel-configuration bundle from a marshaled configuration envelope.
func buildBundle(envelopeBytes []byte) (*channelconfig.Bundle, error) {
	envelope, err := protoutil.UnmarshalEnvelope(envelopeBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal config envelope")
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		return nil, errors.Wrap(err, "failed to build channel configuration bundle")
	}
	return bundle, nil
}
