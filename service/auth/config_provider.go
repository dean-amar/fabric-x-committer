/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/Chaguar/common/api/applicationpb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/utils/retry"
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/jackc/puddle/v2"

	"github.com/Chaguar/committer/utils/monitoring/promutil"
	"github.com/Chaguar/committer/utils/statedb"
)

// errConfigUnavailable is returned before any channel-configuration bundle has loaded, so nothing can be
// authenticated or authorized yet. Expected during bootstrap, before the first config block commits.
var errConfigUnavailable = errors.New("channel configuration not available")

// configProvider exposes the latest committed channel configuration as a bundle; it never mutates it. The
// bundle is swapped atomically.
type configProvider struct {
	db      *database
	metrics *perfMetrics

	bundle  atomic.Pointer[channelconfig.Bundle]
	tracker statedb.ConfigVersionTracker
}

// run reads the configuration now, then every interval.
func (p *configProvider) run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := p.refresh(ctx); err != nil {
			logger.Errorf("Channel-configuration refresh failed: %+v", err)
		} else {
			promutil.SetGauge(p.metrics.configLastRefresh, int(time.Now().Unix()))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// refresh installs a new bundle only when the committed configuration's version has advanced.
func (p *configProvider) refresh(ctx context.Context) error {
	configTX, err := retry.ExecuteWithResult(ctx, p.db.retry, func() (*applicationpb.ConfigTransaction, error) {
		return p.tracker.ReadIfNewer(ctx, p.db.pool)
	}, puddle.ErrClosedPool)
	if err != nil || configTX == nil {
		return err
	}

	envelope, err := protoutil.UnmarshalEnvelope(configTX.GetEnvelope())
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal config envelope")
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		return errors.Wrap(err, "failed to build channel configuration bundle")
	}

	sequence := bundle.ConfigtxValidator().Sequence()
	p.bundle.Store(bundle)
	p.tracker.Accept(configTX)
	logger.Infof("Loaded channel configuration version %d (sequence %d)", configTX.GetVersion(), sequence)
	return nil
}

// current returns the latest loaded bundle, or errConfigUnavailable if none has been loaded yet.
func (p *configProvider) current() (*channelconfig.Bundle, error) {
	bundle := p.bundle.Load()
	if bundle == nil {
		return nil, errConfigUnavailable
	}
	return bundle, nil
}
