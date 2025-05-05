package loadgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/adapters"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/metrics"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
)

const defaultBlockSize = 500

func eventuallyMetrics(
	t *testing.T,
	m *metrics.PerfMetrics,
	condition func(m metrics.MetricState) bool,
) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		return condition(m.GetState())
	}, 10*time.Minute, 5*time.Second) {
		t.Fatalf("Metrics target was not achieved: %+v", m.GetState())
	}
}

// DefaultClientConf returns default config values for client testing.
func DefaultClientConf() *ClientConfig {
	return &ClientConfig{
		LoadProfile: &workload.Profile{
			Key:   workload.KeyProfile{Size: 32},
			Block: workload.BlockProfile{Size: defaultBlockSize},
			Transaction: workload.TransactionProfile{
				ReadWriteCount: workload.NewConstantDistribution(2),
				Policy: &workload.PolicyProfile{
					NamespacePolicies: map[string]*workload.Policy{
						workload.GeneratedNamespaceID: {
							Scheme: signature.Ecdsa,
							Seed:   10,
						},
						types.MetaNamespaceID: {
							Scheme: signature.Ecdsa,
							Seed:   11,
						},
					},
				},
			},
			Seed: 12345,
			// We use small number of workers to reduce the CPU load during tests.
			Workers: 1,
		},
		Stream: &workload.StreamOptions{
			RateLimit: &workload.LimiterConfig{InitialLimit: 1_000},
			// We set low values for the buffer and batch to reduce the CPU load during tests.
			BuffersSize: 1,
			GenBatch:    1,
		},
		Generate: adapters.Phases{
			Config:     true,
			Namespaces: true,
			Load:       true,
		},
		Monitoring: metrics.Config{
			Config: defaultMonitoring(),
		},
	}
}

func defaultMonitoring() monitoring.Config {
	return monitoring.Config{
		Server: connection.NewLocalHostServer(),
	}
}
