package config

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	sprig "github.com/go-task/slim-sprig/v3"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"github.ibm.com/decentralized-trust-research/fabricx-config/internaltools/configtxgen"

	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

type (
	// SystemConfig represents the configuration of the one of the committer's components.
	SystemConfig struct {
		// Tls Options.
		ServiceTLS CommonTLS
		ClientsTls []CommonTLS

		// Instance endpoints.
		ServerEndpoint  *connection.Endpoint
		MetricsEndpoint *connection.Endpoint

		// System's resources.
		Endpoints SystemEndpoints
		DB        DatabaseConfig

		// Per service configurations.
		BlockSize         uint64                  // orderer, loadgen
		BlockTimeout      time.Duration           // orderer
		ConfigBlockPath   string                  // orderer, sidecar, loadgen
		LedgerPath        string                  // sidecar
		ChannelID         string                  // sidecar, loadgen
		Policy            *workload.PolicyProfile // loadgen
		LoadGenBlockLimit uint64                  // loadgen
		LoadGenTXLimit    uint64                  // loadgen
		Logging           *logging.Config         // for all
	}

	CommonTLS struct {
		UseTLS    bool
		MutualTLS bool

		PrivateKeyPath    string
		PublicKeyPath     string
		CACertificatePath string
	}

	// SystemEndpoints represents the endpoints of the system.
	SystemEndpoints struct {
		Database    []*connection.Endpoint
		Verifier    []*connection.Endpoint
		VCService   []*connection.Endpoint
		Orderer     []*connection.Endpoint
		Coordinator *connection.Endpoint
		Sidecar     *connection.Endpoint
		Query       *connection.Endpoint
		LoadGen     *connection.Endpoint
	}

	// DatabaseConfig represents the used DB.
	DatabaseConfig struct {
		Name        string
		LoadBalance bool
	}

	// ConfigBlock represents the configuration of the config block.
	ConfigBlock = workload.ConfigBlock //nolint:revive
)

// Config templates.
var (
	//go:embed templates/coordinator.yaml
	TemplateCoordinator string
	//go:embed templates/mockorderingservice.yaml
	TemplateMockOrderer string
	//go:embed templates/queryexecutor.yaml
	TemplateQueryService string
	//go:embed templates/sidecar.yaml
	TemplateSidecar string
	//go:embed templates/validatorpersister.yaml
	TemplateVC string
	//go:embed templates/signatureverifier.yaml
	TemplateVerifier string
	//go:embed templates/loadgen_orderer.yaml
	TemplateLoadGenOrderer string
	//go:embed templates/loadgen_committer.yaml
	TemplateLoadGenCommitter string
)

// CreateConfigFromTemplate creates a config file using template yaml and writes it to the outputPath.
func CreateConfigFromTemplate(t *testing.T, templateString, outputPath string, conf *SystemConfig) {
	t.Helper()
	tmpl := template.New("").Funcs(sprig.FuncMap())
	tmpl, err := tmpl.Parse(templateString)
	require.NoError(t, err)

	var renderedConfig bytes.Buffer
	require.NoError(t, tmpl.Execute(&renderedConfig, conf))
	err = os.WriteFile(outputPath, renderedConfig.Bytes(), 0o644)
	require.NoError(t, err)
}

// CreateTempConfigFromTemplate creates a temporary config file and returning the temporary output config path.
func CreateTempConfigFromTemplate(t *testing.T, cmdTemplate string, conf *SystemConfig) string {
	t.Helper()
	outputConfigFilePath := path.Join(t.TempDir(), fmt.Sprintf("config-%s.yaml", uuid.NewString()))
	CreateConfigFromTemplate(t, cmdTemplate, outputConfigFilePath, conf)
	return outputConfigFilePath
}

// CreateConfigBlock create and writes a config block to file.
func CreateConfigBlock(t *testing.T, conf *ConfigBlock) string {
	t.Helper()
	block, err := workload.CreateDefaultConfigBlock(conf)
	require.NoError(t, err)
	return WriteConfigBlock(t, block)
}

// WriteConfigBlock writes a config block to file.
func WriteConfigBlock(t *testing.T, block *common.Block) string {
	t.Helper()
	blockDir := t.TempDir()
	configBlockPath := filepath.Join(blockDir, "config.block")
	require.NoError(t, configtxgen.WriteOutputBlock(block, configBlockPath))
	return configBlockPath
}

// WithEndpoint creates a new SystemConfig with a modified ServerEndpoint.
func (c *SystemConfig) WithEndpoint(e *connection.Endpoint) *SystemConfig {
	s := *c
	s.ServerEndpoint = e
	return &s
}

func CreateTlsConfiguration(useTls, mutualTls bool, paths map[string]string) CommonTLS {
	return CommonTLS{
		UseTLS:            useTls,
		MutualTLS:         mutualTls,
		PrivateKeyPath:    paths["PrivateKey"],
		PublicKeyPath:     paths["PublicKey"],
		CACertificatePath: paths["CACertificate"],
	}
}
