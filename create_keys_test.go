package main

import (
	"fmt"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection/tlsgen"
	"os"
	"path/filepath"
	"testing"
)

// saveFiles saves the content of a map to files.
// The key becomes the filename, and the value is the file content.
func saveFiles(dir string, files map[string][]byte) error {
	// Ensure the directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			return fmt.Errorf("failed to write file %s: %w", name, err)
		}
	}

	return nil
}

func TestCreation(t *testing.T) {
	manager := tlsgen.NewSecureCommunicationManager(t)
	data := manager.CreateServerDATA(t, "database")
	//files := map[string][]byte{
	//	"ca-cert.cert":     []byte("-----BEGIN CERTIFICATE-----\n...CA..."),
	//	"server-cert.cert": []byte("-----BEGIN CERTIFICATE-----\n...Server..."),
	//	"server-key.cert":  []byte("-----BEGIN PRIVATE KEY-----\n...Key..."),
	//}

	err := saveFiles("tmp/generated-certs", data)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Files saved successfully.")
	}
}
