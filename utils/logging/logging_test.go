/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		logMsg  string
		logFunc func(logger *Logger, msg string)
	}{
		{
			logMsg:  "info log",
			logFunc: func(l *Logger, msg string) { l.Info(msg) },
		},
		{
			logMsg:  "error log",
			logFunc: func(l *Logger, msg string) { l.Error(msg) },
		},
		{
			logMsg:  "debug log",
			logFunc: func(l *Logger, msg string) { l.Debug(msg) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.logMsg, func(t *testing.T) {
			t.Parallel()
			l, tmpFileName := setupTestLogger(t)
			tc.logFunc(l, tc.logMsg)
			requireContains(t, tmpFileName, tc.logMsg)
		})
	}
}

func setupTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	tmpFileName := filepath.Clean(filepath.Join(t.TempDir(), "log-test.log"))
	l := &Logger{}
	l.updateConfig(&Config{
		Enabled:     true,
		Level:       Debug,
		Output:      tmpFileName,
		Development: true,
		Caller:      false,
	})
	return l, tmpFileName
}

func requireContains(t *testing.T, fileName, contains string) {
	t.Helper()
	logData, err := os.ReadFile(filepath.Clean(fileName))
	require.NoError(t, err)
	require.Contains(t, string(logData), contains)
}
