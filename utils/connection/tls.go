/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	cryptotls "crypto/tls"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/tls"
)

func tlsFromConnectionConfig(connConfig *ClientConfig) (credentials.TransportCredentials, error) {
	var tlsConfig *cryptotls.Config
	var err error
	switch {
	case len(connConfig.RootCA) > 0:
		tlsConfig, err = tls.LoadTLSCredentialsRaw(connConfig.RootCA)
	case len(connConfig.RootCAPaths) > 0:
		tlsConfig, err = tls.LoadTLSCredentials(connConfig.RootCAPaths)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to load TLS config")
	}
	if tlsConfig != nil {
		return credentials.NewTLS(tlsConfig), nil
	}
	return insecure.NewCredentials(), nil
}
