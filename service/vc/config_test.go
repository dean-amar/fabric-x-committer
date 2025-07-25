/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

func TestDatasourceName(t *testing.T) {
	t.Parallel()
	c1 := &DatabaseConfig{
		Endpoints: []*connection.Endpoint{
			connection.CreateEndpoint("localhost:5433"),
		},
		Username:    "yugabyte_user",
		Password:    "yugabyte_pass",
		Database:    "yugabyte_db",
		LoadBalance: false,
	}
	e1 := "postgres://yugabyte_user:yugabyte_pass@localhost:5433/" +
		"yugabyte_db?sslmode=disable"
	require.Equal(t, e1, c1.DataSourceName())

	c2 := &DatabaseConfig{
		Endpoints: []*connection.Endpoint{
			connection.CreateEndpoint("host1:1111"),
			connection.CreateEndpoint("host2:2222"),
		},
		Username:    "yugabyte",
		Password:    "yugabyte",
		Database:    "yugabyte",
		LoadBalance: true,
	}
	//nolint:gosec // fake password.
	e2 := "postgres://yugabyte:yugabyte@host1:1111,host2:2222/yugabyte?sslmode=disable&load_balance=true"
	require.Equal(t, e2, c2.DataSourceName())
}
