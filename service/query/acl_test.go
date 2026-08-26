/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

func TestUnaryServerInterceptorsWiring(t *testing.T) {
	t.Parallel()

	// Without an auth service configured, the query service contributes no interceptors.
	svc := &Service{}
	require.Nil(t, svc.UnaryServerInterceptors())

	// With an enforcer installed (as Run does when Config.Auth is set), it contributes exactly one.
	svc.authEnforcer = acl.NewEnforcer(nil, acl.EnforcerConfig{})
	require.Len(t, svc.UnaryServerInterceptors(), 1)
}
