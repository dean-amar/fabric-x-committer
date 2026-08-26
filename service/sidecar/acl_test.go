/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

func TestInterceptorProvidersWiring(t *testing.T) {
	t.Parallel()

	// Without an auth service configured, the sidecar contributes no interceptors.
	svc := &Service{}
	require.Nil(t, svc.UnaryServerInterceptors())
	require.Nil(t, svc.StreamServerInterceptors())

	// With an enforcer installed (as Run does when Config.Auth is set), it contributes the unary
	// interceptor (block query) and the stream interceptor (delivery and notifications).
	svc.authEnforcer = acl.NewEnforcer(nil, acl.EnforcerConfig{})
	require.Len(t, svc.UnaryServerInterceptors(), 1)
	require.Len(t, svc.StreamServerInterceptors(), 1)
}
