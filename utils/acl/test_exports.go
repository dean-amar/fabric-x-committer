/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// ContextWithToken returns ctx carrying the token in the metadata key the enforcer reads, which is how a
// caller authorizes one RPC without binding a token to a whole connection.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, token)
}
