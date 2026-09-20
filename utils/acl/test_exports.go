/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"

	"google.golang.org/grpc/metadata"
)

func ContextWithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, token)
}
