/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// checkACL verifies read access for the envelope.
// This is called by all query service methods to enforce ACLs.
func (q *Service) checkACL(envelope *common.Envelope) error {
	if q.aclProvider == nil {
		// ACL checking disabled
		return nil
	}

	err := q.aclProvider.CheckReadAccess(envelope)
	if err != nil {
		logger.Warnw("ACL check failed for query operation", "error", err)
		return grpcerror.WrapWithContext(err, "access denied")
	}

	return nil
}

// extractRequestFromEnvelope extracts and unmarshals the request data from an envelope.
// It performs ACL checks before extracting the data.
func (q *Service) extractRequestFromEnvelope(envelope *common.Envelope, request proto.Message) error {
	// Check ACL first
	if err := q.checkACL(envelope); err != nil {
		return err
	}

	// Extract payload from envelope
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal envelope payload"))
	}

	// Unmarshal request data from payload
	if err := proto.Unmarshal(payload.Data, request); err != nil {
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal request data"))
	}

	return nil
}
