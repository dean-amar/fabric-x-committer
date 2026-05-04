/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

// checkACL verifies read access for the envelope.
// This is called for each message in the notification stream to enforce ACLs.
func (s *Service) checkACL(envelope *common.Envelope) error {
	if s.aclProvider == nil {
		// ACL checking disabled
		return nil
	}

	err := s.aclProvider.CheckReadAccess(envelope)
	if err != nil {
		logger.Warnw("ACL check failed for notification stream", "error", err)
		return err
	}

	return nil
}

// Made with Bob
