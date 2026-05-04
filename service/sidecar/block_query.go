/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/common/ledger/blkstorage"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/service/acl"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// ErrEmptyTxID is returned when a transaction ID query is called with an empty tx_id.
var ErrEmptyTxID = errors.New("tx_id must not be empty")

// blockQuery implements committerpb.BlockQueryServiceServer by delegating
// read-only queries directly to the underlying block store.
type blockQuery struct {
	committerpb.UnimplementedBlockQueryServiceServer
	blockStore  *blockStore
	aclProvider acl.Provider
}

func newBlockQuery(bs *blockStore, aclProvider acl.Provider) *blockQuery {
	return &blockQuery{
		blockStore:  bs,
		aclProvider: aclProvider,
	}
}

// checkACL verifies read access for the envelope.
func (s *blockQuery) checkACL(envelope *common.Envelope) error {
	if s.aclProvider == nil {
		// ACL checking disabled
		return nil
	}

	err := s.aclProvider.CheckReadAccess(envelope)
	if err != nil {
		logger.Warnw("ACL check failed for block query operation", "error", err)
		return grpcerror.WrapWithContext(err, "access denied")
	}

	return nil
}

// extractRequestFromEnvelope extracts and unmarshals a request from an envelope
// and performs ACL check.
func (s *blockQuery) extractRequestFromEnvelope(envelope *common.Envelope, request proto.Message) error {
	// Check ACL first
	if err := s.checkACL(envelope); err != nil {
		return err
	}

	// Extract the payload data from the envelope
	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.GetPayload(), payload); err != nil {
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal envelope payload"))
	}

	// Unmarshal the request from payload data
	if err := proto.Unmarshal(payload.GetData(), request); err != nil {
		return grpcerror.WrapInvalidArgument(errors.Wrap(err, "failed to unmarshal request from payload data"))
	}

	return nil
}

// GetBlockchainInfo returns the current blockchain height and hash metadata.
func (s *blockQuery) GetBlockchainInfo(_ context.Context, envelope *common.Envelope) (*common.BlockchainInfo, error) {
	// Perform ACL check (no request data to extract)
	if err := s.checkACL(envelope); err != nil {
		return nil, err
	}

	info, err := s.blockStore.store.GetBlockchainInfo()
	if err != nil {
		logger.Errorf("GetBlockchainInfo failed: %v", err)
		return nil, grpcerror.WrapInternalError(err)
	}
	return info, nil
}

// GetBlockByNumber retrieves a block by its sequence number.
func (s *blockQuery) GetBlockByNumber(_ context.Context, envelope *common.Envelope) (*common.Block, error) {
	// Extract request from envelope (includes ACL check)
	req := &committerpb.BlockNumber{}
	if err := s.extractRequestFromEnvelope(envelope, req); err != nil {
		return nil, err
	}

	block, err := s.blockStore.store.RetrieveBlockByNumber(req.GetNumber())
	if err != nil {
		return nil, wrapQueryError(err)
	}
	return block, nil
}

// GetBlockByTxID retrieves the block that contains the specified transaction.
func (s *blockQuery) GetBlockByTxID(_ context.Context, envelope *common.Envelope) (*common.Block, error) {
	// Extract request from envelope (includes ACL check)
	req := &committerpb.TxID{}
	if err := s.extractRequestFromEnvelope(envelope, req); err != nil {
		return nil, err
	}

	if req.GetTxId() == "" {
		return nil, grpcerror.WrapInvalidArgument(ErrEmptyTxID)
	}
	block, err := s.blockStore.store.RetrieveBlockByTxID(req.GetTxId())
	if err != nil {
		return nil, wrapQueryError(err)
	}
	return block, nil
}

// GetTxByID retrieves the transaction envelope for the specified transaction ID.
func (s *blockQuery) GetTxByID(_ context.Context, envelope *common.Envelope) (*common.Envelope, error) {
	// Extract request from envelope (includes ACL check)
	req := &committerpb.TxID{}
	if err := s.extractRequestFromEnvelope(envelope, req); err != nil {
		return nil, err
	}

	if req.GetTxId() == "" {
		return nil, grpcerror.WrapInvalidArgument(ErrEmptyTxID)
	}
	txEnvelope, err := s.blockStore.store.RetrieveTxByID(req.GetTxId())
	if err != nil {
		return nil, wrapQueryError(err)
	}
	return txEnvelope, nil
}

func wrapQueryError(err error) error {
	if errors.Is(err, blkstorage.ErrNotFound) {
		return grpcerror.WrapNotFound(err)
	}
	logger.Errorf("Unexpected block store error: %v", err)
	return grpcerror.WrapInternalError(err)
}
