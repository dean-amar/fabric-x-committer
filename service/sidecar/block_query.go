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

	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// ErrEmptyTxID is returned when a transaction ID query is called with an empty tx_id.
var ErrEmptyTxID = errors.New("tx_id must not be empty")

// blockQuery implements committerpb.BlockQueryServiceServer by delegating
// read-only queries directly to the underlying block store.
type blockQuery struct {
	committerpb.UnimplementedBlockQueryServiceServer
	blockStore        *blockStore
	configBlockSource func() *common.Block
	acl               *envelopeACL
}

func newBlockQuery(bs *blockStore, configBlockSource func() *common.Block) *blockQuery {
	return &blockQuery{
		blockStore:        bs,
		configBlockSource: configBlockSource,
		acl:               newEnvelopeACL(queryReadersPolicy),
	}
}

// GetBlockchainInfo returns the current blockchain height and hash metadata.
func (s *blockQuery) GetBlockchainInfo(ctx context.Context, envelope *common.Envelope) (*common.BlockchainInfo, error) {
	configEnvelopeBytes, err := s.currentConfigEnvelopeBytes()
	if err != nil {
		return nil, grpcerror.WrapFailedPrecondition(err)
	}
	if _, err := s.acl.authorize(configEnvelopeBytes, envelope); err != nil {
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
func (s *blockQuery) GetBlockByNumber(ctx context.Context, envelope *common.Envelope) (*common.Block, error) {
	configEnvelopeBytes, err := s.currentConfigEnvelopeBytes()
	if err != nil {
		return nil, grpcerror.WrapFailedPrecondition(err)
	}

	req := &committerpb.BlockNumber{}
	if err := s.acl.authorizeAndUnmarshal(configEnvelopeBytes, envelope, req); err != nil {
		return nil, err
	}

	block, err := s.blockStore.store.RetrieveBlockByNumber(req.GetNumber())
	if err != nil {
		return nil, wrapBlockQueryError(err)
	}
	return block, nil
}

// GetBlockByTxID retrieves the block that contains the specified transaction.
func (s *blockQuery) GetBlockByTxID(ctx context.Context, envelope *common.Envelope) (*common.Block, error) {
	configEnvelopeBytes, err := s.currentConfigEnvelopeBytes()
	if err != nil {
		return nil, grpcerror.WrapFailedPrecondition(err)
	}

	req := &committerpb.TxID{}
	if err := s.acl.authorizeAndUnmarshal(configEnvelopeBytes, envelope, req); err != nil {
		return nil, err
	}
	if req.GetTxId() == "" {
		return nil, grpcerror.WrapInvalidArgument(ErrEmptyTxID)
	}

	block, err := s.blockStore.store.RetrieveBlockByTxID(req.GetTxId())
	if err != nil {
		return nil, wrapBlockQueryError(err)
	}
	return block, nil
}

// GetTxByID retrieves the transaction envelope for the specified transaction ID.
func (s *blockQuery) GetTxByID(ctx context.Context, envelope *common.Envelope) (*common.Envelope, error) {
	configEnvelopeBytes, err := s.currentConfigEnvelopeBytes()
	if err != nil {
		return nil, grpcerror.WrapFailedPrecondition(err)
	}

	req := &committerpb.TxID{}
	if err := s.acl.authorizeAndUnmarshal(configEnvelopeBytes, envelope, req); err != nil {
		return nil, err
	}
	if req.GetTxId() == "" {
		return nil, grpcerror.WrapInvalidArgument(ErrEmptyTxID)
	}

	txEnvelope, err := s.blockStore.store.RetrieveTxByID(req.GetTxId())
	if err != nil {
		return nil, wrapBlockQueryError(err)
	}
	return txEnvelope, nil
}

func (s *blockQuery) currentConfigBlock() *common.Block {
	if s.configBlockSource == nil {
		return nil
	}
	return s.configBlockSource()
}

func (s *blockQuery) currentConfigEnvelopeBytes() ([]byte, error) {
	return configEnvelopeBytesFromBlock(s.currentConfigBlock())
}

func wrapBlockQueryError(err error) error {
	if errors.Is(err, blkstorage.ErrNotFound) {
		return grpcerror.WrapNotFound(err)
	}
	logger.Errorf("Unexpected block store error: %v", err)
	return grpcerror.WrapInternalError(err)
}
