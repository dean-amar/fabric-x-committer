/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package delivercommitter

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/deliver"
)

// Parameters needed for deliver to run.
type Parameters struct {
	ClientConfig *connection.ClientConfig
	NextBlockNum uint64
	OutputBlock  chan<- *common.Block
	// Credentials authenticates every RPC on the stream. It is required when the delivery server
	// enforces ACL, and nil otherwise - a server without enforcement ignores the token, so a caller
	// that does not know whether the far side enforces may set it unconditionally.
	Credentials credentials.PerRPCCredentials
}

// ToQueue connects to a committer delivery server and delivers the stream to a queue (go channel).
// It returns when an error occurs or when the context is done.
// It will attempt to reconnect on errors.
func ToQueue(ctx context.Context, cdp Parameters) error {
	// Per-RPC credentials need a dial option, which only NewConnection takes.
	tlsCreds, err := cdp.ClientConfig.TLS.ClientCredentials()
	if err != nil {
		return err
	}
	p := connection.ClientParameters{
		Address: cdp.ClientConfig.Endpoint.Address(),
		Creds:   tlsCreds,
		Retry:   cdp.ClientConfig.Retry,
	}
	if cdp.Credentials != nil {
		p.AdditionalOpts = []grpc.DialOption{grpc.WithPerRPCCredentials(cdp.Credentials)}
	}
	conn, err := connection.NewConnection(p)
	if err != nil {
		return err
	}
	defer connection.CloseConnectionsLog(conn)
	return deliver.ToQueue(ctx, deliver.Parameters{
		Deliverer:    &ledgerDeliverer{client: peer.NewDeliverClient(conn)},
		NextBlockNum: cdp.NextBlockNum,
		OutputBlock:  cdp.OutputBlock,
	})
}

type ledgerDeliverer struct {
	client peer.DeliverClient
}

func (d *ledgerDeliverer) Deliver(ctx context.Context) (deliver.Streamer, error) {
	deliverStream, deliverErr := d.client.Deliver(ctx)
	if deliverErr != nil {
		return nil, deliverErr
	}
	return &ledgerDeliverStream{Deliver_DeliverClient: deliverStream}, nil
}

// ledgerDeliverStream implements deliver.streamer.
type ledgerDeliverStream struct {
	peer.Deliver_DeliverClient
}

// RecvBlockOrStatus receives the committed block from the ledger service. The first
// block number to be received is dependent on the seek position
// sent in DELIVER_SEEK_INFO message.
func (s *ledgerDeliverStream) RecvBlockOrStatus() (*common.Block, *common.Status, error) {
	msg, err := s.Recv()
	if err != nil {
		return nil, nil, err
	}
	switch t := msg.Type.(type) {
	case *peer.DeliverResponse_Status:
		return nil, &t.Status, nil
	case *peer.DeliverResponse_Block:
		return t.Block, nil, nil
	default:
		return nil, nil, errors.New("unexpected message")
	}
}
