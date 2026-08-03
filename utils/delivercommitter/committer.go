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
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/deliver"
)

// Parameters needed for deliver to run.
type Parameters struct {
	ClientConfig *connection.ClientConfig
	NextBlockNum uint64
	OutputBlock  chan<- *common.Block

	// Signer and ChannelID enable ACL authorization against the sidecar's block-deliver API.
	// When Signer is nil, no Authorize call is made (for internal deployments or servers that
	// do not enforce ACL). The client's TLS cert hash for the binding is derived from
	// ClientConfig.TLS.
	Signer    msp.SigningIdentity
	ChannelID string
}

// ToQueue connects to a committer delivery server and delivers the stream to a queue (go channel).
// It returns when an error occurs or when the context is done.
// It will attempt to reconnect on errors.
func ToQueue(ctx context.Context, cdp Parameters) error {
	conn, err := connection.NewSingleConnection(cdp.ClientConfig)
	if err != nil {
		return err
	}
	defer connection.CloseConnectionsLog(conn)

	authParams, err := authParametersFor(cdp)
	if err != nil {
		return err
	}

	return deliver.ToQueue(ctx, deliver.Parameters{
		Deliverer: &ledgerDeliverer{
			conn:       conn,
			client:     peer.NewDeliverClient(conn),
			authParams: authParams,
		},
		NextBlockNum: cdp.NextBlockNum,
		OutputBlock:  cdp.OutputBlock,
	})
}

// authParametersFor builds the per-connection authorization parameters, deriving the client
// TLS cert hash from the delivery client's TLS configuration.
func authParametersFor(cdp Parameters) (auth.AuthorizeParameters, error) {
	if cdp.Signer == nil {
		return auth.AuthorizeParameters{}, nil
	}
	tlsCertHash, err := auth.ClientTLSCertHash(cdp.ClientConfig.TLS)
	if err != nil {
		return auth.AuthorizeParameters{}, err
	}
	return auth.AuthorizeParameters{
		Signer:      cdp.Signer,
		ChannelID:   cdp.ChannelID,
		TLSCertHash: tlsCertHash,
	}, nil
}

type ledgerDeliverer struct {
	conn       grpc.ClientConnInterface
	client     peer.DeliverClient
	authParams auth.AuthorizeParameters
}

func (d *ledgerDeliverer) Deliver(ctx context.Context) (deliver.Streamer, error) {
	// Authorize before opening the stream so the connection carries a bound MSP identity.
	// This runs on every (re)connection attempt; it is a no-op when no signer is configured.
	if err := auth.AuthorizeConnection(ctx, d.conn, d.authParams); err != nil {
		return nil, errors.Wrap(err, "failed to authorize delivery connection")
	}
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
