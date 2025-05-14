/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/grpc"
)

type (
	// Client is a collection of nodes and their connections.
	Client struct {
		config            *Config
		connectionManager *OrdererConnectionManager
		signer            protoutil.Signer
	}
)

// New creates a broadcast/deliver client. It must be closed to release all the associated connections.
func New(config *Config) (*Client, error) {
	if err := validateConfig(config); err != nil {
		return nil, errors.Wrap(err, "error validating config")
	}

	signer, err := NewIdentitySigner(config.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "error creating identity signer")
	}

	cm := &OrdererConnectionManager{}
	if err = cm.Update(&config.Connection); err != nil {
		return nil, errors.Wrap(err, "error creating connections")
	}

	return &Client{
		config:            config,
		connectionManager: cm,
		signer:            signer,
	}, nil
}

// Close closes all the connections for the client.
func (s *Client) Close() {
	s.connectionManager.Close()
}

// UpdateConnections updates the connection config.
func (s *Client) UpdateConnections(config *ConnectionConfig) error {
	return s.connectionManager.Update(config)
}

// Broadcast creates a broadcast stream.
func (s *Client) Broadcast(ctx context.Context) (*EnvelopedStream, error) {
	ret := &EnvelopedStream{
		channelID: s.config.ChannelID,
		signer:    s.signer,
	}
	common := broadcastCommon{
		ctx:               ctx,
		connectionManager: s.connectionManager,
	}
	switch s.config.ConsensusType {
	case Cft:
		ret.BroadcastStream = &broadcastCft{broadcastCommon: common}
	case Bft:
		ret.BroadcastStream = &broadcastBft{broadcastCommon: common}
	default:
		return nil, errors.Newf("invalid consensus type: '%s'", s.config.ConsensusType)
	}
	return ret, nil
}

// Deliver starts the block receiver. The call to Deliver blocks until an error occurs or the context is canceled.
func (s *Client) Deliver(ctx context.Context, deliverConfig *DeliverConfig) error {
	switch s.config.ConsensusType {
	case Bft:
		// TODO: We should borrow Fabric's delivery client implementation that supports BFT.
		logger.Warnf("deliver consensus type %s is not supported; falling back to %s",
			s.config.ConsensusType, Cft)
		fallthrough
	case Cft:
		c := &DeliverCftClient{
			ConnectionManager: s.connectionManager,
			Signer:            s.signer,
			ChannelID:         s.config.ChannelID,
			StreamCreator: func(ctx context.Context, conn grpc.ClientConnInterface) (DeliverStream, error) {
				client, err := orderer.NewAtomicBroadcastClient(conn).Deliver(ctx)
				if err != nil {
					return nil, err
				}
				return &ordererDeliverStream{client}, nil
			},
		}
		return c.Deliver(ctx, deliverConfig)
	default:
		return errors.Newf("invalid consensus type: %s", s.config.ConsensusType)
	}
}
