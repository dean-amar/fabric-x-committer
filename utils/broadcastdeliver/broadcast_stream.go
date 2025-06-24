/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"google.golang.org/grpc"
)

type (
	//nolint:containedctx // grpc's stream contain context.
	broadcastCft struct {
		ctx               context.Context
		connectionManager *OrdererConnectionManager

		configVersion uint64
		conn          *grpc.ClientConn
		streamCtx     context.Context
		streamCancel  context.CancelFunc
		stream        ab.AtomicBroadcast_BroadcastClient
	}

	// broadcastBft supports broadcasting to multiple nodes (one per ID).
	// It should be used only for testing as it does not validate successful broadcast to a valid quorum.
	//
	//nolint:containedctx // grpc's stream contain context.
	broadcastBft struct {
		ctx               context.Context
		connectionManager *OrdererConnectionManager

		configVersion uint64
		streamCtx     context.Context
		streamCancel  context.CancelFunc
		idToStream    map[uint32]*broadcastCft
	}
)

func (s *broadcastCft) Send(m *common.Envelope) error {
	var err error
	var isUpdate bool
	// We try twice. Once with the existing stream and second time with a new one.
	for !isUpdate {
		isUpdate, err = s.update()
		if err != nil {
			return err
		}
		err = s.stream.Send(m)
		if err == nil {
			return nil
		}
		// Force update.
		s.streamCancel()
	}
	return errors.Wrap(err, "failed to send message")
}

// update returns error if there is no alive connection.
func (s *broadcastCft) update() (bool, error) {
	if s.conn != nil && s.stream != nil && s.streamCtx != nil && s.streamCtx.Err() == nil {
		return false, nil
	}
	if s.streamCancel != nil {
		// Ensure the previous stream context is cancelled.
		s.streamCancel()
	}
	//nolint:fatcontext // The previous streamCtx is cancelled prior to this.
	s.streamCtx, s.streamCancel = context.WithCancel(s.ctx)

	// We also support using this module without a connection manager.
	if s.connectionManager != nil {
		isStale := s.connectionManager.IsStale(s.configVersion)
		if isStale {
			s.conn, s.configVersion = s.connectionManager.GetConnection(WithAPI(Broadcast))
		}
	}

	if s.conn == nil {
		return false, ErrNoConnections
	}
	var err error
	s.stream, err = ab.NewAtomicBroadcastClient(s.conn).Broadcast(s.streamCtx)
	if err != nil {
		return true, err
	}

	// We load the parameter on stack before starting the go routine.
	workerCtx := s.streamCtx
	workerStream := s.stream
	workerCancel := s.streamCancel
	go func() {
		defer workerCancel()
		responseCollector(workerCtx, workerStream)
	}()
	return true, nil
}

func responseCollector(ctx context.Context, stream ab.AtomicBroadcast_BroadcastClient) {
	for ctx.Err() == nil {
		_, streamErr := stream.Recv()
		if streamErr != nil {
			return
		}
	}
}

func (s *broadcastBft) Send(m *common.Envelope) error {
	s.update()
	if len(s.idToStream) == 0 {
		return ErrNoConnections
	}
	errs := make([]error, 0, len(s.idToStream))
	for id, stream := range s.idToStream {
		err := stream.Send(m)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to send message to stream [%d]", id))
		}
	}
	return errors.Join(errs...)
}

func (s *broadcastBft) update() {
	// We also support using this module without a connection manager.
	if s.connectionManager == nil {
		return
	}

	isStale := s.connectionManager.IsStale(s.configVersion)
	if !isStale {
		return
	}
	if s.streamCancel != nil {
		// Ensure the previous stream context is cancelled.
		s.streamCancel()
	}
	//nolint:fatcontext // The previous streamCtx is cancelled prior to this.
	s.streamCtx, s.streamCancel = context.WithCancel(s.ctx)

	idToConn, configVersion := s.connectionManager.GetConnectionPerID(WithAPI(Broadcast))
	s.configVersion = configVersion

	streams := make(map[uint32]*broadcastCft)
	for id, conn := range idToConn {
		streams[id] = &broadcastCft{
			ctx:  s.streamCtx,
			conn: conn,
		}
	}
	s.idToStream = streams
}
