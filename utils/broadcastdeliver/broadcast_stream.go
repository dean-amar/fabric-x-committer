/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
)

type (
	//nolint:containedctx // grpc's stream contain context.
	broadcastCommon struct {
		ctx               context.Context
		connectionManager *OrdererConnectionManager
		resiliencyManager *OrdererConnectionResiliencyManager
	}

	//nolint:containedctx // grpc's stream contain context.
	broadcastCft struct {
		broadcastCommon
		streamCtx    context.Context
		streamCancel context.CancelFunc
		conn         *OrdererConnection
		stream       ab.AtomicBroadcast_BroadcastClient
	}

	broadcastBft struct {
		broadcastCommon
		idToStream map[uint32]*broadcastCft
		quorum     int
	}
)

// update returns true if the data was stale.
func (s *broadcastCommon) update() bool {
	// We also support using this module without a connection manager.
	if s.connectionManager == nil {
		return false
	}

	isStale := s.connectionManager.IsStale(s.resiliencyManager)
	if isStale {
		s.resiliencyManager = s.connectionManager.GetResiliencyManager(WithAPI(Broadcast))
	}
	return isStale
}

func (s *broadcastCft) Submit(m *common.Envelope) (*ab.BroadcastResponse, error) {
	return s.apply(func(stream ab.AtomicBroadcast_BroadcastClient) (*ab.BroadcastResponse, error) {
		err := stream.Send(m)
		if err != nil {
			return nil, errors.Wrap(err, "failed to send message")
		}
		resp, err := stream.Recv()
		return resp, errors.Wrap(err, "failed to receive message")
	})
}

func (s *broadcastCft) apply(
	f func(stream ab.AtomicBroadcast_BroadcastClient) (*ab.BroadcastResponse, error),
) (*ab.BroadcastResponse, error) {
	// We retry again for each call to submit, but we keep the previous order.
	s.resiliencyManager.ResetBackoff()
	for {
		if err := s.connect(); err != nil {
			return nil, errors.Wrap(err, "failed connecting")
		}
		var resp *ab.BroadcastResponse
		resp, s.conn.LastError = f(s.stream)
		if s.conn.LastError == nil {
			// If we succeed, we reset the connection's backoff
			s.conn.ResetBackoff()
			return resp, nil
		}
	}
}

// connect returns error if there is no alive node.
func (s *broadcastCft) connect() error {
	if s.conn != nil && s.conn.LastError == nil && s.stream != nil && s.streamCtx != nil && s.streamCtx.Err() == nil {
		return nil
	}
	if s.streamCancel != nil {
		// Ensure the previous stream context is cancelled.
		s.streamCancel()
	}
	//nolint:fatcontext // The previous streamCtx is cancelled prior to this.
	s.streamCtx, s.streamCancel = context.WithCancel(s.ctx)
	// We try any connection until we succeed.
	for s.conn == nil || s.conn.LastError != nil {
		s.update()
		var err error
		s.conn, err = s.resiliencyManager.GetNextConnection(s.streamCtx)
		if err != nil {
			return errors.Wrap(err, "failed getting next connection")
		}
		s.stream, s.conn.LastError = ab.NewAtomicBroadcastClient(s.conn).Broadcast(s.streamCtx)
	}
	return nil
}

func (s *broadcastBft) Submit(m *common.Envelope) (*ab.BroadcastResponse, error) {
	s.update()
	type response struct {
		id   uint32
		resp *ab.BroadcastResponse
		err  error
	}
	respQueue := channel.Make[response](s.ctx, len(s.idToStream))
	for id, stream := range s.idToStream {
		go func(id uint32, stream *broadcastCft) {
			r, err := stream.Submit(m)
			respQueue.Write(response{id: id, resp: r, err: err})
		}(id, stream)
	}

	var infoList []string
	var success int
	for len(infoList) < len(s.idToStream) {
		r, ok := respQueue.Read()
		if !ok {
			break
		}
		var info string
		switch {
		case r.resp != nil:
			if r.resp.Status == common.Status_SUCCESS {
				success++
			}
			info = r.resp.Status.String()
			if len(r.resp.Info) > 0 {
				info += fmt.Sprintf(": %s", r.resp.Info)
			}
		case r.err != nil:
			info = r.err.Error()
		default:
			info = "<nil>"
		}
		infoList = append(infoList, fmt.Sprintf("[%d] %s", r.id, info))
	}

	info := strings.Join(infoList, "\n")
	if success < s.quorum {
		return nil, errors.Newf("insufficient quorum: %s", info)
	}
	return &ab.BroadcastResponse{
		Status: common.Status_SUCCESS,
		Info:   info,
	}, nil
}

func (s *broadcastBft) update() {
	if !s.broadcastCommon.update() && s.idToStream != nil {
		return
	}
	streams := make(map[uint32]*broadcastCft)
	for id := range s.resiliencyManager.IDs() {
		idResiliencyManager := s.resiliencyManager.Filter(WithID(id))
		if s.idToStream != nil && s.idToStream[id] != nil {
			prevStream := s.idToStream[id]
			delete(s.idToStream, id)
			prevStream.resiliencyManager = idResiliencyManager
			streams[id] = prevStream
		} else {
			// We don't provide it with the connection manager to prevent automatic updates.
			// We want to preserve a consistent connection version across all parties.
			streams[id] = &broadcastCft{
				broadcastCommon: broadcastCommon{
					ctx:               s.ctx,
					resiliencyManager: idResiliencyManager,
				},
			}
		}
	}
	for _, stream := range s.idToStream {
		if stream.streamCancel != nil {
			stream.streamCancel()
		}
	}
	s.idToStream = streams
	n := len(streams)
	s.quorum, _ = computeBFTQuorum(n)
}

// Copied from the smartbft library.
// computeBFTQuorum calculates the quorums size Q, given a cluster size N.
//
// The calculation satisfies the following:
// Given a cluster size of N nodes, which tolerates f failures according to:
//
//	f = argmax ( N >= 3f+1 )
//
// Q is the size of the quorum such that:
//
//	any two subsets q1, q2 of size Q, intersect in at least f+1 nodes.
//
// Note that this is different from N-f (the number of correct nodes), when N=3f+3. That is, we have two extra nodes
// above the minimum required to tolerate f failures.
func computeBFTQuorum(n int) (q, f int) {
	f = (n - 1) / 3
	q = int(math.Ceil((float64(n) + float64(f) + 1) / 2.0))
	return q, f
}
