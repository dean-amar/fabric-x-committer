package connection_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protovcservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

func TestGRPCRetry(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	regService := func(server *grpc.Server, _ int) {
		protovcservice.RegisterValidationAndCommitServiceServer(server, mock.NewMockVcService())
	}

	vcGrpc := test.StartGrpcServersForTest(ctx, t, 1, regService)

	conn, err := connection.Connect(connection.NewDialConfig(&vcGrpc.Configs[0].Endpoint))
	require.NoError(t, err)

	connStatus := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "conn_status",
		Help: "connection status: 0 --- disconnected, 1 --- connected.",
	}, []string{"target"})

	client := protovcservice.NewValidationAndCommitServiceClient(conn)
	_, err = client.GetNamespacePolicies(ctx, nil)
	require.NoError(t, err)

	failureCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "failure_total",
		Help: "total number of connection failures.",
	}, []string{"target"})

	waitForConnection(ctx, conn, connStatus, failureCount)

	label := []string{conn.CanonicalTarget()}
	connStatusM, err := connStatus.GetMetricWithLabelValues(label...)
	require.NoError(t, err)
	promutil.RequireIntMetricValue(t, connection.Connected, connStatusM)

	connFailureM, err := failureCount.GetMetricWithLabelValues(label...)
	require.NoError(t, err)
	promutil.RequireIntMetricValue(t, 0, connFailureM)

	// stopping the grpc server
	cancel()
	vcGrpc.Servers[0].Stop()
	test.CheckServerStopped(t, vcGrpc.Configs[0].Endpoint.Address())

	_, err = client.GetNamespacePolicies(ctx, nil)
	require.Error(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	ctx2, cancel2 := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel2()
	go func() {
		defer wg.Done()
		waitForConnection(ctx2, conn, connStatus, failureCount)
	}()

	time.Sleep(5 * time.Second)

	promutil.RequireIntMetricValue(t, 1, connFailureM)
	promutil.RequireIntMetricValue(t, connection.Disconnected, connStatusM)

	test.StartGrpcServersWithConfigForTest(ctx2, t, vcGrpc.Configs, regService)

	wg.Wait()
	promutil.RequireIntMetricValue(t, connection.Connected, connStatusM)
}

type fakeBroadcastDeliver struct{}

func (fakeBroadcastDeliver) Deliver(stream peer.Deliver_DeliverServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch len(msg.Payload) {
		case 0:
			return errors.New("bad env")
		case 1:
			return nil
		}
		err = stream.Send(&peer.DeliverResponse{})
		if err != nil {
			return err
		}
	}
}

func (fakeBroadcastDeliver) DeliverFiltered(peer.Deliver_DeliverFilteredServer) error {
	panic("not implemented")
}

func (fakeBroadcastDeliver) DeliverWithPrivateData(peer.Deliver_DeliverWithPrivateDataServer) error {
	panic("not implemented")
}

var (
	badEnv = &common.Envelope{}
	endEnv = &common.Envelope{
		Payload: make([]byte, 1),
	}
	goodEnv = &common.Envelope{
		Payload: make([]byte, 2),
	}
)

type filterTestEnv struct {
	service       *fakeBroadcastDeliver
	serverConf    *connection.ServerConfig
	server        *grpc.Server
	client        peer.DeliverClient
	deliver       peer.Deliver_DeliverClient
	serviceCancel context.CancelFunc
	clientCancel  context.CancelFunc
}

func newFilterTestEnv(t *testing.T) *filterTestEnv {
	t.Helper()
	env := &filterTestEnv{
		service:    &fakeBroadcastDeliver{},
		serverConf: &connection.ServerConfig{Endpoint: connection.Endpoint{Host: "localhost"}},
	}

	serviceCtx, serviceCancel := context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(serviceCancel)
	env.serviceCancel = serviceCancel

	env.server = test.RunGrpcServerForTest(serviceCtx, t, env.serverConf, func(server *grpc.Server) {
		peer.RegisterDeliverServer(server, env.service)
	})
	conn, err := connection.Connect(connection.NewDialConfig(&env.serverConf.Endpoint))
	require.NoError(t, err)
	env.client = peer.NewDeliverClient(conn)

	clientCtx, clientCancel := context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(clientCancel)
	env.clientCancel = clientCancel
	env.deliver, err = env.client.Deliver(clientCtx)
	require.NoError(t, err)

	// Sanity check.
	err = env.deliver.Send(goodEnv)
	require.NoError(t, err)
	_, err = env.deliver.Recv()
	require.NoError(t, err)
	requireNoWrappedError(t, err)

	return env
}

func TestFilterStreamRPCError(t *testing.T) {
	t.Parallel()

	t.Run("EOF", func(t *testing.T) {
		t.Parallel()
		env := newFilterTestEnv(t)
		err := env.deliver.Send(endEnv)
		require.NoError(t, err)
		_, err = env.deliver.Recv()
		require.ErrorIs(t, err, io.EOF)
		requireNoWrappedError(t, err)
	})

	t.Run("client ctx cancel", func(t *testing.T) {
		t.Parallel()
		env := newFilterTestEnv(t)
		env.clientCancel()
		_, err := env.deliver.Recv()
		require.Error(t, err)
		requireNoWrappedError(t, err)
		requireErrorIsRPC(t, err, codes.Canceled)
	})

	t.Run("client ctx timeout", func(t *testing.T) {
		t.Parallel()
		clientCtx, clientCancel := context.WithTimeout(t.Context(), time.Second)
		t.Cleanup(clientCancel)
		env := newFilterTestEnv(t)
		deliver, err := env.client.Deliver(clientCtx)
		require.NoError(t, err)
		time.Sleep(time.Second)
		_, err = deliver.Recv()
		require.Error(t, err)
		requireNoWrappedError(t, err)
		requireErrorIsRPC(t, err, codes.DeadlineExceeded)
	})

	t.Run("with error", func(t *testing.T) {
		t.Parallel()
		env := newFilterTestEnv(t)
		err := env.deliver.Send(badEnv)
		require.NoError(t, err)
		_, err = env.deliver.Recv()
		require.Error(t, err)
		require.Error(t, connection.FilterStreamRPCError(err))
		require.Error(t, connection.FilterStreamRPCError(errors.Join(err, errors.New("failed"))))
		require.Error(t, connection.FilterStreamRPCError(fmt.Errorf("failed: %w", err)))
	})

	t.Run("server ctx cancel", func(t *testing.T) {
		t.Parallel()
		env := newFilterTestEnv(t)
		go func() {
			time.Sleep(3 * time.Second)
			env.serviceCancel()
		}()

		_, err := env.deliver.Recv()
		require.Error(t, err)
		// This returns either codes.Canceled or codes.Unavailable (EOF).
		requireNoWrappedError(t, err)
	})

	t.Run("server shutdown", func(t *testing.T) {
		t.Parallel()
		env := newFilterTestEnv(t)
		go func() {
			time.Sleep(3 * time.Second)
			env.server.Stop()
		}()
		_, err := env.deliver.Recv()
		require.Error(t, err)
		// This returns either codes.Canceled or codes.Unavailable (EOF).
		requireNoWrappedError(t, err)
	})
}

func requireNoWrappedError(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, connection.FilterStreamRPCError(err))
	if err == nil {
		return
	}
	require.NoError(t, connection.FilterStreamRPCError(errors.Join(err, errors.New("failed"))))
	require.NoError(t, connection.FilterStreamRPCError(fmt.Errorf("failed: %w", err)))
}

func requireErrorIsRPC(t *testing.T, rpcErr error, code codes.Code) {
	t.Helper()
	errStatus, ok := status.FromError(rpcErr)
	require.True(t, ok)
	rpcErrCode := errStatus.Code()
	require.Equal(t, code, rpcErrCode)
}

type closer struct {
	err error
}

func (c *closer) Close() error {
	return c.err
}

func TestCloseConnections(t *testing.T) {
	t.Parallel()
	testErrors := []error{
		io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe, net.ErrClosed, context.Canceled, context.DeadlineExceeded,
	}
	for _, err := range testErrors {
		t.Run(err.Error(), func(t *testing.T) {
			t.Parallel()
			require.NoError(t, connection.CloseConnections(&closer{err: errors.Wrap(err, "failed")}))
		})
	}

	t.Run("all", func(t *testing.T) {
		t.Parallel()
		closers := make([]*closer, len(testErrors))
		for i, err := range testErrors {
			closers[i] = &closer{err: errors.Wrap(err, "failed")}
		}
		require.NoError(t, connection.CloseConnections(closers...))
	})
}

func waitForConnection(
	ctx context.Context,
	conn *grpc.ClientConn,
	connStatus *prometheus.GaugeVec,
	failureCount *prometheus.CounterVec,
) {
	label := []string{conn.CanonicalTarget()}
	defer func() {
		promutil.SetGaugeVec(connStatus, label, connection.Connected)
	}()

	if conn.GetState() == connectivity.Ready {
		return
	}

	promutil.AddToCounterVec(failureCount, label, 1)
	promutil.SetGaugeVec(connStatus, label, connection.Disconnected)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn.Connect()
			if conn.GetState() == connectivity.Ready {
				return
			}
		}
	}
}
