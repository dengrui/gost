package gost_test

import (
	"bufio"
	"context"
	"crypto/tls"
	gost "github.com/ginuerzh/gost"
	quic "github.com/quic-go/quic-go"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ginuerzh/gost/mobile/yqmobile"
)

// TestYQPCClient is a manual PC client for an already running YQ server.
// Example (self-signed development server):
// YQ_ADDR=127.0.0.1:8081 YQ_INSECURE=1 YQ_DURATION=5m \
//   go test -v -run '^TestYQPCClient$' -count=1 -timeout=6m .
// For certificate verification, use YQ_CA and optionally YQ_SERVER_NAME instead
// of YQ_INSECURE. YQ_CERT and YQ_KEY optionally provide a client certificate.
func TestYQPCClient(t *testing.T) {
	addr := os.Getenv("YQ_ADDR")
	if addr == "" {
		t.Skip("set YQ_ADDR=host:port to connect to a running YQ server")
	}
	duration := 5 * time.Minute
	if value := os.Getenv("YQ_DURATION"); value != "" {
		var err error
		duration, err = time.ParseDuration(value)
		if err != nil || duration <= 0 {
			t.Fatalf("invalid YQ_DURATION %q", value)
		}
	}
	readPEM := func(name string) string {
		t.Helper()
		path := os.Getenv(name)
		if path == "" {
			return ""
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(data)
	}
	insecure := os.Getenv("YQ_INSECURE") == "1"
	if insecure {
		t.Log("test mode: server certificate verification disabled")
	}
	if err := yqmobile.ConfigureTLS(readPEM("YQ_CA"), os.Getenv("YQ_SERVER_NAME"), insecure); err != nil {
		t.Fatal(err)
	}
	if err := yqmobile.SetClientCertificate(readPEM("YQ_CERT"), readPEM("YQ_KEY")); err != nil {
		t.Fatal(err)
	}
	var connected atomic.Bool
	callback := yqPCListener(func(status, message string) {
		if status == "connected" {
			connected.Store(true)
		}
		t.Logf("status=%s error=%q", status, message)
	})
	if err := yqmobile.SetConnectionListener(callback); err != nil {
		t.Fatal(err)
	}
	defer func() { yqmobile.Stop(); yqmobile.SetConnectionListener(nil) }()
	if err := yqmobile.Start(addr); err != nil {
		t.Fatal(err)
	}
	t.Logf("phone worker started for %s; running for %s", addr, duration)
	t.Log("send requests to GOST's -L proxy port after the connected callback")
	timer := time.NewTimer(duration)
	defer timer.Stop()
	<-timer.C
	yqmobile.Stop()
	if !connected.Load() {
		t.Fatalf("never connected to %s; see connection callback logs for errors", addr)
	}
}

type yqPCListener func(string, string)

func (f yqPCListener) OnStateChanged(status, message string) { f(status, message) }

func TestYQPCClientLifecycle(t *testing.T) {
	yqmobile.Stop()
	defer yqmobile.Stop()
	cert, err := gost.GenCertificate()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"quic/v1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := yqmobile.ConfigureTLS("", "", true); err != nil {
		t.Fatal(err)
	}
	if err := yqmobile.Start("invalid"); err == nil {
		t.Fatal("accepted invalid address")
	}
	if err := yqmobile.Start(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := yqmobile.Start(listener.Addr().String()); err == nil {
		t.Fatal("duplicate Start succeeded")
	}
	if err := yqmobile.ConfigureTLS("", "", true); err == nil {
		t.Fatal("allowed active reconfiguration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mobile echo") }))
	defer target.Close()
	check := func(conn quic.Connection) {
		t.Helper()
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := &yqPCTestStreamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
		defer wrapped.Close()
		wrapped.SetDeadline(time.Now().Add(5 * time.Second))
		tunnel, err := gost.HTTPConnector(nil).ConnectContext(ctx, wrapped, "tcp", target.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(tunnel, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || string(b) != "mobile echo" {
			t.Fatalf("body %q: %v", b, err)
		}
	}
	check(conn)
	check(conn)
	conn.CloseWithError(0, "simulate disconnect")
	conn, err = listener.Accept(ctx)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	check(conn)
	// Stop must unblock a handler waiting for a request on an active stream.
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.Write([]byte("C"))
	done := make(chan struct{})
	go func() { yqmobile.Stop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Stop blocked")
	}
	// Restart the same package instance after stopping.
	if err := yqmobile.Start(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	conn, err = listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check(conn)
	yqmobile.Stop()
	if err := yqmobile.ConfigureTLS("", "", false); err != nil {
		t.Fatal(err)
	}
}

// Adapter for the test server side; production forwarding lives in yqmobile.
type yqPCTestStreamConn struct {
	quic.Stream
	local, remote net.Addr
}

func (c *yqPCTestStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *yqPCTestStreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *yqPCTestStreamConn) Close() error         { c.CancelRead(0); return c.Stream.Close() }
