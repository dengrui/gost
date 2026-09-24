package gost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// TestYQPhone is a manual phone simulator for an already running YQ server.
// Example (self-signed development server):
// YQ_ADDR=127.0.0.1:8081 YQ_INSECURE=1 YQ_DURATION=5m \
//   go test -v -run '^TestYQPhone$' -count=1 -timeout=6m .
// For certificate verification, use YQ_CA and optionally YQ_SERVER_NAME instead
// of YQ_INSECURE. YQ_CERT and YQ_KEY optionally provide a client certificate.
func TestYQPhone(t *testing.T) {
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
	config := &tls.Config{
		ServerName:         os.Getenv("YQ_SERVER_NAME"),
		InsecureSkipVerify: os.Getenv("YQ_INSECURE") == "1", // Explicit opt-in for local testing only.
	}
	if config.InsecureSkipVerify {
		t.Log("test mode: server certificate verification disabled")
	}
	if path := os.Getenv("YQ_CA"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM(pem) {
			t.Fatal("YQ_CA contains no valid certificates")
		}
	}
	if os.Getenv("YQ_CERT") != "" || os.Getenv("YQ_KEY") != "" {
		cert, err := tls.LoadX509KeyPair(os.Getenv("YQ_CERT"), os.Getenv("YQ_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	phone, err := quic.DialAddr(dialCtx, addr, tlsConfigQUICALPN(config), &quic.Config{KeepAlivePeriod: 10 * time.Second})
	dialCancel()
	if err != nil {
		t.Fatalf("connect to YQ: %v", err)
	}
	var workers sync.WaitGroup
	defer func() {
		phone.CloseWithError(0, "phone test finished")
		workers.Wait()
	}()
	t.Logf("phone connected to %s; serving streams for %s", phone.RemoteAddr(), duration)
	t.Log("send requests to GOST's -L proxy port to create streams")
	count := 0
	for {
		stream, err := phone.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				t.Logf("finished: accepted %d streams", count)
				return
			}
			t.Fatalf("YQ connection interrupted: %v", err)
		}
		count++
		t.Logf("accepted stream %d", stream.StreamID())
		conn := &yqStreamConn{quicConn: &quicConn{
			Stream: stream, laddr: phone.LocalAddr(), raddr: phone.RemoteAddr(),
		}}
		// Avoid workers outliving this manual test, including half-open requests.
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			// Supports default yq (HTTP) and explicit socks5+yq alike.
			AutoHandler(TimeoutHandlerOption(5 * time.Second)).Handle(conn)
		}()
	}
}
