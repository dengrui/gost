package gost

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// go test -v -run '^TestYQReverseQUIC$' -count=1 .
func TestYQReverseQUIC(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := YQTransporter("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.(*yqTransporter)
	defer tr.Close()
	addr := tr.listener.Addr().String()
	if _, err := tr.Dial(addr); err == nil {
		t.Fatal("expected no-phone error")
	}
	if _, err := YQTransporter(addr, &tls.Config{Certificates: []tls.Certificate{cert}}); err == nil {
		t.Fatal("expected port conflict")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	phone, err := quic.DialAddr(ctx, addr, tlsConfigQUICALPN(&tls.Config{InsecureSkipVerify: true}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer phone.CloseWithError(0, "done")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "through phone") }))
	defer target.Close()
	// A phone handles HTTP CONNECT on streams opened by the GOST server.
	go func() {
		for {
			stream, err := phone.AcceptStream(ctx)
			if err != nil {
				return
			}
			conn := &yqStreamConn{quicConn: &quicConn{Stream: stream, laddr: phone.LocalAddr(), raddr: phone.RemoteAddr()}}
			go HTTPHandler().Handle(conn)
		}
	}()
	for {
		tr.mu.Lock()
		ready := len(tr.sessions) == 1
		tr.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- func() error {
				conn, err := tr.Dial(addr)
				if err != nil {
					return err
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn, err = HTTPConnector(nil).ConnectContext(ctx, conn, "tcp", target.Listener.Addr().String())
				if err != nil {
					return err
				}
				if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
					return err
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return err
				}
				if string(body) != "through phone" {
					return fmt.Errorf("unexpected response: %q", body)
				}
				return nil
			}()
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	tr.mu.Lock()
	count := len(tr.sessions)
	tr.mu.Unlock()
	if count != 1 {
		t.Errorf("expected one shared session, got %d", count)
	}
	phone.CloseWithError(0, "disconnect")
	for {
		tr.mu.Lock()
		count = len(tr.sessions)
		tr.mu.Unlock()
		if count == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := tr.Dial(addr); err == nil {
		t.Fatal("expected disconnected-phone error")
	}
	tr.Close()
	if _, err := tr.Dial(addr); err != net.ErrClosed {
		t.Fatalf("closed Dial: %v", err)
	}
}

func TestYQRequestMarkBinding(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := YQTransporter("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.(*yqTransporter)
	defer tr.Close()
	addr := tr.listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var phones []quic.Connection
	for i := 0; i < 2; i++ {
		phone, err := quic.DialAddr(ctx, addr, tlsConfigQUICALPN(&tls.Config{InsecureSkipVerify: true}), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer phone.CloseWithError(0, "done")
		phones = append(phones, phone)
	}
	waitFor := func(ready func() bool) {
		t.Helper()
		for {
			tr.mu.Lock()
			ok := ready()
			tr.mu.Unlock()
			if ok {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitFor(func() bool { return len(tr.sessions) == 2 })
	dial := func(mark string) string {
		t.Helper()
		conn, err := tr.Dial(addr, YQRequestMarkDialOption(mark))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.RemoteAddr().String()
	}
	a := dial("12345678")
	b := dial("87654321")
	if a == b {
		t.Fatal("new marks should distribute across both phones")
	}
	// Concurrent requests with one mark must all reuse the same phone.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := tr.Dial(addr, YQRequestMarkDialOption("12345678"))
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if got := conn.RemoteAddr().String(); got != a {
				t.Errorf("same mark changed phone: got %s, want %s", got, a)
			}
		}()
	}
	wg.Wait()
	if dial("") == dial("") {
		t.Fatal("unmarked requests should continue round robin")
	}
	_, boundPort, _ := net.SplitHostPort(a)
	for _, phone := range phones {
		_, phonePort, _ := net.SplitHostPort(phone.LocalAddr().String())
		if phonePort == boundPort {
			phone.CloseWithError(0, "disconnect bound phone")
		}
	}
	waitFor(func() bool { return len(tr.sessions) == 1 && tr.bindings["12345678"] == nil })
	if got := dial("12345678"); got != b {
		t.Fatalf("disconnected mark did not move to remaining phone: %s", got)
	}
	if got := dial("87654321"); got != b {
		t.Fatalf("unaffected mark moved: %s", got)
	}
	for _, phone := range phones {
		phone.CloseWithError(0, "all phones disconnected")
	}
	waitFor(func() bool { return len(tr.sessions) == 0 && len(tr.bindings) == 0 })
	if _, err := tr.Dial(addr, YQRequestMarkDialOption("12345678")); err == nil {
		t.Fatal("expected error when all phones are offline")
	}
	tr.Close()
	if _, err := tr.Dial(addr, YQRequestMarkDialOption("12345678")); err != net.ErrClosed {
		t.Fatalf("closed Dial: %v", err)
	}
}
