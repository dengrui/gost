// Package yqmobile provides a gomobile-compatible reverse QUIC proxy client.
package yqmobile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	gost "github.com/ginuerzh/gost"
	quic "github.com/quic-go/quic-go"
)

var (
	clientMu   sync.Mutex
	listenerMu sync.Mutex
	activeRun  *clientRun
	clientTLS  tls.Config
	listener   ConnectionListener
)

type ConnectionListener interface {
	OnStateChanged(status string, errorMessage string)
}

func SetConnectionListener(callback ConnectionListener) error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	listener = callback
	return nil
}

type clientRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func Start(serverAddr string) error {
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil || host == "" {
		return errors.New("serverAddr must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid server port")
	}
	clientMu.Lock()
	defer clientMu.Unlock()
	if activeRun != nil {
		return errors.New("yqmobile is already running; call Stop first")
	}
	config := clientTLS.Clone()
	config.NextProtos = []string{"quic/v1"}
	ctx, cancel := context.WithCancel(context.Background())
	run := &clientRun{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	activeRun = run
	go run.loop(serverAddr, config)
	return nil
}

func Stop() {
	clientMu.Lock()
	run := activeRun
	if run == nil {
		clientMu.Unlock()
		return
	}
	run.cancel()
	clientMu.Unlock()
	<-run.done
	clientMu.Lock()
	if activeRun == run {
		activeRun = nil
	}
	clientMu.Unlock()
}

// ConfigureTLS configures server verification before Start. Empty caPEM uses
// system roots; serverName may override the certificate hostname. insecure is
// only for development. Go runtime internals are not exposed to gomobile.
func ConfigureTLS(caPEM, serverName string, insecure bool) error {
	config := tls.Config{ServerName: serverName, InsecureSkipVerify: insecure}
	if caPEM != "" {
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM([]byte(caPEM)) {
			return errors.New("invalid CA certificate PEM")
		}
	}
	clientMu.Lock()
	defer clientMu.Unlock()
	if activeRun != nil {
		return errors.New("call Stop before configuring TLS")
	}
	// Preserve an optional client identity.
	config.Certificates = clientTLS.Certificates
	clientTLS = config
	return nil
}

// SetClientCertificate configures optional mutual TLS; two empty strings clear it.
func SetClientCertificate(certPEM, keyPEM string) error {
	var certificates []tls.Certificate
	if certPEM != "" || keyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return err
		}
		certificates = []tls.Certificate{cert}
	}
	clientMu.Lock()
	defer clientMu.Unlock()
	if activeRun != nil {
		return errors.New("call Stop before configuring TLS")
	}
	clientTLS.Certificates = certificates
	return nil
}

func (r *clientRun) notify(status string, err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	listenerMu.Lock()
	callback := listener
	listenerMu.Unlock()

	if callback != nil {
		callback.OnStateChanged(status, message)
	}
}

func (r *clientRun) loop(addr string, config *tls.Config) {
	defer close(r.done)
	delay := time.Second
	for r.ctx.Err() == nil {
		r.notify("connecting", nil)
		ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
		conn, err := quic.DialAddr(ctx, addr, config, &quic.Config{
			KeepAlivePeriod: 10 * time.Second, MaxIdleTimeout: 60 * time.Second,
		})
		// 超时的context不用了，可以立即清理相关资源。
		cancel()
		if err == nil {
			r.notify("connected", nil)
			delay = time.Second
			err = r.serve(conn)
		} else if r.ctx.Err() == nil {
			r.notify("connect_failed", err)
		}
		if r.ctx.Err() != nil {
			return
		}
		r.notify("reconnecting", err)
		timer := time.NewTimer(delay)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (r *clientRun) serve(conn quic.Connection) error {
	var workers sync.WaitGroup
	// Closing the QUIC connection interrupts active stream reads and writes.
	defer func() { conn.CloseWithError(0, "phone stopped"); workers.Wait() }()
	for {
		stream, err := conn.AcceptStream(r.ctx)
		if err != nil {
			return err
		}
		c := &streamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
		workers.Go(func() {
			defer c.Close()
			gost.AutoHandler(gost.TimeoutHandlerOption(5 * time.Second)).Handle(c)
		})
	}
}

// streamConn adapts each stream, not the entire QUIC session, to net.Conn.
type streamConn struct {
	quic.Stream
	local, remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }
func (c *streamConn) Close() error         { c.CancelRead(0); return c.Stream.Close() }
