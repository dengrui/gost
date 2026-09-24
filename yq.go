package gost

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"
	quic "github.com/quic-go/quic-go"
)

// yqTransporter accepts phone-initiated QUIC sessions and opens streams on them.
// The phone must accept server-initiated bidirectional streams and run the
// configured proxy protocol (HTTP CONNECT by default) on each stream.
type yqTransporter struct {
	listener *quic.Listener
	mu       sync.Mutex
	sessions []quic.Connection
	next     uint64
	closed   bool
}

// YQTransporter starts a reverse QUIC listener. A nil TLS config uses the
// server certificate configured by GOST. The owner may call Close to stop it.
func YQTransporter(addr string, config *tls.Config) (Transporter, error) {
	if config == nil {
		config = DefaultTLSConfig
	}
	if config == nil {
		return nil, errors.New("yq: server TLS configuration is required")
	}
	listener, err := quic.ListenAddr(addr, tlsConfigQUICALPN(config), &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	tr := &yqTransporter{listener: listener}
	go tr.acceptLoop()
	log.Logf("[yq] listening on %s (QUIC/UDP)", listener.Addr())
	return tr, nil
}

func (tr *yqTransporter) acceptLoop() {
	for {
		conn, err := tr.listener.Accept(context.Background())
		if err != nil {
			tr.Close()
			return
		}
		tr.mu.Lock()
		if tr.closed {
			tr.mu.Unlock()
			conn.CloseWithError(0, "listener closed")
			return
		}
		tr.sessions = append(tr.sessions, conn)
		tr.mu.Unlock()
		log.Logf("[yq] phone connected: %s", conn.RemoteAddr())
		go func() {
			<-conn.Context().Done()
			tr.mu.Lock()
			for i, session := range tr.sessions {
				
				if session == conn {
					tr.sessions = append(tr.sessions[:i], tr.sessions[i+1:]...)
					break
				}
			}
			tr.mu.Unlock()
			log.Logf("[yq] phone disconnected: %s", conn.RemoteAddr())
		}()
	}
}

// Dial selects an online phone; addr is the listener address, not a dial target.
func (tr *yqTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}
	tr.mu.Lock()
	if tr.closed {
		tr.mu.Unlock()
		return nil, net.ErrClosed
	}
	// Remove closed sessions even if their cleanup goroutine has not run yet.
	live := tr.sessions[:0]
	for _, session := range tr.sessions {
		if session.Context().Err() == nil {
			live = append(live, session)
		}
	}
	tr.sessions = live
	if len(live) == 0 {
		tr.mu.Unlock()
		return nil, errors.New("yq: no phone connected")
	}
	session := live[tr.next%uint64(len(live))]
	tr.next++
	tr.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &yqStreamConn{quicConn: &quicConn{
		Stream: stream, laddr: session.LocalAddr(), raddr: session.RemoteAddr(),
	}}, nil
}

func (tr *yqTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *yqTransporter) Multiplex() bool { return true }

// Close stops accepting phones and closes all existing sessions.
func (tr *yqTransporter) Close() error {
	tr.mu.Lock()
	if tr.closed {
		tr.mu.Unlock()
		return nil
	}
	tr.closed = true
	sessions := tr.sessions
	tr.sessions = nil
	tr.mu.Unlock()
	err := tr.listener.Close()
	for _, session := range sessions {
		session.CloseWithError(0, "listener closed")
	}
	return err
}

type yqStreamConn struct{ *quicConn }

func (c *yqStreamConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}

var _ Transporter = (*yqTransporter)(nil)
var _ net.Conn = (*yqStreamConn)(nil)
