// Package spoofudp provides a gost listener that accepts KCP+smux tunnel
// connections arriving inside raw UDP packets whose source IP is spoofed.
//
// Stack (bottom → top):
//
//	Raw IPv4 socket  (spoofed source IP for outgoing responses)
//	  └─ SpoofPacketConn  (implements net.PacketConn)
//	       └─ KCP  (reliable, ordered delivery + AES encryption)
//	            └─ smux  (stream multiplexing)
//	                 └─ gost handler
//
// Required privilege: CAP_NET_RAW (Linux) or root.
package spoofudp

import (
	"crypto/sha1"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
	spoofconn "github.com/go-gost/gost/internal/spoofudp"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

func init() {
	registry.ListenerRegistry().Register("spoofudp", NewListener)
}

// spoofListener implements listener.Listener.
type spoofListener struct {
	conn    *spoofconn.SpoofPacketConn
	ln      *kcp.Listener
	cqueue  chan net.Conn
	errChan chan error
	logger  logger.Logger
	md      metadata
	options listener.Options
}

// NewListener creates a new spoofudp listener.
func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &spoofListener{
		logger:  options.Logger,
		options: options,
	}
}

// Init parses metadata, opens a SpoofPacketConn, and starts the KCP listener.
//
// The service addr (l.options.Addr) controls which port to listen on,
// e.g. "0.0.0.0:12345".
func (l *spoofListener) Init(m md.Metadata) error {
	if err := l.parseMetadata(m); err != nil {
		return err
	}

	// Derive the listen port from the service address.
	_, portStr, err := net.SplitHostPort(l.options.Addr)
	if err != nil {
		return fmt.Errorf("spoofudp listener: invalid addr %q: %w", l.options.Addr, err)
	}
	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 {
		return fmt.Errorf("spoofudp listener: invalid port in addr %q", l.options.Addr)
	}

	// Create the spoofed PacketConn.
	// listenAddr = l.options.Addr so the UDP receive socket binds to the same port.
	conn, err := spoofconn.NewSpoofPacketConn(l.md.spoofIP, port, l.options.Addr)
	if err != nil {
		return fmt.Errorf("spoofudp listener: create conn: %w", err)
	}

	// Register the fake-→real address mapping for each known client.
	// KCP will call WriteTo(data, clientFakeIP:port).  Our PacketConn
	// translates that to clientRealIP:port before sending.
	for _, cm := range l.md.clientMappings {
		fakeAddr := fmt.Sprintf("%s:%d", cm.fakeIP, port)
		realAddr := fmt.Sprintf("%s:%d", cm.realIP, port)
		conn.AddAddrMapping(fakeAddr, realAddr)
		l.logger.Infof("spoofudp: addr mapping %s → %s", fakeAddr, realAddr)
	}

	l.conn = conn

	block := deriveBlockCrypt(l.md.key)
	ln, err := kcp.ServeConn(block, l.md.dataShard, l.md.parityShard, conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("spoofudp listener: kcp.ServeConn: %w", err)
	}
	_ = ln.SetReadBuffer(4 * 1024 * 1024)
	_ = ln.SetWriteBuffer(4 * 1024 * 1024)

	l.ln = ln
	l.cqueue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	go l.listenLoop()
	return nil
}

// Accept returns the next accepted stream connection.
func (l *spoofListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case err, ok := <-l.errChan:
		if !ok {
			return nil, listener.ErrClosed
		}
		return nil, err
	}
}

// Addr returns the local address of the KCP listener.
func (l *spoofListener) Addr() net.Addr {
	return l.ln.Addr()
}

// Close closes the listener and the underlying PacketConn.
func (l *spoofListener) Close() error {
	err := l.ln.Close()
	l.conn.Close()
	return err
}

// listenLoop accepts KCP sessions and demuxes them with smux.
func (l *spoofListener) listenLoop() {
	for {
		conn, err := l.ln.AcceptKCP()
		if err != nil {
			l.logger.Error("spoofudp: kcp accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}

		// Apply KCP tuning on the accepted session.
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(l.md.noDelay, l.md.interval, l.md.resend, l.md.noCongestion)
		conn.SetMtu(l.md.mtu)
		conn.SetWindowSize(l.md.sndWnd, l.md.rcvWnd)
		conn.SetACKNoDelay(l.md.ackNoDelay)

		go l.mux(conn)
	}
}

// mux wraps a KCP session in smux and pushes individual streams to cqueue.
func (l *spoofListener) mux(conn net.Conn) {
	defer conn.Close()

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	if l.md.keepAlive > 0 {
		smuxCfg.KeepAliveInterval = time.Duration(l.md.keepAlive) * time.Second
	}

	muxSess, err := smux.Server(conn, smuxCfg)
	if err != nil {
		l.logger.Error("spoofudp: smux server:", err)
		return
	}
	defer muxSess.Close()

	for {
		stream, err := muxSess.AcceptStream()
		if err != nil {
			l.logger.Debug("spoofudp: accept stream:", err)
			return
		}

		select {
		case l.cqueue <- stream:
		case <-stream.GetDieCh():
			stream.Close()
		default:
			stream.Close()
			l.logger.Warnf("spoofudp: queue full, stream from %s discarded",
				stream.RemoteAddr())
		}
	}
}

// deriveBlockCrypt derives an AES-256 BlockCrypt from the key using PBKDF2-SHA1.
func deriveBlockCrypt(key string) kcp.BlockCrypt {
	pass := pbkdf2.Key([]byte(key), []byte("spoofudp-salt"), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)
	return block
}
