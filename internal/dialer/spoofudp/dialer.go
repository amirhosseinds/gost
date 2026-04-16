// Package spoofudp provides a gost dialer that establishes a KCP+smux tunnel
// over raw UDP packets whose source IP is spoofed (faked).
//
// Stack (bottom → top):
//
//	Raw IPv4 socket  (spoofed source IP)
//	  └─ SpoofPacketConn  (implements net.PacketConn)
//	       └─ KCP  (reliable, ordered delivery + AES encryption)
//	            └─ smux  (stream multiplexing)
//	                 └─ gost handler
//
// Required privilege: CAP_NET_RAW (Linux) or root.
package spoofudp

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
	spoofconn "github.com/go-gost/gost/internal/spoofudp"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

func init() {
	registry.DialerRegistry().Register("spoofudp", NewDialer)
}

type spoofDialer struct {
	sessions     map[string]*muxSession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &spoofDialer{
		sessions: make(map[string]*muxSession),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *spoofDialer) Init(m md.Metadata) error {
	return d.parseMetadata(m)
}

// Dial creates (or reuses) a multiplexed KCP session to addr.
// addr must be the server's real IP and port, e.g. "1.2.3.4:12345".
func (d *spoofDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("spoofudp dialer: resolve %q: %w", addr, err)
	}

	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if session != nil && session.IsClosed() {
		// Explicitly close so the underlying PacketConn releases the UDP port.
		session.Close()
		delete(d.sessions, addr)
		ok = false
	}

	if !ok {
		port := d.md.spoofPort
		if port == 0 {
			port = raddr.Port
		}

		listenAddr := fmt.Sprintf("0.0.0.0:%d", port)
		pc, err := spoofconn.NewSpoofPacketConn(d.md.spoofIP, port, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("spoofudp dialer: %w", err)
		}

		// ── Read-side address translation ──────────────────────────────
		// KCP locks onto the first source address it sees and discards
		// packets from any other address.  The server responds using its
		// fake/spoofed IP, not its real IP.  We register a readMap entry
		// so that ReadFrom translates "serverFakeIP:port" → "serverRealIP:port"
		// before handing the packet to KCP.
		if d.md.serverFakeIP != nil {
			fakeAddrStr := fmt.Sprintf("%s:%d", d.md.serverFakeIP.String(), port)
			realAddrStr := fmt.Sprintf("%s:%d", raddr.IP.String(), raddr.Port)
			pc.AddReadAddrMapping(fakeAddrStr, realAddrStr)
			d.logger.Debugf("spoofudp dialer: read mapping %s → %s", fakeAddrStr, realAddrStr)
		}

		session, err = d.initSession(ctx, raddr, pc)
		if err != nil {
			d.logger.Error(err)
			pc.Close()
			return nil, err
		}
		d.sessions[addr] = session
	}

	conn, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(d.sessions, addr)
		return nil, err
	}
	return conn, nil
}

func (d *spoofDialer) initSession(_ context.Context, addr net.Addr, conn *spoofconn.SpoofPacketConn) (*muxSession, error) {
	block := deriveBlockCrypt(d.md.key)

	kcpConn, err := kcp.NewConn(addr.String(), block,
		d.md.dataShard, d.md.parityShard, conn)
	if err != nil {
		return nil, fmt.Errorf("spoofudp dialer: kcp.NewConn: %w", err)
	}
	applyKCPOptions(kcpConn, &d.md)

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	if d.md.keepAlive > 0 {
		smuxCfg.KeepAliveInterval = time.Duration(d.md.keepAlive) * time.Second
	}

	sess, err := smux.Client(kcpConn, smuxCfg)
	if err != nil {
		kcpConn.Close()
		return nil, fmt.Errorf("spoofudp dialer: smux.Client: %w", err)
	}
	return &muxSession{session: sess, conn: conn}, nil
}

// Multiplex implements dialer.Multiplexer.
func (d *spoofDialer) Multiplex() bool { return true }

// ─── helpers ────────────────────────────────────────────────────────────────

func deriveBlockCrypt(key string) kcp.BlockCrypt {
	pass := pbkdf2.Key([]byte(key), []byte("spoofudp-salt"), 4096, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(pass)
	return block
}

func applyKCPOptions(conn *kcp.UDPSession, m *metadata) {
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(m.noDelay, m.interval, m.resend, m.noCongestion)
	conn.SetWindowSize(m.sndWnd, m.rcvWnd)
	conn.SetMtu(m.mtu)
	conn.SetACKNoDelay(m.ackNoDelay)
}

// ─── mux session ────────────────────────────────────────────────────────────

// muxSession wraps a smux session and its underlying SpoofPacketConn.
// Closing the muxSession closes BOTH the smux session AND the UDP socket
// so the port is released immediately for reuse.
type muxSession struct {
	session *smux.Session
	conn    *spoofconn.SpoofPacketConn // closed together with the session
}

func (s *muxSession) GetConn() (net.Conn, error) {
	return s.session.OpenStream()
}

// Close closes the smux session and the underlying SpoofPacketConn (UDP port).
func (s *muxSession) Close() error {
	var err error
	if s.session != nil {
		err = s.session.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	return err
}

func (s *muxSession) IsClosed() bool {
	if s.session == nil {
		return true
	}
	return s.session.IsClosed()
}
