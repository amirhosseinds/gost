package spoofudp

import (
	"fmt"
	"net"

	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// metadata holds configuration parsed from the gost service metadata block.
//
// YAML example (chain node):
//
//	dialer:
//	  type: spoofudp
//	  metadata:
//	    spoofSrc:  "10.0.0.1"   # fake source IP the client will use
//	    spoofPort: 12345         # fake source port (defaults to dst port)
//	    key:       "mysecret"    # pre-shared encryption key
//	    # optional KCP tuning
//	    mtu:   1350
//	    sndwnd: 1024
//	    rcvwnd: 1024
type metadata struct {
	// Spoofing parameters
	spoofIP   net.IP // fake source IPv4 (required)
	spoofPort int    // fake source port  (0 → use dst port)

	// Encryption
	key string // pre-shared key for AES-256 via PBKDF2 (required)

	// KCP tuning (sensible defaults applied in parseMetadata)
	dataShard    int
	parityShard  int
	mtu          int
	sndWnd       int
	rcvWnd       int
	noDelay      int
	interval     int
	resend       int
	noCongestion int
	ackNoDelay   bool
	keepAlive    int // seconds; 0 = use smux default
}

func (d *spoofDialer) parseMetadata(m md.Metadata) error {
	// ── Spoofed source IP ──────────────────────────────────────────
	ipStr := mdutil.GetString(m, "spoofSrc", "fakeSrc", "spoofIP")
	if ipStr == "" {
		return fmt.Errorf("spoofudp dialer: 'spoofSrc' is required")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("spoofudp dialer: invalid spoofSrc %q", ipStr)
	}
	if d.md.spoofIP = ip.To4(); d.md.spoofIP == nil {
		return fmt.Errorf("spoofudp dialer: spoofSrc must be an IPv4 address")
	}

	// ── Optional spoofed source port ───────────────────────────────
	d.md.spoofPort = mdutil.GetInt(m, "spoofPort", "port")

	// ── Encryption key ─────────────────────────────────────────────
	d.md.key = mdutil.GetString(m, "key", "psk")
	if d.md.key == "" {
		return fmt.Errorf("spoofudp dialer: 'key' is required")
	}

	// ── KCP tuning ─────────────────────────────────────────────────
	d.md.dataShard = mdutil.GetInt(m, "dataShard")
	if d.md.dataShard <= 0 {
		d.md.dataShard = 10
	}
	d.md.parityShard = mdutil.GetInt(m, "parityShard")
	if d.md.parityShard <= 0 {
		d.md.parityShard = 3
	}
	d.md.mtu = mdutil.GetInt(m, "mtu")
	if d.md.mtu <= 0 {
		d.md.mtu = 1350
	}
	d.md.sndWnd = mdutil.GetInt(m, "sndwnd", "sndWnd")
	if d.md.sndWnd <= 0 {
		d.md.sndWnd = 1024
	}
	d.md.rcvWnd = mdutil.GetInt(m, "rcvwnd", "rcvWnd")
	if d.md.rcvWnd <= 0 {
		d.md.rcvWnd = 1024
	}
	// fast mode defaults: nodelay=0 interval=30 resend=2 nc=1
	d.md.noDelay = mdutil.GetInt(m, "nodelay", "noDelay")
	d.md.interval = mdutil.GetInt(m, "interval")
	if d.md.interval <= 0 {
		d.md.interval = 30
	}
	d.md.resend = mdutil.GetInt(m, "resend")
	if d.md.resend <= 0 {
		d.md.resend = 2
	}
	d.md.noCongestion = mdutil.GetInt(m, "nc", "noCongestion")
	if d.md.noCongestion <= 0 {
		d.md.noCongestion = 1
	}
	d.md.ackNoDelay = mdutil.GetBool(m, "ackNodelay", "ackNoDelay")
	d.md.keepAlive = mdutil.GetInt(m, "keepalive", "keepAlive")
	if d.md.keepAlive <= 0 {
		d.md.keepAlive = 10
	}

	return nil
}
