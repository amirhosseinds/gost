package spoofudp

import (
	"fmt"
	"net"
	"strings"

	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// clientMapping holds one known client's fake and real IPv4 addresses.
// The server needs this to route spoofed responses to the right destination.
type clientMapping struct {
	fakeIP string // client's spoofed source IP (e.g. "10.0.0.1")
	realIP string // client's actual IP       (e.g. "203.0.113.5")
}

// metadata holds configuration parsed from the gost service metadata block.
//
// YAML example (service listener):
//
//	listener:
//	  type: spoofudp
//	  metadata:
//	    spoofSrc:     "1.2.3.4"   # server's fake source IP for responses
//	    clientFakeIP: "10.0.0.1"  # client's fake/spoofed source IP
//	    clientRealIP: "5.6.7.8"   # client's actual IP (where to send responses)
//	    key:          "mysecret"   # pre-shared encryption key
//	    # Optional: multiple clients separated by comma
//	    # clientFakeIP: "10.0.0.1,10.0.0.2"
//	    # clientRealIP: "5.6.7.8,9.10.11.12"
type metadata struct {
	// Server's fake source IP – used when sending responses to the client.
	spoofIP net.IP

	// clientMappings describes each known client (fake → real).
	clientMappings []clientMapping

	// Encryption
	key string

	// KCP tuning
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
	keepAlive    int
	backlog      int
}

const defaultBacklog = 128

func (l *spoofListener) parseMetadata(m md.Metadata) error {
	// ── Server's fake source IP ────────────────────────────────────
	ipStr := mdutil.GetString(m, "spoofSrc", "fakeSrc", "spoofIP")
	if ipStr == "" {
		return fmt.Errorf("spoofudp listener: 'spoofSrc' is required")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("spoofudp listener: invalid spoofSrc %q", ipStr)
	}
	if l.md.spoofIP = ip.To4(); l.md.spoofIP == nil {
		return fmt.Errorf("spoofudp listener: spoofSrc must be an IPv4 address")
	}

	// ── Client fake/real IP pairs ──────────────────────────────────
	// Support a single value or comma-separated list.
	fakeIPs := splitCSV(mdutil.GetString(m, "clientFakeIP", "clientFake"))
	realIPs := splitCSV(mdutil.GetString(m, "clientRealIP", "clientReal"))

	if len(fakeIPs) != len(realIPs) {
		return fmt.Errorf("spoofudp listener: clientFakeIP and clientRealIP must have the same number of entries")
	}
	for i, f := range fakeIPs {
		if net.ParseIP(f) == nil {
			return fmt.Errorf("spoofudp listener: invalid clientFakeIP %q", f)
		}
		if net.ParseIP(realIPs[i]) == nil {
			return fmt.Errorf("spoofudp listener: invalid clientRealIP %q", realIPs[i])
		}
		l.md.clientMappings = append(l.md.clientMappings, clientMapping{
			fakeIP: f,
			realIP: realIPs[i],
		})
	}
	if len(l.md.clientMappings) == 0 {
		return fmt.Errorf("spoofudp listener: at least one clientFakeIP / clientRealIP pair is required")
	}

	// ── Encryption key ─────────────────────────────────────────────
	l.md.key = mdutil.GetString(m, "key", "psk")
	if l.md.key == "" {
		return fmt.Errorf("spoofudp listener: 'key' is required")
	}

	// ── KCP tuning ─────────────────────────────────────────────────
	l.md.dataShard = mdutil.GetInt(m, "dataShard")
	if l.md.dataShard <= 0 {
		l.md.dataShard = 10
	}
	l.md.parityShard = mdutil.GetInt(m, "parityShard")
	if l.md.parityShard <= 0 {
		l.md.parityShard = 3
	}
	l.md.mtu = mdutil.GetInt(m, "mtu")
	if l.md.mtu <= 0 {
		l.md.mtu = 1350
	}
	l.md.sndWnd = mdutil.GetInt(m, "sndwnd", "sndWnd")
	if l.md.sndWnd <= 0 {
		l.md.sndWnd = 1024
	}
	l.md.rcvWnd = mdutil.GetInt(m, "rcvwnd", "rcvWnd")
	if l.md.rcvWnd <= 0 {
		l.md.rcvWnd = 1024
	}
	l.md.noDelay = mdutil.GetInt(m, "nodelay", "noDelay")
	l.md.interval = mdutil.GetInt(m, "interval")
	if l.md.interval <= 0 {
		l.md.interval = 30
	}
	l.md.resend = mdutil.GetInt(m, "resend")
	if l.md.resend <= 0 {
		l.md.resend = 2
	}
	l.md.noCongestion = mdutil.GetInt(m, "nc", "noCongestion")
	if l.md.noCongestion <= 0 {
		l.md.noCongestion = 1
	}
	l.md.ackNoDelay = mdutil.GetBool(m, "ackNodelay", "ackNoDelay")
	l.md.keepAlive = mdutil.GetInt(m, "keepalive", "keepAlive")
	if l.md.keepAlive <= 0 {
		l.md.keepAlive = 10
	}
	l.md.backlog = mdutil.GetInt(m, "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return nil
}

// splitCSV splits a comma-separated string and trims whitespace.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
