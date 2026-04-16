// Package spoofudp implements a net.PacketConn that sends UDP packets
// with a spoofed (fake) source IP address using a raw socket, while
// receiving via a regular UDP socket bound to the real local IP.
//
// This requires CAP_NET_RAW (Linux) or root privileges.
package spoofudp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	ipv4HeaderLen = 20
	udpHeaderLen  = 8
)

// SpoofPacketConn is a net.PacketConn that:
//   - Sends UDP packets with a configurable fake source IP/port (raw socket).
//   - Receives incoming UDP packets via a regular UDP socket.
//   - Optionally translates fake destination addresses to real ones (server side).
type SpoofPacketConn struct {
	rawFd    int          // raw IPv4 socket (AF_INET/SOCK_RAW/IPPROTO_UDP) for sending
	udpConn  *net.UDPConn // regular UDP socket for receiving
	fakeIP   net.IP       // spoofed source IP (4-byte IPv4)
	fakePort int          // spoofed source port

	// addrMap maps "fakeIP:port" → "realIP:port".
	// Used on the server side so that WriteTo(data, clientFakeAddr)
	// actually sends the packet to the client's real address.
	addrMap map[string]string
	addrMu  sync.RWMutex
}

// NewSpoofPacketConn creates a new SpoofPacketConn.
//
//   - fakeIP:   IP address to use as the packet source (spoofed).
//   - fakePort: UDP port to use as the packet source port.
//   - listenAddr: address for the receiving UDP socket, e.g. "0.0.0.0:12345".
//
// The caller must have CAP_NET_RAW or run as root.
func NewSpoofPacketConn(fakeIP net.IP, fakePort int, listenAddr string) (*SpoofPacketConn, error) {
	ip4 := fakeIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("spoofudp: fakeIP must be an IPv4 address")
	}

	// Raw socket for sending with spoofed source.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("spoofudp: create raw socket: %w", err)
	}

	// Tell the kernel we will supply the IP header ourselves.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("spoofudp: set IP_HDRINCL: %w", err)
	}

	// Regular UDP socket for receiving.
	udpAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("spoofudp: resolve listen addr %q: %w", listenAddr, err)
	}

	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("spoofudp: listen UDP on %s: %w", listenAddr, err)
	}

	return &SpoofPacketConn{
		rawFd:    fd,
		udpConn:  udpConn,
		fakeIP:   ip4,
		fakePort: fakePort,
		addrMap:  make(map[string]string),
	}, nil
}

// AddAddrMapping registers a fake→real address translation.
// When WriteTo is called with fakeAddr as the destination,
// the packet is actually sent to realAddr.
//
// Example (server side):
//
//	conn.AddAddrMapping("10.0.0.1:12345", "192.168.1.5:12345")
func (c *SpoofPacketConn) AddAddrMapping(fakeAddr, realAddr string) {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	c.addrMap[fakeAddr] = realAddr
}

// ReadFrom reads a UDP datagram from the receive socket.
// The returned addr is the source address embedded in the received packet
// (which may be the peer's spoofed/fake IP).
func (c *SpoofPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.udpConn.ReadFrom(b)
}

// WriteTo sends b as a UDP datagram with the spoofed source IP/port.
// If addr is registered in the address map (via AddAddrMapping) the
// packet is forwarded to the mapped real address instead.
func (c *SpoofPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("spoofudp: expected *net.UDPAddr, got %T", addr)
	}

	c.addrMu.RLock()
	realAddrStr, mapped := c.addrMap[udpAddr.String()]
	c.addrMu.RUnlock()

	dst := udpAddr
	if mapped {
		var err error
		dst, err = net.ResolveUDPAddr("udp4", realAddrStr)
		if err != nil {
			return 0, fmt.Errorf("spoofudp: resolve real addr %q: %w", realAddrStr, err)
		}
	}

	return c.sendRaw(b, dst)
}

// sendRaw builds a raw IPv4+UDP packet with the fake source and sends it.
func (c *SpoofPacketConn) sendRaw(payload []byte, dst *net.UDPAddr) (int, error) {
	dstIP := dst.IP.To4()
	if dstIP == nil {
		return 0, fmt.Errorf("spoofudp: destination must be an IPv4 address")
	}

	totalLen := ipv4HeaderLen + udpHeaderLen + len(payload)
	pkt := make([]byte, totalLen)

	// ── IPv4 header (20 bytes) ────────────────────────────────────────
	pkt[0] = 0x45 // Version=4, IHL=5 (5×4=20 bytes, no options)
	pkt[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)      // Identification (0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Flags: DF=1, no fragment
	pkt[8] = 64                                   // TTL
	pkt[9] = syscall.IPPROTO_UDP                  // Protocol = 17
	// [10:12] checksum – filled in below
	copy(pkt[12:16], c.fakeIP) // Source IP  (spoofed)
	copy(pkt[16:20], dstIP)    // Destination IP (real)

	// ── UDP header (8 bytes) ─────────────────────────────────────────
	binary.BigEndian.PutUint16(pkt[20:22], uint16(c.fakePort)) // Src port (spoofed)
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dst.Port))   // Dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(pkt[26:28], 0) // Checksum=0 means disabled for UDP/IPv4

	// ── Payload ──────────────────────────────────────────────────────
	copy(pkt[28:], payload)

	// Compute IPv4 header checksum (RFC 1071).
	csum := ipv4Checksum(pkt[:ipv4HeaderLen])
	binary.BigEndian.PutUint16(pkt[10:12], csum)

	sa := syscall.SockaddrInet4{}
	copy(sa.Addr[:], dstIP)
	if err := syscall.Sendto(c.rawFd, pkt, 0, &sa); err != nil {
		return 0, fmt.Errorf("spoofudp: sendto: %w", err)
	}
	return len(payload), nil
}

// ipv4Checksum computes the one's complement checksum for an IPv4 header.
func ipv4Checksum(header []byte) uint16 {
	sum := 0
	for i := 0; i+1 < len(header); i += 2 {
		sum += int(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += int(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Close closes both the raw send socket and the UDP receive socket.
func (c *SpoofPacketConn) Close() error {
	syscall.Close(c.rawFd)
	return c.udpConn.Close()
}

// LocalAddr returns the spoofed source address (fake IP + fake port).
func (c *SpoofPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.fakeIP, Port: c.fakePort}
}

func (c *SpoofPacketConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *SpoofPacketConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *SpoofPacketConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
