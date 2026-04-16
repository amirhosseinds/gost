// Package spoofudp implements a net.PacketConn that sends UDP packets
// with a spoofed (fake) source IP address using a raw socket, while
// receiving via a regular UDP socket bound to the real local IP.
//
// This requires CAP_NET_RAW (Linux) or root privileges.
package spoofudp

import (
	"context"
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
//   - Translates write-side fake destinations to real addresses (server side).
//   - Translates read-side fake source addresses to real ones (client side).
type SpoofPacketConn struct {
	rawFd    int          // raw IPv4 socket (AF_INET/SOCK_RAW/IPPROTO_UDP) for sending
	udpConn  *net.UDPConn // regular UDP socket for receiving
	fakeIP   net.IP       // spoofed source IP (4-byte IPv4)
	fakePort int          // spoofed source port

	// writeMap: fake_dst_addr → real_dst_addr
	// Server side: WriteTo(data, clientFakeIP) → actually sends to clientRealIP.
	writeMap map[string]string

	// readMap: fake_src_addr → real_src_addr
	// Client side: when a packet arrives from serverFakeIP, pretend it came from
	// serverRealIP so KCP's source-address filter accepts it.
	readMap map[string]string

	addrMu sync.RWMutex
}

// NewSpoofPacketConn creates a new SpoofPacketConn.
//
//   - fakeIP:     IP address to use as the packet source (spoofed).
//   - fakePort:   UDP port to use as the packet source port.
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
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("spoofudp: set IP_HDRINCL: %w", err)
	}

	// Regular UDP socket for receiving.
	// SO_REUSEPORT lets a replacement socket reclaim the port immediately
	// after the previous one is closed (avoids "address already in use").
	// SO_REUSEPORT = 15 (0xF) on Linux x86/x64/arm.
	const soReusePort = 0xF
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			})
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("spoofudp: listen UDP on %s: %w", listenAddr, err)
	}
	udpConn := pc.(*net.UDPConn)

	return &SpoofPacketConn{
		rawFd:    fd,
		udpConn:  udpConn,
		fakeIP:   ip4,
		fakePort: fakePort,
		writeMap: make(map[string]string),
		readMap:  make(map[string]string),
	}, nil
}

// AddAddrMapping registers a write-side fake→real address translation.
// When WriteTo is called with fakeAddr as the destination,
// the packet is actually sent to realAddr.
// Used on the server side: clientFakeIP:port → clientRealIP:port.
func (c *SpoofPacketConn) AddAddrMapping(fakeAddr, realAddr string) {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	c.writeMap[fakeAddr] = realAddr
}

// AddReadAddrMapping registers a read-side fake→real source translation.
// When a packet is received whose source matches fakeAddr, ReadFrom returns
// realAddr as the source instead.
// Used on the client side: serverFakeIP:port → serverRealIP:port.
// This is necessary because KCP's source-filter only accepts packets from
// the address the session was dialed to (the real server address).
func (c *SpoofPacketConn) AddReadAddrMapping(fakeAddr, realAddr string) {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	c.readMap[fakeAddr] = realAddr
}

// ReadFrom reads a UDP datagram.
// If the source address is registered in the read map it is translated
// before being returned, hiding the spoofing from upper layers (e.g. KCP).
func (c *SpoofPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.udpConn.ReadFrom(b)
	if err != nil || addr == nil {
		return
	}

	c.addrMu.RLock()
	realAddrStr, mapped := c.readMap[addr.String()]
	c.addrMu.RUnlock()

	if mapped {
		if ra, parseErr := net.ResolveUDPAddr("udp4", realAddrStr); parseErr == nil {
			addr = ra
		}
	}
	return
}

// WriteTo sends b as a UDP datagram with the spoofed source IP/port.
// If the destination is registered in the write map (via AddAddrMapping)
// the packet is forwarded to the mapped real address instead.
func (c *SpoofPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("spoofudp: expected *net.UDPAddr, got %T", addr)
	}

	c.addrMu.RLock()
	realAddrStr, mapped := c.writeMap[udpAddr.String()]
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
// The UDP checksum is computed (RFC 768 pseudo-header) for maximum
// compatibility with network equipment that rejects checksum=0.
func (c *SpoofPacketConn) sendRaw(payload []byte, dst *net.UDPAddr) (int, error) {
	dstIP := dst.IP.To4()
	if dstIP == nil {
		return 0, fmt.Errorf("spoofudp: destination must be an IPv4 address")
	}

	totalLen := ipv4HeaderLen + udpHeaderLen + len(payload)
	pkt := make([]byte, totalLen)

	srcPort := uint16(c.fakePort)
	dstPort := uint16(dst.Port)
	udpLen := uint16(udpHeaderLen + len(payload))

	// ── IPv4 header (20 bytes) ────────────────────────────────────────
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)      // ID
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF=1
	pkt[8] = 64                                   // TTL
	pkt[9] = syscall.IPPROTO_UDP                  // Protocol=17
	// [10:12] IP checksum – filled after
	copy(pkt[12:16], c.fakeIP) // Source IP (spoofed)
	copy(pkt[16:20], dstIP)    // Destination IP

	// ── UDP header (8 bytes) ─────────────────────────────────────────
	binary.BigEndian.PutUint16(pkt[20:22], srcPort) // Src port
	binary.BigEndian.PutUint16(pkt[22:24], dstPort) // Dst port
	binary.BigEndian.PutUint16(pkt[24:26], udpLen)  // UDP length
	// [26:28] UDP checksum – computed below

	// ── Payload ──────────────────────────────────────────────────────
	copy(pkt[28:], payload)

	// ── UDP checksum (RFC 768 pseudo-header) ─────────────────────────
	udpCsum := udpChecksum(c.fakeIP, dstIP, srcPort, dstPort, udpLen, pkt[28:28+len(payload)])
	binary.BigEndian.PutUint16(pkt[26:28], udpCsum)

	// ── IPv4 header checksum (RFC 1071) ──────────────────────────────
	ipCsum := onesComplementChecksum(pkt[:ipv4HeaderLen])
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum)

	sa := syscall.SockaddrInet4{}
	copy(sa.Addr[:], dstIP)
	if err := syscall.Sendto(c.rawFd, pkt, 0, &sa); err != nil {
		return 0, fmt.Errorf("spoofudp: sendto: %w", err)
	}
	return len(payload), nil
}

// udpChecksum computes the UDP checksum using the IPv4 pseudo-header (RFC 768).
func udpChecksum(srcIP, dstIP net.IP, srcPort, dstPort, udpLen uint16, payload []byte) uint16 {
	// Pseudo-header: src IP (4) + dst IP (4) + zero (1) + proto (1) + UDP len (2)
	pseudo := make([]byte, 12+udpHeaderLen+len(payload))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], udpLen)
	// UDP header inside pseudo for checksum
	binary.BigEndian.PutUint16(pseudo[12:14], srcPort)
	binary.BigEndian.PutUint16(pseudo[14:16], dstPort)
	binary.BigEndian.PutUint16(pseudo[16:18], udpLen)
	binary.BigEndian.PutUint16(pseudo[18:20], 0) // checksum=0 placeholder
	copy(pseudo[20:], payload)

	csum := onesComplementChecksum(pseudo)
	if csum == 0 {
		csum = 0xFFFF // RFC 768: transmit 0xFFFF if computed sum is 0
	}
	return csum
}

// onesComplementChecksum is the RFC 1071 one's complement sum.
func onesComplementChecksum(data []byte) uint16 {
	sum := 0
	for i := 0; i+1 < len(data); i += 2 {
		sum += int(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += int(data[len(data)-1]) << 8
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
