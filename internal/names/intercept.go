package names

import (
	"encoding/binary"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// Intercept wraps the tunnel WireGuard reads from. A DNS query over UDP to
// server (wire.DNSAddr of the network) never reaches WireGuard: it is
// answered on the spot and the reply written back into the tunnel, as if it
// had come from a name server at that address. Everything else passes through
// untouched. Nothing listens on port 53, so this cannot clash with a DNS
// server the machine already runs.
//
// table gives the current names: nil until the first member list, when
// queries fail for the moment. If the table says a member holds server, its
// traffic passes through too.
func Intercept(dev tun.Device, server netip.Addr, table func() *Table) tun.Device {
	return &interceptor{Device: dev, server: server, table: table}
}

type interceptor struct {
	tun.Device
	server netip.Addr
	table  func() *Table
}

func (d *interceptor) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	t := d.table()
	if t != nil && t.Server != d.server {
		return n, err
	}
	for i := range n {
		if sizes[i] < 1 {
			continue
		}
		reply, caught := answerPacket(t, d.server, bufs[i][offset:offset+sizes[i]])
		if !caught {
			continue
		}
		// Taken out of the batch: WireGuard skips empty slots.
		sizes[i] = 0
		if reply == nil {
			continue
		}
		buf := make([]byte, offset+len(reply))
		copy(buf[offset:], reply)
		_, _ = d.Device.Write([][]byte{buf}, offset)
	}
	return n, err
}

// answerPacket handles one IPv4 packet leaving the operating system. caught
// says it was a DNS query to server, which WireGuard must not see; reply is
// the packet to send back, nil for a query that gets none.
func answerPacket(t *Table, server netip.Addr, pkt []byte) (reply []byte, caught bool) {
	if !server.IsValid() || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total < ihl+8 || total > len(pkt) || pkt[9] != 17 {
		return nil, false
	}
	if netip.AddrFrom4([4]byte(pkt[16:20])) != server {
		return nil, false
	}
	udp := pkt[ihl:total]
	if binary.BigEndian.Uint16(udp[2:4]) != 53 {
		return nil, false
	}
	// A fragment, or a datagram that does not fit its packet: a query this
	// small is never either, so drop it rather than guess.
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return nil, true
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		return nil, true
	}
	resp := Answer(t, udp[8:ulen])
	if resp == nil {
		return nil, true
	}
	client := netip.AddrFrom4([4]byte(pkt[12:16]))
	return udpPacket(server, client, 53, binary.BigEndian.Uint16(udp[0:2]), resp), true
}

// udpPacket builds an IPv4 UDP packet with both checksums.
func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20], 0))

	u := p[20:]
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	// The pseudo-header: addresses, protocol, length.
	pseudo := sum(p[12:20], 0) + 17 + uint32(len(u))
	c := checksum(u, pseudo)
	if c == 0 {
		c = 0xffff // zero means "no checksum" in UDP
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return p
}

// sum adds b as big-endian 16-bit words onto acc.
func sum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// checksum is the Internet checksum of b, starting from acc.
func checksum(b []byte, acc uint32) uint16 {
	acc = sum(b, acc)
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}
