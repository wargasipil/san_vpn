package names

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN hands out a fixed batch of packets and records what is written.
type fakeTUN struct {
	tun.Device // unused methods
	in         [][]byte
	written    [][]byte
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for ; n < len(f.in) && n < len(bufs); n++ {
		sizes[n] = copy(bufs[n][offset:], f.in[n])
	}
	f.in = f.in[n:]
	return n, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

// readBatch reads one batch through dev the way WireGuard does, with the
// same headroom, and returns what WireGuard would get.
func readBatch(t *testing.T, dev tun.Device, n int) [][]byte {
	t.Helper()
	const offset = 16
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, n)
	got, err := dev.Read(bufs, sizes, offset)
	if err != nil || got != n {
		t.Fatalf("read %d, %v; want %d", got, err, n)
	}
	out := make([][]byte, n)
	for i := range n {
		out[i] = bufs[i][offset : offset+sizes[i]]
	}
	return out
}

// checkUDP checks both checksums of an IPv4 UDP packet and returns its
// addresses and payload.
func checkUDP(t *testing.T, p []byte) (src, dst netip.AddrPort, payload []byte) {
	t.Helper()
	if len(p) < 28 || p[0] != 0x45 || p[9] != 17 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		t.Fatalf("not an IPv4 UDP packet: % x", p)
	}
	if checksum(p[:20], 0) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}
	u := p[20:]
	if int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
		t.Fatal("bad UDP length")
	}
	if checksum(u, sum(p[12:20], 0)+17+uint32(len(u))) != 0 {
		t.Fatal("bad UDP checksum")
	}
	src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(u[0:2]))
	dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[16:20])), binary.BigEndian.Uint16(u[2:4]))
	return src, dst, u[8:]
}

func TestInterceptAnswersQueriesToTheServer(t *testing.T) {
	client := netip.MustParseAddr("10.77.0.2")
	q := query(t, "office.vpn.", dnsmessage.TypeA, false)
	toServer := udpPacket(client, server, 40000, 53, q)
	otherPort := udpPacket(client, server, 40000, 80, []byte("not dns"))
	otherDNS := udpPacket(client, netip.MustParseAddr("8.8.8.8"), 40000, 53, q)
	toPeer := udpPacket(client, office, 40000, 53, q) // a member running its own DNS server
	f := &fakeTUN{in: [][]byte{otherPort, toServer, otherDNS, toPeer}}

	got := readBatch(t, Intercept(f, server, table), 4)
	// Only the query to the server is taken out; WireGuard gets the rest.
	if len(got[1]) != 0 {
		t.Fatal("WireGuard got the DNS query")
	}
	for i, want := range [][]byte{otherPort, nil, otherDNS, toPeer} {
		if i != 1 && !bytes.Equal(got[i], want) {
			t.Fatalf("packet %d changed or dropped", i)
		}
	}
	if len(f.written) != 1 {
		t.Fatalf("%d replies written, want 1", len(f.written))
	}
	src, dst, payload := checkUDP(t, f.written[0])
	if src != netip.AddrPortFrom(server, 53) || dst != netip.AddrPortFrom(client, 40000) {
		t.Fatalf("reply from %s to %s", src, dst)
	}
	m := parse(t, payload)
	if len(m.Answers) != 1 || netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A) != office {
		t.Fatalf("reply %+v", m)
	}
}

func TestInterceptBeforeAndAside(t *testing.T) {
	client := netip.MustParseAddr("10.77.0.2")
	q := udpPacket(client, server, 40000, 53, query(t, "office.vpn.", dnsmessage.TypeA, false))

	// Before the first member list: caught, and told to try again.
	f := &fakeTUN{in: [][]byte{q}}
	if got := readBatch(t, Intercept(f, server, func() *Table { return nil }), 1); len(got[0]) != 0 || len(f.written) != 1 {
		t.Fatalf("no table: passed %d bytes, wrote %d", len(got[0]), len(f.written))
	}
	_, _, payload := checkUDP(t, f.written[0])
	if m := parse(t, payload); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("no table: %v", m.RCode)
	}

	// A member holds the address: its traffic, not ours.
	f = &fakeTUN{in: [][]byte{q}}
	held := func() *Table { tb := table(); tb.Server = netip.Addr{}; return tb }
	if got := readBatch(t, Intercept(f, server, held), 1); !bytes.Equal(got[0], q) || len(f.written) != 0 {
		t.Fatal("caught a query to an address a member holds")
	}

	// A fragment: caught, no reply.
	frag := bytes.Clone(q)
	frag[6] |= 0x20 // more fragments
	f = &fakeTUN{in: [][]byte{frag}}
	if got := readBatch(t, Intercept(f, server, table), 1); len(got[0]) != 0 || len(f.written) != 0 {
		t.Fatal("fragment answered or passed on")
	}

	// IPv6, and truncated junk: passed through untouched.
	v6 := make([]byte, 60)
	v6[0] = 0x60
	short := q[:24]
	f = &fakeTUN{in: [][]byte{v6, short}}
	if got := readBatch(t, Intercept(f, server, table), 2); !bytes.Equal(got[0], v6) || !bytes.Equal(got[1], short) || len(f.written) != 0 {
		t.Fatal("non-IPv4 or short packet touched")
	}
}
