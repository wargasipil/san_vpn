package node_test

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// lookup asks the network's DNS address for name over UDP, from inside n's
// tunnel: the path a query takes once the operating system sends the domain
// there.
func lookup(t *testing.T, n *testNode, name string, typ dnsmessage.Type) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	server, ok := wire.DNSAddr(n.cfg.Network)
	if !ok {
		t.Fatalf("no DNS address in %s", n.cfg.Network)
	}
	c, err := n.net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id := uint16(rand.Uint32())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	nr, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s: no answer from %s: %v", name, server, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:nr]); err != nil || m.ID != id {
		t.Fatalf("%s: bad answer (id %d, want %d): %v", name, m.ID, id, err)
	}
	var ips []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, netip.AddrFrom4(r.A))
		}
	}
	return m.RCode, ips
}

// resolvesTo reports whether name has exactly the address want.
func resolvesTo(t *testing.T, n *testNode, name string, want netip.Addr) bool {
	rc, ips := lookup(t, n, name, dnsmessage.TypeA)
	return rc == dnsmessage.RCodeSuccess && len(ips) == 1 && ips[0] == want
}

func TestNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)
	home := joinAndStart(t, ctx, r.invite(t, "home"))
	office := joinAndStart(t, ctx, r.invite(t, "office"))
	eventually(t, "home to see office", func() bool { return sees(home, "office", true) })

	// Each member answers for every member, itself included.
	if !resolvesTo(t, home, "office.vpn", office.cfg.IP) || !resolvesTo(t, home, "home.vpn", home.cfg.IP) || !resolvesTo(t, office, "HOME.vpn", home.cfg.IP) {
		t.Fatal("names do not resolve")
	}
	if rc, ips := lookup(t, home, "office.vpn", dnsmessage.TypeAAAA); rc != dnsmessage.RCodeSuccess || len(ips) != 0 {
		t.Fatalf("AAAA: %v %v, want an empty answer", rc, ips)
	}
	if rc, _ := lookup(t, home, "nobody.vpn", dnsmessage.TypeA); rc != dnsmessage.RCodeNameError {
		t.Fatalf("unknown name: %v", rc)
	}
	if rc, _ := lookup(t, home, "example.com", dnsmessage.TypeA); rc != dnsmessage.RCodeRefused {
		t.Fatalf("outside the domain: %v", rc)
	}
	st := home.node.Status()
	if st.Domain != "vpn" || st.DNS != netip.MustParseAddr("10.77.0.254") {
		t.Fatalf("status names: %q at %s", st.Domain, st.DNS)
	}

	// Traffic still flows beside the caught queries.
	echo(t, office, 7000)
	if err := roundTrip(ctx, home, office, 7000, "still here"); err != nil {
		t.Fatal(err)
	}

	// A member joining later is a name at once; a removed one is gone.
	lab := joinAndStart(t, ctx, r.invite(t, "lab"))
	eventually(t, "home to know lab.vpn", func() bool { return resolvesTo(t, home, "lab.vpn", lab.cfg.IP) })
	var rs relay.State
	if err := r.store.Update(ctx, &rs, func() error { _, err := rs.Remove("lab"); return err }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "lab.vpn to be gone", func() bool {
		rc, _ := lookup(t, home, "lab.vpn", dnsmessage.TypeA)
		return rc == dnsmessage.RCodeNameError
	})

	// The relay's domain reaches every member without a restart.
	if err := r.store.Update(ctx, &rs, func() error { rs.Domain = "corp.internal"; return nil }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "office.corp.internal", func() bool { return resolvesTo(t, home, "office.corp.internal", office.cfg.IP) })
	if rc, _ := lookup(t, home, "office.vpn", dnsmessage.TypeA); rc != dnsmessage.RCodeRefused {
		t.Fatalf("old domain after the change: %v", rc)
	}
}
