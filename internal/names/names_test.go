package names

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wargasipil/san_vpn/internal/wire"
)

var (
	network = netip.MustParsePrefix("10.77.0.0/24")
	server  = netip.MustParseAddr("10.77.0.254")
	home    = netip.MustParseAddr("10.77.0.2")
	office  = netip.MustParseAddr("10.77.0.1")
)

func table() *Table {
	return &Table{Domain: "vpn", Server: server, Hosts: map[string]netip.Addr{"home": home, "office": office}}
}

// query builds a DNS query for name and type, with an EDNS record if edns.
func query(t *testing.T, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		var h dnsmessage.ResourceHeader
		if err := h.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	return m
}

func TestAnswer(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  dnsmessage.Type
		rc   dnsmessage.RCode
		a    netip.Addr // the one A record expected, if valid
	}{
		{"office.vpn.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, office},
		{"HOME.Vpn.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, home},
		{"office.vpn.", dnsmessage.TypeALL, dnsmessage.RCodeSuccess, office},
		// The name exists, with no record of that type: an empty answer.
		{"office.vpn.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, netip.Addr{}},
		{"office.vpn.", dnsmessage.Type(65), dnsmessage.RCodeSuccess, netip.Addr{}}, // HTTPS, which browsers ask for
		{"vpn.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, netip.Addr{}},
		{"nobody.vpn.", dnsmessage.TypeA, dnsmessage.RCodeNameError, netip.Addr{}},
		{"www.office.vpn.", dnsmessage.TypeA, dnsmessage.RCodeNameError, netip.Addr{}},
		// Not ours: refused, so a resolver asks elsewhere.
		{"example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, netip.Addr{}},
		{"notvpn.", dnsmessage.TypeA, dnsmessage.RCodeRefused, netip.Addr{}},
	} {
		m := parse(t, Answer(table(), query(t, c.name, c.typ, false)))
		if m.ID != 0x1234 || !m.Response || !m.RecursionDesired || m.RecursionAvailable {
			t.Errorf("%s %v: header %+v", c.name, c.typ, m.Header)
		}
		if m.RCode != c.rc || m.Authoritative != (c.rc != dnsmessage.RCodeRefused) {
			t.Errorf("%s %v: rcode %v authoritative %v, want %v", c.name, c.typ, m.RCode, m.Authoritative, c.rc)
		}
		if len(m.Questions) != 1 || m.Questions[0].Name.String() != c.name {
			t.Errorf("%s %v: question not echoed: %+v", c.name, c.typ, m.Questions)
		}
		switch {
		case c.a.IsValid():
			if len(m.Answers) != 1 {
				t.Fatalf("%s %v: %d answers", c.name, c.typ, len(m.Answers))
			}
			a, ok := m.Answers[0].Body.(*dnsmessage.AResource)
			if !ok || netip.AddrFrom4(a.A) != c.a || m.Answers[0].Header.TTL != TTL || m.Answers[0].Header.Name.String() != c.name {
				t.Errorf("%s %v: answer %+v, want %s", c.name, c.typ, m.Answers[0], c.a)
			}
		case len(m.Answers) != 0:
			t.Errorf("%s %v: answers %+v, want none", c.name, c.typ, m.Answers)
		}
	}
}

func TestAnswerEdgeCases(t *testing.T) {
	// Before the first member list: fail for now, rather than "no such name".
	if m := parse(t, Answer(nil, query(t, "office.vpn.", dnsmessage.TypeA, false))); m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("no table: %v", m.RCode)
	}
	// EDNS is echoed, or resolvers log that the server cannot do it.
	m := parse(t, Answer(table(), query(t, "office.vpn.", dnsmessage.TypeA, true)))
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Type != dnsmessage.TypeOPT || len(m.Answers) != 1 {
		t.Errorf("EDNS query: additionals %+v answers %d", m.Additionals, len(m.Answers))
	}
	if m := parse(t, Answer(table(), query(t, "office.vpn.", dnsmessage.TypeA, false))); len(m.Additionals) != 0 {
		t.Errorf("EDNS in reply to a query without it")
	}
	// Not queries: no reply at all.
	reply := Answer(table(), query(t, "office.vpn.", dnsmessage.TypeA, false))
	if Answer(table(), reply) != nil {
		t.Error("answered a response")
	}
	for _, junk := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)[:11]} {
		if Answer(table(), junk) != nil {
			t.Errorf("answered %v", junk)
		}
	}
	// Another opcode (a NOTIFY, say): not implemented.
	q := query(t, "office.vpn.", dnsmessage.TypeA, false)
	q[2] |= 4 << 3
	if m := parse(t, Answer(table(), q)); m.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("opcode 4: %v", m.RCode)
	}
}

func TestFromNetmap(t *testing.T) {
	nm := &wire.Netmap{
		Network: network,
		Self:    wire.Peer{Name: "home", IP: home},
		Peers: []wire.Peer{
			{Name: "office", IP: office},
			{Name: "stray", IP: netip.MustParseAddr("192.168.1.5")}, // outside the network: not a name of ours
		},
	}
	tb := FromNetmap(nm)
	if tb.Domain != wire.DefaultDomain || tb.Server != server {
		t.Fatalf("domain %q server %s", tb.Domain, tb.Server)
	}
	if len(tb.Hosts) != 2 || tb.Hosts["home"] != home || tb.Hosts["office"] != office {
		t.Fatalf("hosts %v", tb.Hosts)
	}
	if tb.Name("office") != "office.vpn" {
		t.Fatalf("name %q", tb.Name("office"))
	}

	nm.Domain = "corp.internal"
	if tb := FromNetmap(nm); tb.Domain != "corp.internal" {
		t.Fatalf("domain %q", tb.Domain)
	}

	// A relay from before names may have given the address to a member: then
	// there is no server, and that member's traffic is left alone.
	nm.Peers = append(nm.Peers, wire.Peer{Name: "late", IP: server})
	if tb := FromNetmap(nm); tb.Server.IsValid() {
		t.Fatalf("server %s, though a member holds it", tb.Server)
	}

	// A network with no address to spare.
	small := &wire.Netmap{Network: netip.MustParsePrefix("10.77.0.0/30"), Self: wire.Peer{Name: "a", IP: netip.MustParseAddr("10.77.0.1")}}
	if tb := FromNetmap(small); tb.Server.IsValid() {
		t.Fatalf("server %s in a /30", tb.Server)
	}
}
