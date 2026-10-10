// Package names lets members find each other by name: office.vpn instead of
// 10.77.0.1.
//
// Every member answers for the names itself, from the member list the relay
// already sends it. There is no name server anywhere on the network: the
// relay is not on the overlay, and making it a WireGuard peer would let it
// read traffic. Instead the member catches DNS queries to the network's DNS
// address (wire.DNSAddr) as they leave the operating system for the tunnel,
// and writes the answer straight back. osnet points the operating system's
// lookups for the domain at that address, or, where it cannot, writes the
// names into the hosts file (HostsBlock).
package names

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// TTL is how long resolvers may keep an answer. Short, because a removed
// member's address goes to the next one to join.
const TTL = 30

// Table is the names of one network, as one member list gave them.
type Table struct {
	Domain string
	// Server is where they are answered, wire.DNSAddr; invalid when the
	// network has no address to spare, or a member already holds it (a relay
	// older than names may have given it out).
	Server netip.Addr
	// Hosts maps each member's name, this machine's own included, to its
	// address.
	Hosts map[string]netip.Addr
}

// FromNetmap builds the table for a member list.
func FromNetmap(nm *wire.Netmap) *Table {
	t := &Table{Domain: nm.Domain, Hosts: map[string]netip.Addr{}}
	if t.Domain == "" {
		t.Domain = wire.DefaultDomain
	}
	server, ok := wire.DNSAddr(nm.Network)
	for _, p := range append([]wire.Peer{nm.Self}, nm.Peers...) {
		if p.Name == "" || !nm.Network.Contains(p.IP) {
			continue
		}
		t.Hosts[strings.ToLower(p.Name)] = p.IP
		if p.IP == server {
			ok = false
		}
	}
	if ok {
		t.Server = server
	}
	return t
}

// Name is a member's full name: office.vpn.
func (t *Table) Name(member string) string { return member + "." + t.Domain }

// Answer answers one DNS query. It returns nil for something that is not a
// query, which is dropped. t may be nil before the first member list: then
// every query fails for now, rather than being told that no such name exists.
func Answer(t *Table, query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil
	}
	// The resolver's EDNS record, if any: echo one back, or it may decide
	// this server cannot do EDNS and keep saying so in its logs.
	edns := false
	if p.SkipAllAnswers() == nil && p.SkipAllAuthorities() == nil {
		for {
			ah, err := p.AdditionalHeader()
			if err != nil {
				break
			}
			edns = edns || ah.Type == dnsmessage.TypeOPT
			if p.SkipAdditional() != nil {
				break
			}
		}
	}

	rh := dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired}
	var answer *dnsmessage.AResource
	switch {
	case h.OpCode != 0:
		rh.RCode = dnsmessage.RCodeNotImplemented
	case len(qs) != 1:
		rh.RCode = dnsmessage.RCodeFormatError
	case t == nil:
		rh.RCode = dnsmessage.RCodeServerFailure
	default:
		rh.RCode, answer = t.lookup(qs[0])
		rh.Authoritative = rh.RCode != dnsmessage.RCodeRefused
	}

	b := dnsmessage.NewBuilder(nil, rh)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil
	}
	if answer != nil {
		if err := b.AResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: TTL}, *answer); err != nil {
			return nil
		}
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			return nil
		}
		var oh dnsmessage.ResourceHeader
		if err := oh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			return nil
		}
		if err := b.OPTResource(oh, dnsmessage.OPTResource{}); err != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// lookup answers one question: an address for a member's name, no data for
// other types of record or the domain itself, no such name for anything else
// in the domain, and a refusal outside it.
func (t *Table) lookup(q dnsmessage.Question) (dnsmessage.RCode, *dnsmessage.AResource) {
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	if q.Class != dnsmessage.ClassINET && q.Class != dnsmessage.ClassANY {
		return dnsmessage.RCodeRefused, nil
	}
	if name == t.Domain {
		return dnsmessage.RCodeSuccess, nil
	}
	label, ok := strings.CutSuffix(name, "."+t.Domain)
	if !ok {
		return dnsmessage.RCodeRefused, nil
	}
	ip, ok := t.Hosts[label]
	if !ok {
		return dnsmessage.RCodeNameError, nil
	}
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeALL {
		// AAAA, HTTPS and the rest: the name exists but has none. Saying so
		// at once keeps browsers and resolvers from waiting on a timeout.
		return dnsmessage.RCodeSuccess, nil
	}
	return dnsmessage.RCodeSuccess, &dnsmessage.AResource{A: ip.As4()}
}
