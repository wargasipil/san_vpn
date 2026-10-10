package wire_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/wire"
)

func mustKey(t *testing.T) wire.Key {
	t.Helper()
	k, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// WireGuard rejects nothing, but clamping is what makes our keys identical in
// shape to `wg genkey`'s, so a key can move between the two.
func TestGenerateKeyIsClamped(t *testing.T) {
	for range 50 {
		k := mustKey(t)
		if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
			t.Fatalf("key %x is not clamped", k)
		}
	}
}

func TestSharedIsSymmetric(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	ab, err := a.Shared(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.Shared(a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("the two sides computed different secrets")
	}
}

// A low-order point would make the shared secret all zeroes, known to anyone.
func TestSharedRejectsLowOrderKey(t *testing.T) {
	if _, err := mustKey(t).Shared(wire.Key{}); err == nil {
		t.Fatal("agreement with the zero key succeeded")
	}
}

func TestKeyEncodings(t *testing.T) {
	k := mustKey(t).Public()

	if got, err := wire.ParseKey(k.String()); err != nil || got != k {
		t.Fatalf("base64 round trip: %v, %v", got, err)
	}
	if got, err := wire.ParseHexKey(k.Hex()); err != nil || got != k {
		t.Fatalf("hex round trip: %v, %v", got, err)
	}

	b, err := json.Marshal(struct{ K wire.Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	var back struct{ K wire.Key }
	if err := json.Unmarshal(b, &back); err != nil || back.K != k {
		t.Fatalf("json round trip: %s -> %v, %v", b, back.K, err)
	}

	for _, bad := range []string{"", "AAAA", "not base64!"} {
		if _, err := wire.ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) succeeded", bad)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	k := mustKey(t).Public()
	packet := []byte("a wireguard packet")
	got, p, err := wire.SplitFrame(wire.Frame(k, packet))
	if err != nil {
		t.Fatal(err)
	}
	if got != k || !bytes.Equal(p, packet) {
		t.Fatalf("got %v %q", got, p)
	}
	if _, _, err := wire.SplitFrame(make([]byte, wire.KeySize-1)); err == nil {
		t.Fatal("a frame shorter than a key split without error")
	}
}

// The handshake's whole security rests on these properties.
func TestProof(t *testing.T) {
	node, relay := mustKey(t), mustKey(t)
	rn, nn := bytes.Repeat([]byte{1}, wire.NonceSize), bytes.Repeat([]byte{2}, wire.NonceSize)

	nodeSide, _ := node.Shared(relay.Public())
	relaySide, _ := relay.Shared(node.Public())

	// Both ends compute the same proof for each role...
	if !bytes.Equal(wire.Proof(nodeSide, wire.RoleNode, rn, nn), wire.Proof(relaySide, wire.RoleNode, rn, nn)) {
		t.Fatal("node proof differs between the two sides")
	}
	// ...a proof for one role is not a proof for the other, so it cannot be
	// reflected back...
	if bytes.Equal(wire.Proof(nodeSide, wire.RoleNode, rn, nn), wire.Proof(nodeSide, wire.RoleRelay, rn, nn)) {
		t.Fatal("node and relay proofs are interchangeable")
	}
	// ...and fresh nonces make an old proof useless.
	if bytes.Equal(wire.Proof(nodeSide, wire.RoleNode, rn, nn), wire.Proof(nodeSide, wire.RoleNode, nn, rn)) {
		t.Fatal("proof does not depend on the nonces")
	}
	// A third key gets a different secret, so cannot forge either proof.
	other := mustKey(t)
	forged, _ := other.Shared(relay.Public())
	if bytes.Equal(forged, relaySide) {
		t.Fatal("a third key computed the same secret")
	}
}

func TestJoinMACBindsTheKey(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, b := mustKey(t).Public(), mustKey(t).Public()
	if bytes.Equal(wire.JoinMAC(secret, "id", a), wire.JoinMAC(secret, "id", b)) {
		t.Fatal("the MAC does not depend on the key, so an observer could swap in their own")
	}
	if bytes.Equal(wire.JoinMAC(secret, "id", a), wire.JoinMAC(secret, "other", a)) {
		t.Fatal("the MAC does not depend on the invite id")
	}
}

func TestDNSAddr(t *testing.T) {
	for network, want := range map[string]string{
		"10.77.0.0/24": "10.77.0.254",
		"10.77.0.9/24": "10.77.0.254", // not masked
		"10.77.0.0/16": "10.77.255.254",
		"10.77.0.8/29": "10.77.0.14",
	} {
		got, ok := wire.DNSAddr(netip.MustParsePrefix(network))
		if !ok || got.String() != want {
			t.Errorf("%s: %s %v, want %s", network, got, ok, want)
		}
	}
	// No address to spare in a /30, and none in IPv6.
	for _, network := range []string{"10.77.0.0/30", "fd00::/64"} {
		if got, ok := wire.DNSAddr(netip.MustParsePrefix(network)); ok {
			t.Errorf("%s: %s", network, got)
		}
	}
}

func TestValidDomain(t *testing.T) {
	for _, ok := range []string{"vpn", "corp.internal", "home.arpa", "a-b.c1"} {
		if err := wire.ValidDomain(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "VPN", ".vpn", "vpn.", "a..b", "-vpn", "vpn-", "my vpn", "vpn_1", strings.Repeat("a.", 101) + "a"} {
		if wire.ValidDomain(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
