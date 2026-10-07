package node

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/wire"
)

func key(b byte) wire.Key {
	var k wire.Key
	k[0] = b
	return k
}

func TestPeerUpdateTouchesOnlyChanges(t *testing.T) {
	a, b, c := key(1), key(2), key(3)
	ipA, ipB, ipC := netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")

	have := map[wire.Key]netip.Addr{a: ipA, b: ipB}
	want := map[wire.Key]netip.Addr{a: ipA, c: ipC}
	got := peerUpdate(have, want, nil)

	if strings.Contains(got, a.Hex()) {
		t.Errorf("unchanged peer a was rewritten, which resets its session:\n%s", got)
	}
	if !strings.Contains(got, "public_key="+b.Hex()+"\nremove=true\n") {
		t.Errorf("departed peer b not removed:\n%s", got)
	}
	wantC := "public_key=" + c.Hex() + "\nendpoint=" + c.Hex() + "\nreplace_allowed_ips=true\nallowed_ip=10.77.0.3/32\n"
	if !strings.Contains(got, wantC) {
		t.Errorf("new peer c not added as\n%s\ngot:\n%s", wantC, got)
	}
	if strings.Contains(got, "replace_peers") {
		t.Errorf("update replaces all peers:\n%s", got)
	}

	if peerUpdate(want, want, nil) != "" {
		t.Error("no change produced an update")
	}
}

// A reset is a removal followed by the same peer added back, in one update,
// so WireGuard drops the session but never the route.
func TestPeerUpdateReset(t *testing.T) {
	a := key(1)
	peers := map[wire.Key]netip.Addr{a: netip.MustParseAddr("10.77.0.1")}
	got := peerUpdate(peers, peers, map[wire.Key]bool{a: true})
	remove := strings.Index(got, "public_key="+a.Hex()+"\nremove=true\n")
	add := strings.Index(got, "public_key="+a.Hex()+"\nendpoint=")
	if remove < 0 || add < 0 || add < remove {
		t.Fatalf("want remove then add, got:\n%s", got)
	}
}

func TestParseStats(t *testing.T) {
	a, b := key(1), key(2)
	dump := strings.Join([]string{
		"private_key=" + key(9).Hex(),
		"listen_port=0",
		"public_key=" + a.Hex(),
		"endpoint=" + a.Hex(),
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=5",
		"tx_bytes=100",
		"rx_bytes=200",
		"allowed_ip=10.77.0.1/32",
		"public_key=" + b.Hex(),
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=0",
		"rx_bytes=0",
		"errno=0",
	}, "\n")
	got := parseStats(dump)
	if len(got) != 2 {
		t.Fatalf("got %d peers", len(got))
	}
	if s := got[a]; !s.LastHandshake.Equal(time.Unix(1700000000, 5)) || s.TxBytes != 100 || s.RxBytes != 200 {
		t.Errorf("peer a: %+v", s)
	}
	if s := got[b]; !s.LastHandshake.IsZero() {
		t.Errorf("peer b never shook hands but shows %v", s.LastHandshake)
	}
}

func TestHTTPURL(t *testing.T) {
	cases := map[string]string{
		"https://x.devtunnels.ms/":      "https://x.devtunnels.ms",
		"wss://x.devtunnels.ms":         "https://x.devtunnels.ms",
		"ws://127.0.0.1:8443":           "http://127.0.0.1:8443",
		" https://relay.example/vpn/  ": "https://relay.example/vpn",
	}
	for in, want := range cases {
		if got, err := HTTPURL(in); err != nil || got != want {
			t.Errorf("HTTPURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "relay.example", "ftp://relay.example", "https://"} {
		if _, err := HTTPURL(bad); err == nil {
			t.Errorf("HTTPURL(%q) accepted", bad)
		}
	}
}
