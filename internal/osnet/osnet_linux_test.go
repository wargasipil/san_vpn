package osnet

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/names"
)

func TestNamesInHostsFile(t *testing.T) {
	if resolvedInUse() {
		t.Skip("systemd-resolved answers lookups here, so Set would use it instead of the hosts file")
	}
	old := hostsPath
	hostsPath = filepath.Join(t.TempDir(), "hosts")
	t.Cleanup(func() { hostsPath = old })
	const base = "127.0.0.1\tlocalhost\n"
	if err := os.WriteFile(hostsPath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		b, err := os.ReadFile(hostsPath)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	tb := &names.Table{Domain: "vpn", Server: netip.MustParseAddr("10.77.0.254"), Hosts: map[string]netip.Addr{
		"office": netip.MustParseAddr("10.77.0.1"),
		"home":   netip.MustParseAddr("10.77.0.2"),
	}}
	n := &Names{Interface: "sanvpn0"}
	if how, err := n.Set(tb); err != nil || how != hostsPath {
		t.Fatalf("set: %q, %v", how, err)
	}
	if got := read(); !strings.HasPrefix(got, base) || !strings.Contains(got, "10.77.0.1\toffice.vpn\n10.77.0.2\thome.vpn\n") {
		t.Fatalf("hosts file:\n%s", got)
	}
	if how, err := n.Set(tb); err != nil || how != "" {
		t.Fatalf("setting the same again: %q, %v", how, err)
	}

	// A member joins: the block is rewritten in place.
	tb.Hosts["lab"] = netip.MustParseAddr("10.77.0.3")
	if how, err := n.Set(tb); err != nil || how == "" || !strings.Contains(read(), "10.77.0.3\tlab.vpn") {
		t.Fatalf("new member: %q, %v\n%s", how, err, read())
	}
	if strings.Count(read(), "# san_vpn begin") != 1 {
		t.Fatalf("two blocks:\n%s", read())
	}

	// Clear, or a table with no server, leaves the file as it was.
	if err := n.Clear(); err != nil || read() != base {
		t.Fatalf("clear: %v\n%s", err, read())
	}
	if _, err := n.Set(tb); err != nil {
		t.Fatal(err)
	}
	tb.Server = netip.Addr{}
	if _, err := n.Set(tb); err != nil || read() != base {
		t.Fatalf("no server: %v\n%s", err, read())
	}
}
