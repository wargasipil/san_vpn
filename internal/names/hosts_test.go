package names

import (
	"strings"
	"testing"
)

func TestHostsBlock(t *testing.T) {
	want := hostsBegin + "\n10.77.0.1\toffice.vpn\n10.77.0.2\thome.vpn\n" + hostsEnd + "\n"
	if got := HostsBlock(table()); got != want {
		t.Fatalf("block:\n%s\nwant:\n%s", got, want)
	}
	if HostsBlock(nil) != "" || HostsBlock(&Table{Domain: "vpn"}) != "" {
		t.Fatal("block for no names")
	}
}

func TestReplaceHostsBlock(t *testing.T) {
	block := HostsBlock(table())
	other := HostsBlock(&Table{Domain: "vpn", Hosts: table().Hosts}) // same names, rebuilt
	const base = "127.0.0.1\tlocalhost\n::1\tlocalhost\n"

	// Added at the end, with a newline first if the file lacks one.
	added := ReplaceHostsBlock(base, block)
	if added != base+block {
		t.Fatalf("added:\n%s", added)
	}
	if got := ReplaceHostsBlock(strings.TrimSuffix(base, "\n"), block); got != base+block {
		t.Fatalf("added to a file without a final newline:\n%s", got)
	}
	if got := ReplaceHostsBlock("", block); got != block {
		t.Fatalf("added to an empty file:\n%s", got)
	}

	// Replaced where it is; others' lines after it stay after it.
	after := added + "192.168.1.10\tnas\n"
	newer := strings.Replace(other, "10.77.0.2\thome.vpn", "10.77.0.3\thome.vpn", 1)
	if got := ReplaceHostsBlock(after, newer); got != base+newer+"192.168.1.10\tnas\n" {
		t.Fatalf("replaced:\n%s", got)
	}
	if ReplaceHostsBlock(added, block) != added {
		t.Fatal("setting the same block changed the file")
	}

	// Removed, leaving the file as it was.
	if got := ReplaceHostsBlock(after, ""); got != base+"192.168.1.10\tnas\n" {
		t.Fatalf("removed:\n%s", got)
	}
	if ReplaceHostsBlock(base, "") != base {
		t.Fatal("removing an absent block changed the file")
	}

	// Windows line endings in the markers still match.
	crlf := strings.ReplaceAll(added, "\n", "\r\n")
	if got := ReplaceHostsBlock(crlf, ""); got != strings.ReplaceAll(base, "\n", "\r\n") {
		t.Fatalf("CRLF removal:\n%q", got)
	}

	// Someone deleted the end line: only the begin line is ours to drop,
	// never the entries after it.
	broken := base + hostsBegin + "\n10.77.0.1\toffice.vpn\n192.168.1.10\tnas\n"
	if got := ReplaceHostsBlock(broken, ""); got != base+"10.77.0.1\toffice.vpn\n192.168.1.10\tnas\n" {
		t.Fatalf("broken block:\n%s", got)
	}
}
