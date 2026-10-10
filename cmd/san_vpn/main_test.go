package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := root(&out).Run(context.Background(), append([]string{"san_vpn"}, args...))
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("san_vpn %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

var inviteRE = regexp.MustCompile(`sanvpn1_[A-Za-z0-9_-]+`)

// The administration flow through the real command tree: everything but
// `up`, which needs an administrator and a real tunnel interface.
func TestAdminFlow(t *testing.T) {
	relayDir, nodeDir := t.TempDir(), t.TempDir()

	// The relay's URL must exist before init records it, and the relay
	// itself can only load once init has run.
	var h http.Handler = http.NotFoundHandler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer ts.Close()

	out := mustRun(t, "--state", relayDir, "relay", "init", "--url", ts.URL+"/")
	if !strings.Contains(out, "created relay") || !strings.Contains(out, "10.77.0.0/24") || !strings.Contains(out, ts.URL+"\n") {
		t.Fatalf("relay init said:\n%s", out)
	}
	// Running it again keeps the key.
	again := mustRun(t, "--state", relayDir, "relay", "init")
	if !strings.Contains(again, "updated relay") || keyLine(out) != keyLine(again) {
		t.Fatalf("second init changed the relay:\n%s\nvs\n%s", out, again)
	}

	srv, err := relay.New(context.Background(), state.File(filepath.Join(relayDir, state.RelayFile)), nil)
	if err != nil {
		t.Fatal(err)
	}
	h = srv.Handler()

	out = mustRun(t, "--state", relayDir, "relay", "invite", "home")
	blob := inviteRE.FindString(out)
	if blob == "" {
		t.Fatalf("no invite in:\n%s", out)
	}
	if _, err := run(t, "--state", relayDir, "relay", "invite", "Home Office"); err == nil {
		t.Fatal("invited a name with spaces and capitals")
	}

	out = mustRun(t, "--state", nodeDir, "join", blob)
	if !strings.Contains(out, `joined as "home" with address 10.77.0.1/24`) {
		t.Fatalf("join said:\n%s", out)
	}
	if _, err := run(t, "--state", nodeDir, "join", blob); err == nil || !strings.Contains(err.Error(), "already joined") {
		t.Fatalf("joining twice: %v", err)
	}

	out = mustRun(t, "--state", relayDir, "relay", "list")
	if !strings.Contains(out, "home") || !strings.Contains(out, "10.77.0.1") {
		t.Fatalf("relay list:\n%s", out)
	}
	out = mustRun(t, "--state", nodeDir, "status")
	if !strings.Contains(out, "home (10.77.0.1/24) is not running") {
		t.Fatalf("status:\n%s", out)
	}

	mustRun(t, "--state", relayDir, "relay", "remove", "home")
	out = mustRun(t, "--state", relayDir, "relay", "list", "--json")
	if strings.Contains(out, `"home"`) {
		t.Fatalf("home still listed after remove:\n%s", out)
	}
}

// The relay machine joins its own relay over loopback rather than out
// through its public front and back.
func TestJoinURLOverride(t *testing.T) {
	relayDir, nodeDir := t.TempDir(), t.TempDir()
	mustRun(t, "--state", relayDir, "relay", "init", "--url", "https://unreachable.invalid")
	srv, err := relay.New(context.Background(), state.File(filepath.Join(relayDir, state.RelayFile)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	blob := inviteRE.FindString(mustRun(t, "--state", relayDir, "relay", "invite", "office"))
	out := mustRun(t, "--state", nodeDir, "join", "--url", ts.URL, blob)
	if !strings.Contains(out, `joined as "office"`) {
		t.Fatalf("join said:\n%s", out)
	}
	var cfg struct {
		RelayURL string `json:"relay_url"`
	}
	if err := state.Load(filepath.Join(nodeDir, state.NodeFile), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.RelayURL != ts.URL {
		t.Fatalf("node will dial %q, want %q", cfg.RelayURL, ts.URL)
	}
}

func TestInviteNeedsURL(t *testing.T) {
	dir := t.TempDir()
	mustRun(t, "--state", dir, "relay", "init")
	if _, err := run(t, "--state", dir, "relay", "invite", "home"); err == nil || !strings.Contains(err.Error(), "--url") {
		t.Fatalf("invite without a URL: %v", err)
	}
}

func TestStatusBeforeJoin(t *testing.T) {
	out := mustRun(t, "--state", t.TempDir(), "status")
	if !strings.Contains(out, "has not joined") {
		t.Fatalf("status:\n%s", out)
	}
}

func keyLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "key") {
			return l
		}
	}
	return ""
}

func TestRelayDomain(t *testing.T) {
	dir := t.TempDir()
	if out := mustRun(t, "--state", dir, "relay", "init"); !strings.Contains(out, "domain   vpn\n") || strings.Contains(out, "multicast") {
		t.Fatalf("relay init said:\n%s", out)
	}
	if out := mustRun(t, "--state", dir, "relay", "init", "--domain", ".Corp.Internal."); !strings.Contains(out, "domain   corp.internal\n") {
		t.Fatalf("relay init --domain said:\n%s", out)
	}
	// Kept when init runs again without it.
	if out := mustRun(t, "--state", dir, "relay", "init"); !strings.Contains(out, "domain   corp.internal\n") {
		t.Fatalf("second init lost the domain:\n%s", out)
	}
	if out := mustRun(t, "--state", dir, "relay", "list"); !strings.Contains(out, "domain corp.internal") {
		t.Fatalf("relay list:\n%s", out)
	}
	if out := mustRun(t, "--state", dir, "relay", "list", "--json"); !strings.Contains(out, `"domain": "corp.internal"`) {
		t.Fatalf("relay list --json:\n%s", out)
	}
	if _, err := run(t, "--state", dir, "relay", "init", "--domain", "my vpn"); err == nil {
		t.Fatal("accepted a domain with a space")
	}
	if out := mustRun(t, "--state", dir, "relay", "init", "--domain", "local"); !strings.Contains(out, "multicast DNS") {
		t.Fatalf(".local without a note:\n%s", out)
	}
}

func TestStatusShowsNames(t *testing.T) {
	dir := t.TempDir()
	st := node.Status{
		Updated: time.Now(), PID: 1, Name: "home", IP: netip.MustParseAddr("10.77.0.2"), Network: relay.DefaultNetwork,
		Relay: "https://relay.example", Connected: true, Since: time.Now(),
		Domain: "vpn", DNS: netip.MustParseAddr("10.77.0.254"),
		Peers: []node.PeerStatus{{Name: "office", IP: netip.MustParseAddr("10.77.0.1"), Online: true}},
	}
	if err := state.Save(filepath.Join(dir, state.StatusFile), st); err != nil {
		t.Fatal(err)
	}
	out := mustRun(t, "--state", dir, "status")
	if !strings.Contains(out, "names home.vpn and the others below, answered at 10.77.0.254") || !strings.Contains(out, "office.vpn  10.77.0.1") {
		t.Fatalf("status:\n%s", out)
	}
	// Names off: the plain names, and no line about them.
	st.Domain, st.DNS = "", netip.Addr{}
	if err := state.Save(filepath.Join(dir, state.StatusFile), st); err != nil {
		t.Fatal(err)
	}
	if out := mustRun(t, "--state", dir, "status"); strings.Contains(out, "names ") || strings.Contains(out, ".vpn") || !strings.Contains(out, "office  10.77.0.1") {
		t.Fatalf("status without names:\n%s", out)
	}
}
