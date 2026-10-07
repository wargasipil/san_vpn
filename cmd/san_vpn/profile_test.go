package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// startRelay runs a relay in process, a network of its own, and returns its
// state directory.
func startRelay(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// The listener exists before the server starts, so init can record its
	// URL before the relay loads.
	ts := httptest.NewUnstartedServer(nil)
	mustRun(t, "--state", dir, "relay", "init", "--url", "http://"+ts.Listener.Addr().String())
	srv, err := relay.New(context.Background(), state.File(filepath.Join(dir, state.RelayFile)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return dir
}

func inviteFrom(t *testing.T, relayDir, name string) string {
	t.Helper()
	blob := inviteRE.FindString(mustRun(t, "--state", relayDir, "relay", "invite", name))
	if blob == "" {
		t.Fatal("no invite printed")
	}
	return blob
}

type profileList struct {
	Current  string `json:"current"`
	Profiles []struct {
		Profile string `json:"profile"`
		Name    string `json:"name"`
		Relay   string `json:"relay"`
		Current bool   `json:"current"`
		Running bool   `json:"running"`
	} `json:"profiles"`
}

func listProfiles(t *testing.T, nodeDir string) profileList {
	t.Helper()
	var l profileList
	if err := json.Unmarshal([]byte(mustRun(t, "--state", nodeDir, "profile", "list", "--json")), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// One machine in two networks -- a dev tunnel relay and a Cloud Run one, here
// two local relays -- switching between them.
func TestProfiles(t *testing.T) {
	tunnel, cloud := startRelay(t), startRelay(t)
	nodeDir := t.TempDir()

	// The first network goes where it always went: the default profile.
	out := mustRun(t, "--state", nodeDir, "join", inviteFrom(t, tunnel, "home"))
	if out != "joined as \"home\" with address 10.77.0.1/24\nStart it with: san_vpn up\n" {
		t.Fatalf("first join said:\n%s", out)
	}

	// A second network needs a profile of its own, and the refusal says so.
	cloudInvite := inviteFrom(t, cloud, "home")
	if _, err := run(t, "--state", nodeDir, "join", cloudInvite); err == nil || !strings.Contains(err.Error(), "--profile <name>") {
		t.Fatalf("second join without a profile: %v", err)
	}
	out = mustRun(t, "--state", nodeDir, "join", "--profile", "cloudrun", cloudInvite)
	if !strings.Contains(out, `in profile "cloudrun"`) || !strings.Contains(out, "san_vpn up --profile cloudrun") || !strings.Contains(out, "san_vpn profile use cloudrun") {
		t.Fatalf("join --profile said:\n%s", out)
	}
	if _, err := run(t, "--state", nodeDir, "join", "--profile", "cloudrun", inviteFrom(t, cloud, "other")); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("joining a taken profile: %v", err)
	}

	out = mustRun(t, "--state", nodeDir, "profile", "list")
	if !strings.Contains(out, "* default") || !strings.Contains(out, "  cloudrun") {
		t.Fatalf("profile list:\n%s", out)
	}
	l := listProfiles(t, nodeDir)
	if l.Current != "default" || len(l.Profiles) != 2 || l.Profiles[0].Relay == l.Profiles[1].Relay {
		t.Fatalf("profile list --json: %+v", l)
	}

	// Switch.
	out = mustRun(t, "--state", nodeDir, "profile", "use", "cloudrun")
	if !strings.Contains(out, `san_vpn up now brings up profile "cloudrun"`) {
		t.Fatalf("profile use said:\n%s", out)
	}
	if out = mustRun(t, "--state", nodeDir, "status"); out != "home (10.77.0.1/24, profile cloudrun) is not running; start it with: san_vpn up\n" {
		t.Fatalf("status after the switch:\n%s", out)
	}
	if out = mustRun(t, "--state", nodeDir, "status", "--profile", "default"); !strings.Contains(out, "start it with: san_vpn up --profile default") {
		t.Fatalf("status --profile default:\n%s", out)
	}

	// Name the first one after its relay; the files follow.
	mustRun(t, "--state", nodeDir, "profile", "rename", "default", "tunnel")
	if _, err := os.Stat(filepath.Join(nodeDir, "profiles", "tunnel", state.NodeFile)); err != nil {
		t.Fatal(err)
	}
	l = listProfiles(t, nodeDir)
	if l.Current != "cloudrun" || len(l.Profiles) != 2 || l.Profiles[0].Profile != "cloudrun" || l.Profiles[1].Profile != "tunnel" {
		t.Fatalf("after rename: %+v", l)
	}
	mustRun(t, "--state", nodeDir, "profile", "use", "tunnel")
	if out = mustRun(t, "--state", nodeDir, "status"); !strings.Contains(out, "profile tunnel) is not running; start it with: san_vpn up\n") {
		t.Fatalf("status on tunnel:\n%s", out)
	}

	if _, err := run(t, "--state", nodeDir, "profile", "use", "nope"); err == nil || !strings.Contains(err.Error(), "join --profile nope") {
		t.Fatalf("using a profile never joined: %v", err)
	}
	if _, err := run(t, "--state", nodeDir, "profile", "use", "Cloud Run"); err == nil {
		t.Fatal("used a profile name with spaces and capitals")
	}
	if _, err := run(t, "--state", nodeDir, "status", "--profile", "../x"); err == nil {
		t.Fatal("status took a path as a profile")
	}
}

// On a fresh machine the first membership is the one `up` brings up, whatever
// its profile is called.
func TestFirstJoinIntoProfile(t *testing.T) {
	cloud, nodeDir := startRelay(t), t.TempDir()
	out := mustRun(t, "--state", nodeDir, "join", "--profile", "cloudrun", inviteFrom(t, cloud, "home"))
	if !strings.HasSuffix(out, "Start it with: san_vpn up\n") {
		t.Fatalf("join said:\n%s", out)
	}
	if l := listProfiles(t, nodeDir); l.Current != "cloudrun" {
		t.Fatalf("current profile %q, want cloudrun", l.Current)
	}
}

// While `up` runs on one profile, status shows that one, a switch waits for a
// restart, and the running profile cannot be renamed from under it.
func TestProfileWhileRunning(t *testing.T) {
	tunnel, cloud, nodeDir := startRelay(t), startRelay(t), t.TempDir()
	mustRun(t, "--state", nodeDir, "join", "--profile", "tunnel", inviteFrom(t, tunnel, "home"))
	mustRun(t, "--state", nodeDir, "join", "--profile", "cloudrun", inviteFrom(t, cloud, "home"))

	// `up` on cloudrun, as its status file says, while tunnel is current.
	if err := state.Save(filepath.Join(nodeDir, "profiles", "cloudrun", state.StatusFile), node.Status{
		Updated: time.Now(), PID: 4242, Name: "home", IP: netip.MustParseAddr("10.77.0.1"),
		Network: netip.MustParsePrefix("10.77.0.0/24"), Relay: "http://relay", Connected: true, Since: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if out := mustRun(t, "--state", nodeDir, "status"); !strings.Contains(out, "profile cloudrun  connected to http://relay") {
		t.Fatalf("status did not show the running profile:\n%s", out)
	}
	if out := mustRun(t, "--state", nodeDir, "profile", "use", "tunnel"); !strings.Contains(out, `still running on profile "cloudrun" (pid 4242)`) {
		t.Fatalf("profile use said:\n%s", out)
	}
	if out := mustRun(t, "--state", nodeDir, "profile", "list"); !strings.Contains(out, "running") {
		t.Fatalf("profile list:\n%s", out)
	}
	if _, err := run(t, "--state", nodeDir, "profile", "rename", "cloudrun", "cr"); err == nil || !strings.Contains(err.Error(), "stop it first") {
		t.Fatalf("renamed the running profile: %v", err)
	}
	if name, _, ok := runningProfile(nodeDir); !ok || name != "cloudrun" {
		t.Fatalf("running profile %q, %v", name, ok)
	}
}
