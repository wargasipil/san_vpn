package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/setup"
	"github.com/wargasipil/san_vpn/internal/state"
)

type relayProfileList struct {
	Current string `json:"current"`
	Relays  []struct {
		Relay    string `json:"relay"`
		Location string `json:"location"`
		URL      string `json:"url"`
		Members  int    `json:"members"`
		Current  bool   `json:"current"`
		Error    string `json:"error"`
	} `json:"relays"`
}

func listRelays(t *testing.T, dir string) relayProfileList {
	t.Helper()
	var l relayProfileList
	if err := json.Unmarshal([]byte(mustRun(t, "--state", dir, "relay", "profile", "list", "--json")), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// inviteURL is the relay URL an invite printed in out pins.
func inviteURL(t *testing.T, out string) string {
	t.Helper()
	inv, err := invite.Decode(inviteRE.FindString(out))
	if err != nil {
		t.Fatalf("%v in:\n%s", err, out)
	}
	return inv.URL
}

// One machine looking after two relays, picking which one the relay commands
// work on.
func TestRelayProfiles(t *testing.T) {
	dir := t.TempDir()
	// The relay from before relay profiles is the default one.
	mustRun(t, "--state", dir, "relay", "init", "--url", "https://tunnel.example")
	out := mustRun(t, "--state", dir, "relay", "invite", "home")
	if !strings.Contains(out, `Invite for "home" to the relay at https://tunnel.example,`) || inviteURL(t, out) != "https://tunnel.example" {
		t.Fatalf("invite said:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, state.RelaysFile)); err == nil {
		t.Fatal("one relay wrote relays.json")
	}

	// A second relay, by name, in a folder of its own.
	out = mustRun(t, "--state", dir, "relay", "init", "--relay", "lab", "--url", "https://lab.example")
	if !strings.Contains(out, `created relay "lab" in `+filepath.Join(dir, "relays", "lab", state.RelayFile)) ||
		!strings.Contains(out, "--relay lab, or make it the one they use: san_vpn relay profile use lab") {
		t.Fatalf("relay init --relay lab said:\n%s", out)
	}
	// Plain commands still use default; --relay picks the other.
	if out = mustRun(t, "--state", dir, "relay", "invite", "office"); inviteURL(t, out) != "https://tunnel.example" || !strings.Contains(out, `to relay "default"`) {
		t.Fatalf("plain invite went elsewhere:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "--relay", "lab", "office"); inviteURL(t, out) != "https://lab.example" || !strings.Contains(out, `to relay "lab" at https://lab.example`) {
		t.Fatalf("invite --relay lab:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "list", "--relay", "lab"); !strings.HasPrefix(out, "relay lab  network") || !strings.Contains(out, "office") || strings.Contains(out, "home") {
		t.Fatalf("relay list --relay lab:\n%s", out)
	}

	l := listRelays(t, dir)
	if l.Current != "default" || len(l.Relays) != 2 || l.Relays[0].Relay != "default" || l.Relays[1].URL != "https://lab.example" || l.Relays[1].Location != filepath.Join(dir, "relays", "lab") {
		t.Fatalf("relay profile list: %+v", l)
	}
	if out = mustRun(t, "--state", dir, "relay", "profile", "list"); !strings.Contains(out, "* default  https://tunnel.example  0") || !strings.Contains(out, "  lab      https://lab.example     0") {
		t.Fatalf("relay profile list:\n%s", out)
	}

	// Switch.
	if out = mustRun(t, "--state", dir, "relay", "profile", "use", "lab"); !strings.Contains(out, `relay commands now use relay "lab": https://lab.example`) {
		t.Fatalf("relay profile use said:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "vps"); inviteURL(t, out) != "https://lab.example" {
		t.Fatalf("invite after the switch:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "remove", "vps"); !strings.Contains(out, `"vps" from relay "lab"`) {
		t.Fatalf("remove said:\n%s", out)
	}

	// Name the first after its front: only the name changes.
	mustRun(t, "--state", dir, "relay", "profile", "rename", "default", "tunnel")
	if _, err := os.Stat(filepath.Join(dir, state.RelayFile)); err != nil {
		t.Fatalf("rename moved the relay: %v", err)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "--relay", "tunnel", "pi"); inviteURL(t, out) != "https://tunnel.example" {
		t.Fatalf("invite --relay tunnel:\n%s", out)
	}
	l = listRelays(t, dir)
	if l.Current != "lab" || len(l.Relays) != 2 || l.Relays[0].Relay != "lab" || l.Relays[1].Relay != "tunnel" || l.Relays[1].URL != "https://tunnel.example" {
		t.Fatalf("after rename: %+v", l)
	}

	// Mistakes say what to run.
	if _, err := run(t, "--state", dir, "relay", "invite", "--relay", "nope", "x"); err == nil || !strings.Contains(err.Error(), "relay init --relay nope") || !strings.Contains(err.Error(), "lab, tunnel") {
		t.Fatalf("invite to a relay never made: %v", err)
	}
	if _, err := run(t, "--state", dir, "relay", "profile", "use", "nope"); err == nil || !strings.Contains(err.Error(), "no relay profile") {
		t.Fatalf("using a relay never made: %v", err)
	}
	if _, err := run(t, "--state", dir, "relay", "list", "--relay", "Lab Relay"); err == nil {
		t.Fatal("took a relay name with spaces and capitals")
	}

	// Forgetting a name leaves the relay, and add names it again.
	out = mustRun(t, "--state", dir, "relay", "profile", "forget", "lab")
	if !strings.Contains(out, "relay profile add lab "+filepath.Join(dir, "relays", "lab")) {
		t.Fatalf("forget said:\n%s", out)
	}
	if l = listRelays(t, dir); len(l.Relays) != 1 || l.Current != "tunnel" {
		t.Fatalf("after forget: %+v", l)
	}
	if _, err := run(t, "--state", dir, "relay", "invite", "x"); err != nil {
		t.Fatalf("invite after forgetting the current relay, back on tunnel: %v", err)
	}
	mustRun(t, "--state", dir, "relay", "profile", "add", "lab", filepath.Join(dir, "relays", "lab", state.RelayFile))
	if out = mustRun(t, "--state", dir, "relay", "invite", "--relay", "lab", "y"); inviteURL(t, out) != "https://lab.example" {
		t.Fatalf("invite after adding lab again:\n%s", out)
	}
}

// On a fresh machine the first relay is the one the relay commands use,
// whatever it is called.
func TestFirstRelayIsCurrent(t *testing.T) {
	dir := t.TempDir()
	out := mustRun(t, "--state", dir, "relay", "init", "--relay", "lab", "--url", "https://lab.example")
	if strings.Contains(out, "relay profile use") {
		t.Fatalf("the only relay was not made current:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "home"); inviteURL(t, out) != "https://lab.example" {
		t.Fatalf("invite:\n%s", out)
	}
	if l := listRelays(t, dir); l.Current != "lab" || len(l.Relays) != 1 {
		t.Fatalf("relay profile list: %+v", l)
	}
}

// A relay kept in Cloud Storage, named on this machine.
func TestRelayProfileOnCloudStorage(t *testing.T) {
	srv := gcstest.New()
	defer srv.Close()
	t.Setenv("STORAGE_EMULATOR_HOST", srv.URL)
	const bucket = "gs://team-relay/san_vpn"
	dir := t.TempDir()
	mustRun(t, "--state", dir, "relay", "init", "--url", "https://tunnel.example")
	mustRun(t, "--state", bucket, "relay", "init", "--url", "https://relay-abc-as.a.run.app")

	if _, err := run(t, "--state", dir, "relay", "profile", "add", "cloudrun", "gs://team-relay/elsewhere"); err == nil || !strings.Contains(err.Error(), "no relay at") {
		t.Fatalf("added a location holding no relay: %v", err)
	}
	out := mustRun(t, "--state", dir, "relay", "profile", "add", "cloudrun", bucket+"/")
	if !strings.Contains(out, `added relay "cloudrun": https://relay-abc-as.a.run.app`) || !strings.Contains(out, "--relay cloudrun") {
		t.Fatalf("relay profile add said:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "--relay", "cloudrun", "home"); inviteURL(t, out) != "https://relay-abc-as.a.run.app" {
		t.Fatalf("invite --relay cloudrun:\n%s", out)
	}
	if out = mustRun(t, "--state", dir, "relay", "invite", "home"); inviteURL(t, out) != "https://tunnel.example" {
		t.Fatalf("plain invite left default:\n%s", out)
	}
	if l := listRelays(t, dir); len(l.Relays) != 2 || l.Relays[1].Relay != "cloudrun" || l.Relays[1].Location != bucket || l.Relays[1].URL != "https://relay-abc-as.a.run.app" {
		t.Fatalf("relay profile list: %+v", l)
	}

	// Switched to it, relay run still serves only a relay of this machine.
	out = mustRun(t, "--state", dir, "relay", "profile", "use", "cloudrun")
	if !strings.Contains(out, "san_vpn relay run --relay default") {
		t.Fatalf("relay profile use said:\n%s", out)
	}
	if _, err := run(t, "--state", dir, "relay", "run"); err == nil || !strings.Contains(err.Error(), "served from there") || !strings.Contains(err.Error(), "relay run --relay default") {
		t.Fatalf("relay run on the Cloud Storage relay: %v", err)
	}
	// setup init fronts a relay on this machine.
	if _, err := run(t, "--state", dir, "setup", "init", "--no-install"); err == nil || !strings.Contains(err.Error(), "not one kept in gs://") {
		t.Fatalf("setup init on the Cloud Storage relay: %v", err)
	}

	// A gs:// --state names the relay outright, so --relay beside it is a
	// mistake, and the relay profiles are kept on this machine.
	if _, err := run(t, "--state", bucket, "relay", "invite", "--relay", "cloudrun", "x"); err == nil || !strings.Contains(err.Error(), "names the relay already") {
		t.Fatalf("--state gs:// with --relay: %v", err)
	}
	if _, err := run(t, "--state", bucket, "relay", "profile", "list"); err == nil || !strings.Contains(err.Error(), "kept on this machine") {
		t.Fatalf("relay profile list with a gs:// state: %v", err)
	}
	if _, err := run(t, "--state", dir, "relay", "profile", "add", "cr", bucket); err == nil || !strings.Contains(err.Error(), `relay profile "cloudrun" already`) {
		t.Fatalf("a second name for one relay: %v", err)
	}
}

// Which relay the cloudrun commands work on, and how the relay is kept.
func TestCloudRunRelayProfile(t *testing.T) {
	dir := t.TempDir()
	mustRun(t, "--state", dir, "relay", "init", "--url", "https://tunnel.example")
	res := &setup.CloudRunResult{State: "gs://proj-san-vpn"}

	// Nothing named: the cloudrun profile, whose relay setup puts in the
	// project's bucket.
	loc, p, err := cloudRunRelayIn(dir, "", "")
	if err != nil || loc != "" || p.name != "cloudrun" || p.known {
		t.Fatalf("first pick: %q %+v %v", loc, p, err)
	}
	if p, err = keepCloudRunRelay(p, res); err != nil {
		t.Fatal(err)
	}
	if cloudRunArg(p, res) != "" || relayArg(p) != " --relay cloudrun" {
		t.Fatalf("next commands: deploy%q, invite%q", cloudRunArg(p, res), relayArg(p))
	}
	if cur, _ := state.CurrentRelay(dir); cur != "default" {
		t.Fatalf("keeping the Cloud Run relay took over the current relay: %q", cur)
	}
	// Found again by deploy, from its profile.
	if loc, p, err = cloudRunRelayIn(dir, "", ""); err != nil || loc != "gs://proj-san-vpn" || p.name != "cloudrun" || !p.known {
		t.Fatalf("second pick: %q %+v %v", loc, p, err)
	}

	// A relay of this machine is not one for Cloud Run.
	if _, _, err := cloudRunRelayIn(dir, "", "default"); err == nil || !strings.Contains(err.Error(), "relay on this machine") {
		t.Fatalf("--relay default: %v", err)
	}
	// A profile and a different --state disagree.
	if _, _, err := cloudRunRelayIn(dir, "gs://other", "cloudrun"); err == nil || !strings.Contains(err.Error(), "kept in gs://proj-san-vpn") {
		t.Fatalf("--relay cloudrun --state gs://other: %v", err)
	}
	// A new name with its own bucket.
	loc, p, err = cloudRunRelayIn(dir, "gs://staging-relay", "staging")
	if err != nil || loc != "gs://staging-relay" || p.known {
		t.Fatalf("new name: %q %+v %v", loc, p, err)
	}
	if p, err = keepCloudRunRelay(p, &setup.CloudRunResult{State: loc}); err != nil {
		t.Fatal(err)
	}
	if cloudRunArg(p, res) != " --relay staging" {
		t.Fatalf("deploy arg %q", cloudRunArg(p, res))
	}

	// Once a Cloud Run relay is current, the cloudrun commands use it.
	if err := state.SetCurrentRelay(dir, "staging"); err != nil {
		t.Fatal(err)
	}
	if _, p, err = cloudRunRelayIn(dir, "", ""); err != nil || p.name != "staging" {
		t.Fatalf("pick with staging current: %+v %v", p, err)
	}
	// Only --state, as before relay profiles: not kept under any name.
	if cloudRunArg(relayPick{}, res) != " --state gs://proj-san-vpn" {
		t.Fatalf("--state arg %q", cloudRunArg(relayPick{}, res))
	}
}
