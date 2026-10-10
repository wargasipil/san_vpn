package state_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/state"
)

// makeRelay stands in for `san_vpn relay init`: a relay.json in loc.
func makeRelay(t *testing.T, loc string) {
	t.Helper()
	if err := os.MkdirAll(loc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(loc, state.RelayFile), map[string]string{"url": "https://" + filepath.Base(loc)}); err != nil {
		t.Fatal(err)
	}
}

func relayNames(t *testing.T, dir string) []string {
	t.Helper()
	ps, err := state.RelayProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.Name+"="+p.Location)
	}
	return names
}

func currentRelay(t *testing.T, dir string) string {
	t.Helper()
	cur, err := state.CurrentRelay(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

// A relay from before relay profiles is the default one, where it always was;
// other relays are names for where their files are, which never move.
func TestRelayProfiles(t *testing.T) {
	dir := t.TempDir()
	if got := relayNames(t, dir); len(got) != 0 {
		t.Fatalf("fresh directory has relays %v", got)
	}
	if cur := currentRelay(t, dir); cur != state.DefaultRelay {
		t.Fatalf("current relay %q, want default", cur)
	}
	// The default relay is known before it exists: relay init makes it there.
	if loc, known, err := state.RelayLocation(dir, "default"); err != nil || !known || loc != dir {
		t.Fatalf("default: %q %v %v", loc, known, err)
	}
	// Another name is not, and says where a new one would go.
	if loc, known, err := state.RelayLocation(dir, "lab"); err != nil || known || loc != filepath.Join(dir, "relays", "lab") {
		t.Fatalf("lab: %q %v %v", loc, known, err)
	}

	makeRelay(t, dir)
	makeRelay(t, filepath.Join(dir, "relays", "lab"))
	for _, add := range [][2]string{{"lab", filepath.Join(dir, "relays", "lab")}, {"cloudrun", "gs://proj-san-vpn/"}} {
		if err := state.AddRelay(dir, add[0], add[1]); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"default=" + dir, "cloudrun=gs://proj-san-vpn", "lab=" + filepath.Join(dir, "relays", "lab")}
	if got := relayNames(t, dir); !slices.Equal(got, want) {
		t.Fatalf("relays %v, want %v", got, want)
	}
	// A folder inside the relay directory is kept relative, so it can move.
	var idx struct {
		Relays map[string]string `json:"relays"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, state.RelaysFile))
	if err := json.Unmarshal(b, &idx); err != nil || idx.Relays["lab"] != "relays/lab" {
		t.Fatalf("relays.json: %s (%v)", b, err)
	}

	// Adding again by the same name is fine; a taken name or relay is not.
	if err := state.AddRelay(dir, "cloudrun", "gs://proj-san-vpn"); err != nil {
		t.Fatalf("adding the same again: %v", err)
	}
	for _, bad := range [][2]string{
		{"cloudrun", "gs://other"},      // the name is taken
		{"cr", "gs://proj-san-vpn"},     // the relay has a name
		{"tunnel", dir},                 // that is default: rename it instead
		{"default", "gs://elsewhere"},   // default is the relay directory's
		{"Cloud Run", "gs://elsewhere"}, // not a name
		{"bucketless", "gs://"},         // not a location
	} {
		if err := state.AddRelay(dir, bad[0], bad[1]); err == nil {
			t.Errorf("added %s = %s", bad[0], bad[1])
		}
	}
	if err := state.AddRelay(dir, "tunnel", dir); err == nil || !strings.Contains(err.Error(), "relay profile rename default tunnel") {
		t.Fatalf("naming default by add: %v", err)
	}

	if err := state.SetCurrentRelay(dir, "cloudrun"); err != nil {
		t.Fatal(err)
	}
	if cur := currentRelay(t, dir); cur != "cloudrun" {
		t.Fatalf("current relay %q", cur)
	}
	if err := state.SetCurrentRelay(dir, "nope"); err == nil {
		t.Fatal("chose a relay profile that does not exist")
	}
}

// Renaming changes names only, and the current choice follows.
func TestRenameRelay(t *testing.T) {
	dir := t.TempDir()
	makeRelay(t, dir)
	if err := state.AddRelay(dir, "cloudrun", "gs://proj-san-vpn"); err != nil {
		t.Fatal(err)
	}

	if err := state.RenameRelay(dir, "default", "tunnel"); err != nil {
		t.Fatal(err)
	}
	if got, want := relayNames(t, dir), []string{"cloudrun=gs://proj-san-vpn", "tunnel=" + dir}; !slices.Equal(got, want) {
		t.Fatalf("after rename: %v, want %v", got, want)
	}
	if cur := currentRelay(t, dir); cur != "tunnel" {
		t.Fatalf("current relay %q, want tunnel: it was default", cur)
	}
	if _, err := os.Stat(filepath.Join(dir, state.RelayFile)); err != nil {
		t.Fatalf("the relay's file moved: %v", err)
	}

	for _, bad := range [][2]string{{"tunnel", "cloudrun"}, {"nope", "x"}, {"default", "x"}, {"cloudrun", "cloudrun"}} {
		if err := state.RenameRelay(dir, bad[0], bad[1]); err == nil {
			t.Errorf("renamed %s to %s", bad[0], bad[1])
		}
	}

	// Back to default: the plain relay directory again, with no entry.
	if err := state.RenameRelay(dir, "tunnel", "default"); err != nil {
		t.Fatal(err)
	}
	if got, want := relayNames(t, dir), []string{"default=" + dir, "cloudrun=gs://proj-san-vpn"}; !slices.Equal(got, want) {
		t.Fatalf("after renaming back: %v, want %v", got, want)
	}
	if cur := currentRelay(t, dir); cur != "default" {
		t.Fatalf("current relay %q, want default", cur)
	}
	if err := state.RenameRelay(dir, "cloudrun", "default"); err == nil {
		t.Fatal("renamed cloudrun over the default relay")
	}
}

// Forgetting drops the name, never the relay.
func TestForgetRelay(t *testing.T) {
	dir := t.TempDir()
	makeRelay(t, dir)
	lab := filepath.Join(dir, "relays", "lab")
	makeRelay(t, lab)
	if err := state.AddRelay(dir, "lab", lab); err != nil {
		t.Fatal(err)
	}
	if err := state.SetCurrentRelay(dir, "lab"); err != nil {
		t.Fatal(err)
	}
	loc, err := state.ForgetRelay(dir, "lab")
	if err != nil || loc != lab {
		t.Fatalf("forget: %q %v", loc, err)
	}
	if _, err := os.Stat(filepath.Join(lab, state.RelayFile)); err != nil {
		t.Fatalf("forgetting deleted the relay: %v", err)
	}
	if cur := currentRelay(t, dir); cur != "default" {
		t.Fatalf("current relay %q after forgetting it, want default", cur)
	}
	if _, err := state.ForgetRelay(dir, "default"); err == nil {
		t.Fatal("forgot the relay directory itself")
	}
	if _, err := state.ForgetRelay(dir, "lab"); err == nil {
		t.Fatal("forgot lab twice")
	}
}
