package state_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/wargasipil/san_vpn/internal/state"
)

// join stands in for `san_vpn join`: a node.json in the profile's folder.
func join(t *testing.T, dir, profile string) {
	t.Helper()
	pdir := state.ProfileDir(dir, profile)
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(pdir, state.NodeFile), map[string]string{"name": profile}); err != nil {
		t.Fatal(err)
	}
}

func profiles(t *testing.T, dir string) []string {
	t.Helper()
	names, err := state.Profiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// The default profile is the node directory itself, so a machine that joined
// before profiles existed keeps its membership where it was.
func TestProfileLayout(t *testing.T) {
	dir := t.TempDir()
	if got := profiles(t, dir); len(got) != 0 {
		t.Fatalf("fresh directory has profiles %v", got)
	}
	if cur, err := state.CurrentProfile(dir); err != nil || cur != state.DefaultProfile {
		t.Fatalf("current profile of a fresh directory: %q, %v", cur, err)
	}
	if state.ProfileDir(dir, state.DefaultProfile) != dir {
		t.Fatalf("default profile lives in %s, not the node directory", state.ProfileDir(dir, state.DefaultProfile))
	}

	join(t, dir, "zeta")
	join(t, dir, state.DefaultProfile)
	join(t, dir, "cloudrun")
	// Folders that hold no membership, or could not be a profile, are not one.
	if err := os.MkdirAll(filepath.Join(dir, "profiles", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "profiles", "Not A Name"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "profiles", "Not A Name", state.NodeFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := profiles(t, dir), []string{"default", "cloudrun", "zeta"}; !slices.Equal(got, want) {
		t.Fatalf("profiles %v, want %v", got, want)
	}

	if err := state.SetCurrentProfile(dir, "cloudrun"); err != nil {
		t.Fatal(err)
	}
	if cur, err := state.CurrentProfile(dir); err != nil || cur != "cloudrun" {
		t.Fatalf("current profile %q, %v; want cloudrun", cur, err)
	}
	if err := state.SetCurrentProfile(dir, "../escape"); err == nil {
		t.Fatal("a path was accepted as a profile name")
	}
}

func TestValidProfile(t *testing.T) {
	for _, ok := range []string{"default", "tunnel", "cloudrun", "office-2", "a"} {
		if err := state.ValidProfile(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Cloud Run", "-x", "x-", "../x", `a\b`, "profiles/x", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if err := state.ValidProfile(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Renaming moves the membership, in and out of the node directory itself, and
// the current choice follows it.
func TestRenameProfile(t *testing.T) {
	dir := t.TempDir()
	join(t, dir, state.DefaultProfile)
	join(t, dir, "cloudrun")
	if err := os.WriteFile(filepath.Join(dir, state.StatusFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := state.RenameProfile(dir, state.DefaultProfile, "tunnel"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, state.NodeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node.json still in the node directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, state.StatusFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stale status.json stayed behind: %v", err)
	}
	if got, want := profiles(t, dir), []string{"cloudrun", "tunnel"}; !slices.Equal(got, want) {
		t.Fatalf("profiles %v, want %v", got, want)
	}
	if cur, _ := state.CurrentProfile(dir); cur != "tunnel" {
		t.Fatalf("current profile %q did not follow the rename to tunnel", cur)
	}

	if err := state.RenameProfile(dir, "tunnel", "cloudrun"); err == nil {
		t.Fatal("renamed onto a profile that holds a membership")
	}
	if err := state.RenameProfile(dir, "nope", "other"); err == nil {
		t.Fatal("renamed a profile that holds no membership")
	}

	// And back: the folder it leaves goes too.
	if err := state.RenameProfile(dir, "tunnel", state.DefaultProfile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "profiles", "tunnel")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty profile folder left behind: %v", err)
	}
	if got, want := profiles(t, dir), []string{"default", "cloudrun"}; !slices.Equal(got, want) {
		t.Fatalf("profiles %v, want %v", got, want)
	}
	if cur, _ := state.CurrentProfile(dir); cur != state.DefaultProfile {
		t.Fatalf("current profile %q, want default", cur)
	}
}
