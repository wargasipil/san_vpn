package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/update"
)

// fakeUpdates stands in for GitHub's releases, this binary and its version,
// and returns the scratch binary `update` will replace.
func fakeUpdates(t *testing.T, running, latest string, binaries map[string]string) (exe string, downloads *int) {
	t.Helper()
	asset, err := update.AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	files := map[string]string{}
	for tag, body := range binaries {
		files[tag+"/"+asset] = body
		files[tag+"/"+update.SumsFile] = fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(body)), asset)
	}
	downloads = new(int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" {
			http.Redirect(w, r, "/releases/tag/"+latest, http.StatusFound)
			return
		}
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/releases/download/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		*downloads++
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ts.Close)

	exe = filepath.Join(t.TempDir(), "san_vpn"+filepath.Ext(asset))
	if err := os.WriteFile(exe, []byte("binary "+running), 0o755); err != nil {
		t.Fatal(err)
	}
	oldReleases, oldExecutable, oldCheck, oldVersion := releases, executable, checkBinary, version
	t.Cleanup(func() { releases, executable, checkBinary, version = oldReleases, oldExecutable, oldCheck, oldVersion })
	releases = &update.Client{Base: ts.URL}
	executable = func() (string, error) { return exe, nil }
	checkBinary = func(_ context.Context, path, tag string) error {
		if b, _ := os.ReadFile(path); string(b) != "binary "+tag {
			return fmt.Errorf("%s holds %q, not release %s", path, b, tag)
		}
		return nil
	}
	version = running
	return exe, downloads
}

func holds(t *testing.T, exe string) string {
	t.Helper()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(string(b), "binary ")
}

func TestUpdate(t *testing.T) {
	exe, _ := fakeUpdates(t, "v0.1.0", "v0.2.0", map[string]string{"v0.2.0": "binary v0.2.0"})

	out := mustRun(t, "update", "--check")
	if !strings.Contains(out, "v0.2.0 is out") || holds(t, exe) != "v0.1.0" {
		t.Fatalf("--check said:\n%s", out)
	}
	out = mustRun(t, "update")
	if !strings.Contains(out, "  ok   replaced ") || holds(t, exe) != "v0.2.0" {
		t.Fatalf("update said:\n%s", out)
	}
}

func TestUpdateUpToDate(t *testing.T) {
	exe, downloads := fakeUpdates(t, "v0.2.0", "v0.2.0", map[string]string{"v0.2.0": "binary v0.2.0"})
	out := mustRun(t, "update")
	if !strings.Contains(out, "up to date") || *downloads != 0 || holds(t, exe) != "v0.2.0" {
		t.Fatalf("update said (%d downloads):\n%s", *downloads, out)
	}
}

// A local build is not compared with releases; replacing it takes --force.
func TestUpdateLocalBuild(t *testing.T) {
	exe, _ := fakeUpdates(t, "2026.10.07-1723", "v0.2.0", map[string]string{"v0.2.0": "binary v0.2.0"})
	if _, err := run(t, "update"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("update of a local build: %v", err)
	}
	mustRun(t, "update", "--force")
	if got := holds(t, exe); got != "v0.2.0" {
		t.Fatalf("exe is %s", got)
	}
}

// A named release is installed even when it is older.
func TestUpdateToTag(t *testing.T) {
	exe, _ := fakeUpdates(t, "v0.2.0", "v0.2.0", map[string]string{"v0.1.5": "binary v0.1.5"})
	mustRun(t, "update", "0.1.5")
	if got := holds(t, exe); got != "v0.1.5" {
		t.Fatalf("exe is %s", got)
	}
	if _, err := run(t, "update", "v9.9.9"); err == nil || !strings.Contains(err.Error(), "no such release") {
		t.Fatalf("update to a missing release: %v", err)
	}
}

// A download that does not match SHA256SUMS never replaces the binary.
func TestUpdateTampered(t *testing.T) {
	exe, _ := fakeUpdates(t, "v0.1.0", "v0.2.0", map[string]string{"v0.2.0": "binary v0.2.0"})
	sums := fmt.Sprintf("%x", sha256.Sum256([]byte("something else")))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/releases/latest":
			http.Redirect(w, r, "/releases/tag/v0.2.0", http.StatusFound)
		case strings.HasSuffix(r.URL.Path, update.SumsFile):
			asset, _ := update.AssetName(runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(w, "%s  %s\n", sums, asset)
		default:
			fmt.Fprint(w, "binary v0.2.0")
		}
	}))
	defer ts.Close()
	releases.Base = ts.URL
	if _, err := run(t, "update"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered update: %v", err)
	}
	if got := holds(t, exe); got != "v0.1.0" {
		t.Fatalf("exe is %s", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".san_vpn-update-*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}
