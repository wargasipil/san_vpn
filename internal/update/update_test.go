package update

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The test binary doubles as a downloaded release: run with
// SAN_VPN_FAKE_VERSION set, it answers --version the way san_vpn does.
func TestMain(m *testing.M) {
	if v := os.Getenv("SAN_VPN_FAKE_VERSION"); v != "" {
		fmt.Println("san_vpn version " + v)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeGitHub answers the release links the way github.com does: latest
// redirects to the tag's page, and downloads redirect to storage.
type fakeGitHub struct {
	latest string            // "" = no release published yet
	files  map[string][]byte // "<tag>/<name>"
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/releases/latest" && g.latest == "":
		http.Redirect(w, r, "/releases", http.StatusFound)
	case p == "/releases/latest":
		http.Redirect(w, r, "/releases/tag/"+g.latest, http.StatusFound)
	case strings.HasPrefix(p, "/releases/download/"):
		http.Redirect(w, r, "/storage/"+strings.TrimPrefix(p, "/releases/download/"), http.StatusFound)
	case strings.HasPrefix(p, "/storage/"):
		body, ok := g.files[strings.TrimPrefix(p, "/storage/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	default:
		http.NotFound(w, r)
	}
}

// publish adds a release with these files and their SHA256SUMS.
func (g *fakeGitHub) publish(tag string, files map[string]string) {
	if g.files == nil {
		g.files = map[string][]byte{}
	}
	var sums strings.Builder
	for name, body := range files {
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256([]byte(body)), name)
		g.files[tag+"/"+name] = []byte(body)
	}
	g.files[tag+"/"+SumsFile] = []byte(sums.String())
	g.latest = tag
}

func serve(t *testing.T, g *fakeGitHub) *Client {
	ts := httptest.NewServer(g)
	t.Cleanup(ts.Close)
	return &Client{Base: ts.URL}
}

func TestLatest(t *testing.T) {
	g := &fakeGitHub{}
	c := serve(t, g)
	if _, err := c.Latest(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("no release yet: %v", err)
	}
	g.publish("v0.2.0", map[string]string{"a": "a"})
	tag, err := c.Latest(context.Background())
	if err != nil || tag != "v0.2.0" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
}

func TestDownload(t *testing.T) {
	ctx := context.Background()
	const name = "san_vpn-linux-amd64"
	g := &fakeGitHub{}
	g.publish("v0.2.0", map[string]string{name: "new binary", "san_vpn-windows-amd64.exe": "windows"})
	c := serve(t, g)
	dir := t.TempDir()

	path, err := c.Download(ctx, "v0.2.0", name, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new binary" || filepath.Dir(path) != dir {
		t.Fatalf("downloaded %q to %s", b, path)
	}
	os.Remove(path)

	// A file that does not match SHA256SUMS is refused and leaves nothing.
	g.files["v0.2.0/"+name] = []byte("tampered")
	if _, err := c.Download(ctx, "v0.2.0", name, dir); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered download: %v", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}

	if _, err := c.Download(ctx, "v0.2.0", "san_vpn-plan9-amd64", dir); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Fatalf("a file the release does not have: %v", err)
	}
	if _, err := c.Download(ctx, "v9.9.9", name, dir); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("a release that does not exist: %v", err)
	}
}

func TestSumFor(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	if got, err := sumFor([]byte(sum+" *bin\n"), "bin"); err != nil || got != sum {
		t.Fatalf("binary-mode line: %q, %v", got, err)
	}
	if _, err := sumFor([]byte("abc  bin\n"), "bin"); err == nil {
		t.Fatal("accepted a short sum")
	}
}

func TestCheck(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAN_VPN_FAKE_VERSION", "v0.2.0")
	ctx := context.Background()
	if err := Check(ctx, exe, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, exe, "v0.3.0"); err == nil {
		t.Fatal("accepted a binary that reports another version")
	}
	if err := Check(ctx, filepath.Join(t.TempDir(), "missing"), "v0.2.0"); err == nil {
		t.Fatal("accepted a binary that does not run")
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "san_vpn.exe")
	write := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		b, _ := os.ReadFile(path)
		return string(b)
	}
	write(exe, "v1")
	fresh := filepath.Join(dir, "fresh")
	write(fresh, "v2")
	if err := Replace(exe, fresh); err != nil {
		t.Fatal(err)
	}
	if got := read(exe); got != "v2" {
		t.Fatalf("exe holds %q", got)
	}
	if runtime.GOOS != "windows" {
		return
	}
	if got := read(exe + ".old"); got != "v1" {
		t.Fatalf("the old binary is not aside: %q", got)
	}

	// An old binary still in use stays where it is, and the next one moves
	// aside under a name of its own.
	held, err := os.Open(exe + ".old")
	if err != nil {
		t.Fatal(err)
	}
	write(fresh, "v3")
	if err := Replace(exe, fresh); err != nil {
		t.Fatal(err)
	}
	if got := read(exe); got != "v3" {
		t.Fatalf("exe holds %q", got)
	}
	held.Close()
	RemoveOld(exe)
	if _, err := os.Stat(exe + ".old"); !os.IsNotExist(err) {
		t.Fatalf("RemoveOld left %s.old: %v", exe, err)
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b      string
		newer, ok bool
	}{
		{"v0.1.0", "v0.2.0", true, true},
		{"v0.2.0", "v0.1.0", false, true},
		{"v0.1.0", "v0.1.0", false, true},
		{"v0.9.0", "v0.10.0", true, true},
		{"v1.0.0-rc1", "v1.0.0", true, true},
		{"v1.0.0", "v1.0.0-rc1", false, true},
		{"v1.0.0-rc1", "v1.0.0-rc2", true, true},
		{"dev", "v0.1.0", false, false},
		{"2026.10.07-1723", "v0.1.0", false, false},
		{"v0.1", "v0.1.0", false, false},
	} {
		if newer, ok := Newer(c.a, c.b); newer != c.newer || ok != c.ok {
			t.Errorf("Newer(%q, %q) = %v, %v; want %v, %v", c.a, c.b, newer, ok, c.newer, c.ok)
		}
	}
}

func TestAssetName(t *testing.T) {
	if n, _ := AssetName("windows", "amd64"); n != "san_vpn-windows-amd64.exe" {
		t.Error(n)
	}
	if n, _ := AssetName("linux", "amd64"); n != "san_vpn-linux-amd64" {
		t.Error(n)
	}
	if n, _ := AssetName("linux", "arm64"); n != "san_vpn-linux-arm64" {
		t.Error(n)
	}
	if n, _ := AssetName("linux", "arm"); n != "san_vpn-linux-arm" {
		t.Error(n)
	}
	if _, err := AssetName("darwin", "arm64"); err == nil {
		t.Error("no error for a platform without a release binary")
	}
}
