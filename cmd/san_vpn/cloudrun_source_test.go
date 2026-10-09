package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/update"
)

// The old place says where Cloud Run went, flags and all.
func TestSetupCloudRunMoved(t *testing.T) {
	_, err := run(t, "setup", "cloudrun", "--project", "p", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "san_vpn cloudrun setup") || !strings.Contains(err.Error(), "san_vpn cloudrun deploy") {
		t.Fatalf("got %v, want a pointer to both cloudrun commands", err)
	}
}

// A dev build outside a checkout has nothing to build, and says what to
// pass; this runs before gcloud is looked for.
func TestCloudRunDeployDevNeedsSource(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := run(t, "cloudrun", "deploy"); err == nil || !strings.Contains(err.Error(), "--source") {
		t.Fatalf("got %v, want a pointer to --source", err)
	}
	if _, err := run(t, "cloudrun", "deploy", "--source", t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a san_vpn source tree") {
		t.Fatalf("--source of an empty folder: %v", err)
	}
}

// tree makes a minimal san_vpn source tree, with CRLF line ends as a Windows
// checkout has them.
func tree(t *testing.T) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/wargasipil/san_vpn\r\n\r\ngo 1.26\r\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	return dir
}

func TestPickSource(t *testing.T) {
	ctx := context.Background()

	// A tree of one's own, named or the working directory: a dev tag.
	own := tree(t)
	tag, src, done, err := pickSource(own, "v0.4.2", io.Discard, nil)
	if err != nil || !strings.HasPrefix(tag, "dev-") {
		t.Fatalf("--source: %q, %v", tag, err)
	}
	if dir, err := src(ctx); err != nil || dir != own {
		t.Fatalf("--source gave %q, %v", dir, err)
	}
	done()
	t.Chdir(own)
	if tag, src, _, err = pickSource("", "dev", io.Discard, nil); err != nil || !strings.HasPrefix(tag, "dev-") {
		t.Fatalf("go run in a checkout: %q, %v", tag, err)
	}
	if dir, _ := src(ctx); dir != own {
		t.Fatalf("go run in a checkout built %q", dir)
	}

	// A release: its own tag, its source from GitHub, fetched only when
	// asked and removed when done.
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"go.mod": "module github.com/wargasipil/san_vpn\n", "Dockerfile": "FROM scratch\n"} {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "san_vpn-0.4.2/" + name, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	fetches := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/archive/refs/tags/v0.4.2.tar.gz" {
			http.NotFound(w, r)
			return
		}
		fetches++
		w.Write(archive.Bytes())
	}))
	defer gh.Close()
	tag, src, done, err = pickSource("", "v0.4.2", io.Discard, &update.Client{Base: gh.URL})
	if err != nil || tag != "v0.4.2" || fetches != 0 {
		t.Fatalf("release: %q, %v, fetched %d times before asked", tag, err, fetches)
	}
	dir, err := src(ctx)
	if err != nil || sourceTree(dir) != nil {
		t.Fatalf("release source in %q: %v / %v", dir, err, sourceTree(dir))
	}
	done()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the fetched source was left in %s", dir)
	}
}
