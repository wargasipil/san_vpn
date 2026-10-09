package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archive is a tag's source as GitHub serves it: a pax global header, then
// everything under <repo>-<version>/.
func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "08fb5cf"}}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "san_vpn-0.4.2/", Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		h := &tar.Header{Typeflag: tar.TypeReg, Name: "san_vpn-0.4.2/" + name, Mode: 0o644, Size: int64(len(body))}
		if strings.HasSuffix(name, ".sh") {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// serveArchive answers like github.com: the archive link redirects to
// codeload, which sends the file.
func serveArchive(t *testing.T, tag string, body []byte) *Client {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/archive/refs/tags/" + tag + ".tar.gz":
			http.Redirect(w, r, "/codeload/"+tag, http.StatusFound)
		case "/codeload/" + tag:
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return &Client{Base: ts.URL}
}

func TestSource(t *testing.T) {
	c := serveArchive(t, "v0.4.2", archive(t, map[string]string{
		"go.mod":              "module github.com/wargasipil/san_vpn\n",
		"Dockerfile":          "FROM scratch\n",
		"cmd/san_vpn/main.go": "package main\n",
		"build.sh":            "#!/bin/sh\n",
	}))
	dir := t.TempDir()
	if err := c.Source(context.Background(), "v0.4.2", dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cmd", "san_vpn", "main.go"))
	if err != nil || string(b) != "package main\n" {
		t.Fatalf("main.go: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pax_global_header")); err == nil {
		t.Error("the pax header was written out as a file")
	}

	if err := c.Source(context.Background(), "v9.9.9", t.TempDir()); !errors.Is(err, ErrNoRelease) {
		t.Errorf("a missing tag: %v, want ErrNoRelease", err)
	}
}

// An entry that climbs out of the folder is refused, and nothing lands
// outside it.
func TestSourceRefusesUnsafePaths(t *testing.T) {
	c := serveArchive(t, "v0.4.2", archive(t, map[string]string{"../../evil.txt": "x", "go.mod": "module x\n"}))
	dir := filepath.Join(t.TempDir(), "src")
	err := c.Source(context.Background(), "v0.4.2", dir)
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("got %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.txt")); err == nil {
		t.Fatal("a file was written outside the folder")
	}
}

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{"v0.4.2": true, "v1.0.0-rc1": true, "dev": false, "2026.10.09-1128": false, "dev-20261009-120000": false} {
		if IsRelease(v) != want {
			t.Errorf("IsRelease(%q) = %v", v, !want)
		}
	}
}
