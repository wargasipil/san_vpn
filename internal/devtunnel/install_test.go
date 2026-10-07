package devtunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DownloadExe is the way in on Windows without winget: it must keep a whole
// executable and nothing else, and leave an existing copy alone otherwise.
func TestDownloadExe(t *testing.T) {
	exe := "MZ" + strings.Repeat("x", 100<<10)
	mux := http.NewServeMux()
	mux.HandleFunc("/exe", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(exe)) })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/exe", http.StatusMovedPermanently) })
	// A retired aka.ms link sends you to a search page with a 200.
	mux.HandleFunc("/retired", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Bing</title>"))
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/cut", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("MZ short"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "san_vpn", "devtunnel.exe")
	ctx := context.Background()

	if err := DownloadExe(ctx, srv.Client(), srv.URL+"/moved", path); err != nil {
		t.Fatalf("download: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != exe {
		t.Fatalf("saved %d bytes, want the %d served", len(got), len(exe))
	}

	for _, bad := range []string{"/retired", "/empty", "/cut", "/missing"} {
		if err := DownloadExe(ctx, srv.Client(), srv.URL+bad, path); err == nil {
			t.Errorf("%s: downloaded, want an error", bad)
		}
		if got, _ := os.ReadFile(path); string(got) != exe {
			t.Errorf("%s: the good copy was replaced", bad)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestInstallHint(t *testing.T) {
	hint := InstallHint()
	if downloadPath() != "" && !strings.Contains(hint, DownloadURL) {
		t.Errorf("hint %q does not mention the download for machines without winget", hint)
	}
	if hint == "" {
		t.Error("empty hint")
	}
}

// `relay run` finds the CLI with Find, so a downloaded copy must be among the
// places it looks.
func TestFindLooksAtDownload(t *testing.T) {
	p := downloadPath()
	if p == "" {
		t.Skip("downloads are for Windows")
	}
	for _, l := range installLocations() {
		if l == p {
			return
		}
	}
	t.Errorf("%s is not among %v", p, installLocations())
}
