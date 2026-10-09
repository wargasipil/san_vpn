package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// IsRelease reports whether v is a release tag, such as v0.4.2, and not a
// local build's time stamp or `dev`.
func IsRelease(v string) bool {
	_, _, ok := parse(v)
	return ok
}

// Source saves the source tree of release tag into dir, from GitHub's archive
// of the tag. GitHub makes that archive on request, so no SHA256SUMS lists it:
// it rests on HTTPS to GitHub alone, as `go install` from the repository
// would.
func (c *Client) Source(ctx context.Context, tag, dir string) error {
	u := c.Base + "/archive/refs/tags/" + url.PathEscape(tag) + ".tar.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s (see %s/releases)", ErrNoRelease, tag, c.Base)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("source of %s: %w", tag, err)
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("source of %s: %w", tag, err)
		}
		// Every entry sits under one folder, <repo>-<version>/; GitHub's
		// pax_global_header, outside it, carries only the commit id.
		_, rel, ok := strings.Cut(h.Name, "/")
		if !ok || rel == "" {
			continue
		}
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("source of %s: unsafe path %q", tag, h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; total > maxSize {
				return fmt.Errorf("source of %s: larger than %d MiB", tag, maxSize>>20)
			}
			if err := writeFile(p, tr, h.FileInfo().Mode()); err != nil {
				return err
			}
		}
		// Links and anything else: a Go source tree needs neither.
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return fmt.Errorf("source of %s: no go.mod in the archive", tag)
	}
	return nil
}

func writeFile(p string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	perm := os.FileMode(0o644)
	if mode&0o111 != 0 {
		perm = 0o755
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
