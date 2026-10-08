// Package update replaces the san_vpn binary with one from a GitHub release.
//
// It reads GitHub's web links, not its API. The API allows 60 unauthenticated
// calls an hour per IP, and behind carrier-grade NAT one IP is shared by many
// customers. The web links need no quota: releases/latest redirects to the
// newest release's tag (drafts and prereleases skipped), and asset names carry
// no version, so a tag and an asset name are all a download needs.
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Base is the repository san_vpn updates from.
const Base = "https://github.com/wargasipil/san_vpn"

// SumsFile lists the SHA-256 of every file in a release.
const SumsFile = "SHA256SUMS"

// maxSize bounds a download; a release binary is a few tens of MB.
const maxSize = 256 << 20

// ErrNoRelease is returned when the tag, or any release at all, is missing.
var ErrNoRelease = errors.New("no such release")

// Client fetches releases from a repository's web pages.
type Client struct {
	Base string       // e.g. Base; a test server in tests
	HTTP *http.Client // nil: a client with a 10-minute timeout
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// Latest returns the tag of the newest release, the one GitHub's
// releases/latest link points at.
func (c *Client) Latest(ctx context.Context) (string, error) {
	u := c.Base + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	hc := *c.client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 3 {
		if resp.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("%w: %s has no published release", ErrNoRelease, c.Base)
		}
		return "", fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	// With no release yet, GitHub redirects to the releases list instead.
	_, tag, ok := strings.Cut(resp.Header.Get("Location"), "/releases/tag/")
	if !ok || tag == "" {
		return "", fmt.Errorf("%w: %s has no published release", ErrNoRelease, c.Base)
	}
	return url.PathUnescape(tag)
}

// AssetName is the release file for an OS and architecture, as the release
// workflow names it. Linux on ARM is for the Raspberry Pi: arm64 for a 64-bit
// OS, arm for a 32-bit one, built for ARMv6 so it runs on every Pi.
func AssetName(goos, goarch string) (string, error) {
	switch goos + "/" + goarch {
	case "windows/amd64":
		return "san_vpn-windows-amd64.exe", nil
	case "linux/amd64":
		return "san_vpn-linux-amd64", nil
	case "linux/arm64":
		return "san_vpn-linux-arm64", nil
	case "linux/arm":
		return "san_vpn-linux-arm", nil
	}
	return "", fmt.Errorf("releases have no binary for %s/%s; build san_vpn from source", goos, goarch)
}

// Download saves the file name from release tag as a new file in dir, checks
// it against the release's SHA256SUMS, and returns its path. The file is
// executable. When it fails, nothing is left in dir.
func (c *Client) Download(ctx context.Context, tag, name, dir string) (string, error) {
	resp, err := c.get(ctx, tag, SumsFile)
	if err != nil {
		return "", err
	}
	sums, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	want, err := sumFor(sums, name)
	if err != nil {
		return "", fmt.Errorf("release %s: %w", tag, err)
	}

	resp, err = c.get(ctx, tag, name)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// The extension matters on Windows: Check runs the file.
	f, err := os.CreateTemp(dir, ".san_vpn-update-*"+filepath.Ext(name))
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return "", fmt.Errorf("download %s: %w", name, err)
	}
	if n > maxSize {
		return "", fmt.Errorf("download %s: larger than %d MiB", name, maxSize>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("download %s: its SHA-256 is %s, but %s says %s", name, got, SumsFile, want)
	}
	if err := f.Chmod(0o755); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return f.Name(), nil
}

// get fetches a file of release tag, following GitHub's redirect to its
// storage.
func (c *Client) get(ctx context.Context, tag, name string) (*http.Response, error) {
	u := c.Base + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		if name == SumsFile {
			return nil, fmt.Errorf("%w: %s (see %s/releases)", ErrNoRelease, tag, c.Base)
		}
		return nil, fmt.Errorf("release %s has no %s", tag, name)
	}
	return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
}

// sumFor finds name's SHA-256 in a sha256sum listing.
func sumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			sum := strings.ToLower(f[0])
			if b, err := hex.DecodeString(sum); err != nil || len(b) != sha256.Size {
				return "", fmt.Errorf("%s has a bad line for %s", SumsFile, name)
			}
			return sum, nil
		}
	}
	return "", fmt.Errorf("%s does not list %s", SumsFile, name)
}

// Check runs the downloaded binary's --version. A file that does not run on
// this machine, or is not the release it was fetched as, never replaces a
// working binary.
func Check(ctx context.Context, path, tag string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	got := string(bytes.TrimSpace(out))
	if err != nil {
		return fmt.Errorf("the downloaded binary does not run: %v %s", err, got)
	}
	if want := "san_vpn version " + tag; got != want {
		return fmt.Errorf("the downloaded binary says %q, want %q", got, want)
	}
	return nil
}

// Replace puts the file fresh in place of exe.
//
// Windows refuses to overwrite or delete a running executable, but lets it be
// renamed. So there the old binary first moves aside to exe.old, and RemoveOld
// deletes it on a later start. Elsewhere one rename replaces it; processes
// already running keep the old file open until they exit.
func Replace(exe, fresh string) error {
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(exe); err == nil {
			if err := os.Chmod(fresh, info.Mode().Perm()); err != nil {
				return err
			}
		}
		return os.Rename(fresh, exe)
	}
	removeAside(exe)
	aside := exe + ".old"
	if _, err := os.Lstat(aside); err == nil {
		// An older san_vpn still runs from it: an `up` that was never
		// restarted after the last update.
		aside = exe + ".old-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	if err := os.Rename(exe, aside); err != nil {
		return err
	}
	if err := os.Rename(fresh, exe); err != nil {
		if rerr := os.Rename(aside, exe); rerr != nil {
			return fmt.Errorf("%w; the previous binary is at %s", err, aside)
		}
		return err
	}
	return nil
}

// RemoveOld deletes the binary the last update moved aside, once nothing
// runs from it any more. It is one call, cheap enough for every start, and
// does nothing outside Windows.
func RemoveOld(exe string) {
	if runtime.GOOS == "windows" {
		_ = os.Remove(exe + ".old")
	}
}

// removeAside deletes every binary earlier updates moved aside that is no
// longer running.
func removeAside(exe string) {
	dir, prefix := filepath.Dir(exe), filepath.Base(exe)+".old"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			_ = os.Remove(filepath.Join(dir, e.Name())) // fails while it runs
		}
	}
}

// Newer reports whether release tag b is newer than a. Tags are
// vMAJOR.MINOR.PATCH, optionally with a -prerelease, which sorts before its
// release; two prereleases of one version compare as text. ok is false when
// either is not such a tag, as with a local build, which is stamped with its
// build time.
func Newer(a, b string) (newer, ok bool) {
	va, preA, okA := parse(a)
	vb, preB, okB := parse(b)
	if !okA || !okB {
		return false, false
	}
	for i := range va {
		if va[i] != vb[i] {
			return vb[i] > va[i], true
		}
	}
	switch {
	case preA == preB:
		return false, true
	case preB == "":
		return true, true // v1.0.0 is newer than v1.0.0-rc1
	case preA == "":
		return false, true
	}
	return preB > preA, true
}

func parse(tag string) (v [3]int, pre string, ok bool) {
	rest, found := strings.CutPrefix(tag, "v")
	if !found {
		return v, "", false
	}
	rest, pre, _ = strings.Cut(rest, "-")
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return v, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, "", false
		}
		v[i] = n
	}
	return v, pre, true
}
