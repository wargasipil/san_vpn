// Package state keeps san_vpn's JSON files: where they live, and how to change
// them without two processes trampling each other.
//
// The relay's file is written by two kinds of process at once: the running
// relay (a join consumes an invite and adds a node) and the admin commands
// beside it (invite, remove). Rather than give the relay an admin port to
// protect, both sides change the file under a lock and the relay notices
// changes by its modification time. Nothing listens that need not.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// File names inside a state directory.
const (
	RelayFile  = "relay.json"
	NodeFile   = "node.json"
	StatusFile = "status.json"
)

// RelayDir is where the relay keeps its keys and members by default: the
// user's own config directory, because the relay needs no privileges and may
// run as an ordinary user on a server.
func RelayDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(dir, "san_vpn"), nil
}

// NodeDir is where a node keeps its key by default: a system directory, since
// creating the tunnel interface takes an administrator anyway, and a service
// running at boot will not be any particular user.
func NodeDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "san_vpn")
	}
	return "/var/lib/san_vpn"
}

// EnsureDir creates dir readable only by its owner.
//
// With admins set -- the node's directory -- Windows gets an explicit list
// instead: SYSTEM and Administrators only, because ProgramData lets every user
// read what is created in it by default. The relay's directory is under the
// user's own profile, which is private already, and restricting it to
// Administrators would lock out a relay running unelevated.
func EnsureDir(dir string, admins bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := restrict(dir, admins); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}
	return nil
}

// Load reads path into v. A missing file is reported as os.ErrNotExist so the
// caller can say what to run first.
func Load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// Save writes v to path atomically, readable by its owner only.
//
// The write goes to a temporary file that is renamed over the original, so an
// interrupted save never leaves half a file where a working one was. Windows
// refuses the rename while someone else has the file open; that is brief, so
// it is retried rather than reported.
func Save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	b = append(b, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	for attempt := 0; ; attempt++ {
		err = os.Rename(tmp, path)
		if err == nil {
			return nil
		}
		if attempt == 20 {
			_ = os.Remove(tmp)
			return fmt.Errorf("replace %s: %w", path, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Update changes the JSON file at path under its lock: load (a missing file
// leaves v as the caller made it), call fn, and save if fn succeeded.
func Update(path string, v any, fn func() error) error {
	unlock, err := Lock(path)
	if err != nil {
		return err
	}
	defer unlock()

	if err := Load(path, v); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return Save(path, v)
}

// Read loads the JSON file at path under its lock, so it never sees a file
// another process is halfway through replacing.
func Read(path string, v any) error {
	unlock, err := Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	return Load(path, v)
}

const (
	lockWait  = 10 * time.Second
	lockStale = 30 * time.Second
)

// ErrLocked means another process held the lock for longer than we waited.
var ErrLocked = errors.New("san_vpn: state file is locked by another process")

// Lock takes the advisory lock beside path: a file created exclusively, which
// every platform supports the same way. A lock older than lockStale belongs to
// a process that died holding it -- no holder keeps it for more than a single
// read-modify-write -- and is broken.
func Lock(path string) (unlock func(), err error) {
	lock := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if fi, serr := os.Stat(lock); serr == nil && time.Since(fi.ModTime()) > lockStale {
			_ = os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w (%s)", ErrLocked, lock)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
