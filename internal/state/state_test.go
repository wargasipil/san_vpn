package state_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/state"
)

type counter struct {
	N int `json:"n"`
}

// The relay and the admin commands beside it change the same file; no update
// may be lost, which is what the lock is for.
func TestUpdateSerialises(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				var c counter
				if err := state.Update(path, &c, func() error { c.N++; return nil }); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	var c counter
	if err := state.Read(path, &c); err != nil {
		t.Fatal(err)
	}
	if c.N != 100 {
		t.Fatalf("counter is %d after 100 increments", c.N)
	}
}

// A failed change writes nothing.
func TestUpdateAbortsOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	var c counter
	if err := state.Update(path, &c, func() error { c.N = 1; return nil }); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	if err := state.Update(path, &c, func() error { c.N = 2; return boom }); !errors.Is(err, boom) {
		t.Fatalf("got %v, want boom", err)
	}
	var back counter
	if err := state.Read(path, &back); err != nil || back.N != 1 {
		t.Fatalf("file holds %d (%v), want 1", back.N, err)
	}
}

// A process that died holding the lock must not wedge every later one.
func TestStaleLockIsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	lock := path + ".lock"
	if err := os.WriteFile(lock, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	var c counter
	if err := state.Update(path, &c, func() error { c.N = 7; return nil }); err != nil {
		t.Fatalf("stale lock was not broken: %v", err)
	}
}

func TestLoadMissing(t *testing.T) {
	var c counter
	if err := state.Load(filepath.Join(t.TempDir(), "none.json"), &c); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want os.ErrNotExist", err)
	}
}
