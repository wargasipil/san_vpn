package state_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wargasipil/san_vpn/internal/gcs"
	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
	"github.com/wargasipil/san_vpn/internal/state"
)

// Both kinds of store keep the same promises; each test runs on both.
func stores(t *testing.T) map[string]state.Store {
	t.Helper()
	srv := gcstest.New()
	t.Cleanup(srv.Close)
	return map[string]state.Store{
		"file": state.File(filepath.Join(t.TempDir(), "c.json")),
		"gcs":  &state.GCS{Client: &gcs.Client{HTTP: srv.Client(), Base: srv.URL}, Bucket: "b", Object: "team/c.json"},
	}
}

func TestStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	for kind, s := range stores(t) {
		t.Run(kind, func(t *testing.T) {
			var c counter
			if _, err := s.Read(ctx, &c); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read before any write: %v, want os.ErrNotExist", err)
			}
			if _, err := s.Version(ctx); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("version before any write: %v, want os.ErrNotExist", err)
			}

			if err := s.Update(ctx, &c, func() error { c.N = 1; return nil }); err != nil {
				t.Fatal(err)
			}
			v1, err := s.Version(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var back counter
			if read, err := s.Read(ctx, &back); err != nil || back.N != 1 || read != v1 {
				t.Fatalf("read %d at version %q (%v), want 1 at %q", back.N, read, err, v1)
			}

			boom := errors.New("boom")
			if err := s.Update(ctx, &c, func() error { c.N = 99; return boom }); !errors.Is(err, boom) {
				t.Fatalf("got %v, want boom", err)
			}
			if v, _ := s.Version(ctx); v != v1 {
				t.Fatal("a failed update changed the document")
			}

			if err := s.Update(ctx, &c, func() error { c.N++; return nil }); err != nil {
				t.Fatal(err)
			}
			if v, _ := s.Version(ctx); v == v1 {
				t.Fatal("the version did not change with the document")
			}
		})
	}
}

// The relay records joins while an admin issues invites: concurrent writers,
// and not one change may be lost.
func TestStoreConcurrentUpdates(t *testing.T) {
	ctx := context.Background()
	for kind, s := range stores(t) {
		t.Run(kind, func(t *testing.T) {
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 15 {
						var c counter
						if err := s.Update(ctx, &c, func() error { c.N++; return nil }); err != nil {
							t.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
			var c counter
			if _, err := s.Read(ctx, &c); err != nil || c.N != 60 {
				t.Fatalf("counter is %d (%v) after 60 increments", c.N, err)
			}
		})
	}
}

func TestOpen(t *testing.T) {
	s, err := state.Open("gs://my-bucket/team", "relay.json")
	if err != nil || s.String() != "gs://my-bucket/team/relay.json" || !state.Remote(s) {
		t.Fatalf("gs://my-bucket/team: %v, %v", s, err)
	}
	if s, _ := state.Open("gs://my-bucket", "relay.json"); s.String() != "gs://my-bucket/relay.json" {
		t.Fatalf("gs://my-bucket: %v", s)
	}
	if _, err := state.Open("gs://", "relay.json"); err == nil {
		t.Fatal("gs:// with no bucket was accepted")
	}
	dir := t.TempDir()
	if s, _ := state.Open(dir, "relay.json"); s.String() != filepath.Join(dir, "relay.json") || state.Remote(s) {
		t.Fatalf("local dir: %v", s)
	}
}
