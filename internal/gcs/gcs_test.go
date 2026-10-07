package gcs_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/wargasipil/san_vpn/internal/gcs"
	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
)

func TestObjectLifecycle(t *testing.T) {
	srv := gcstest.New()
	defer srv.Close()
	c := &gcs.Client{HTTP: srv.Client(), Base: srv.URL}
	ctx := context.Background()
	const bucket, name = "relay-bucket", "team/relay.json" // a slash in the name must survive

	if _, _, err := c.Get(ctx, bucket, name); !errors.Is(err, gcs.ErrNotFound) {
		t.Fatalf("get before any write: %v, want ErrNotFound", err)
	}
	if _, err := c.Generation(ctx, bucket, name); !errors.Is(err, gcs.ErrNotFound) {
		t.Fatalf("generation before any write: %v, want ErrNotFound", err)
	}

	g1, err := c.Put(ctx, bucket, name, []byte(`{"v":1}`), 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.Put(ctx, bucket, name, []byte(`{"v":"again"}`), 0); !errors.Is(err, gcs.ErrConflict) {
		t.Fatalf("create over an existing object: %v, want ErrConflict", err)
	}

	data, gen, err := c.Get(ctx, bucket, name)
	if err != nil || string(data) != `{"v":1}` || gen != g1 {
		t.Fatalf("get: %q gen %d err %v, want the first write at gen %d", data, gen, err, g1)
	}
	if got := srv.Object(bucket, name); string(got) != `{"v":1}` {
		t.Fatalf("stored under the wrong name: %q", got)
	}

	g2, err := c.Put(ctx, bucket, name, []byte(`{"v":2}`), g1)
	if err != nil {
		t.Fatalf("update at the current generation: %v", err)
	}
	if _, err := c.Put(ctx, bucket, name, []byte(`{"v":"stale"}`), g1); !errors.Is(err, gcs.ErrConflict) {
		t.Fatalf("update at a stale generation: %v, want ErrConflict", err)
	}
	if gen, err := c.Generation(ctx, bucket, name); err != nil || gen != g2 {
		t.Fatalf("generation %d err %v, want %d", gen, err, g2)
	}
}

// A token the server refuses is fetched again once, since a cached token can
// expire before its stated lifetime.
func TestRetriesWithAFreshToken(t *testing.T) {
	var issued atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-2" {
			http.Error(w, `{"error":{"message":"Invalid Credentials"}}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"generation":"7"}`))
	}))
	defer srv.Close()

	c := &gcs.Client{
		HTTP: srv.Client(),
		Base: srv.URL,
		Token: func(context.Context) (string, error) {
			return "token-" + string(rune('0'+issued.Load())), nil
		},
		Forget: func() { issued.Add(1) },
	}
	issued.Store(1)
	gen, err := c.Generation(context.Background(), "b", "o")
	if err != nil || gen != 7 {
		t.Fatalf("generation %d err %v, want 7 after one retry", gen, err)
	}

	issued.Store(-10) // a token no retry will fix
	if _, err := c.Generation(context.Background(), "b", "o"); err == nil {
		t.Fatal("a refused token was not reported")
	}
}
