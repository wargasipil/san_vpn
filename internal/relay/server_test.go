package relay_test

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// member is a relay with one member, and that member's key.
func member(t *testing.T) (*relay.Server, string, wire.Key) {
	t.Helper()
	ctx := context.Background()
	store := state.File(filepath.Join(t.TempDir(), state.RelayFile))
	key, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var st relay.State
	if err := store.Update(ctx, &st, func() error {
		if err := st.Init(relay.DefaultNetwork); err != nil {
			return err
		}
		st.Nodes = append(st.Nodes, relay.Node{Name: "a", PublicKey: key.Public(), IP: st.Network.Addr().Next()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(ctx, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts.URL, key
}

// connect authenticates as key and returns the connection and the welcome.
func connect(t *testing.T, ctx context.Context, url string, srv *relay.Server, key wire.Key, resume uint64) (*websocket.Conn, wire.Message) {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http")+wire.ConnectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	ch, err := wire.ReadMessage(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, wire.NonceSize)
	_, _ = rand.Read(nonce)
	shared, err := key.Shared(srv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	if err := wire.WriteMessage(ctx, c, wire.Message{
		Type: wire.TypeAuth, Nonce: nonce, PublicKey: &pub, Version: wire.ProtocolVersion,
		Proof: wire.Proof(shared, wire.RoleNode, ch.Nonce, nonce), Resume: resume,
	}); err != nil {
		t.Fatal(err)
	}
	w, err := wire.ReadMessage(ctx, c)
	if err != nil || w.Type != wire.TypeWelcome {
		t.Fatalf("welcome: %+v, %v", w, err)
	}
	return c, w
}

// selfConn reads up to the first member list and returns this member's
// connection id from it.
func selfConn(t *testing.T, ctx context.Context, c *websocket.Conn) uint64 {
	t.Helper()
	for {
		m, err := wire.ReadMessage(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if m.Type == wire.TypeNetmap {
			return m.Netmap.Self.Conn
		}
	}
}

// With a session limit, the welcome says when to renew, and a connection
// that does not renew is ended at the limit: as Cloud Run would end it, but
// with a reason the node can log.
func TestSessionLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv, url, key := member(t)

	_, w := connect(t, ctx, url, srv, key, 0)
	if w.RenewAfterMs != 0 {
		t.Fatalf("no limit, yet the welcome asks for renewal after %dms", w.RenewAfterMs)
	}

	srv.SetSessionLimit(time.Second)
	c, w := connect(t, ctx, url, srv, key, 0)
	if want := wire.RenewAfter(time.Second).Milliseconds(); w.RenewAfterMs != want || want != 900 {
		t.Fatalf("renew after %dms, want %dms", w.RenewAfterMs, want)
	}
	start := time.Now()
	for {
		m, err := wire.ReadMessage(ctx, c)
		if err != nil {
			t.Fatalf("connection ended without a reason after %s: %v", time.Since(start), err)
		}
		if m.Type == wire.TypeError {
			if !strings.Contains(m.Error, "session limit") {
				t.Fatalf("ended with %q", m.Error)
			}
			break
		}
	}
	if d := time.Since(start); d < 800*time.Millisecond || d > 3*time.Second {
		t.Fatalf("ended after %s, want about the 1s limit", d)
	}
}

// A renewing node names the connection it replaces and keeps its id, so
// peers do not mistake a renewal for a restart. A stale id gets a new one.
func TestRenewKeepsTheConnectionID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv, url, key := member(t)

	first, _ := connect(t, ctx, url, srv, key, 0)
	id := selfConn(t, ctx, first)
	if id == 0 {
		t.Fatal("no connection id")
	}

	second, _ := connect(t, ctx, url, srv, key, id)
	if got := selfConn(t, ctx, second); got != id {
		t.Fatalf("renewed connection got id %d, want %d", got, id)
	}
	// The relay tells the replaced connection why it is going.
	for {
		m, err := wire.ReadMessage(ctx, first)
		if err != nil {
			break
		}
		if m.Type == wire.TypeError {
			break
		}
	}

	third, _ := connect(t, ctx, url, srv, key, id+2) // not its current id
	if got := selfConn(t, ctx, third); got == id || got == 0 {
		t.Fatalf("a wrong resume id was honoured: got %d", got)
	}
}
