package node_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/gcs"
	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// These tests cover what a relay on Cloud Run needs: connections renewed
// before the front cuts them, and the relay's file in Cloud Storage.

// Behind a front that ends every connection at a fixed age, members move to a
// new connection before the cut, and nothing above notices: a TCP stream
// across the mesh keeps going, no one is seen to disconnect, and WireGuard
// keeps its sessions instead of starting new handshakes.
func TestRenewalIsSeamless(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)
	const limit = 1500 * time.Millisecond
	r.srv.SetSessionLimit(limit)

	a := joinAndStart(t, ctx, r.invite(t, "a"))
	b := joinAndStart(t, ctx, r.invite(t, "b"))
	echo(t, b, 7000)
	eventually(t, "a to see b", func() bool { return sees(a, "b", true) })
	if err := roundTrip(ctx, a, b, 7000, "warm up"); err != nil {
		t.Fatal(err)
	}
	sinceA, sinceB := a.node.Status().Since, b.node.Status().Since
	handshake := peer(a, "b").LastHandshake
	connects := r.connects.Load()

	// One TCP connection, one line every 50ms, across several renewals.
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	c, err := a.net.DialContextTCP(dctx, &net.TCPAddr{IP: b.cfg.IP.AsSlice(), Port: 7000})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := bufio.NewReader(c)
	deadline := time.Now().Add(4 * limit)
	lines := 0
	for time.Now().Before(deadline) {
		msg := fmt.Sprintf("line %d", lines)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := fmt.Fprintln(c, msg); err != nil {
			t.Fatalf("after %d lines: %v", lines, err)
		}
		got, err := in.ReadString('\n')
		if err != nil || strings.TrimSpace(got) != msg {
			t.Fatalf("after %d lines: got %q, %v", lines, got, err)
		}
		lines++
		time.Sleep(50 * time.Millisecond)
	}

	if renewed := r.connects.Load() - connects; renewed < 4 {
		t.Fatalf("%d new connections in %s with a %s limit; the members did not renew", renewed, 4*limit, limit)
	}
	if st := a.node.Status(); !st.Connected || !st.Since.Equal(sinceA) {
		t.Errorf("a was seen to disconnect: %+v", st)
	}
	if st := b.node.Status(); !st.Connected || !st.Since.Equal(sinceB) {
		t.Errorf("b was seen to disconnect: %+v", st)
	}
	if !sees(a, "b", true) {
		t.Error("a sees b offline")
	}
	if got := peer(a, "b").LastHandshake; !got.Equal(handshake) {
		t.Errorf("WireGuard started a new handshake (%s, was %s): a renewal looked like a restart", got, handshake)
	}
}

func peer(n *testNode, name string) (p struct {
	LastHandshake time.Time
}) {
	for _, s := range n.node.Status().Peers {
		if s.Name == name {
			p.LastHandshake = s.LastHandshake
		}
	}
	return p
}

// A relay whose file is a Cloud Storage object works like one on disk, and
// admin commands run elsewhere -- another process, another machine, with its
// own client -- take effect on it: an invite becomes a member, a removal cuts
// the member off.
func TestMeshOverCloudStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := gcstest.New()
	defer srv.Close()
	store := func() state.Store {
		return &state.GCS{Client: &gcs.Client{HTTP: srv.Client(), Base: srv.URL}, Bucket: "relay", Object: "team/relay.json"}
	}

	r := startRelayOn(t, ctx, store())
	admin := &testRelay{store: store(), url: r.url} // the relay's own client is not used
	home := joinAndStart(t, ctx, admin.invite(t, "home"))
	office := joinAndStart(t, ctx, admin.invite(t, "office"))
	echo(t, office, 7000)
	eventually(t, "home to see office", func() bool { return sees(home, "office", true) })
	if err := roundTrip(ctx, home, office, 7000, "via cloud storage"); err != nil {
		t.Fatal(err)
	}
	if got := srv.Object("relay", "team/relay.json"); !strings.Contains(string(got), `"office"`) {
		t.Fatalf("the join is not in the object: %s", got)
	}

	var st relay.State
	if err := admin.store.Update(ctx, &st, func() error { _, err := st.Remove("office"); return err }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "office to be cut off", func() bool { return !office.node.Status().Connected })
	eventually(t, "home to forget office", func() bool { return !hasPeer(home, "office") })
}
