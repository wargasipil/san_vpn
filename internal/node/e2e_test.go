package node_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// These tests run the real thing end to end -- relay over HTTP, invites,
// joins, WireGuard on both sides -- with gVisor's userspace network stack in
// place of an OS tunnel, so they need no administrator and no driver. Only
// internal/osnet is left out.

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

type testRelay struct {
	path string
	url  string
	srv  *relay.Server
}

func startRelay(t *testing.T, ctx context.Context) *testRelay {
	t.Helper()
	path := filepath.Join(t.TempDir(), state.RelayFile)
	var st relay.State
	if err := state.Update(path, &st, func() error { return st.Init(relay.DefaultNetwork) }); err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	go srv.Watch(ctx, 20*time.Millisecond)
	return &testRelay{path: path, url: ts.URL, srv: srv}
}

func (r *testRelay) invite(t *testing.T, name string) invite.Invite {
	t.Helper()
	var st relay.State
	var inv relay.Invite
	if err := state.Update(r.path, &st, func() error {
		var err error
		inv, err = st.NewInvite(name, time.Hour, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return invite.Invite{URL: r.url, RelayKey: st.PrivateKey.Public(), ID: inv.ID, Secret: inv.Secret, Name: name}
}

type testNode struct {
	cfg  *node.Config
	node *node.Node
	net  *netstack.Net
	done chan struct{} // closed when Run returns
}

func joinAndStart(t *testing.T, ctx context.Context, inv invite.Invite) *testNode {
	t.Helper()
	cfg, err := node.Join(ctx, inv, nil, nil)
	if err != nil {
		t.Fatalf("join %s: %v", inv.Name, err)
	}
	return start(t, ctx, cfg)
}

func start(t *testing.T, ctx context.Context, cfg *node.Config) *testNode {
	t.Helper()
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.IP}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	n, err := node.New(node.Options{Config: cfg, TUN: dev, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	tn := &testNode{cfg: cfg, node: n, net: tnet, done: make(chan struct{})}
	go func() { defer close(tn.done); _ = n.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-tn.done })
	return tn
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sees(n *testNode, name string, online bool) bool {
	for _, p := range n.node.Status().Peers {
		if p.Name == name {
			return p.Online == online
		}
	}
	return false
}

func hasPeer(n *testNode, name string) bool {
	for _, p := range n.node.Status().Peers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// echo serves one line-echo TCP server on the node's overlay address.
func echo(t *testing.T, n *testNode, port int) {
	t.Helper()
	ln, err := n.net.ListenTCP(&net.TCPAddr{IP: n.cfg.IP.AsSlice(), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// roundTrip dials from one node to another across the mesh and checks that a
// message comes back intact.
func roundTrip(ctx context.Context, from, to *testNode, port int, msg string) error {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := from.net.DialContextTCP(dctx, &net.TCPAddr{IP: to.cfg.IP.AsSlice(), Port: port})
	if err != nil {
		return fmt.Errorf("dial %s from %s: %w", to.cfg.IP, from.cfg.Name, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		return err
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(got) != msg {
		return fmt.Errorf("echo returned %q, want %q", got, msg)
	}
	return nil
}

func TestMeshOverRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)

	home := joinAndStart(t, ctx, r.invite(t, "home"))
	office := joinAndStart(t, ctx, r.invite(t, "office"))
	if home.cfg.IP == office.cfg.IP {
		t.Fatalf("both nodes got %s", home.cfg.IP)
	}
	if home.cfg.Network != relay.DefaultNetwork {
		t.Fatalf("network %s, want %s", home.cfg.Network, relay.DefaultNetwork)
	}

	eventually(t, "home to see office online", func() bool { return sees(home, "office", true) })
	eventually(t, "office to see home online", func() bool { return sees(office, "home", true) })

	echo(t, office, 7000)
	echo(t, home, 7000)
	if err := roundTrip(ctx, home, office, 7000, "hello from home"); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(ctx, office, home, 7000, "hello from office"); err != nil {
		t.Fatal(err)
	}

	// WireGuard itself confirms the session, not just the relay.
	for _, p := range home.node.Status().Peers {
		if p.Name == "office" && (p.LastHandshake.IsZero() || p.TxBytes == 0 || p.RxBytes == 0) {
			t.Fatalf("home's view of office shows no WireGuard session: %+v", p)
		}
	}

	// A third member joining later is reachable without anyone restarting,
	// and its arrival does not break the session already running.
	region := joinAndStart(t, ctx, r.invite(t, "region"))
	echo(t, region, 7000)
	eventually(t, "home to see region", func() bool { return sees(home, "region", true) })
	if err := roundTrip(ctx, home, region, 7000, "hello region"); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(ctx, region, office, 7000, "region to office"); err != nil {
		t.Fatal(err)
	}

	// Removing a member on the relay disconnects it and drops it from
	// everyone else's peers.
	var st relay.State
	if err := state.Update(r.path, &st, func() error { _, err := st.Remove("region"); return err }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "home to forget region", func() bool { return !hasPeer(home, "region") })
	eventually(t, "region to be cut off", func() bool { return !region.node.Status().Connected })
	if err := roundTrip(ctx, home, office, 7000, "still here"); err != nil {
		t.Fatalf("after removing region: %v", err)
	}
}

// A node that restarts keeps its address and is reachable again.
func TestReconnectAfterNodeRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)

	a := joinAndStart(t, ctx, r.invite(t, "a"))
	cfgB, err := node.Join(ctx, r.invite(t, "b"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	bctx, stopB := context.WithCancel(ctx)
	b := start(t, bctx, cfgB)
	echo(t, b, 7000)
	eventually(t, "a to see b", func() bool { return sees(a, "b", true) })
	if err := roundTrip(ctx, a, b, 7000, "first"); err != nil {
		t.Fatal(err)
	}

	stopB()
	<-b.done
	eventually(t, "a to see b offline", func() bool { return sees(a, "b", false) })

	b2 := start(t, ctx, cfgB)
	echo(t, b2, 7001)
	eventually(t, "a to see b online again", func() bool { return sees(a, "b", true) })
	if err := roundTrip(ctx, a, b2, 7001, "second"); err != nil {
		t.Fatal(err)
	}
}

// The relay restarting -- an office PC rebooting, a dev tunnel host
// restarted -- costs a reconnect, not the network: members come back on
// their own and traffic flows again without anyone touching them.
func TestRelayRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	path := filepath.Join(t.TempDir(), state.RelayFile)
	var st relay.State
	if err := state.Update(path, &st, func() error { return st.Init(relay.DefaultNetwork) }); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	serve := func(ln net.Listener) (*relay.Server, *http.Server) {
		srv, err := relay.New(path, quiet())
		if err != nil {
			t.Fatal(err)
		}
		hs := &http.Server{Handler: srv.Handler()}
		go func() { _ = hs.Serve(ln) }()
		return srv, hs
	}
	srv1, hs1 := serve(ln)

	r := &testRelay{path: path, url: "http://" + addr}
	a := joinAndStart(t, ctx, r.invite(t, "a"))
	b := joinAndStart(t, ctx, r.invite(t, "b"))
	echo(t, b, 7000)
	eventually(t, "a to see b", func() bool { return sees(a, "b", true) })
	if err := roundTrip(ctx, a, b, 7000, "before"); err != nil {
		t.Fatal(err)
	}

	sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
	srv1.Shutdown(sctx)
	scancel()
	_ = hs1.Close()
	eventually(t, "a to notice", func() bool { return !a.node.Status().Connected })

	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen again on %s: %v", addr, err)
	}
	srv2, hs2 := serve(ln2)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv2.Shutdown(c)
		_ = hs2.Close()
	})

	eventually(t, "a to see b again", func() bool { return a.node.Status().Connected && sees(a, "b", true) })
	if err := roundTrip(ctx, a, b, 7000, "after"); err != nil {
		t.Fatal(err)
	}
}

// The relay's proof is checked against the key in the invite: something else
// answering at the relay's URL -- a hijacked DNS name, a hostile front -- is
// refused however welcoming it is.
func TestImpostorRelayRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)
	cfg, err := node.Join(ctx, r.invite(t, "a"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The impostor plays the protocol perfectly but does not hold the relay's
	// private key, so the best it can send is a proof made with its own.
	impostorKey, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		nonce := make([]byte, wire.NonceSize)
		_ = wire.WriteMessage(req.Context(), c, wire.Message{Type: wire.TypeChallenge, Nonce: nonce})
		auth, err := wire.ReadMessage(req.Context(), c)
		if err != nil || auth.PublicKey == nil {
			return
		}
		shared, _ := impostorKey.Shared(*auth.PublicKey)
		_ = wire.WriteMessage(req.Context(), c, wire.Message{Type: wire.TypeWelcome, Proof: wire.Proof(shared, wire.RoleRelay, nonce, auth.Nonce)})
		_, _, _ = c.Read(req.Context())
	}))
	t.Cleanup(impostor.Close)
	cfg.RelayURL = impostor.URL

	n := start(t, ctx, cfg)
	eventually(t, "the handshake to fail", func() bool {
		return strings.Contains(n.node.Status().LastError, "could not prove")
	})
	if n.node.Status().Connected {
		t.Fatal("connected to a relay holding the wrong key")
	}
}

// A key the relay does not know cannot connect, even with the right relay key.
func TestNonMemberRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)

	cfg, err := node.Join(ctx, r.invite(t, "a"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PrivateKey = stranger

	n := start(t, ctx, cfg)
	eventually(t, "the relay to refuse", func() bool {
		return strings.Contains(n.node.Status().LastError, "not a member")
	})
}

// `setup check` probes the relay with a member's own key while that member's
// `up` is connected. The probe must not take over the connection -- a real
// second connection with the same key would replace the first.
func TestProbeLeavesTheRunningNodeAlone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)
	a := joinAndStart(t, ctx, r.invite(t, "a"))
	b := joinAndStart(t, ctx, r.invite(t, "b"))
	echo(t, b, 7000)
	eventually(t, "a to see b", func() bool { return sees(a, "b", true) })
	since := b.node.Status().Since

	for range 3 {
		if err := node.Probe(ctx, b.cfg, nil); err != nil {
			t.Fatalf("probe: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if st := b.node.Status(); !st.Connected || !st.Since.Equal(since) {
		t.Fatalf("probing b disturbed its connection: %+v", st)
	}
	if err := roundTrip(ctx, a, b, 7000, "after probes"); err != nil {
		t.Fatal(err)
	}

	stranger := *b.cfg
	stranger.PrivateKey, _ = wire.GenerateKey()
	if err := node.Probe(ctx, &stranger, nil); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("probe with an unknown key: %v", err)
	}
}

// An invite works once.
func TestInviteSingleUse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startRelay(t, ctx)

	inv := r.invite(t, "a")
	if _, err := node.Join(ctx, inv, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Join(ctx, inv, nil, nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("second join with the same invite: %v, want a 403 refusal", err)
	}
}
