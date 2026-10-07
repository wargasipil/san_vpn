package node

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/wargasipil/san_vpn/internal/wire"
)

const (
	backoffMin = time.Second
	backoffMax = 30 * time.Second
	// writeTimeout bounds one write to the relay; past it the connection is
	// treated as dead and redialled.
	writeTimeout = 15 * time.Second
)

// Options configure a node.
type Options struct {
	Config *Config
	// TUN is the interface WireGuard reads from and writes to: a real one in
	// production, a userspace network stack in tests.
	TUN tun.Device
	Log *slog.Logger
	// HTTPClient dials the relay. Nil means http.DefaultClient.
	HTTPClient *http.Client
	// OnChange, if set, is called when the connection or the member list
	// changes, so a status display can refresh at once. It must not block.
	OnChange func()
}

// Node is a running member.
type Node struct {
	o    Options
	log  *slog.Logger
	bind *relayBind
	dev  *device.Device

	mu        sync.Mutex
	peers     map[wire.Key]netip.Addr
	conns     map[wire.Key]uint64 // last relay connection seen per peer
	fresh     bool                // no member list applied since we (re)connected
	netmap    *wire.Netmap
	connected bool
	since     time.Time
	lastErr   string
}

// New creates the WireGuard device on o.TUN. Nothing is sent until Run.
func New(o Options) (*Node, error) {
	if err := o.Config.Validate(); err != nil {
		return nil, err
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	n := &Node{o: o, log: o.Log, bind: newRelayBind(), peers: map[wire.Key]netip.Addr{}, conns: map[wire.Key]uint64{}}

	wglog := o.Log.With("component", "wireguard")
	n.dev = device.NewDevice(o.TUN, n.bind, &device.Logger{
		Verbosef: func(f string, a ...any) { wglog.Debug(fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { wglog.Warn(fmt.Sprintf(f, a...)) },
	})
	if err := n.dev.IpcSet("private_key=" + o.Config.PrivateKey.Hex() + "\n"); err != nil {
		n.dev.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}
	if err := n.dev.Up(); err != nil {
		n.dev.Close()
		return nil, fmt.Errorf("start wireguard: %w", err)
	}
	return n, nil
}

// Run keeps the node connected to the relay until ctx ends, then shuts the
// device down. A lost connection is redialled with backoff; it is never an
// error, because a relay restart or a network change is ordinary.
func (n *Node) Run(ctx context.Context) error {
	defer n.dev.Close()
	backoff := backoffMin
	for {
		start := time.Now()
		err := n.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		n.setError(err)
		n.log.Warn("relay connection lost", "err", err)
		if time.Since(start) > time.Minute {
			backoff = backoffMin
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jitter(backoff)):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

// dial opens the WebSocket to the relay.
func dial(ctx context.Context, cfg *Config, client *http.Client) (*websocket.Conn, error) {
	h := http.Header{}
	setHeaders(h, cfg.Headers)
	dctx, cancel := context.WithTimeout(ctx, wire.HandshakeTimeout)
	defer cancel()
	c, _, err := websocket.Dial(dctx, cfg.RelayURL+wire.ConnectPath, &websocket.DialOptions{
		HTTPClient:      client,
		HTTPHeader:      h,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.RelayURL, err)
	}
	c.SetReadLimit(wire.ReadLimit)
	return c, nil
}

// Probe checks that the relay is reachable, is the relay this node joined,
// and accepts this node's key -- without becoming the node's connection, so
// it is safe while `up` runs.
func Probe(ctx context.Context, cfg *Config, client *http.Client) error {
	if client == nil {
		client = http.DefaultClient
	}
	c, err := dial(ctx, cfg, client)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	if err := handshake(ctx, c, cfg, true); err != nil {
		return err
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
	return nil
}

// session is one connection to the relay, from dial to failure.
func (n *Node) session(ctx context.Context) error {
	cfg := n.o.Config
	c, err := dial(ctx, cfg, n.o.HTTPClient)
	if err != nil {
		return err
	}
	defer c.CloseNow()

	if err := handshake(ctx, c, cfg, false); err != nil {
		return err
	}
	n.log.Info("connected to relay", "relay", cfg.RelayURL, "ip", cfg.IP)
	n.setConnected(true)
	defer n.setConnected(false)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n.writeLoop(sctx, cancel, c) }()
	go func() { defer wg.Done(); wire.Keepalive(sctx, c, wire.KeepaliveInterval, wire.KeepaliveTimeout) }()
	defer wg.Wait() // the next session's writer must not race this one's
	defer cancel()

	for {
		typ, b, err := c.Read(sctx)
		if err != nil {
			return err
		}
		if typ == websocket.MessageBinary {
			from, packet, err := wire.SplitFrame(b)
			if err == nil {
				n.bind.deliver(from, packet)
			}
			continue
		}
		m, err := wire.ParseMessage(b)
		if err != nil {
			return err
		}
		switch m.Type {
		case wire.TypeNetmap:
			if m.Netmap != nil {
				n.applyNetmap(m.Netmap)
			}
		case wire.TypeError:
			return fmt.Errorf("relay: %s", m.Error)
		}
	}
}

// handshake proves our key to the relay and checks the relay's proof against
// the key our invite named.
func handshake(ctx context.Context, c *websocket.Conn, cfg *Config, probe bool) error {
	hctx, cancel := context.WithTimeout(ctx, wire.HandshakeTimeout)
	defer cancel()

	ch, err := wire.ReadMessage(hctx, c)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if ch.Type != wire.TypeChallenge || len(ch.Nonce) != wire.NonceSize {
		return errors.New("handshake: relay did not send a challenge")
	}
	nonce := make([]byte, wire.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	shared, err := cfg.PrivateKey.Shared(cfg.RelayKey)
	if err != nil {
		return err
	}
	pub := cfg.PrivateKey.Public()
	auth := wire.Message{
		Type:      wire.TypeAuth,
		Nonce:     nonce,
		PublicKey: &pub,
		Version:   wire.ProtocolVersion,
		Proof:     wire.Proof(shared, wire.RoleNode, ch.Nonce, nonce),
		Probe:     probe,
	}
	if err := wire.WriteMessage(hctx, c, auth); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	w, err := wire.ReadMessage(hctx, c)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if w.Type == wire.TypeError {
		return fmt.Errorf("relay refused us: %s", w.Error)
	}
	if w.Type != wire.TypeWelcome || !hmac.Equal(w.Proof, wire.Proof(shared, wire.RoleRelay, ch.Nonce, nonce)) {
		// Whatever answered does not hold the relay key from our invite.
		return errors.New("handshake: the relay could not prove it is the relay this node joined")
	}
	return nil
}

func (n *Node) writeLoop(ctx context.Context, cancel context.CancelFunc, c *websocket.Conn) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-n.bind.out:
			wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
			err := c.Write(wctx, websocket.MessageBinary, b)
			wcancel()
			if err != nil {
				return
			}
		}
	}
}

// applyNetmap makes WireGuard's peers match the relay's member list.
func (n *Node) applyNetmap(nm *wire.Netmap) {
	cfg := n.o.Config
	self := cfg.PrivateKey.Public()
	if nm.Self.PublicKey == self && nm.Self.IP != cfg.IP {
		n.log.Warn("relay lists this node at a different address", "relay_says", nm.Self.IP, "configured", cfg.IP)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Sessions to start over. A peer whose relay connection changed may have
	// restarted, and its old session is then dead on one side only. And when
	// we ourselves have just reconnected, every peer resets its session with
	// us on seeing that, so we reset ours with all of them to match. Either
	// way the next packet starts a fresh handshake, instead of WireGuard
	// waiting out fifteen seconds of silence to find out.
	want := make(map[wire.Key]netip.Addr, len(nm.Peers))
	reset := map[wire.Key]bool{}
	for _, p := range nm.Peers {
		if p.PublicKey == self || !cfg.Network.Contains(p.IP) || p.IP == cfg.IP {
			continue
		}
		want[p.PublicKey] = p.IP
		if p.Conn != 0 {
			if old := n.conns[p.PublicKey]; n.fresh || (old != 0 && old != p.Conn) {
				reset[p.PublicKey] = true
			}
			n.conns[p.PublicKey] = p.Conn
		}
	}
	n.fresh = false
	for k := range n.conns {
		if _, ok := want[k]; !ok {
			delete(n.conns, k)
		}
	}

	if set := peerUpdate(n.peers, want, reset); set != "" {
		if err := n.dev.IpcSet(set); err != nil {
			n.log.Error("configure peers", "err", err)
			return
		}
	}
	n.peers = want
	n.netmap = nm
	n.log.Debug("member list", "peers", len(want))
	n.changed()
}

func (n *Node) changed() {
	if n.o.OnChange != nil {
		n.o.OnChange()
	}
}

func (n *Node) setConnected(v bool) {
	n.bind.connected.Store(v)
	n.mu.Lock()
	n.connected = v
	if v {
		n.since = time.Now()
		n.lastErr = ""
		n.fresh = true
	}
	n.mu.Unlock()
	n.changed()
}

func (n *Node) setError(err error) {
	n.mu.Lock()
	if err != nil {
		n.lastErr = err.Error()
	}
	n.mu.Unlock()
	n.changed()
}

// Status is a snapshot of the node, as `san_vpn status` shows it.
type Status struct {
	Updated   time.Time    `json:"updated"`
	PID       int          `json:"pid"`
	Name      string       `json:"name"`
	IP        netip.Addr   `json:"ip"`
	Network   netip.Prefix `json:"network"`
	Relay     string       `json:"relay"`
	Connected bool         `json:"connected"`
	Since     time.Time    `json:"since,omitzero"`
	LastError string       `json:"last_error,omitempty"`
	Peers     []PeerStatus `json:"peers"`
}

// PeerStatus is one other member.
type PeerStatus struct {
	Name      string     `json:"name"`
	IP        netip.Addr `json:"ip"`
	PublicKey wire.Key   `json:"public_key"`
	// Online is the relay's word: it has a connection from this peer.
	Online bool `json:"online"`
	// LastHandshake is WireGuard's: when the encrypted session with this
	// peer was last renewed. Unlike Online, it proves the path end to end.
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
}

// Status reports the node's state now.
func (n *Node) Status() Status {
	dump, _ := n.dev.IpcGet()
	stats := parseStats(dump)

	n.mu.Lock()
	defer n.mu.Unlock()
	cfg := n.o.Config
	st := Status{
		Updated:   time.Now(),
		PID:       os.Getpid(),
		Name:      cfg.Name,
		IP:        cfg.IP,
		Network:   cfg.Network,
		Relay:     cfg.RelayURL,
		Connected: n.connected,
		LastError: n.lastErr,
		Peers:     []PeerStatus{},
	}
	if n.connected {
		st.Since = n.since
	}
	if n.netmap != nil {
		for _, p := range n.netmap.Peers {
			if _, ok := n.peers[p.PublicKey]; !ok {
				continue
			}
			s := stats[p.PublicKey]
			st.Peers = append(st.Peers, PeerStatus{
				Name: p.Name, IP: p.IP, PublicKey: p.PublicKey, Online: p.Online,
				LastHandshake: s.LastHandshake, RxBytes: s.RxBytes, TxBytes: s.TxBytes,
			})
		}
	}
	return st
}

// jitter spreads reconnects over [d/2, d) so nodes cut off by one relay
// restart do not all come back in the same instant.
func jitter(d time.Duration) time.Duration {
	half := int64(d / 2)
	r, err := rand.Int(rand.Reader, big.NewInt(half))
	if err != nil {
		return d
	}
	return time.Duration(half + r.Int64())
}
