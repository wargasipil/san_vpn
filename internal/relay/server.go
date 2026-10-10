package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/wire"
)

const (
	// queueSize is how many packets may wait for one slow node before the
	// relay starts dropping. Dropping is what UDP would do, and WireGuard and
	// the TCP inside it are built for it; blocking would let one stalled node
	// hold up every sender.
	queueSize = 512

	// writeTimeout bounds one write to a node. A node that accepts nothing
	// for this long is gone, and its connection is closed.
	writeTimeout = 15 * time.Second
)

// Server is a running relay.
type Server struct {
	store state.Store
	log   *slog.Logger
	now   func() time.Time

	mu       sync.RWMutex
	priv     wire.Key
	network  netip.Prefix
	domain   string
	members  map[wire.Key]Node
	sessions map[wire.Key]*session
	version  string
	closing  bool
	limit    time.Duration // 0: sessions may last forever

	handlers sync.WaitGroup // connect handlers still running
}

type session struct {
	key    wire.Key
	id     uint64 // random, so a restarted relay never reuses one
	data   chan []byte
	netmap chan struct{}
	kick   chan string
	// renewed is set when the node replaced this connection with a renewal:
	// routine, hourly on Cloud Run, so not worth an info line.
	renewed atomic.Bool
}

// New loads the relay from store, which `relay init` must have filled.
func New(ctx context.Context, store state.Store, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{store: store, log: log, now: time.Now, sessions: map[wire.Key]*session{}}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// SetSessionLimit makes the relay end every connection after d, and tell
// nodes to open their next one before that. It is for fronts that cut
// connections at a fixed age -- Cloud Run ends each request at its timeout --
// so that nodes move to a new connection on their own schedule, without a
// gap, instead of being cut. Zero, the default, means no limit.
func (s *Server) SetSessionLimit(d time.Duration) {
	s.mu.Lock()
	s.limit = d
	s.mu.Unlock()
}

// PublicKey is the relay's key, as invites carry it.
func (s *Server) PublicKey() wire.Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.priv.Public()
}

// Reload rereads the state, then disconnects nodes that are no longer
// members and sends everyone else the new member list.
func (s *Server) Reload(ctx context.Context) error {
	var st State
	version, err := s.store.Read(ctx, &st)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no relay at %s; run `san_vpn relay init` first", s.store)
	}
	if err != nil {
		return err
	}
	if st.PrivateKey.IsZero() || !st.Network.IsValid() {
		return fmt.Errorf("%s has no key or network; run `san_vpn relay init`", s.store)
	}

	members := make(map[wire.Key]Node, len(st.Nodes))
	for _, n := range st.Nodes {
		members[n.PublicKey] = n
	}

	s.mu.Lock()
	s.priv = st.PrivateKey
	s.network = st.Network
	s.domain = st.DomainOrDefault()
	s.members = members
	s.version = version
	for k, sess := range s.sessions {
		if _, ok := members[k]; !ok {
			kick(sess, "removed from the network")
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()

	s.broadcast()
	return nil
}

// Watch reloads whenever the state changes, until ctx ends. This is how
// `relay invite` and `relay remove` take effect on a live relay: run beside
// it on the same file, or from anywhere against its Cloud Storage object.
func (s *Server) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		version, err := s.store.Version(ctx)
		if err != nil {
			// A remote store can be briefly unreachable; say so once, not
			// every tick, and keep serving what we have.
			if !failing && ctx.Err() == nil {
				s.log.Warn("check state", "err", err)
			}
			failing = true
			continue
		}
		failing = false
		s.mu.RLock()
		changed := version != s.version
		s.mu.RUnlock()
		if changed {
			if err := s.Reload(ctx); err != nil {
				s.log.Warn("reload state", "err", err)
			}
		}
	}
}

// Handler serves the relay's HTTP surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "san_vpn relay\n")
	})
	mux.HandleFunc("POST "+wire.JoinPath, s.handleJoin)
	mux.HandleFunc("GET "+wire.ConnectPath, s.handleConnect)
	return mux
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req wire.JoinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJoin(w, http.StatusBadRequest, wire.JoinResponse{Error: "malformed join request"})
		return
	}

	var st State
	var node Node
	err := s.store.Update(r.Context(), &st, func() error {
		var err error
		node, err = st.Join(req, s.now())
		return err
	})
	switch {
	case errors.Is(err, ErrUnknownInvite):
		s.log.Warn("join refused", "invite", req.Invite, "remote", r.RemoteAddr)
		writeJoin(w, http.StatusForbidden, wire.JoinResponse{Error: err.Error()})
		return
	case errors.Is(err, ErrAlreadyMember), errors.Is(err, ErrNetworkFull):
		writeJoin(w, http.StatusConflict, wire.JoinResponse{Error: err.Error()})
		return
	case err != nil:
		s.log.Error("join", "err", err)
		writeJoin(w, http.StatusInternalServerError, wire.JoinResponse{Error: "relay could not record the join"})
		return
	}

	s.log.Info("node joined", "name", node.Name, "ip", node.IP, "key", node.PublicKey)
	if err := s.Reload(r.Context()); err != nil {
		s.log.Warn("reload after join", "err", err)
	}
	writeJoin(w, http.StatusOK, wire.JoinResponse{Name: node.Name, IP: node.IP, Network: st.Network})
}

func writeJoin(w http.ResponseWriter, code int, resp wire.JoinResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept has already written the HTTP error.
	}
	defer c.CloseNow()
	c.SetReadLimit(wire.ReadLimit)
	if !s.enter() {
		reject(r.Context(), c, "relay is shutting down")
		return
	}
	defer s.handlers.Done()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	key, auth, err := s.handshake(ctx, c)
	if errors.Is(err, errNoAuth) {
		// Hung up before saying who it is: a health check, a scanner.
		s.log.Debug("connection closed before auth", "remote", r.RemoteAddr, "err", err)
		return
	}
	if err != nil {
		s.log.Info("connection refused", "remote", r.RemoteAddr, "err", err)
		reject(ctx, c, err.Error())
		return
	}
	name := s.nameOf(key)
	log := s.log.With("node", name)
	if auth.Probe {
		log.Debug("probe answered", "remote", r.RemoteAddr)
		_ = c.Close(websocket.StatusNormalClosure, "")
		return
	}

	sess := &session{
		key:    key,
		id:     randomID(),
		data:   make(chan []byte, queueSize),
		netmap: make(chan struct{}, 1),
		kick:   make(chan string, 1),
	}
	if !s.attach(sess, auth.Resume) {
		reject(ctx, c, "relay is shutting down")
		return
	}
	defer s.detach(sess)
	if auth.Resume != 0 {
		log.Debug("node renewed its connection", "remote", r.RemoteAddr)
	} else {
		log.Info("node connected", "remote", r.RemoteAddr)
	}
	if limit := s.sessionLimit(); limit > 0 {
		t := time.AfterFunc(limit, func() { kick(sess, "session limit reached") })
		defer t.Stop()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.writeLoop(ctx, cancel, c, sess, log) }()
	go func() { defer wg.Done(); wire.Keepalive(ctx, c, wire.KeepaliveInterval, wire.KeepaliveTimeout) }()

	for {
		typ, b, err := c.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageBinary {
			s.forward(key, b)
		}
		// Nodes send no control messages after the handshake; anything else
		// is ignored rather than trusted.
	}
	cancel()
	wg.Wait()
	if sess.renewed.Load() {
		log.Debug("renewed connection closed")
	} else {
		log.Info("node disconnected")
	}
}

// errNoAuth is a connection that ended before its auth message arrived.
var errNoAuth = errors.New("no auth message")

// handshake runs the relay's half: challenge, check the node's proof, prove
// ourselves back. It returns the node's auth message too, for its Probe flag.
func (s *Server) handshake(ctx context.Context, c *websocket.Conn) (wire.Key, wire.Message, error) {
	relayNonce := make([]byte, wire.NonceSize)
	if _, err := rand.Read(relayNonce); err != nil {
		return wire.Key{}, wire.Message{}, err
	}
	if err := wire.WriteMessage(ctx, c, wire.Message{Type: wire.TypeChallenge, Nonce: relayNonce}); err != nil {
		return wire.Key{}, wire.Message{}, err
	}

	hctx, cancel := context.WithTimeout(ctx, wire.HandshakeTimeout)
	defer cancel()
	auth, err := wire.ReadMessage(hctx, c)
	if err != nil {
		return wire.Key{}, wire.Message{}, fmt.Errorf("%w: %v", errNoAuth, err)
	}
	if auth.Type != wire.TypeAuth || auth.PublicKey == nil || len(auth.Nonce) != wire.NonceSize {
		return wire.Key{}, auth, errors.New("expected an auth message")
	}
	if auth.Version != wire.ProtocolVersion {
		return wire.Key{}, auth, fmt.Errorf("protocol version %d is not supported (relay speaks %d)", auth.Version, wire.ProtocolVersion)
	}
	key := *auth.PublicKey

	s.mu.RLock()
	_, member := s.members[key]
	priv := s.priv
	s.mu.RUnlock()
	if !member {
		return wire.Key{}, auth, errors.New("not a member of this network")
	}

	shared, err := priv.Shared(key)
	if err != nil {
		return wire.Key{}, wire.Message{}, err
	}
	if !hmac.Equal(auth.Proof, wire.Proof(shared, wire.RoleNode, relayNonce, auth.Nonce)) {
		return wire.Key{}, auth, errors.New("proof does not match the node's key")
	}
	welcome := wire.Message{
		Type:         wire.TypeWelcome,
		Proof:        wire.Proof(shared, wire.RoleRelay, relayNonce, auth.Nonce),
		RenewAfterMs: wire.RenewAfter(s.sessionLimit()).Milliseconds(),
	}
	if err := wire.WriteMessage(ctx, c, welcome); err != nil {
		return wire.Key{}, wire.Message{}, err
	}
	return key, auth, nil
}

func reject(ctx context.Context, c *websocket.Conn, reason string) {
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = wire.WriteMessage(wctx, c, wire.Message{Type: wire.TypeError, Error: reason})
	_ = c.Close(websocket.StatusPolicyViolation, "")
}

// attach registers a session. A second connection with the same key replaces
// the first: either a node that restarted before the relay noticed the old
// connection was dead, and the new one is the one that works, or a node
// renewing its connection before the session limit. The renewing node names
// the connection it is replacing, and keeps its id.
func (s *Server) attach(sess *session, resume uint64) bool {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return false
	}
	if old := s.sessions[sess.key]; old != nil {
		if resume != 0 && old.id == resume {
			sess.id = old.id
			old.renewed.Store(true)
		}
		kick(old, "replaced by a newer connection")
	}
	s.sessions[sess.key] = sess
	s.mu.Unlock()
	s.broadcast()
	return true
}

// enter counts a connect handler in, unless the relay is shutting down. The
// check and the count happen under one lock, so Shutdown never waits on a
// group that is still growing.
func (s *Server) enter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.handlers.Add(1)
	return true
}

// Shutdown tells every node the relay is going away and waits, until ctx
// ends, for their connections to close. Told, a node redials at once; left to
// find out from its keepalive, it would sit on a dead connection for up to
// forty seconds. http.Server.Shutdown cannot do this for us: it stops
// tracking a connection once it becomes a WebSocket.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	s.closing = true
	for _, sess := range s.sessions {
		kick(sess, "relay is shutting down")
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.handlers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Server) detach(sess *session) {
	s.mu.Lock()
	removed := s.sessions[sess.key] == sess
	if removed {
		delete(s.sessions, sess.key)
	}
	s.mu.Unlock()
	if removed {
		s.broadcast()
	}
}

func kick(sess *session, reason string) {
	select {
	case sess.kick <- reason:
	default:
	}
}

// broadcast asks every session to send its node a fresh member list. The
// signal is coalesced, so a burst of changes costs one message per node.
func (s *Server) broadcast() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		select {
		case sess.netmap <- struct{}{}:
		default:
		}
	}
}

// forward relays one packet from src. The frame's key is rewritten from the
// destination to the source in place, so receivers learn the sender from the
// relay's authentication, never from the sender's say-so.
func (s *Server) forward(src wire.Key, b []byte) {
	dst, _, err := wire.SplitFrame(b)
	if err != nil {
		return
	}
	s.mu.RLock()
	to := s.sessions[dst]
	s.mu.RUnlock()
	if to == nil {
		return
	}
	copy(b[:wire.KeySize], src[:])
	select {
	case to.data <- b:
	default:
	}
}

func (s *Server) writeLoop(ctx context.Context, cancel context.CancelFunc, c *websocket.Conn, sess *session, log *slog.Logger) {
	defer cancel()
	write := func(typ websocket.MessageType, b []byte) bool {
		wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
		defer wcancel()
		return c.Write(wctx, typ, b) == nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case reason := <-sess.kick:
			if !sess.renewed.Load() {
				log.Info("disconnecting node", "reason", reason)
			}
			reject(ctx, c, reason)
			return
		case <-sess.netmap:
			b, err := json.Marshal(wire.Message{Type: wire.TypeNetmap, Netmap: s.netmapFor(sess.key)})
			if err != nil || !write(websocket.MessageText, b) {
				return
			}
		case b := <-sess.data:
			if !write(websocket.MessageBinary, b) {
				return
			}
		}
	}
}

// netmapFor is the network as one member sees it.
func (s *Server) netmapFor(key wire.Key) *wire.Netmap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nm := &wire.Netmap{Network: s.network, Domain: s.domain, Peers: []wire.Peer{}}
	for k, n := range s.members {
		p := wire.Peer{Name: n.Name, PublicKey: k, IP: n.IP}
		if sess := s.sessions[k]; sess != nil {
			p.Online, p.Conn = true, sess.id
		}
		if k == key {
			nm.Self = p
			continue
		}
		nm.Peers = append(nm.Peers, p)
	}
	slices.SortFunc(nm.Peers, func(a, b wire.Peer) int { return a.IP.Compare(b.IP) })
	return nm
}

func (s *Server) sessionLimit() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.limit
}

func (s *Server) nameOf(key wire.Key) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.members[key].Name
}

func randomID() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) | 1 // never 0, which means offline
}
