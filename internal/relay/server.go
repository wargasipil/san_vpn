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
	path string
	log  *slog.Logger
	now  func() time.Time

	mu       sync.RWMutex
	priv     wire.Key
	network  netip.Prefix
	members  map[wire.Key]Node
	sessions map[wire.Key]*session
	modTime  time.Time
	closing  bool

	handlers sync.WaitGroup // connect handlers still running
}

type session struct {
	key    wire.Key
	id     uint64 // random, so a restarted relay never reuses one
	data   chan []byte
	netmap chan struct{}
	kick   chan string
}

// New loads the relay at path, which `relay init` must have created.
func New(path string, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{path: path, log: log, now: time.Now, sessions: map[wire.Key]*session{}}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// PublicKey is the relay's key, as invites carry it.
func (s *Server) PublicKey() wire.Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.priv.Public()
}

// Reload rereads the state file, then disconnects nodes that are no longer
// members and sends everyone else the new member list.
func (s *Server) Reload() error {
	var st State
	unlock, err := state.Lock(s.path)
	if err != nil {
		return err
	}
	err = state.Load(s.path, &st)
	fi, serr := os.Stat(s.path)
	unlock()
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no relay at %s; run `san_vpn relay init` first", s.path)
	}
	if err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	if st.PrivateKey.IsZero() || !st.Network.IsValid() {
		return fmt.Errorf("%s has no key or network; run `san_vpn relay init`", s.path)
	}

	members := make(map[wire.Key]Node, len(st.Nodes))
	for _, n := range st.Nodes {
		members[n.PublicKey] = n
	}

	s.mu.Lock()
	s.priv = st.PrivateKey
	s.network = st.Network
	s.members = members
	s.modTime = fi.ModTime()
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

// Watch reloads whenever the state file changes, until ctx ends. This is how
// `relay invite` and `relay remove`, run beside a live relay, take effect.
func (s *Server) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fi, err := os.Stat(s.path)
		if err != nil {
			continue
		}
		s.mu.RLock()
		changed := !fi.ModTime().Equal(s.modTime)
		s.mu.RUnlock()
		if changed {
			if err := s.Reload(); err != nil {
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
	err := state.Update(s.path, &st, func() error {
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
	if err := s.Reload(); err != nil {
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
	if !s.attach(sess) {
		reject(ctx, c, "relay is shutting down")
		return
	}
	defer s.detach(sess)
	log.Info("node connected", "remote", r.RemoteAddr)

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
	log.Info("node disconnected")
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
	welcome := wire.Message{Type: wire.TypeWelcome, Proof: wire.Proof(shared, wire.RoleRelay, relayNonce, auth.Nonce)}
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
// the first: that is a node that restarted before the relay noticed the old
// connection was dead, and the new one is the one that works.
func (s *Server) attach(sess *session) bool {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return false
	}
	if old := s.sessions[sess.key]; old != nil {
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
			log.Info("disconnecting node", "reason", reason)
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
	nm := &wire.Netmap{Network: s.network, Peers: []wire.Peer{}}
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
