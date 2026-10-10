package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// The wire convention on the relay's WebSocket:
//
//	binary message  one WireGuard packet: 32-byte key, then the packet
//	text message    one control Message, as JSON
//
// The key in a binary message is the destination when a node sends it and the
// source when the relay delivers it. The relay rewrites it in place, so a node
// can never claim to be someone else: the source is whoever authenticated the
// connection the packet arrived on.
//
// Control and data never share a message type, so a packet can never be
// mistaken for a command however its bytes happen to fall.

const (
	// ConnectPath is the WebSocket a node keeps open to the relay.
	ConnectPath = "/v1/connect"
	// JoinPath is where a node trades an invite for membership.
	JoinPath = "/v1/join"

	// ProtocolVersion is sent in Auth. A relay refuses a version it does not
	// speak instead of guessing at what the node means.
	ProtocolVersion = 1

	// ReadLimit caps one WebSocket message. A WireGuard packet is the tunnel
	// MTU plus 32 bytes of transport header plus our 32-byte key; this leaves
	// room for MTUs far above the default without letting a peer make us
	// buffer arbitrary amounts.
	ReadLimit = 1 << 17

	// SkipAntiPhishingHeader suppresses the warning page Microsoft dev tunnels
	// can put in front of anonymous tunnels. It is harmless anywhere else.
	SkipAntiPhishingHeader = "X-Tunnel-Skip-AntiPhishing-Page"
)

// Frame builds a binary message for key and packet.
func Frame(key Key, packet []byte) []byte {
	b := make([]byte, KeySize+len(packet))
	copy(b, key[:])
	copy(b[KeySize:], packet)
	return b
}

// ErrShortFrame is a binary message too small to carry a key.
var ErrShortFrame = errors.New("san_vpn: frame shorter than a key")

// SplitFrame returns the key and packet of a binary message. The packet
// aliases b.
func SplitFrame(b []byte) (Key, []byte, error) {
	if len(b) < KeySize {
		return Key{}, nil, ErrShortFrame
	}
	var k Key
	copy(k[:], b[:KeySize])
	return k, b[KeySize:], nil
}

// Message types.
const (
	TypeChallenge = "challenge" // relay -> node, first message
	TypeAuth      = "auth"      // node -> relay, the answer
	TypeWelcome   = "welcome"   // relay -> node, the relay's own proof
	TypeNetmap    = "netmap"    // relay -> node, whenever membership changes
	TypeError     = "error"     // relay -> node, just before it closes
)

// Message is every control message. Each type uses a subset of the fields.
type Message struct {
	Type string `json:"type"`

	// Challenge and Auth: each side's fresh random nonce.
	Nonce []byte `json:"nonce,omitempty"`

	// Auth: who the node claims to be, and its proof.
	PublicKey *Key `json:"public_key,omitempty"`
	Version   int  `json:"version,omitempty"`
	// Probe asks the relay to check the node and hang up, without making it
	// the node's connection: `setup check` can test a member's key while
	// that member's `up` stays connected.
	Probe bool `json:"probe,omitempty"`
	// Resume is set when a node renews a connection that is still up: the
	// relay connection id it had (its Conn in the netmap). The relay gives
	// the new connection the same id, so peers see a node that carried on,
	// not one that restarted, and keep their WireGuard sessions with it.
	Resume uint64 `json:"resume,omitempty"`

	// Auth and Welcome.
	Proof []byte `json:"proof,omitempty"`

	// Welcome: when the node should open its next connection, in
	// milliseconds, because something in front of the relay cuts connections
	// at a fixed age -- Cloud Run ends every request after its timeout, at
	// most an hour. Zero means connections may live forever. Old nodes ignore
	// it and simply reconnect when cut.
	RenewAfterMs int64 `json:"renew_after_ms,omitempty"`

	// Netmap.
	Netmap *Netmap `json:"netmap,omitempty"`

	// Error.
	Error string `json:"error,omitempty"`
}

// Netmap is one node's view of the network: itself and everyone else.
type Netmap struct {
	Network netip.Prefix `json:"network"`
	// Domain is what members' names end in: office.vpn. Empty from a relay
	// older than names, which means DefaultDomain.
	Domain string `json:"domain,omitempty"`
	Self   Peer   `json:"self"`
	Peers  []Peer `json:"peers"`
}

// Peer is one member as the relay describes it.
type Peer struct {
	Name      string     `json:"name"`
	PublicKey Key        `json:"public_key"`
	IP        netip.Addr `json:"ip"`
	// Online is whether the relay currently has a connection from it.
	Online bool `json:"online"`
	// Conn names the peer's current connection to the relay, and changes
	// whenever it reconnects. A peer that reconnected may have restarted and
	// lost its WireGuard sessions; plain WireGuard would only notice after
	// fifteen seconds of unanswered packets, so nodes reset their session
	// with a peer as soon as this changes.
	Conn uint64 `json:"conn,omitempty"`
}

// JoinRequest is what a node posts to JoinPath.
type JoinRequest struct {
	Invite    string `json:"invite"` // the invite's id, never its secret
	PublicKey Key    `json:"public_key"`
	MAC       []byte `json:"mac"`
}

// JoinResponse tells the node where it sits in the network.
type JoinResponse struct {
	Name    string       `json:"name"`
	IP      netip.Addr   `json:"ip"`
	Network netip.Prefix `json:"network"`
	Error   string       `json:"error,omitempty"`
}

// JoinMAC proves knowledge of an invite's secret without sending it, bound to
// the public key being registered.
//
// The binding is the point. Over a path that is not encrypted, an observer who
// copies the request still cannot use the invite for a key of their own, and
// the invite is spent by the time they could replay it.
func JoinMAC(secret []byte, inviteID string, pub Key) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("san_vpn/v1 join\n"))
	m.Write([]byte(inviteID))
	m.Write([]byte{'\n'})
	m.Write(pub[:])
	return m.Sum(nil)
}

// Roles in Proof. Each side proves under its own label, so a proof cannot be
// reflected back at the side that made it.
const (
	RoleNode  = "node"
	RoleRelay = "relay"
)

// Proof shows that whoever computed it holds the private half of one of the
// two keys behind shared, for this connection only.
//
// X25519 keys cannot sign, but they can agree: only the node and the relay can
// compute the secret between their two keys. A MAC under that secret, over
// both sides' fresh nonces, therefore proves possession without exposing
// anything, and cannot be replayed on a later connection. This lets the relay
// authenticate nodes by the very key WireGuard uses, and lets a node detect a
// relay that is not the one its invite named.
func Proof(shared []byte, role string, relayNonce, nodeNonce []byte) []byte {
	m := hmac.New(sha256.New, shared)
	m.Write([]byte("san_vpn/v1 auth " + role + "\n"))
	m.Write(relayNonce)
	m.Write(nodeNonce)
	return m.Sum(nil)
}

// NonceSize is the length of the handshake nonces.
const NonceSize = 32

// HandshakeTimeout bounds each side's wait for the other's handshake message.
const HandshakeTimeout = 15 * time.Second

// RenewAfter is when a node should replace a connection that the relay will
// end at limit: a tenth of the way before, at most five minutes before. That
// leaves time to retry a renewal that fails.
func RenewAfter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return limit - min(limit/10, 5*time.Minute)
}

// DefaultDomain is the domain members' names end in unless the relay names
// another. Not .local: that is multicast DNS's, and Linux machines with
// nss-mdns never ask a DNS server about it.
const DefaultDomain = "vpn"

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidDomain reports whether d can be the members' domain: lowercase DNS
// labels, such as vpn or corp.internal.
func ValidDomain(d string) error {
	if len(d) > 200 || !domainRE.MatchString(d) {
		return fmt.Errorf("domain %q: use lowercase letters, digits, hyphens and dots, such as vpn or corp.internal", d)
	}
	return nil
}

// DNSAddr is the address where every member answers for the members' names:
// the network's last host address, 10.77.0.254 in 10.77.0.0/24. The relay
// never gives it to a member. Inside the network, the route to the overlay
// already carries it into each member's tunnel, where the member answers it
// itself. A network smaller than /29 has no address to spare, so no DNS.
func DNSAddr(network netip.Prefix) (netip.Addr, bool) {
	if !network.Addr().Is4() || network.Bits() > 29 {
		return netip.Addr{}, false
	}
	b := network.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-network.Bits()) - 1) // broadcast
	binary.BigEndian.PutUint32(b[:], v-1)
	return netip.AddrFrom4(b), true
}

// EncodeSecret and DecodeSecret give secrets a printable form.
func EncodeSecret(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeSecret is the inverse of EncodeSecret.
func DecodeSecret(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
