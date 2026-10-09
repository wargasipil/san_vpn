// Package relay is the meeting point of a san_vpn network: it knows who the
// members are, hands each of them the list of the others, and forwards their
// WireGuard packets over WebSockets.
//
// It forwards, it never decrypts. Every pair of nodes runs WireGuard end to
// end with keys the relay never holds, so the relay -- and whatever HTTPS
// front it sits behind, such as a dev tunnel -- only ever sees ciphertext
// addressed to a public key.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// DefaultNetwork is the overlay range. 10.77/24 is rarely used by home or
// office routers (unlike 192.168.x and 10.0.x), and stays clear of 100.64/10,
// which Indonesian ISPs use for carrier-grade NAT on the WAN side.
var DefaultNetwork = netip.MustParsePrefix("10.77.0.0/24")

// DefaultInviteTTL is how long an invite stays usable.
const DefaultInviteTTL = 24 * time.Hour

// State is the relay's file.
type State struct {
	PrivateKey wire.Key `json:"private_key"`
	// URL is what nodes dial, as the outside world sees it: for a dev tunnel,
	// its https URL, not the local listen address.
	URL     string       `json:"url,omitempty"`
	Network netip.Prefix `json:"network"`
	Nodes   []Node       `json:"nodes"`
	Invites []Invite     `json:"invites"`
	// Tunnel is the dev tunnel `setup init` put in front of the relay, which
	// `relay run` hosts. Nil when the relay is fronted some other way.
	Tunnel *Tunnel `json:"tunnel,omitempty"`
	// CloudRun is the Cloud Run service `cloudrun setup` readied and
	// `cloudrun deploy` runs the relay as.
	// Nil when the relay runs anywhere else.
	CloudRun *CloudRun `json:"cloud_run,omitempty"`
}

// Tunnel names the relay's dev tunnel.
type Tunnel struct {
	ID   string `json:"id"`   // as the service reports it, with its region: san-vpn-ab12cd.asse
	Port int    `json:"port"` // forwarded to 127.0.0.1:Port, where the relay listens
}

// CloudRun names the relay's Cloud Run service.
type CloudRun struct {
	Project string `json:"project"`
	Region  string `json:"region"`
	Service string `json:"service"`
}

// Node is a member.
type Node struct {
	Name      string     `json:"name"`
	PublicKey wire.Key   `json:"public_key"`
	IP        netip.Addr `json:"ip"`
	Joined    time.Time  `json:"joined"`
}

// Invite is an unused invitation.
type Invite struct {
	ID      string    `json:"id"`
	Secret  string    `json:"secret"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
}

// Errors a join can fail with. All but the last are the invite's fault, and
// look the same from outside so a guesser learns nothing from which one.
var (
	ErrUnknownInvite = errors.New("san_vpn: invite unknown, used or expired")
	ErrAlreadyMember = errors.New("san_vpn: this key is already a member")
	ErrNetworkFull   = errors.New("san_vpn: no free address left in the network")
)

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidName reports whether name can name a node: lowercase letters, digits
// and inner hyphens, at most 32 characters. Hostname-shaped, so names can
// become DNS names later without renaming anyone.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("node name %q: use lowercase letters, digits and hyphens, at most 32", name)
	}
	return nil
}

// Init fills a new state: a fresh key and the network.
func (s *State) Init(network netip.Prefix) error {
	if !network.Addr().Is4() || network.Bits() > 30 || network.Bits() < 8 {
		return fmt.Errorf("network %s: want an IPv4 range between /8 and /30", network)
	}
	key, err := wire.GenerateKey()
	if err != nil {
		return err
	}
	s.PrivateKey = key
	s.Network = network.Masked()
	return nil
}

// NewInvite records an invite for name.
func (s *State) NewInvite(name string, ttl time.Duration, now time.Time) (Invite, error) {
	if err := ValidName(name); err != nil {
		return Invite{}, err
	}
	s.pruneInvites(now)
	if s.nodeByName(name) >= 0 {
		return Invite{}, fmt.Errorf("a node named %q is already a member; remove it first to invite it again", name)
	}
	if slices.ContainsFunc(s.Invites, func(i Invite) bool { return i.Name == name }) {
		return Invite{}, fmt.Errorf("an invite for %q is already waiting; remove it first to issue a new one", name)
	}

	id := make([]byte, 8)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Invite{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return Invite{}, err
	}
	inv := Invite{
		ID:      hex.EncodeToString(id),
		Secret:  wire.EncodeSecret(secret),
		Name:    name,
		Expires: now.Add(ttl).UTC().Truncate(time.Second),
	}
	s.Invites = append(s.Invites, inv)
	return inv, nil
}

// Join spends an invite on a public key and returns the new member.
func (s *State) Join(req wire.JoinRequest, now time.Time) (Node, error) {
	s.pruneInvites(now)
	i := slices.IndexFunc(s.Invites, func(i Invite) bool { return i.ID == req.Invite })
	if i < 0 {
		return Node{}, ErrUnknownInvite
	}
	inv := s.Invites[i]
	secret, err := wire.DecodeSecret(inv.Secret)
	if err != nil {
		return Node{}, fmt.Errorf("invite %s has a corrupt secret: %w", inv.ID, err)
	}
	if !hmac.Equal(req.MAC, wire.JoinMAC(secret, inv.ID, req.PublicKey)) {
		return Node{}, ErrUnknownInvite
	}
	if req.PublicKey.IsZero() || s.nodeByKey(req.PublicKey) >= 0 || req.PublicKey == s.PrivateKey.Public() {
		return Node{}, ErrAlreadyMember
	}
	ip, err := s.allocate()
	if err != nil {
		return Node{}, err
	}

	n := Node{Name: inv.Name, PublicKey: req.PublicKey, IP: ip, Joined: now.UTC().Truncate(time.Second)}
	s.Nodes = append(s.Nodes, n)
	s.Invites = slices.Delete(s.Invites, i, i+1)
	return n, nil
}

// Remove drops a member or a waiting invite by name, and says which it was.
func (s *State) Remove(name string) (string, error) {
	if i := s.nodeByName(name); i >= 0 {
		s.Nodes = slices.Delete(s.Nodes, i, i+1)
		return "node", nil
	}
	if i := slices.IndexFunc(s.Invites, func(i Invite) bool { return i.Name == name }); i >= 0 {
		s.Invites = slices.Delete(s.Invites, i, i+1)
		return "invite", nil
	}
	return "", fmt.Errorf("no node or invite named %q", name)
}

// allocate returns the lowest free host address. Addresses of removed nodes
// are reused; WireGuard keys, not addresses, are what peers trust.
func (s *State) allocate() (netip.Addr, error) {
	used := make(map[netip.Addr]bool, len(s.Nodes))
	for _, n := range s.Nodes {
		used[n.IP] = true
	}
	broadcast := lastAddr(s.Network)
	for a := s.Network.Addr().Next(); s.Network.Contains(a) && a != broadcast; a = a.Next() {
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrNetworkFull
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (s *State) pruneInvites(now time.Time) {
	s.Invites = slices.DeleteFunc(s.Invites, func(i Invite) bool { return !now.Before(i.Expires) })
}

func (s *State) nodeByName(name string) int {
	return slices.IndexFunc(s.Nodes, func(n Node) bool { return n.Name == name })
}

func (s *State) nodeByKey(k wire.Key) int {
	return slices.IndexFunc(s.Nodes, func(n Node) bool { return n.PublicKey == k })
}
