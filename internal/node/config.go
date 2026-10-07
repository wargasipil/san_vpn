// Package node is one member of a san_vpn network: a WireGuard device whose
// packets travel over a WebSocket to the relay instead of over UDP.
//
// WireGuard itself is unchanged. The only thing replaced is its network
// binding (conn.Bind): where it would send a datagram to a peer's IP and port,
// it hands the packet to the relay addressed by the peer's public key. Every
// peer is still a full WireGuard peer with its own keys, so the mesh is end to
// end encrypted even though every packet passes the relay.
package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// Config is the node's file.
type Config struct {
	Name       string       `json:"name"`
	PrivateKey wire.Key     `json:"private_key"`
	IP         netip.Addr   `json:"ip"`
	Network    netip.Prefix `json:"network"`
	RelayURL   string       `json:"relay_url"`
	RelayKey   wire.Key     `json:"relay_key"`
	// Headers are added to every request to the relay, for fronts that want
	// their own credentials (a private dev tunnel's X-Tunnel-Authorization).
	Headers map[string]string `json:"headers,omitempty"`
}

// Prefix is the node's address with the network's length, as the interface
// carries it: 10.77.0.2/24 routes the whole overlay to the tunnel.
func (c *Config) Prefix() netip.Prefix { return netip.PrefixFrom(c.IP, c.Network.Bits()) }

// Validate checks a loaded config is usable.
func (c *Config) Validate() error {
	switch {
	case c.PrivateKey.IsZero():
		return errors.New("node config has no private key")
	case c.RelayKey.IsZero() || c.RelayURL == "":
		return errors.New("node config has no relay")
	case !c.Network.IsValid() || !c.Network.Contains(c.IP):
		return fmt.Errorf("node address %s is not inside network %s", c.IP, c.Network)
	}
	return nil
}

// Join trades an invite for membership. The private key is made here and
// never leaves this machine; the relay only learns the public half.
func Join(ctx context.Context, inv invite.Invite, headers map[string]string, client *http.Client) (*Config, error) {
	if client == nil {
		client = http.DefaultClient
	}
	base, err := HTTPURL(inv.URL)
	if err != nil {
		return nil, err
	}
	secret, err := wire.DecodeSecret(inv.Secret)
	if err != nil {
		return nil, fmt.Errorf("invite secret: %w", err)
	}
	priv, err := wire.GenerateKey()
	if err != nil {
		return nil, err
	}
	pub := priv.Public()

	body, err := json.Marshal(wire.JoinRequest{Invite: inv.ID, PublicKey: pub, MAC: wire.JoinMAC(secret, inv.ID, pub)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+wire.JoinPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setHeaders(req.Header, headers)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach relay: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("read join response: %w", err)
	}
	var jr wire.JoinResponse
	if err := json.Unmarshal(raw, &jr); err != nil {
		// Not our relay talking: a front's error page, a login wall.
		return nil, fmt.Errorf("relay answered %s, and not with a join response: %.200s", resp.Status, strings.TrimSpace(string(raw)))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("join refused (%s): %s", resp.Status, jr.Error)
	}

	c := &Config{
		Name:       jr.Name,
		PrivateKey: priv,
		IP:         jr.IP,
		Network:    jr.Network,
		RelayURL:   base,
		RelayKey:   inv.RelayKey,
		Headers:    headers,
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("relay sent an unusable answer: %w", err)
	}
	return c, nil
}

// HTTPURL normalises a relay URL to http(s) with no trailing slash. People
// paste ws:// and wss:// forms too; they name the same place.
func HTTPURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("relay url: %w", err)
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return "", fmt.Errorf("relay url %q: want http(s):// or ws(s)://", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("relay url %q has no host", raw)
	}
	u.RawQuery, u.Fragment = "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

func setHeaders(h http.Header, extra map[string]string) {
	h.Set(wire.SkipAntiPhishingHeader, "true")
	for k, v := range extra {
		h.Set(k, v)
	}
}
