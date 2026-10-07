// Package setup puts the relay behind a Microsoft dev tunnel in one command,
// and checks a machine's whole path -- tunnel, relay, membership, `up` --
// in another.
//
// Init is idempotent: each step looks before it acts, so running it again on
// a working setup changes nothing, and running it after something broke (a
// tunnel that expired, anonymous access turned off) repairs only that.
package setup

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/wargasipil/san_vpn/internal/devtunnel"
	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// DefaultPort is the local port the relay listens on and the tunnel forwards.
const DefaultPort = 8443

// InitOptions configure Init.
type InitOptions struct {
	RelayPath string
	// Port overrides the forwarded port; 0 keeps the current one, or 8443.
	Port int
	// TunnelID adopts an existing tunnel instead of the recorded or a new one.
	TunnelID string
	// DeviceCode signs in with a code entered on another device, for
	// machines with no browser.
	DeviceCode bool
	// Out receives one line per step.
	Out io.Writer
}

// Result is what Init set up.
type Result struct {
	TunnelID string
	Port     int
	URL      string
}

// Init signs in, makes sure the relay, the tunnel, its anonymous access and
// its port exist, and records the tunnel's public URL as the relay's URL.
func Init(ctx context.Context, cli *devtunnel.CLI, o InitOptions) (*Result, error) {
	p := printer{o.Out}

	u, err := cli.User(ctx)
	if err != nil {
		return nil, err
	}
	if !u.LoggedIn() {
		p.line("..", "signing in to dev tunnels with GitHub")
		if err := cli.Login(ctx, o.DeviceCode); err != nil {
			return nil, fmt.Errorf("sign in to dev tunnels: %w", err)
		}
		if u, err = cli.User(ctx); err != nil {
			return nil, err
		}
		if !u.LoggedIn() {
			return nil, errors.New("still not signed in to dev tunnels; try `devtunnel user login -g`")
		}
	}
	p.line("ok", "signed in to dev tunnels as %s (%s)", u.Username, u.Provider)

	var st relay.State
	created := false
	if err := state.EnsureDir(filepath.Dir(o.RelayPath), false); err != nil {
		return nil, err
	}
	if err := state.Update(o.RelayPath, &st, func() error {
		if st.PrivateKey.IsZero() {
			created = true
			return st.Init(relay.DefaultNetwork)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	p.line("ok", "relay key %s, network %s%s", st.PrivateKey.Public(), st.Network, when(created, " (created)"))

	port := o.Port
	if port == 0 && st.Tunnel != nil {
		port = st.Tunnel.Port
	}
	if port == 0 {
		port = DefaultPort
	}

	t, err := ensureTunnel(ctx, cli, &p, o.TunnelID, st.Tunnel)
	if err != nil {
		return nil, err
	}
	id := t.TunnelID

	anon, err := cli.AllowsAnonymous(ctx, id)
	if err != nil {
		return nil, err
	}
	if !anon {
		if err := cli.AllowAnonymous(ctx, id); err != nil {
			return nil, err
		}
	}
	p.line("ok", "anonymous access%s: members carry no dev tunnels sign-in; the relay admits only its own members' keys", when(!anon, " (turned on)"))

	if _, ok := t.Port(port); !ok {
		if err := cli.CreatePort(ctx, id, port); err != nil && !errors.Is(err, devtunnel.ErrExists) {
			return nil, err
		}
		if t, err = cli.Show(ctx, id); err != nil {
			return nil, err
		}
		p.line("ok", "port %d (created)", port)
	} else {
		p.line("ok", "port %d", port)
	}

	url, err := PortURL(t, port)
	if err != nil {
		return nil, err
	}
	old := st.URL
	if err := state.Update(o.RelayPath, &st, func() error {
		st.Tunnel = &relay.Tunnel{ID: id, Port: port}
		st.URL = url
		return nil
	}); err != nil {
		return nil, err
	}
	p.line("ok", "public URL %s", url)
	if old != "" && old != url && len(st.Nodes) > 0 {
		p.line("!!", "the relay's URL was %s; members that joined before still dial it until they join again", old)
	}
	return &Result{TunnelID: id, Port: port, URL: url}, nil
}

// ensureTunnel finds the tunnel to use -- the one asked for, else the one on
// record -- or creates one.
func ensureTunnel(ctx context.Context, cli *devtunnel.CLI, p *printer, asked string, recorded *relay.Tunnel) (devtunnel.Tunnel, error) {
	id := asked
	if id == "" && recorded != nil {
		id = recorded.ID
	}
	if id != "" {
		t, err := cli.Show(ctx, id)
		switch {
		case err == nil:
			if t.TunnelID == "" {
				t.TunnelID = id
			}
			p.line("ok", "tunnel %s", t.TunnelID)
			return t, nil
		case !errors.Is(err, devtunnel.ErrNotFound):
			return devtunnel.Tunnel{}, err
		case asked == "":
			// Tunnels nobody hosts for 30 days are deleted by the service.
			p.line("!!", "tunnel %s no longer exists (unused tunnels expire after 30 days); making a new one", id)
			id = ""
		}
	}

	// A generated name can collide with someone else's; a chosen one is
	// tried as given.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cand := id
		if cand == "" {
			cand = NewTunnelID()
		}
		t, err := cli.Create(ctx, cand)
		if err == nil {
			if t.TunnelID == "" {
				t.TunnelID = cand
			}
			p.line("ok", "tunnel %s (created)", t.TunnelID)
			return t, nil
		}
		lastErr = err
		if !errors.Is(err, devtunnel.ErrExists) || id != "" {
			break
		}
	}
	return devtunnel.Tunnel{}, lastErr
}

// NewTunnelID makes a tunnel name unlikely to be taken.
func NewTunnelID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "san-vpn-" + string(b)
}

// PortURL is the public URL of one port of a tunnel. The service reports it;
// when it does not, it follows the documented shape
// https://<name>-<port>.<region>.devtunnels.ms from the full tunnel id.
func PortURL(t devtunnel.Tunnel, port int) (string, error) {
	if p, ok := t.Port(port); ok && p.PortURI != "" {
		return node.HTTPURL(p.PortURI)
	}
	name, region, ok := strings.Cut(t.TunnelID, ".")
	if !ok || name == "" || region == "" {
		return "", fmt.Errorf("cannot tell the public URL of tunnel %q port %d; see `devtunnel show %s`", t.TunnelID, port, t.TunnelID)
	}
	return fmt.Sprintf("https://%s-%d.%s.devtunnels.ms", name, port, region), nil
}

type printer struct{ w io.Writer }

func (p *printer) line(mark, format string, a ...any) {
	if p.w != nil {
		fmt.Fprintf(p.w, "  %-4s %s\n", mark, fmt.Sprintf(format, a...))
	}
}

func when(b bool, s string) string {
	if b {
		return s
	}
	return ""
}
