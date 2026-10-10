package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/wargasipil/san_vpn/internal/devtunnel"
	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// Mark is an item's outcome.
type Mark string

const (
	OK   Mark = "ok"
	Fail Mark = "FAIL"
	Skip Mark = "--"
)

// Item is one line of a check.
type Item struct {
	Mark Mark   `json:"mark"`
	Text string `json:"text"`
	// Fix is the command or step that resolves a failure.
	Fix string `json:"fix,omitempty"`
}

// Section is the relay's or the member's half of a check.
type Section struct {
	Title string `json:"title"`
	Path  string `json:"path,omitempty"`
	Items []Item `json:"items"`
}

func (s *Section) add(m Mark, fix, format string, a ...any) {
	s.Items = append(s.Items, Item{Mark: m, Text: fmt.Sprintf(format, a...), Fix: fix})
}

// Failed reports whether any item failed.
func Failed(sections []Section) bool {
	for _, s := range sections {
		for _, i := range s.Items {
			if i.Mark == Fail {
				return true
			}
		}
	}
	return false
}

// CheckOptions configure Check.
type CheckOptions struct {
	// Relay is where the relay's file would be; nil checks no relay.
	Relay state.Store
	// NodeDir holds the member's node.json and status.json: the node
	// directory, or one profile's folder in it.
	NodeDir string
	// Profile names the member's profile in the title and the fixes; empty
	// when the machine has only the default one.
	Profile string
	// FindCLI locates devtunnel; it is only called for a relay with a tunnel.
	FindCLI    func() (*devtunnel.CLI, error)
	HTTPClient *http.Client
	// StaleAfter is how old status.json may be before `up` counts as stopped.
	StaleAfter time.Duration
	// LookupIP resolves a name the way programs on this machine do. Nil
	// means the system resolver.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Check examines whatever is set up on this machine: the relay, a member, or
// both.
func Check(ctx context.Context, o CheckOptions) []Section {
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if o.StaleAfter == 0 {
		o.StaleAfter = 10 * time.Second
	}
	if o.LookupIP == nil {
		o.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		}
	}
	var out []Section
	if s, ok := checkRelay(ctx, o); ok {
		out = append(out, s)
	}
	if s, ok := checkMember(ctx, o); ok {
		out = append(out, s)
	}
	if len(out) == 0 {
		s := Section{Title: "nothing set up on this machine"}
		s.add(Fail, "on the relay machine: san_vpn setup init; on a member: san_vpn join <invite> (as administrator)", "no relay and no membership found")
		out = append(out, s)
	}
	return out
}

func checkRelay(ctx context.Context, o CheckOptions) (Section, bool) {
	if o.Relay == nil {
		return Section{}, false
	}
	s := Section{Title: "relay", Path: o.Relay.String()}
	var st relay.State
	if _, err := o.Relay.Read(ctx, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, false
		}
		s.add(Fail, "", "read relay: %v", err)
		return s, true
	}
	s.add(OK, "", "relay key %s, network %s, %d member(s)", st.PrivateKey.Public(), st.Network, len(st.Nodes))

	if state.Remote(o.Relay) {
		// The relay runs elsewhere, on Cloud Run or another host sharing the
		// bucket: only its public side can be checked from here.
		if c := st.CloudRun; c != nil {
			s.add(OK, "", "runs on Cloud Run: service %s, region %s, project %s", c.Service, c.Region, c.Project)
		}
		return checkPublic(ctx, o, s, &st, true)
	}

	port := DefaultPort
	hosted := true // unknown without a tunnel; do not blame it
	if st.Tunnel == nil {
		s.add(Skip, "", "no dev tunnel recorded; the relay is fronted some other way (or run san_vpn setup init)")
	} else {
		port = st.Tunnel.Port
		hosted = checkTunnel(ctx, o, &s, &st)
	}

	local := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := expectRelay(ctx, o.HTTPClient, local); err != nil {
		if strings.Contains(err.Error(), "refused") {
			s.add(Fail, "san_vpn relay run", "relay is not running: nothing listens on %s", local)
		} else {
			s.add(Fail, "san_vpn relay run", "relay is not answering on %s: %v", local, err)
		}
	} else {
		s.add(OK, "", "relay answers on %s", local)
	}

	return checkPublic(ctx, o, s, &st, hosted)
}

// checkPublic checks the relay where members reach it: its public URL.
func checkPublic(ctx context.Context, o CheckOptions, s Section, st *relay.State, hosted bool) (Section, bool) {
	if st.URL == "" {
		s.add(Fail, "san_vpn setup init (or relay init --url)", "relay has no public URL, so invites cannot be made")
		return s, true
	}
	fix := ""
	if !hosted {
		fix = "san_vpn relay run (it hosts the tunnel)"
	}
	if err := expectRelay(ctx, o.HTTPClient, st.URL); err != nil {
		s.add(Fail, fix, "relay is not reachable at %s: %v", st.URL, err)
		return s, true
	}
	s.add(OK, "", "relay answers at %s", st.URL)
	if err := expectChallenge(ctx, o.HTTPClient, st.URL); err != nil {
		s.add(Fail, "", "WebSocket to %s fails, so members cannot connect: %v", st.URL, err)
	} else {
		s.add(OK, "", "WebSocket through %s works", hostOf(st.URL))
	}
	return s, true
}

// checkTunnel reports on the dev tunnel and says whether it is hosted.
func checkTunnel(ctx context.Context, o CheckOptions, s *Section, st *relay.State) bool {
	if o.FindCLI == nil {
		return true
	}
	cli, err := o.FindCLI()
	if err != nil {
		s.add(Fail, "san_vpn setup init", "devtunnel CLI: %v", err)
		return true
	}
	if v, err := cli.Version(ctx); err == nil {
		s.add(OK, "", "devtunnel CLI %s", v)
	}
	u, err := cli.User(ctx)
	if err != nil {
		s.add(Fail, "", "devtunnel user show: %v", err)
		return true
	}
	if !u.LoggedIn() {
		s.add(Fail, "san_vpn setup init (or devtunnel user login -g)", "not signed in to dev tunnels (%s), so the tunnel cannot be hosted", u.Status)
		return false
	}
	s.add(OK, "", "signed in to dev tunnels as %s (%s)", u.Username, u.Provider)

	id := st.Tunnel.ID
	t, err := cli.Show(ctx, id)
	if errors.Is(err, devtunnel.ErrNotFound) {
		s.add(Fail, "san_vpn setup init", "tunnel %s no longer exists (unused tunnels expire after 30 days)", id)
		return false
	}
	if err != nil {
		s.add(Fail, "", "devtunnel show %s: %v", id, err)
		return true
	}
	s.add(OK, "", "tunnel %s", id)

	if anon, err := cli.AllowsAnonymous(ctx, id); err != nil {
		s.add(Fail, "", "devtunnel access list %s: %v", id, err)
	} else if !anon {
		s.add(Fail, "san_vpn setup init", "tunnel does not allow anonymous clients, so members are turned away by the tunnel")
	} else {
		s.add(OK, "", "anonymous access")
	}

	if _, ok := t.Port(st.Tunnel.Port); !ok {
		s.add(Fail, "san_vpn setup init", "tunnel has no port %d", st.Tunnel.Port)
	} else if url, err := PortURL(t, st.Tunnel.Port); err == nil && url != st.URL {
		s.add(Fail, "san_vpn setup init", "the relay's URL is %s but the tunnel's is %s", st.URL, url)
	} else {
		s.add(OK, "", "port %d forwarded", st.Tunnel.Port)
	}

	if t.HostConnections == 0 {
		s.add(Fail, "san_vpn relay run (it hosts the tunnel)", "tunnel is not hosted")
		return false
	}
	s.add(OK, "", "tunnel is hosted")
	return true
}

func checkMember(ctx context.Context, o CheckOptions) (Section, bool) {
	path := filepath.Join(o.NodeDir, state.NodeFile)
	s := Section{Title: "member", Path: path}
	flag := ""
	if o.Profile != "" {
		s.Title = "member, profile " + o.Profile
		flag = " --profile " + o.Profile
	}
	var cfg node.Config
	if err := state.Load(path, &cfg); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return s, false
		case errors.Is(err, os.ErrPermission):
			s.add(Fail, "run san_vpn setup check from an administrator terminal (sudo on Linux)", "cannot read the membership")
		default:
			s.add(Fail, "", "%v", err)
		}
		return s, true
	}
	s.add(OK, "", "%s at %s, via %s", cfg.Name, cfg.Prefix(), cfg.RelayURL)

	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := node.Probe(pctx, &cfg, o.HTTPClient)
	cancel()
	switch {
	case err == nil:
		s.add(OK, "", "relay accepts this machine's key")
	case strings.Contains(err.Error(), "not a member"):
		s.add(Fail, "ask the relay for a new invite, then san_vpn join --force"+flag+" <invite>", "the relay no longer lists this machine: %v", err)
	default:
		s.add(Fail, "san_vpn setup check on the relay machine", "relay check failed: %v", err)
	}

	var st node.Status
	err = state.Load(filepath.Join(o.NodeDir, state.StatusFile), &st)
	switch {
	case err != nil || time.Since(st.Updated) > o.StaleAfter:
		s.add(Fail, "san_vpn up"+flag+" (as administrator)", "san_vpn up is not running")
	case !st.Connected && st.LastError == "":
		s.add(Fail, "", "san_vpn up is running, still connecting to the relay")
	case !st.Connected:
		s.add(Fail, "", "san_vpn up is running but not connected: %s", st.LastError)
	default:
		online := 0
		for _, p := range st.Peers {
			if p.Online {
				online++
			}
		}
		s.add(OK, "", "san_vpn up is connected, %d of %d peer(s) online", online, len(st.Peers))
		if st.DNS.IsValid() {
			checkNames(ctx, o, &s, st)
		}
	}
	return s, true
}

// checkNames resolves this machine's own name the way any program here would,
// which proves the whole path: the operating system sends the domain to the
// node, and the node answers.
func checkNames(ctx context.Context, o CheckOptions, s *Section, st node.Status) {
	host := st.Name + "." + st.Domain
	fix := "restart san_vpn up as administrator and look for \"names\" in its log; Get-DnsClientNrptRule should list ." + st.Domain + " -> " + st.DNS.String()
	if runtime.GOOS == "linux" {
		fix = "restart san_vpn up as root and look for \"names\" in its log; see resolvectl status, or the san_vpn block in /etc/hosts"
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := o.LookupIP(lctx, host)
	cancel()
	for i := range ips {
		ips[i] = ips[i].Unmap() // Go's resolver gives ::ffff:10.77.0.2 for a hosts file entry
	}
	switch {
	case err != nil:
		s.add(Fail, fix, "%s does not resolve: %v", host, err)
	case !slices.Contains(ips, st.IP):
		s.add(Fail, fix, "%s resolves to %v, not to this machine's %s", host, ips, st.IP)
	default:
		s.add(OK, "", "%s resolves to %s (names answered at %s)", host, st.IP, st.DNS)
	}
}

// expectRelay checks that base answers as a san_vpn relay, rather than as a
// front's error or sign-in page.
func expectRelay(ctx context.Context, client *http.Client, base string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set(wire.SkipAntiPhishingHeader, "true")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(string(body), "san_vpn relay") {
		return nil
	}
	return fmt.Errorf("got %s, not a san_vpn relay: %.80q", resp.Status, strings.TrimSpace(string(body)))
}

// expectChallenge opens the members' WebSocket and waits for the relay's
// first message. That proves the front carries WebSockets, which some
// proxies do not, without authenticating as anyone.
func expectChallenge(ctx context.Context, client *http.Client, base string) error {
	url, err := node.HTTPURL(base)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	h := http.Header{}
	h.Set(wire.SkipAntiPhishingHeader, "true")
	c, _, err := websocket.Dial(ctx, url+wire.ConnectPath, &websocket.DialOptions{HTTPClient: client, HTTPHeader: h})
	if err != nil {
		return err
	}
	defer c.CloseNow()
	m, err := wire.ReadMessage(ctx, c)
	if err != nil {
		return err
	}
	if m.Type != wire.TypeChallenge {
		return fmt.Errorf("first message was %q, not a challenge", m.Type)
	}
	_ = c.Close(websocket.StatusNormalClosure, "")
	return nil
}

func hostOf(url string) string {
	_, rest, ok := strings.Cut(url, "://")
	if !ok {
		return url
	}
	host, _, _ := strings.Cut(rest, "/")
	return host
}
