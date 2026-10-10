package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/devtunnel"
	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// fakeService plays the dev tunnels service behind the CLI, speaking the CLI's
// JSON and exit codes.
type fakeService struct {
	loggedIn  bool
	tunnels   map[string]*fakeTunnel // by full id, name.region
	taken     map[string]bool        // names someone else owns
	portURI   func(id string, port int) string
	calls     []string
	mutations []string
}

type fakeTunnel struct {
	anonymous bool
	ports     []int
	hosts     int
}

func newFake() *fakeService {
	return &fakeService{tunnels: map[string]*fakeTunnel{}, taken: map[string]bool{}}
}

func (f *fakeService) full(id string) string {
	if strings.Contains(id, ".") {
		return id
	}
	return id + ".asse"
}

func (f *fakeService) uri(id string, port int) string {
	if f.portURI != nil {
		return f.portURI(id, port)
	}
	name, region, _ := strings.Cut(id, ".")
	return fmt.Sprintf("https://%s-%d.%s.devtunnels.ms/", name, port, region)
}

func (f *fakeService) tunnelJSON(id string) map[string]any {
	t := f.tunnels[id]
	ports := []map[string]any{}
	for _, p := range t.ports {
		ports = append(ports, map[string]any{"portNumber": p, "protocol": "http", "portUri": f.uri(id, p)})
	}
	return map[string]any{"tunnelId": id, "hostConnections": t.hosts, "clientConnections": 0, "ports": ports}
}

func (f *fakeService) cli() *devtunnel.CLI {
	return &devtunnel.CLI{
		Path: "devtunnel",
		Run: func(_ context.Context, _ string, args []string) ([]byte, []byte, int, error) {
			f.calls = append(f.calls, strings.Join(args, " "))
			out, code := f.handle(args)
			b, _ := json.Marshal(out)
			if s, ok := out.(string); ok {
				b = []byte(s)
			}
			if code != 0 {
				return nil, b, code, nil
			}
			return b, nil, 0, nil
		},
		Interactive: func(_ context.Context, _ string, args []string) error {
			f.mutations = append(f.mutations, strings.Join(args, " "))
			f.loggedIn = true
			return nil
		},
	}
}

func (f *fakeService) handle(args []string) (any, int) {
	switch {
	case args[0] == "--version":
		return "Tunnel CLI version: 1.0.1516+1a2b3c\n", 0
	case args[0] == "user" && args[1] == "show":
		if !f.loggedIn {
			return map[string]any{"status": "Not logged in"}, 0
		}
		return map[string]any{"status": "Logged in", "provider": "github", "username": "vaziria"}, 0
	}
	if !f.loggedIn {
		return "not logged in", 3
	}
	switch {
	case args[0] == "show":
		id := f.full(args[1])
		if f.tunnels[id] == nil {
			return "Tunnel not found", 2
		}
		return map[string]any{"tunnel": f.tunnelJSON(id)}, 0
	case args[0] == "create":
		f.mutations = append(f.mutations, strings.Join(args, " "))
		id := f.full(args[1])
		if f.tunnels[id] != nil || f.taken[args[1]] {
			return "Conflict with existing entity", 1
		}
		f.tunnels[id] = &fakeTunnel{anonymous: contains(args, "--allow-anonymous")}
		return map[string]any{"tunnel": f.tunnelJSON(id)}, 0
	case args[0] == "access" && args[1] == "list":
		t := f.tunnels[f.full(args[2])]
		entries := []map[string]any{}
		if t.anonymous {
			entries = append(entries, map[string]any{"type": "Anonymous", "isDeny": false, "isInherited": false, "subjects": []string{}, "scopes": []string{"connect"}})
		}
		return map[string]any{"accessControlEntries": entries}, 0
	case args[0] == "access" && args[1] == "create":
		f.mutations = append(f.mutations, strings.Join(args, " "))
		f.tunnels[f.full(args[2])].anonymous = true
		return map[string]any{"accessControlEntries": []any{}}, 0
	case args[0] == "port" && args[1] == "create":
		f.mutations = append(f.mutations, strings.Join(args, " "))
		t := f.tunnels[f.full(args[2])]
		var port int
		fmt.Sscan(args[4], &port)
		for _, p := range t.ports {
			if p == port {
				return "Conflict", 1
			}
		}
		t.ports = append(t.ports, port)
		return map[string]any{"portNumber": port}, 0
	}
	return "unknown command " + strings.Join(args, " "), 9
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

var generatedID = regexp.MustCompile(`^san-vpn-[a-z0-9]{6}\.asse$`)

func TestInitFromScratch(t *testing.T) {
	f := newFake()
	path := filepath.Join(t.TempDir(), state.RelayFile)
	var out bytes.Buffer

	res, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path, Out: &out})
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.mutations) == 0 || !strings.HasPrefix(f.mutations[0], "user login -g") {
		t.Fatalf("did not sign in first: %v", f.mutations)
	}
	if !generatedID.MatchString(res.TunnelID) {
		t.Fatalf("tunnel id %q", res.TunnelID)
	}
	if res.Port != DefaultPort {
		t.Fatalf("port %d", res.Port)
	}
	name := strings.TrimSuffix(res.TunnelID, ".asse")
	if want := "https://" + name + "-8443.asse.devtunnels.ms"; res.URL != want {
		t.Fatalf("url %q, want %q", res.URL, want)
	}
	tun := f.tunnels[res.TunnelID]
	if !tun.anonymous || len(tun.ports) != 1 || tun.ports[0] != 8443 {
		t.Fatalf("tunnel %+v", tun)
	}

	var st relay.State
	if err := state.Read(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.PrivateKey.IsZero() || st.URL != res.URL || st.Tunnel == nil || st.Tunnel.ID != res.TunnelID || st.Tunnel.Port != 8443 {
		t.Fatalf("relay state %+v", st)
	}
	for _, want := range []string{"signed in to dev tunnels as vaziria", "(created)", "public URL " + res.URL} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// Running it again on a working setup changes nothing, and keeps the relay's
// key -- members and invites depend on it.
func TestInitIsIdempotent(t *testing.T) {
	f := newFake()
	path := filepath.Join(t.TempDir(), state.RelayFile)
	first, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path})
	if err != nil {
		t.Fatal(err)
	}
	var before relay.State
	_ = state.Read(path, &before)

	f.mutations = nil
	second, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("second run changed things: %v", f.mutations)
	}
	if *second != *first {
		t.Fatalf("second run gave %+v, first %+v", second, first)
	}
	var after relay.State
	_ = state.Read(path, &after)
	if after.PrivateKey != before.PrivateKey {
		t.Fatal("the relay key changed")
	}
}

// Rerunning repairs what broke: a tunnel the service expired, anonymous
// access someone turned off.
func TestInitRepairs(t *testing.T) {
	f := newFake()
	path := filepath.Join(t.TempDir(), state.RelayFile)
	first, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path})
	if err != nil {
		t.Fatal(err)
	}

	f.tunnels[first.TunnelID].anonymous = false
	if _, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path}); err != nil {
		t.Fatal(err)
	}
	if !f.tunnels[first.TunnelID].anonymous {
		t.Fatal("anonymous access was not turned back on")
	}

	delete(f.tunnels, first.TunnelID)
	var out bytes.Buffer
	again, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: path, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if again.TunnelID == first.TunnelID || f.tunnels[again.TunnelID] == nil {
		t.Fatalf("expired tunnel not replaced: %+v", again)
	}
	if !strings.Contains(out.String(), "no longer exists") {
		t.Errorf("the replacement was not explained:\n%s", out.String())
	}
}

// A generated name someone else already owns is replaced by another.
func TestInitRetriesTakenName(t *testing.T) {
	f := newFake()
	cli := f.cli()
	run := cli.Run
	first := true
	cli.Run = func(ctx context.Context, p string, args []string) ([]byte, []byte, int, error) {
		if args[0] == "create" && first {
			first = false
			f.taken[args[1]] = true
		}
		return run(ctx, p, args)
	}
	f.loggedIn = true
	res, err := Init(context.Background(), cli, InitOptions{RelayPath: filepath.Join(t.TempDir(), state.RelayFile)})
	if err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(f.mutations, "create "); n != 2 || !generatedID.MatchString(res.TunnelID) {
		t.Fatalf("%d creates, tunnel %q", n, res.TunnelID)
	}
}

// A tunnel the user names is used as given, not swapped for a generated one.
func TestInitAdoptsNamedTunnel(t *testing.T) {
	f := newFake()
	f.loggedIn = true
	f.tunnels["office-relay.asse"] = &fakeTunnel{anonymous: true, ports: []int{9000}}
	res, err := Init(context.Background(), f.cli(), InitOptions{RelayPath: filepath.Join(t.TempDir(), state.RelayFile), TunnelID: "office-relay", Port: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if res.TunnelID != "office-relay.asse" || res.URL != "https://office-relay-9000.asse.devtunnels.ms" || len(f.mutations) != 0 {
		t.Fatalf("%+v, mutations %v", res, f.mutations)
	}
}

func TestPortURLFallsBackToTheDocumentedShape(t *testing.T) {
	url, err := PortURL(devtunnel.Tunnel{TunnelID: "san-vpn-abc123.asse"}, 8443)
	if err != nil || url != "https://san-vpn-abc123-8443.asse.devtunnels.ms" {
		t.Fatalf("%q, %v", url, err)
	}
	if _, err := PortURL(devtunnel.Tunnel{TunnelID: "no-region"}, 8443); err == nil {
		t.Fatal("guessed a URL without a region")
	}
}

func countPrefix(xs []string, p string) int {
	n := 0
	for _, x := range xs {
		if strings.HasPrefix(x, p) {
			n++
		}
	}
	return n
}

// Check, end to end: a relay "behind" a fake tunnel that points at a real
// local relay, and a member of it.
func TestCheck(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	relayPath := filepath.Join(dir, state.RelayFile)
	nodeDir := filepath.Join(dir, "node")

	// A real relay on a local port; the fake tunnel claims that port and
	// reports the relay's local URL as its public one.
	var st relay.State
	if err := state.Update(relayPath, &st, func() error { return st.Init(relay.DefaultNetwork) }); err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(context.Background(), state.File(relayPath), nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	var port int
	fmt.Sscanf(ts.URL, "http://127.0.0.1:%d", &port)

	f := newFake()
	f.loggedIn = true
	f.portURI = func(string, int) string { return ts.URL + "/" }
	f.tunnels["san-vpn-test01.asse"] = &fakeTunnel{anonymous: true, ports: []int{port}, hosts: 1}
	if err := state.Update(relayPath, &st, func() error {
		st.URL = ts.URL
		st.Tunnel = &relay.Tunnel{ID: "san-vpn-test01.asse", Port: port}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	opts := CheckOptions{Relay: state.File(relayPath), NodeDir: nodeDir, FindCLI: func() (*devtunnel.CLI, error) { return f.cli(), nil }}

	sections := Check(ctx, opts)
	if Failed(sections) || len(sections) != 1 {
		t.Fatalf("healthy relay failed its check:\n%s", dump(sections))
	}

	// Not hosted: the failure names the fix.
	f.tunnels["san-vpn-test01.asse"].hosts = 0
	sections = Check(ctx, opts)
	if !Failed(sections) || !strings.Contains(dump(sections), "tunnel is not hosted") || !strings.Contains(dump(sections), "san_vpn relay run") {
		t.Fatalf("unhosted tunnel not reported:\n%s", dump(sections))
	}
	f.tunnels["san-vpn-test01.asse"].hosts = 1

	// A member: joined, but `up` not running.
	var inv relay.Invite
	if err := state.Update(relayPath, &st, func() error {
		var err error
		inv, err = st.NewInvite("home", time.Hour, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg, err := node.Join(ctx, invite.Invite{URL: ts.URL, RelayKey: st.PrivateKey.Public(), ID: inv.ID, Secret: inv.Secret}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.EnsureDir(nodeDir, false); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(filepath.Join(nodeDir, state.NodeFile), cfg); err != nil {
		t.Fatal(err)
	}
	sections = Check(ctx, opts)
	text := dump(sections)
	if len(sections) != 2 || !strings.Contains(text, "relay accepts this machine's key") || !strings.Contains(text, "san_vpn up is not running") {
		t.Fatalf("member check:\n%s", text)
	}

	// `up` running and connected.
	if err := state.Save(filepath.Join(nodeDir, state.StatusFile), node.Status{Updated: time.Now(), Connected: true}); err != nil {
		t.Fatal(err)
	}
	if sections = Check(ctx, opts); Failed(sections) {
		t.Fatalf("everything healthy, yet:\n%s", dump(sections))
	}

	// With names on, the check resolves this machine's own name the way any
	// program here would.
	named := node.Status{Updated: time.Now(), Connected: true, Name: "home", IP: cfg.IP, Domain: "vpn", DNS: netip.MustParseAddr("10.77.0.254")}
	if err := state.Save(filepath.Join(nodeDir, state.StatusFile), named); err != nil {
		t.Fatal(err)
	}
	resolves := map[string][]netip.Addr{"home.vpn": {cfg.IP}}
	opts.LookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		if ips, ok := resolves[host]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	if sections = Check(ctx, opts); Failed(sections) || !strings.Contains(dump(sections), "home.vpn resolves to "+cfg.IP.String()) {
		t.Fatalf("names healthy, yet:\n%s", dump(sections))
	}
	// Go's resolver gives a hosts file entry as ::ffff:10.77.0.1.
	resolves["home.vpn"] = []netip.Addr{netip.AddrFrom16(cfg.IP.As16())}
	if sections = Check(ctx, opts); Failed(sections) {
		t.Fatalf("IPv4-mapped answer failed:\n%s", dump(sections))
	}
	delete(resolves, "home.vpn")
	if text = dump(Check(ctx, opts)); !strings.Contains(text, "FAIL home.vpn does not resolve") || !strings.Contains(text, "names") {
		t.Fatalf("unresolved name not reported:\n%s", text)
	}
	resolves["home.vpn"] = []netip.Addr{netip.MustParseAddr("192.168.1.9")}
	if text = dump(Check(ctx, opts)); !strings.Contains(text, "not to this machine's "+cfg.IP.String()) {
		t.Fatalf("wrong address not reported:\n%s", text)
	}
	if err := state.Save(filepath.Join(nodeDir, state.StatusFile), node.Status{Updated: time.Now(), Connected: true}); err != nil {
		t.Fatal(err)
	}

	// Removed on the relay: the member's check says so and how to come back.
	if err := state.Update(relayPath, &st, func() error { _, err := st.Remove("home"); return err }); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	text = dump(Check(ctx, opts))
	if !strings.Contains(text, "no longer lists this machine") || !strings.Contains(text, "join --force") {
		t.Fatalf("removal not reported:\n%s", text)
	}

	// A machine with profiles: the title and the fix name the one checked.
	opts.Profile = "cloudrun"
	text = dump(Check(ctx, opts))
	if !strings.Contains(text, "member, profile cloudrun") || !strings.Contains(text, "join --force --profile cloudrun <invite>") {
		t.Fatalf("profile not named:\n%s", text)
	}
}

func TestCheckNothingSetUp(t *testing.T) {
	dir := t.TempDir()
	sections := Check(context.Background(), CheckOptions{Relay: state.File(filepath.Join(dir, state.RelayFile)), NodeDir: dir})
	if !Failed(sections) || !strings.Contains(dump(sections), "setup init") {
		t.Fatalf("%s", dump(sections))
	}
}

func dump(sections []Section) string {
	var b strings.Builder
	for _, s := range sections {
		fmt.Fprintf(&b, "%s\n", s.Title)
		for _, i := range s.Items {
			fmt.Fprintf(&b, "  %s %s", i.Mark, i.Text)
			if i.Fix != "" {
				fmt.Fprintf(&b, " [fix: %s]", i.Fix)
			}
			b.WriteByte('\n')
		}
	}
	return b.String()
}
