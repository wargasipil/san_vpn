// Command san_vpn joins machines at home, the office and other regions into one
// private network, carried over WebSockets through a relay.
//
// One binary, two roles. `san_vpn relay ...` runs and administers the relay
// that every member dials out to. `san_vpn join` and `san_vpn up` make a
// machine a member.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/devtunnel"
	"github.com/wargasipil/san_vpn/internal/invite"
	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/osnet"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/update"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// version is stamped by the build scripts.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root(os.Stdout).Run(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "san_vpn: %v\n", err)
		os.Exit(1)
	}
}

func root(out io.Writer) *cli.Command {
	return &cli.Command{
		Name:    "san_vpn",
		Usage:   "a private network between your machines, carried over WebSockets",
		Version: version,
		Writer:  out,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "log-level", Value: "info", Sources: cli.EnvVars("SAN_VPN_LOG_LEVEL"), Usage: "debug, info, warn or error"},
			&cli.StringFlag{Name: "state", Sources: cli.EnvVars("SAN_VPN_STATE"), Usage: "state directory (default: the user config dir for the relay, " + state.NodeDir() + " for a node); for the relay also gs://<bucket>[/<folder>]"},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			// Logs go to stderr, always: stdout carries invites and tables
			// that people pipe and paste.
			var level slog.Level
			if err := level.UnmarshalText([]byte(cmd.String("log-level"))); err != nil {
				return ctx, fmt.Errorf("bad --log-level %q", cmd.String("log-level"))
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			if exe, err := os.Executable(); err == nil {
				update.RemoveOld(exe) // what the last `update` moved aside on Windows
			}
			return ctx, nil
		},
		Commands: []*cli.Command{setupCommand(), cloudrunCommand(), relayCommand(), joinCommand(), upCommand(), statusCommand(), profileCommand(), updateCommand()},
	}
}

// ----------------------------------------------------------------- relay ---

func relayCommand() *cli.Command {
	return &cli.Command{
		Name:  "relay",
		Usage: "run and administer the relay every member connects to",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "create the relay's key and network, or update its public URL",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "url", Usage: "the URL members dial, e.g. https://<id>-8443.asse.devtunnels.ms"},
					&cli.StringFlag{Name: "network", Value: relay.DefaultNetwork.String(), Usage: "overlay address range"},
					&cli.StringFlag{Name: "domain", Value: wire.DefaultDomain, Usage: "what the members' names end in: office.vpn"},
				},
				Action: runRelayInit,
			},
			{
				Name:  "run",
				Usage: "serve the relay",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "listen", Value: "127.0.0.1:8443", Usage: "address to listen on; put TLS (a dev tunnel, Caddy) in front. Default: the dev tunnel's port when setup init made one, else :$PORT when PORT is set (Cloud Run)"},
					&cli.BoolFlag{Name: "no-tunnel", Usage: "do not host the dev tunnel from setup init (host it yourself, or front the relay another way)"},
					&cli.DurationFlag{Name: "session-limit", Sources: cli.EnvVars("SAN_VPN_SESSION_LIMIT"), Usage: "end each member connection after this long, and have members renew it first; set it to Cloud Run's request timeout (0: no limit)"},
				},
				Action: runRelay,
			},
			{
				Name:      "invite",
				Usage:     "print a one-time invite for a new member",
				ArgsUsage: "<name>",
				Flags: []cli.Flag{
					&cli.DurationFlag{Name: "ttl", Value: relay.DefaultInviteTTL, Usage: "how long the invite stays usable"},
				},
				Action: runRelayInvite,
			},
			{
				Name:   "list",
				Usage:  "list members and waiting invites",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}},
				Action: runRelayList,
			},
			{
				Name:      "remove",
				Usage:     "remove a member or a waiting invite",
				ArgsUsage: "<name>",
				Action:    runRelayRemove,
			},
		},
	}
}

// relayStore is where the relay's file lives: --state, a local directory or
// a gs:// bucket, else the user config dir.
func relayStore(cmd *cli.Command) (state.Store, error) {
	dir := cmd.String("state")
	if dir == "" {
		var err error
		if dir, err = state.RelayDir(); err != nil {
			return nil, err
		}
	}
	return state.Open(dir, state.RelayFile)
}

// relayPath is the relay's file for commands that only work on local disk.
func relayPath(cmd *cli.Command, what string) (string, error) {
	store, err := relayStore(cmd)
	if err != nil {
		return "", err
	}
	f, ok := store.(state.File)
	if !ok {
		return "", fmt.Errorf("%s works on a relay on this machine, not one kept in %s", what, store)
	}
	return string(f), nil
}

// errNoRelay is a relay store that `relay init` never filled.
func errNoRelay(store state.Store) error {
	return fmt.Errorf("no relay at %s; run `san_vpn relay init` first", store)
}

func runRelayInit(ctx context.Context, cmd *cli.Command) error {
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}
	network, err := netip.ParsePrefix(cmd.String("network"))
	if err != nil {
		return fmt.Errorf("--network: %w", err)
	}
	var url string
	if cmd.IsSet("url") {
		if url, err = node.HTTPURL(cmd.String("url")); err != nil {
			return err
		}
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(cmd.String("domain"), "."), "."))
	if err := wire.ValidDomain(domain); err != nil {
		return fmt.Errorf("--domain: %w", err)
	}
	if f, ok := store.(state.File); ok {
		if err := state.EnsureDir(filepath.Dir(string(f)), false); err != nil {
			return err
		}
	}

	var st relay.State
	created := false
	err = store.Update(ctx, &st, func() error {
		created = false
		if st.PrivateKey.IsZero() {
			created = true
			if err := st.Init(network); err != nil {
				return err
			}
		} else if cmd.IsSet("network") && network.Masked() != st.Network {
			if len(st.Nodes) > 0 {
				return fmt.Errorf("the network is %s and has members; it cannot move to %s", st.Network, network)
			}
			if err := st.Init(network); err != nil {
				return err
			}
		}
		if url != "" {
			st.URL = url
		}
		if cmd.IsSet("domain") {
			st.Domain = domain
		}
		return nil
	})
	if err != nil {
		return err
	}

	w := cmd.Root().Writer
	if created {
		fmt.Fprintf(w, "created relay %s\n", store)
	} else {
		fmt.Fprintf(w, "updated relay %s\n", store)
	}
	fmt.Fprintf(w, "  key      %s\n  network  %s\n  domain   %s\n  url      %s\n", st.PrivateKey.Public(), st.Network, st.DomainOrDefault(), orNone(st.URL))
	if d := st.DomainOrDefault(); d == "local" || strings.HasSuffix(d, ".local") {
		fmt.Fprintln(w, "\nNote: .local belongs to multicast DNS. Linux machines with nss-mdns never ask a DNS server about it,\nand Windows may send printer.local and other LAN names to san_vpn while up runs.")
	}
	if st.URL == "" {
		fmt.Fprintln(w, "\nInvites need the URL members will dial. Set it with: san_vpn relay init --url <https://...>")
	}
	return nil
}

func runRelay(ctx context.Context, cmd *cli.Command) error {
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}
	log := slog.Default()
	srv, err := relay.New(ctx, store, log)
	if err != nil {
		return err
	}
	limit := cmd.Duration("session-limit")
	srv.SetSessionLimit(limit)
	if limit == 0 && os.Getenv("K_SERVICE") != "" {
		log.Warn("on Cloud Run, set SAN_VPN_SESSION_LIMIT to the service's request timeout, so members renew their connections before Cloud Run cuts them")
	}
	// A file beside the relay is cheap to look at every second. Cloud
	// Storage charges per request and admin changes are rare, so poll it
	// less often: an invite or a removal takes effect within five seconds.
	every := time.Second
	if state.Remote(store) {
		every = 5 * time.Second
	}
	go srv.Watch(ctx, every)

	var st relay.State
	_, _ = store.Read(ctx, &st)
	listen := cmd.String("listen")
	switch {
	case cmd.IsSet("listen"):
	case st.Tunnel != nil:
		listen = fmt.Sprintf("127.0.0.1:%d", st.Tunnel.Port)
	case os.Getenv("PORT") != "":
		listen = ":" + os.Getenv("PORT") // Cloud Run and similar hosts say where to listen
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx) // tell the nodes, so they redial at once
		_ = hs.Shutdown(sctx)
	}()

	log.Info("relay listening", "addr", ln.Addr().String(), "url", orNone(st.URL), "key", srv.PublicKey(), "state", store.String(), "session_limit", limit)
	if st.URL == "" {
		log.Warn("no public URL set, so invites cannot be made yet; run `san_vpn setup init` (dev tunnel) or `san_vpn relay init --url ...`")
	}
	if st.Tunnel != nil && !cmd.Bool("no-tunnel") {
		hostTunnel(ctx, st.Tunnel, log)
	}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hostTunnel runs `devtunnel host` beside the relay for as long as it runs,
// so the relay machine has one thing to start, not two.
func hostTunnel(ctx context.Context, t *relay.Tunnel, log *slog.Logger) {
	p, err := devtunnel.Find()
	if err != nil {
		log.Warn("the dev tunnel is not hosted: devtunnel CLI not found; run `san_vpn setup init`", "tunnel", t.ID)
		return
	}
	log.Info("hosting dev tunnel", "tunnel", t.ID, "port", t.Port)
	go devtunnel.New(p, nil, io.Discard, io.Discard).Host(ctx, t.ID, log)
}

func runRelayInvite(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" || cmd.Args().Len() > 1 {
		return errors.New("usage: san_vpn relay invite <name>")
	}
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}

	var st relay.State
	var inv relay.Invite
	err = store.Update(ctx, &st, func() error {
		if st.PrivateKey.IsZero() {
			return errNoRelay(store)
		}
		if st.URL == "" {
			return errors.New("the relay has no public URL; set it with `san_vpn relay init --url <https://...>`")
		}
		var err error
		inv, err = st.NewInvite(name, cmd.Duration("ttl"), time.Now())
		return err
	})
	if err != nil {
		return err
	}
	blob, err := invite.Encode(invite.Invite{URL: st.URL, RelayKey: st.PrivateKey.Public(), ID: inv.ID, Secret: inv.Secret, Name: inv.Name})
	if err != nil {
		return err
	}

	w := cmd.Root().Writer
	fmt.Fprintf(w, "Invite for %q, usable once until %s:\n\n%s\n\n", name, inv.Expires.Local().Format("2006-01-02 15:04"), blob)
	fmt.Fprintln(w, "On the new machine, from an administrator terminal (sudo on Linux):")
	fmt.Fprintln(w, "  san_vpn join <invite>")
	fmt.Fprintln(w, "  san_vpn up")
	fmt.Fprintln(w, "A machine already in another network keeps both with: san_vpn join --profile <name> <invite>")
	return nil
}

func runRelayList(ctx context.Context, cmd *cli.Command) error {
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}
	var st relay.State
	if _, err := store.Read(ctx, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errNoRelay(store)
		}
		return err
	}
	w := cmd.Root().Writer
	if cmd.Bool("json") {
		type member struct {
			Name      string     `json:"name"`
			IP        netip.Addr `json:"ip"`
			PublicKey string     `json:"public_key"`
			Joined    time.Time  `json:"joined"`
		}
		type pending struct {
			Name    string    `json:"name"`
			Expires time.Time `json:"expires"`
		}
		out := struct {
			Network netip.Prefix `json:"network"`
			Domain  string       `json:"domain"`
			URL     string       `json:"url"`
			Nodes   []member     `json:"nodes"`
			Invites []pending    `json:"invites"`
		}{Network: st.Network, Domain: st.DomainOrDefault(), URL: st.URL, Nodes: []member{}, Invites: []pending{}}
		for _, n := range st.Nodes {
			out.Nodes = append(out.Nodes, member{n.Name, n.IP, n.PublicKey.String(), n.Joined})
		}
		for _, i := range st.Invites {
			if time.Now().Before(i.Expires) {
				out.Invites = append(out.Invites, pending{i.Name, i.Expires})
			}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Fprintf(w, "network %s  domain %s  url %s\n\n", st.Network, st.DomainOrDefault(), orNone(st.URL))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tJOINED\tKEY")
	for _, n := range st.Nodes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n.Name, n.IP, n.Joined.Local().Format("2006-01-02 15:04"), n.PublicKey)
	}
	for _, i := range st.Invites {
		if time.Now().Before(i.Expires) {
			fmt.Fprintf(tw, "%s\t(invited)\tuntil %s\t\n", i.Name, i.Expires.Local().Format("2006-01-02 15:04"))
		}
	}
	return tw.Flush()
}

func runRelayRemove(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" || cmd.Args().Len() > 1 {
		return errors.New("usage: san_vpn relay remove <name>")
	}
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}
	var st relay.State
	var what string
	if err := store.Update(ctx, &st, func() error {
		if st.PrivateKey.IsZero() {
			return errNoRelay(store)
		}
		var err error
		what, err = st.Remove(name)
		return err
	}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "removed %s %q; a running relay disconnects it within seconds\n", what, name)
	return nil
}

// ------------------------------------------------------------------ node ---

func nodeDir(cmd *cli.Command) (dir string, isDefault bool, err error) {
	d := cmd.String("state")
	if strings.HasPrefix(d, "gs://") {
		return "", false, fmt.Errorf("--state %s: a member keeps its key on its own disk; gs:// is for the relay", d)
	}
	if d != "" {
		return d, false, nil
	}
	return state.NodeDir(), true, nil
}

// requireAdmin stops early, with the fix in the message, rather than failing
// halfway through on an access-denied error that does not say why.
func requireAdmin(what string) error {
	if osnet.Elevated() {
		return nil
	}
	return fmt.Errorf("%s needs an administrator terminal on Windows, or root (sudo) on Linux", what)
}

func joinCommand() *cli.Command {
	return &cli.Command{
		Name:      "join",
		Usage:     "make this machine a member, using an invite from `san_vpn relay invite`",
		ArgsUsage: "<invite>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "url", Usage: "reach the relay here instead of the invite's URL, e.g. http://127.0.0.1:8443 on the relay machine itself"},
			&cli.StringSliceFlag{Name: "header", Usage: `extra header for the relay's front, as "Name: value" (repeatable)`},
			&cli.BoolFlag{Name: "force", Usage: "replace this machine's existing membership"},
			&cli.StringFlag{Name: "profile", Sources: cli.EnvVars("SAN_VPN_PROFILE"), Usage: "keep this membership under profile `name`, beside the networks this machine is already in (default: the current profile)"},
		},
		Action: runJoin,
	}
}

func runJoin(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return errors.New("usage: san_vpn join <invite>")
	}
	inv, err := invite.Decode(cmd.Args().First())
	if err != nil {
		return err
	}
	if cmd.IsSet("url") {
		// Safe to override: the relay is pinned by its key, not its URL.
		inv.URL = cmd.String("url")
	}
	headers := map[string]string{}
	for _, h := range cmd.StringSlice("header") {
		k, v, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return fmt.Errorf("--header %q: want \"Name: value\"", h)
		}
		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(headers) == 0 {
		headers = nil
	}

	dir, isDefault, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	if isDefault {
		if err := requireAdmin("san_vpn join"); err != nil {
			return err
		}
	}
	profile, err := memberProfile(cmd, dir, false)
	if err != nil {
		return memberErr("san_vpn join", err)
	}
	pdir := state.ProfileDir(dir, profile)
	path := filepath.Join(pdir, state.NodeFile)
	var existing node.Config
	if err := state.Load(path, &existing); err == nil && !cmd.Bool("force") {
		if cmd.String("profile") != "" {
			return fmt.Errorf("profile %q already joined as %q (%s); pass --force to replace it", profile, existing.Name, existing.IP)
		}
		return fmt.Errorf("this machine already joined as %q (%s); to join another network beside it, pass --profile <name>; to replace it, --force", existing.Name, existing.IP)
	}

	jctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg, err := node.Join(jctx, inv, headers, nil)
	if err != nil {
		return err
	}
	// Elevated, the directory is locked to administrators, which is what `up`
	// will run as. Unelevated -- only possible with an explicit --state, for
	// trying things out -- it stays private to this user instead, or the user
	// could not read back what they just wrote.
	if err := state.EnsureDir(dir, osnet.Elevated()); err != nil {
		return err
	}
	if pdir != dir {
		if err := state.EnsureDir(pdir, osnet.Elevated()); err != nil {
			return err
		}
	}
	if err := state.Save(path, cfg); err != nil {
		return err
	}
	// The first membership is the one `up` brings up, whatever its profile is
	// called, so `join --profile x` then `up` works on a fresh machine.
	if cur, err := state.CurrentProfile(dir); err == nil && cur != profile {
		if ok, err := state.Joined(dir, cur); err == nil && !ok {
			if err := state.SetCurrentProfile(dir, profile); err != nil {
				return err
			}
		}
	}

	w := cmd.Root().Writer
	if profile == state.DefaultProfile {
		fmt.Fprintf(w, "joined as %q with address %s\n", cfg.Name, cfg.Prefix())
	} else {
		fmt.Fprintf(w, "joined as %q with address %s, in profile %q\n", cfg.Name, cfg.Prefix(), profile)
	}
	fmt.Fprintf(w, "Start it with: %s\n", upFor(dir, profile))
	if upFor(dir, profile) != "san_vpn up" {
		fmt.Fprintf(w, "or make it the one san_vpn up brings up: san_vpn profile use %s\n", profile)
	}
	return nil
}

func upCommand() *cli.Command {
	return &cli.Command{
		Name:  "up",
		Usage: "bring this machine onto the network and keep it there (Ctrl+C to leave)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "interface", Value: osnet.DefaultName, Usage: "tunnel interface name"},
			&cli.IntFlag{Name: "mtu", Value: osnet.DefaultMTU, Usage: "tunnel MTU"},
			&cli.BoolFlag{Name: "no-firewall", Usage: "on Windows, do not add the inbound firewall rule for the other members"},
			&cli.BoolFlag{Name: "no-dns", Usage: "do not answer or resolve the members' names (office.vpn)"},
			profileFlag(),
		},
		Action: runUp,
	}
}

func runUp(ctx context.Context, cmd *cli.Command) error {
	if err := requireAdmin("san_vpn up"); err != nil {
		return err
	}
	dir, _, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	profile, err := memberProfile(cmd, dir, false)
	if err != nil {
		return err
	}
	// One profile at a time: each would make an interface of the same name,
	// and both networks are usually 10.77.0.0/24.
	if run, st, ok := runningProfile(dir); ok {
		if run == profile {
			return fmt.Errorf("san_vpn up is already running (pid %d)", st.PID)
		}
		return fmt.Errorf("san_vpn up is already running on profile %q (pid %d); stop it first, one profile is up at a time", run, st.PID)
	}
	pdir := state.ProfileDir(dir, profile)
	var cfg node.Config
	if err := state.Load(filepath.Join(pdir, state.NodeFile), &cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return notJoined(dir, profile)
		}
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := slog.Default()
	mtu := int(cmd.Int("mtu"))

	dev, err := osnet.Create(cmd.String("interface"), mtu, cfg.PrivateKey.Public())
	if err != nil {
		return err
	}
	changed := make(chan struct{}, 1)
	namesChanged := make(chan struct{}, 1)
	withNames := !cmd.Bool("no-dns")
	n, err := node.New(node.Options{Config: &cfg, TUN: dev, Log: log, Names: withNames, OnChange: func() {
		poke(changed)
		poke(namesChanged)
	}})
	if err != nil {
		_ = dev.Close()
		return err
	}
	if err := osnet.Configure(dev, cfg.Prefix(), mtu); err != nil {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_ = n.Run(cancelled) // closes the device
		return err
	}
	if !cmd.Bool("no-firewall") {
		if err := osnet.AllowInbound(cfg.Network, cfg.IP); err != nil {
			log.Warn("other members may not reach this machine", "err", err)
		}
	}
	log.Info("san_vpn up", "name", cfg.Name, "address", cfg.Prefix(), "interface", cmd.String("interface"), "profile", profile)

	statusPath := filepath.Join(pdir, state.StatusFile)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			if err := state.Save(statusPath, n.Status()); err != nil {
				log.Debug("write status", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-changed: // connected, disconnected, new members: show it now
			}
		}
	}()

	runCtx, stopped := context.WithCancel(ctx)
	namesDone := make(chan struct{})
	var osNames *osnet.Names
	if withNames {
		ifname, _ := dev.Name()
		osNames = &osnet.Names{Interface: ifname}
		go func() { defer close(namesDone); keepNames(runCtx, n, osNames, namesChanged, log) }()
	} else {
		close(namesDone)
	}
	err = n.Run(runCtx)
	stopped()
	<-namesDone
	if osNames != nil {
		if err := osNames.Clear(); err != nil {
			log.Warn("names", "err", err)
		}
	}
	_ = os.Remove(statusPath)
	return err
}

func poke(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// keepNames points this machine's lookups of the members' names at the node,
// and keeps them current as members come and go, until ctx ends.
func keepNames(ctx context.Context, n *node.Node, on *osnet.Names, changed <-chan struct{}, log *slog.Logger) {
	said := false
	for {
		if t := n.Names(); t != nil {
			how, err := on.Set(t)
			switch {
			case err != nil:
				log.Warn("this machine may not resolve the members' names", "err", err)
			case how != "" && !said:
				said = true
				log.Info("members' names resolve", "domain", t.Domain, "dns", t.Server, "via", how)
			case how != "":
				log.Debug("members' names updated", "via", how)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:   "status",
		Usage:  "show this machine's connection and the other members (the running profile, else the current one)",
		Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}, profileFlag()},
		Action: runStatus,
	}
}

// staleAfter is how old the status file may be before `up` is presumed dead;
// a running node rewrites it every two seconds.
const staleAfter = 10 * time.Second

func runStatus(_ context.Context, cmd *cli.Command) error {
	dir, _, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	profile, err := memberProfile(cmd, dir, true)
	if err != nil {
		return memberErr("san_vpn status", err)
	}
	pdir := state.ProfileDir(dir, profile)
	// Name the profile only once there is more than one to tell apart.
	label := ""
	if profilesInUse(dir) {
		label = ", profile " + profile
	}

	w := cmd.Root().Writer
	var st node.Status
	err = state.Load(filepath.Join(pdir, state.StatusFile), &st)
	if errors.Is(err, os.ErrNotExist) {
		// Not running; say whether it has joined at all.
		var cfg node.Config
		err = state.Load(filepath.Join(pdir, state.NodeFile), &cfg)
		switch {
		case err == nil:
			fmt.Fprintf(w, "%s (%s%s) is not running; start it with: %s\n", cfg.Name, cfg.Prefix(), label, upFor(dir, profile))
			return nil
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintln(w, notJoined(dir, profile))
			return nil
		}
	}
	if errors.Is(err, os.ErrPermission) {
		return requireAdmin("san_vpn status")
	}
	if err != nil {
		return err
	}
	if age := time.Since(st.Updated); age > staleAfter {
		fmt.Fprintf(w, "%s (%s%s) is not running (last seen %s ago)\n", st.Name, st.IP, label, age.Round(time.Second))
		return nil
	}
	if cmd.Bool("json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Profile string `json:"profile"`
			node.Status
		}{profile, st})
	}

	fmt.Fprintf(w, "%s  %s/%d  ", st.Name, st.IP, st.Network.Bits())
	if label != "" {
		fmt.Fprintf(w, "profile %s  ", profile)
	}
	if st.Connected {
		fmt.Fprintf(w, "connected to %s for %s\n", st.Relay, ago(st.Since))
	} else {
		fmt.Fprintf(w, "NOT connected to %s", st.Relay)
		if st.LastError != "" {
			fmt.Fprintf(w, ": %s", st.LastError)
		}
		fmt.Fprintln(w)
	}
	if st.DNS.IsValid() {
		fmt.Fprintf(w, "names %s.%s and the others below, answered at %s\n", st.Name, st.Domain, st.DNS)
	}
	if len(st.Peers) == 0 {
		fmt.Fprintln(w, "\nno other members yet; invite one with `san_vpn relay invite <name>` on the relay")
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tRELAY\tHANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		name := p.Name
		if st.Domain != "" {
			name += "." + st.Domain
		}
		online := "offline"
		if p.Online {
			online = "online"
		}
		hs := "never"
		if !p.LastHandshake.IsZero() {
			hs = ago(p.LastHandshake) + " ago"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", name, p.IP, online, hs, bytesize(p.RxBytes), bytesize(p.TxBytes))
	}
	return tw.Flush()
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	default:
		return d.Round(time.Hour).String()
	}
}

func bytesize(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
