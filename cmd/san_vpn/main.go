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
			&cli.StringFlag{Name: "state", Sources: cli.EnvVars("SAN_VPN_STATE"), Usage: "state directory (default: the user config dir for the relay, " + state.NodeDir() + " for a node)"},
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
		Commands: []*cli.Command{setupCommand(), relayCommand(), joinCommand(), upCommand(), statusCommand(), updateCommand()},
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
				},
				Action: runRelayInit,
			},
			{
				Name:  "run",
				Usage: "serve the relay",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "listen", Value: "127.0.0.1:8443", Usage: "address to listen on; put TLS (a dev tunnel, Caddy) in front. Default: the dev tunnel's port when setup init made one"},
					&cli.BoolFlag{Name: "no-tunnel", Usage: "do not host the dev tunnel from setup init (host it yourself, or front the relay another way)"},
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

func relayPath(cmd *cli.Command) (string, error) {
	dir := cmd.String("state")
	if dir == "" {
		var err error
		if dir, err = state.RelayDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, state.RelayFile), nil
}

func runRelayInit(_ context.Context, cmd *cli.Command) error {
	path, err := relayPath(cmd)
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
	if err := state.EnsureDir(filepath.Dir(path), false); err != nil {
		return err
	}

	var st relay.State
	created := false
	err = state.Update(path, &st, func() error {
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
		return nil
	})
	if err != nil {
		return err
	}

	w := cmd.Root().Writer
	if created {
		fmt.Fprintf(w, "created relay %s\n", path)
	} else {
		fmt.Fprintf(w, "updated relay %s\n", path)
	}
	fmt.Fprintf(w, "  key      %s\n  network  %s\n  url      %s\n", st.PrivateKey.Public(), st.Network, orNone(st.URL))
	if st.URL == "" {
		fmt.Fprintln(w, "\nInvites need the URL members will dial. Set it with: san_vpn relay init --url <https://...>")
	}
	return nil
}

func runRelay(ctx context.Context, cmd *cli.Command) error {
	path, err := relayPath(cmd)
	if err != nil {
		return err
	}
	log := slog.Default()
	srv, err := relay.New(path, log)
	if err != nil {
		return err
	}
	go srv.Watch(ctx, time.Second)

	var st relay.State
	_ = state.Read(path, &st)
	listen := cmd.String("listen")
	if st.Tunnel != nil && !cmd.IsSet("listen") {
		listen = fmt.Sprintf("127.0.0.1:%d", st.Tunnel.Port)
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

	log.Info("relay listening", "addr", ln.Addr().String(), "url", orNone(st.URL), "key", srv.PublicKey(), "state", path)
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

func runRelayInvite(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" || cmd.Args().Len() > 1 {
		return errors.New("usage: san_vpn relay invite <name>")
	}
	path, err := relayPath(cmd)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no relay at %s; run `san_vpn relay init` first", path)
	}

	var st relay.State
	var inv relay.Invite
	err = state.Update(path, &st, func() error {
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
	return nil
}

func runRelayList(_ context.Context, cmd *cli.Command) error {
	path, err := relayPath(cmd)
	if err != nil {
		return err
	}
	var st relay.State
	if err := state.Read(path, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no relay at %s; run `san_vpn relay init` first", path)
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
			URL     string       `json:"url"`
			Nodes   []member     `json:"nodes"`
			Invites []pending    `json:"invites"`
		}{Network: st.Network, URL: st.URL, Nodes: []member{}, Invites: []pending{}}
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

	fmt.Fprintf(w, "network %s  url %s\n\n", st.Network, orNone(st.URL))
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

func runRelayRemove(_ context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" || cmd.Args().Len() > 1 {
		return errors.New("usage: san_vpn relay remove <name>")
	}
	path, err := relayPath(cmd)
	if err != nil {
		return err
	}
	var st relay.State
	var what string
	if err := state.Update(path, &st, func() error {
		var err error
		what, err = st.Remove(name)
		return err
	}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "removed %s %q; a running relay disconnects it within a second\n", what, name)
	return nil
}

// ------------------------------------------------------------------ node ---

func nodeDir(cmd *cli.Command) (dir string, isDefault bool) {
	if d := cmd.String("state"); d != "" {
		return d, false
	}
	return state.NodeDir(), true
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

	dir, isDefault := nodeDir(cmd)
	if isDefault {
		if err := requireAdmin("san_vpn join"); err != nil {
			return err
		}
	}
	path := filepath.Join(dir, state.NodeFile)
	var existing node.Config
	if err := state.Load(path, &existing); err == nil && !cmd.Bool("force") {
		return fmt.Errorf("this machine already joined as %q (%s); pass --force to replace it", existing.Name, existing.IP)
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
	if err := state.Save(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "joined as %q with address %s\nStart it with: san_vpn up\n", cfg.Name, cfg.Prefix())
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
		},
		Action: runUp,
	}
}

func runUp(ctx context.Context, cmd *cli.Command) error {
	if err := requireAdmin("san_vpn up"); err != nil {
		return err
	}
	dir, _ := nodeDir(cmd)
	var cfg node.Config
	if err := state.Load(filepath.Join(dir, state.NodeFile), &cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("this machine has not joined a network yet; run `san_vpn join <invite>` first")
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
	n, err := node.New(node.Options{Config: &cfg, TUN: dev, Log: log, OnChange: func() {
		select {
		case changed <- struct{}{}:
		default:
		}
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
	log.Info("san_vpn up", "name", cfg.Name, "address", cfg.Prefix(), "interface", cmd.String("interface"))

	statusPath := filepath.Join(dir, state.StatusFile)
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
	err = n.Run(ctx)
	_ = os.Remove(statusPath)
	return err
}

func statusCommand() *cli.Command {
	return &cli.Command{
		Name:   "status",
		Usage:  "show this machine's connection and the other members",
		Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}},
		Action: runStatus,
	}
}

// staleAfter is how old the status file may be before `up` is presumed dead;
// a running node rewrites it every two seconds.
const staleAfter = 10 * time.Second

func runStatus(_ context.Context, cmd *cli.Command) error {
	dir, _ := nodeDir(cmd)
	w := cmd.Root().Writer
	var st node.Status
	err := state.Load(filepath.Join(dir, state.StatusFile), &st)
	if errors.Is(err, os.ErrNotExist) {
		// Not running; say whether it has joined at all.
		var cfg node.Config
		err = state.Load(filepath.Join(dir, state.NodeFile), &cfg)
		switch {
		case err == nil:
			fmt.Fprintf(w, "%s (%s) is not running; start it with: san_vpn up\n", cfg.Name, cfg.Prefix())
			return nil
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintln(w, "this machine has not joined a network; run `san_vpn join <invite>`")
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
		fmt.Fprintf(w, "%s (%s) is not running (last seen %s ago)\n", st.Name, st.IP, age.Round(time.Second))
		return nil
	}
	if cmd.Bool("json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	fmt.Fprintf(w, "%s  %s/%d  ", st.Name, st.IP, st.Network.Bits())
	if st.Connected {
		fmt.Fprintf(w, "connected to %s for %s\n", st.Relay, ago(st.Since))
	} else {
		fmt.Fprintf(w, "NOT connected to %s", st.Relay)
		if st.LastError != "" {
			fmt.Fprintf(w, ": %s", st.LastError)
		}
		fmt.Fprintln(w)
	}
	if len(st.Peers) == 0 {
		fmt.Fprintln(w, "\nno other members yet; invite one with `san_vpn relay invite <name>` on the relay")
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tRELAY\tHANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		online := "offline"
		if p.Online {
			online = "online"
		}
		hs := "never"
		if !p.LastHandshake.IsZero() {
			hs = ago(p.LastHandshake) + " ago"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.IP, online, hs, bytesize(p.RxBytes), bytesize(p.TxBytes))
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
