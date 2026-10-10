package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// relayFlag picks which of the relays this machine looks after a relay
// command works on. It is a flag of its own rather than --profile: a member's
// profile and a relay profile are different things that often share a name,
// and setup check takes both.
func relayFlag() cli.Flag {
	return &cli.StringFlag{Name: "relay", Sources: cli.EnvVars("SAN_VPN_RELAY"), Usage: "which relay, by relay profile `name` (default: the one chosen with san_vpn relay profile use)"}
}

// relayDir is the directory holding this machine's relays and their
// profiles: --state when it names one, else the user config dir.
func relayDir(cmd *cli.Command) (string, error) {
	d := cmd.String("state")
	if state.RemoteLocation(d) {
		return "", fmt.Errorf("--state %s: relay profiles are kept on this machine; leave out --state, or pass a directory", d)
	}
	if d != "" {
		return d, nil
	}
	return state.RelayDir()
}

// relayPick is the relay a relay command works on.
type relayPick struct {
	dir   string // the relay directory; empty when --state names a gs:// relay outright
	name  string // its relay profile; empty when --state names it outright
	loc   string // a directory, or a gs:// location
	known bool   // false when --relay names a relay not made yet
	store state.Store
}

// pickRelay finds the relay: a gs:// --state names it outright; else --relay
// names a relay profile in the relay directory, or the current one is used.
func pickRelay(cmd *cli.Command) (relayPick, error) {
	name := cmd.String("relay")
	if loc := cmd.String("state"); state.RemoteLocation(loc) {
		if name != "" {
			return relayPick{}, fmt.Errorf("--state %s (or SAN_VPN_STATE) names the relay already; leave out it or --relay %s", loc, name)
		}
		store, err := state.Open(loc, state.RelayFile)
		return relayPick{loc: loc, known: true, store: store}, err
	}
	dir, err := relayDir(cmd)
	if err != nil {
		return relayPick{}, err
	}
	if name == "" {
		if name, err = state.CurrentRelay(dir); err != nil {
			return relayPick{}, err
		}
	}
	loc, known, err := state.RelayLocation(dir, name)
	if err != nil {
		return relayPick{}, err
	}
	store, err := state.Open(loc, state.RelayFile)
	return relayPick{dir: dir, name: name, loc: loc, known: known, store: store}, err
}

// relayStore is the relay of a command that works on one already made.
func relayStore(cmd *cli.Command) (relayPick, error) {
	p, err := pickRelay(cmd)
	if err == nil && !p.known {
		err = unknownRelay(p.dir, p.name)
	}
	return p, err
}

func unknownRelay(dir, name string) error {
	have := ""
	if names := relayNamesIn(dir); len(names) > 0 {
		have = " (this machine has " + strings.Join(names, ", ") + ")"
	}
	return fmt.Errorf("no relay profile %q%s; make it with `san_vpn relay init --relay %s`, or name a relay kept elsewhere with `san_vpn relay profile add %s <dir or gs://...>`", name, have, name, name)
}

func relayNamesIn(dir string) []string {
	ps, _ := state.RelayProfiles(dir)
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return names
}

// errNoRelay is a relay that `relay init` never filled.
func errNoRelay(p relayPick) error {
	return fmt.Errorf("no relay at %s; run `san_vpn relay init%s` first", p.store, relayArg(p))
}

// rememberRelay keeps the relay a command just made at loc under relay
// profile name, and makes that the current one when the current one holds no
// relay: on a fresh machine, `relay init --relay lab` then `relay invite`
// works on lab.
func rememberRelay(dir, name, loc string) error {
	if dir == "" || name == "" {
		return nil
	}
	if err := state.AddRelay(dir, name, loc); err != nil {
		return err
	}
	cur, err := state.CurrentRelay(dir)
	if err != nil || cur == name {
		return err
	}
	curLoc, _, err := state.RelayLocation(dir, cur)
	if err != nil {
		return err
	}
	if ok, err := state.HasRelay(curLoc); err != nil || ok {
		return err
	}
	return state.SetCurrentRelay(dir, name)
}

// relayArg is " --relay <name>" when a command has to name the relay to
// reach it, for the next command to print.
func relayArg(p relayPick) string {
	if p.name == "" {
		return ""
	}
	if cur, err := state.CurrentRelay(p.dir); err == nil && cur == p.name {
		return ""
	}
	return " --relay " + p.name
}

// relayLabel is the relay's profile name, for messages, once there is more
// than one relay to tell apart; else empty.
func relayLabel(p relayPick) string {
	if p.name == "" {
		return ""
	}
	ps, _ := state.RelayProfiles(p.dir)
	if !slices.ContainsFunc(ps, func(r state.RelayProfile) bool { return r.Name != state.DefaultRelay }) {
		return ""
	}
	return p.name
}

func relayProfileCommand() *cli.Command {
	return &cli.Command{
		Name:  "profile",
		Usage: "name the relays this machine looks after, e.g. its dev tunnel relay and a Cloud Run one, and pick the one relay commands use",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list the relay profiles, with their URLs and members, and the one relay commands use",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}},
				Action: runRelayProfileList,
			},
			{
				Name:      "use",
				Usage:     "make a relay profile the one relay commands use when --relay names none",
				ArgsUsage: "<name>",
				Action:    runRelayProfileUse,
			},
			{
				Name:      "add",
				Usage:     "name a relay made elsewhere: a directory, or gs://<bucket>[/<folder>] for one on Cloud Run",
				ArgsUsage: "<name> <location>",
				Action:    runRelayProfileAdd,
			},
			{
				Name:      "rename",
				Usage:     "rename a relay profile, e.g. default to tunnel; no file moves",
				ArgsUsage: "<old> <new>",
				Action:    runRelayProfileRename,
			},
			{
				Name:      "forget",
				Usage:     "drop a relay profile's name; the relay itself stays as it is",
				ArgsUsage: "<name>",
				Action:    runRelayProfileForget,
			},
		},
	}
}

func runRelayProfileList(ctx context.Context, cmd *cli.Command) error {
	dir, err := relayDir(cmd)
	if err != nil {
		return err
	}
	ps, err := state.RelayProfiles(dir)
	if err != nil {
		return err
	}
	cur, err := state.CurrentRelay(dir)
	if err != nil {
		return err
	}

	type entry struct {
		Relay    string `json:"relay"`
		Location string `json:"location"`
		URL      string `json:"url"`
		Members  int    `json:"members"`
		Current  bool   `json:"current"`
		Error    string `json:"error,omitempty"`
	}
	entries := []entry{}
	for _, p := range ps {
		e := entry{Relay: p.Name, Location: p.Location, Current: p.Name == cur}
		store, err := state.Open(p.Location, state.RelayFile)
		var st relay.State
		if err == nil {
			_, err = store.Read(ctx, &st)
		}
		switch {
		case errors.Is(err, os.ErrNotExist):
			e.Error = "no relay there; it was moved or deleted"
		case err != nil:
			e.Error = err.Error()
		default:
			e.URL, e.Members = st.URL, len(st.Nodes)
		}
		entries = append(entries, e)
	}

	w := cmd.Root().Writer
	if cmd.Bool("json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Current string  `json:"current"`
			Relays  []entry `json:"relays"`
		}{cur, entries})
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "this machine looks after no relay; make one with `san_vpn setup init` (dev tunnel) or `san_vpn cloudrun setup`")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  RELAY\tURL\tMEMBERS\tWHERE")
	var failed []entry
	for _, e := range entries {
		mark, url, members := " ", orNone(e.URL), fmt.Sprint(e.Members)
		if e.Current {
			mark = "*"
		}
		if e.Error != "" {
			url, members = "?", "?"
			failed = append(failed, e)
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", mark, e.Relay, url, members, e.Location)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, e := range failed {
		fmt.Fprintf(w, "\n%s: %s", e.Relay, e.Error)
	}
	if len(failed) > 0 {
		fmt.Fprintln(w)
	}
	if slices.ContainsFunc(entries, func(e entry) bool { return e.Current }) {
		fmt.Fprintln(w, "\n* is the relay the relay commands use; switch with: san_vpn relay profile use <name>, or pass --relay <name>")
	} else {
		fmt.Fprintf(w, "\nThe current relay profile, %q, holds no relay; pick one with: san_vpn relay profile use <name>\n", cur)
	}
	return nil
}

func runRelayProfileUse(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return errors.New("usage: san_vpn relay profile use <name>")
	}
	name := cmd.Args().First()
	dir, err := relayDir(cmd)
	if err != nil {
		return err
	}
	loc, known, err := state.RelayLocation(dir, name)
	if err != nil {
		return err
	}
	if !known {
		return unknownRelay(dir, name)
	}
	p := relayPick{dir: dir, name: name, loc: loc, known: true}
	st, err := readRelay(ctx, &p)
	if err != nil {
		return err
	}
	if err := state.SetCurrentRelay(dir, name); err != nil {
		return err
	}

	w := cmd.Root().Writer
	fmt.Fprintf(w, "relay commands now use relay %q: %s, kept in %s\n", name, orNone(st.URL), p.store)
	if state.RemoteLocation(loc) && len(localRelays(dir)) > 0 {
		fmt.Fprintf(w, "relay run serves a relay of this machine, so name it there: %s\n", localRelayHint(dir))
	}
	return nil
}

// localRelays are the relay profiles kept on this machine's disk, which
// relay run can serve.
func localRelays(dir string) []string {
	ps, _ := state.RelayProfiles(dir)
	var names []string
	for _, r := range ps {
		if !state.RemoteLocation(r.Location) {
			names = append(names, r.Name)
		}
	}
	return names
}

// localRelayHint is the command that serves a relay of this machine.
func localRelayHint(dir string) string {
	local := localRelays(dir)
	switch len(local) {
	case 0:
		return "make one with `san_vpn setup init --relay <name>`"
	case 1:
		return "san_vpn relay run --relay " + local[0]
	}
	return "san_vpn relay run --relay <" + strings.Join(local, "|") + ">"
}

func runRelayProfileAdd(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 2 {
		return errors.New("usage: san_vpn relay profile add <name> <location>")
	}
	name, loc := cmd.Args().Get(0), cmd.Args().Get(1)
	dir, err := relayDir(cmd)
	if err != nil {
		return err
	}
	if err := state.ValidRelayName(name); err != nil {
		return err
	}
	// The location is the folder holding relay.json; take the file's own
	// path too, since that is what other commands print.
	if state.RemoteLocation(loc) {
		loc = strings.TrimSuffix(loc, "/"+state.RelayFile)
	} else if filepath.Base(loc) == state.RelayFile {
		loc = filepath.Dir(loc)
	}
	p := relayPick{dir: dir, name: name, loc: loc, known: true}
	st, err := readRelay(ctx, &p)
	if err != nil {
		return err
	}
	if err := rememberRelay(dir, name, loc); err != nil {
		return err
	}
	w := cmd.Root().Writer
	fmt.Fprintf(w, "added relay %q: %s, kept in %s\n", name, orNone(st.URL), p.store)
	if arg := relayArg(p); arg != "" {
		fmt.Fprintf(w, "Use it with --relay %s, or make it the one relay commands use: san_vpn relay profile use %s\n", name, name)
	}
	return nil
}

// readRelay opens p's store and reads the relay in it, which must be there.
func readRelay(ctx context.Context, p *relayPick) (relay.State, error) {
	var st relay.State
	store, err := state.Open(p.loc, state.RelayFile)
	if err != nil {
		return st, err
	}
	p.store = store
	if _, err := store.Read(ctx, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, fmt.Errorf("no relay at %s", store)
		}
		return st, err
	}
	return st, nil
}

func runRelayProfileRename(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 2 {
		return errors.New("usage: san_vpn relay profile rename <old> <new>")
	}
	from, to := cmd.Args().Get(0), cmd.Args().Get(1)
	dir, err := relayDir(cmd)
	if err != nil {
		return err
	}
	if err := state.RenameRelay(dir, from, to); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "renamed relay profile %q to %q; its file stays where it is\n", from, to)
	return nil
}

func runRelayProfileForget(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return errors.New("usage: san_vpn relay profile forget <name>")
	}
	dir, err := relayDir(cmd)
	if err != nil {
		return err
	}
	name := cmd.Args().First()
	loc, err := state.ForgetRelay(dir, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "forgot relay profile %q; the relay is still in %s (add it again with: san_vpn relay profile add %s %s)\n", name, loc, name, loc)
	return nil
}
