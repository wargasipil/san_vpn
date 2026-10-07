package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/state"
)

// profileFlag picks which of this machine's memberships a member command
// works on. It is not global on purpose: the relay commands pick their relay
// with --state, and a --profile they silently ignored could send an invite to
// the wrong network.
func profileFlag() cli.Flag {
	return &cli.StringFlag{Name: "profile", Sources: cli.EnvVars("SAN_VPN_PROFILE"), Usage: "which of this machine's networks, by profile `name` (default: the one chosen with san_vpn profile use)"}
}

func profileCommand() *cli.Command {
	return &cli.Command{
		Name:  "profile",
		Usage: "switch this machine between the networks it joined, e.g. a dev tunnel relay and a Cloud Run one",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list this machine's profiles, the one `up` uses and the one running",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}},
				Action: runProfileList,
			},
			{
				Name:      "use",
				Usage:     "make a profile the one `san_vpn up` brings up",
				ArgsUsage: "<profile>",
				Action:    runProfileUse,
			},
			{
				Name:      "rename",
				Usage:     "rename a profile, e.g. default to tunnel",
				ArgsUsage: "<old> <new>",
				Action:    runProfileRename,
			},
		},
	}
}

// memberProfile is the profile a member command works on, in the node
// directory dir: --profile, else -- for the commands that look at what runs
// -- the profile `up` is running, else the current one.
func memberProfile(cmd *cli.Command, dir string, preferRunning bool) (string, error) {
	if name := cmd.String("profile"); name != "" {
		return name, state.ValidProfile(name)
	}
	if preferRunning {
		if name, _, ok := runningProfile(dir); ok {
			return name, nil
		}
	}
	return state.CurrentProfile(dir)
}

// upStatus reads the status `up` keeps in a profile's directory, and says
// whether it is fresh: whether `up` is running on that profile.
func upStatus(pdir string) (node.Status, bool) {
	var st node.Status
	if err := state.Load(filepath.Join(pdir, state.StatusFile), &st); err != nil {
		return st, false
	}
	return st, time.Since(st.Updated) <= staleAfter
}

// runningProfile is the profile `up` is running on, if any.
func runningProfile(dir string) (string, node.Status, bool) {
	names, _ := state.Profiles(dir)
	for _, name := range names {
		if st, ok := upStatus(state.ProfileDir(dir, name)); ok {
			return name, st, true
		}
	}
	return "", node.Status{}, false
}

// profilesInUse reports whether this machine has a profile besides default,
// which is when messages start naming them.
func profilesInUse(dir string) bool {
	names, _ := state.Profiles(dir)
	return slices.ContainsFunc(names, func(n string) bool { return n != state.DefaultProfile })
}

// upFor is the command that brings up profile name: plain `san_vpn up` when
// it is the current one.
func upFor(dir, name string) string {
	if cur, err := state.CurrentProfile(dir); err == nil && cur == name {
		return "san_vpn up"
	}
	return "san_vpn up --profile " + name
}

// notJoined says what to run when a profile holds no membership.
func notJoined(dir, name string) error {
	names, _ := state.Profiles(dir)
	if len(names) == 0 {
		return errors.New("this machine has not joined a network yet; run `san_vpn join <invite>` first")
	}
	return fmt.Errorf("profile %q has not joined a network; join it with `san_vpn join --profile %s <invite>`, or pick one of %s with `san_vpn profile use <profile>`",
		name, name, strings.Join(names, ", "))
}

// memberErr turns a refusal to read the node directory into its fix.
func memberErr(what string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		if e := requireAdmin(what); e != nil {
			return e
		}
	}
	return err
}

func runProfileList(_ context.Context, cmd *cli.Command) error {
	dir, _, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	names, err := state.Profiles(dir)
	if err != nil {
		return memberErr("san_vpn profile list", err)
	}
	cur, err := state.CurrentProfile(dir)
	if err != nil {
		return memberErr("san_vpn profile list", err)
	}

	type entry struct {
		Profile string       `json:"profile"`
		Name    string       `json:"name"`
		Address netip.Prefix `json:"address"`
		Relay   string       `json:"relay"`
		Current bool         `json:"current"`
		Running bool         `json:"running"`
	}
	entries := []entry{}
	for _, name := range names {
		pdir := state.ProfileDir(dir, name)
		var cfg node.Config
		if err := state.Load(filepath.Join(pdir, state.NodeFile), &cfg); err != nil {
			return memberErr("san_vpn profile list", err)
		}
		_, running := upStatus(pdir)
		entries = append(entries, entry{name, cfg.Name, cfg.Prefix(), cfg.RelayURL, name == cur, running})
	}

	w := cmd.Root().Writer
	if cmd.Bool("json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Current  string  `json:"current"`
			Profiles []entry `json:"profiles"`
		}{cur, entries})
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "this machine has not joined a network; run `san_vpn join <invite>`")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  PROFILE\tMEMBER\tADDRESS\tRELAY\tSTATE")
	for _, e := range entries {
		mark, st := " ", "stopped"
		if e.Current {
			mark = "*"
		}
		if e.Running {
			st = "running"
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\t%s\n", mark, e.Profile, e.Name, e.Address, e.Relay, st)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if slices.Contains(names, cur) {
		fmt.Fprintln(w, "\n* is the profile `san_vpn up` brings up; switch with: san_vpn profile use <profile>")
	} else {
		fmt.Fprintf(w, "\nThe current profile, %q, has not joined a network; pick one with: san_vpn profile use <profile>\n", cur)
	}
	return nil
}

func runProfileUse(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return errors.New("usage: san_vpn profile use <profile>")
	}
	name := cmd.Args().First()
	if err := state.ValidProfile(name); err != nil {
		return err
	}
	dir, isDefault, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	if isDefault {
		if err := requireAdmin("san_vpn profile use"); err != nil {
			return err
		}
	}
	var cfg node.Config
	if err := state.Load(filepath.Join(state.ProfileDir(dir, name), state.NodeFile), &cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return notJoined(dir, name)
		}
		return err
	}
	if err := state.SetCurrentProfile(dir, name); err != nil {
		return err
	}

	w := cmd.Root().Writer
	fmt.Fprintf(w, "san_vpn up now brings up profile %q: %s at %s, via %s\n", name, cfg.Name, cfg.Prefix(), cfg.RelayURL)
	if run, st, ok := runningProfile(dir); ok && run != name {
		fmt.Fprintf(w, "san_vpn up is still running on profile %q (pid %d); stop it and start it again to switch\n", run, st.PID)
	}
	return nil
}

func runProfileRename(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 2 {
		return errors.New("usage: san_vpn profile rename <old> <new>")
	}
	from, to := cmd.Args().Get(0), cmd.Args().Get(1)
	dir, isDefault, err := nodeDir(cmd)
	if err != nil {
		return err
	}
	if isDefault {
		if err := requireAdmin("san_vpn profile rename"); err != nil {
			return err
		}
	}
	// `up` keeps writing its status where it started; moving the membership
	// from under it would make it look stopped.
	if st, ok := upStatus(state.ProfileDir(dir, from)); ok {
		return fmt.Errorf("san_vpn up is running on profile %q (pid %d); stop it first", from, st.PID)
	}
	if err := state.RenameProfile(dir, from, to); err != nil {
		return err
	}
	fmt.Fprintf(cmd.Root().Writer, "renamed profile %q to %q\n", from, to)
	return nil
}
