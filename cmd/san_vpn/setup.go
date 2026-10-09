package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/devtunnel"
	"github.com/wargasipil/san_vpn/internal/setup"
	"github.com/wargasipil/san_vpn/internal/state"
)

func setupCommand() *cli.Command {
	return &cli.Command{
		Name:  "setup",
		Usage: "put the relay behind a Microsoft dev tunnel, and check a machine's whole path",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "on the relay machine: install devtunnel, sign in with GitHub, create the relay and its tunnel (safe to rerun)",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "port", Usage: "local port the relay listens on and the tunnel forwards (default 8443, or the current one)"},
					&cli.StringFlag{Name: "tunnel", Usage: "use this existing dev tunnel instead of creating one"},
					&cli.BoolFlag{Name: "device-code", Usage: "sign in with a code entered on another device (automatic on Linux without a display)"},
					&cli.BoolFlag{Name: "no-install", Usage: "do not install the devtunnel CLI when it is missing"},
				},
				Action: runSetupInit,
			},
			{
				// Where it was until v0.4.2, which took a prebuilt image.
				Name:            "cloudrun",
				Hidden:          true,
				SkipFlagParsing: true,
				Action: func(context.Context, *cli.Command) error {
					return errors.New("`setup cloudrun` is now two commands: `san_vpn cloudrun setup` readies the project, then `san_vpn cloudrun deploy` builds the relay from source and runs it")
				},
			},
			{
				Name:   "check",
				Usage:  "check this machine: the relay and its tunnel, and/or this member's connection",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "json", Usage: "print JSON"}, profileFlag()},
				Action: runSetupCheck,
			},
		},
	}
}

func runSetupInit(ctx context.Context, cmd *cli.Command) error {
	path, err := relayPath(cmd, "setup init (a dev tunnel in front of this machine)")
	if err != nil {
		return err
	}
	w := cmd.Root().Writer
	fmt.Fprintln(w, "Setting up the relay behind a Microsoft dev tunnel")

	cliPath, err := devtunnel.Find()
	if errors.Is(err, devtunnel.ErrNotInstalled) {
		if cmd.Bool("no-install") {
			return fmt.Errorf("the devtunnel CLI is not installed; install it with: %s", devtunnel.InstallHint())
		}
		cliPath, err = devtunnel.Install(ctx, w, os.Stdout, os.Stderr)
	}
	if err != nil {
		return err
	}
	dt := devtunnel.New(cliPath, os.Stdin, os.Stdout, os.Stderr)
	version, err := dt.Version(ctx)
	if err != nil {
		return fmt.Errorf("devtunnel at %s does not run: %w", cliPath, err)
	}
	fmt.Fprintf(w, "  ok   devtunnel CLI %s (%s)\n", version, cliPath)

	res, err := setup.Init(ctx, dt, setup.InitOptions{
		RelayPath:  path,
		Port:       int(cmd.Int("port")),
		TunnelID:   cmd.String("tunnel"),
		DeviceCode: cmd.Bool("device-code") || headless(),
		Out:        w,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "\nThe relay will be reachable at %s\n\n", res.URL)
	fmt.Fprintln(w, "Next, on this machine:")
	fmt.Fprintf(w, "  san_vpn relay run              serves the relay on 127.0.0.1:%d and hosts the tunnel; keep it running\n", res.Port)
	fmt.Fprintln(w, "  san_vpn relay invite <name>    one invite per machine, then on that machine: san_vpn join <invite>")
	fmt.Fprintln(w, "  san_vpn setup check            confirms everything, end to end")
	return nil
}

// headless is a Linux machine with no display, where the browser sign-in
// cannot open: a VPS over SSH.
func headless() bool {
	return runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

func runSetupCheck(ctx context.Context, cmd *cli.Command) error {
	store, err := relayStore(cmd)
	if err != nil {
		return err
	}
	// A gs:// --state names the relay's bucket; this machine's membership is
	// still where it always is.
	dir, _, err := nodeDir(cmd)
	if err != nil {
		dir = state.NodeDir()
	}
	// The member half checks one profile: the one named, else the running
	// one, else the current one. A directory this terminal may not read is
	// left to the member check, which says to run it as administrator.
	profile, err := memberProfile(cmd, dir, true)
	switch {
	case errors.Is(err, os.ErrPermission):
		profile = state.DefaultProfile
	case err != nil:
		return err
	case cmd.String("profile") != "":
		if ok, err := state.Joined(dir, profile); err == nil && !ok {
			return notJoined(dir, profile)
		}
	}
	shown := ""
	if profilesInUse(dir) {
		shown = profile
	}
	sections := setup.Check(ctx, setup.CheckOptions{
		Relay:   store,
		NodeDir: state.ProfileDir(dir, profile),
		Profile: shown,
		FindCLI: func() (*devtunnel.CLI, error) {
			p, err := devtunnel.Find()
			if err != nil {
				return nil, err
			}
			return devtunnel.New(p, nil, io.Discard, io.Discard), nil
		},
		StaleAfter: staleAfter,
	})

	w := cmd.Root().Writer
	if cmd.Bool("json") {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sections); err != nil {
			return err
		}
	} else {
		printCheck(w, sections)
	}
	if setup.Failed(sections) {
		return errors.New("some checks failed")
	}
	return nil
}

func printCheck(w io.Writer, sections []setup.Section) {
	for i, s := range sections {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if s.Path != "" {
			fmt.Fprintf(w, "%s  (%s)\n", s.Title, s.Path)
		} else {
			fmt.Fprintln(w, s.Title)
		}
		for _, it := range s.Items {
			fmt.Fprintf(w, "  %-4s %s\n", it.Mark, it.Text)
			if it.Fix != "" && it.Mark == setup.Fail {
				fmt.Fprintf(w, "       fix: %s\n", it.Fix)
			}
		}
	}
}
