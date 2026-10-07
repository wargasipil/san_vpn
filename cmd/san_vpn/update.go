package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/update"
)

// Tests point these at a fake GitHub, a scratch binary and a fake --version.
var (
	releases    = &update.Client{Base: update.Base}
	executable  = os.Executable
	checkBinary = update.Check
)

func updateCommand() *cli.Command {
	return &cli.Command{
		Name:      "update",
		Usage:     "replace this binary with the latest GitHub release, or with release <tag>",
		ArgsUsage: "[tag]",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "check", Usage: "only say whether a newer release is out"},
			&cli.BoolFlag{Name: "force", Usage: "install even when this binary is as new, or is a local build"},
		},
		Action: runUpdate,
	}
}

func runUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() > 1 {
		return errors.New("usage: san_vpn update [tag]")
	}
	w := cmd.Root().Writer
	tag := cmd.Args().First()
	latest := tag == ""
	if latest {
		var err error
		if tag, err = releases.Latest(ctx); err != nil {
			return err
		}
	} else if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	newer, comparable := update.Newer(version, tag)

	if cmd.Bool("check") {
		switch {
		case !comparable:
			fmt.Fprintf(w, "this is a local build (%s); the latest release is %s\n", version, tag)
		case newer:
			fmt.Fprintf(w, "san_vpn %s is out (this is %s); install it with: san_vpn update\n", tag, version)
		case version == tag:
			fmt.Fprintf(w, "san_vpn %s is up to date\n", version)
		default:
			fmt.Fprintf(w, "san_vpn %s is newer than the latest release, %s\n", version, tag)
		}
		return nil
	}
	if !cmd.Bool("force") {
		switch {
		case version == tag:
			fmt.Fprintf(w, "san_vpn %s is up to date\n", version)
			return nil
		case latest && !comparable:
			return fmt.Errorf("this is a local build (%s), not a release; pass --force to replace it with %s", version, tag)
		case latest && !newer:
			fmt.Fprintf(w, "san_vpn %s is newer than the latest release, %s\n", version, tag)
			return nil
		}
	}

	name, err := update.AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("find this binary: %w", err)
	}
	fmt.Fprintf(w, "Updating %s from %s to %s\n", exe, version, tag)
	fresh, err := releases.Download(ctx, tag, name, filepath.Dir(exe))
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w\n%s is not writable here; run san_vpn update from an administrator terminal (sudo on Linux)", err, filepath.Dir(exe))
	}
	if err != nil {
		return err
	}
	defer os.Remove(fresh) // gone already once it has replaced exe
	fmt.Fprintf(w, "  ok   downloaded %s; it matches %s\n", name, update.SumsFile)
	if err := checkBinary(ctx, fresh, tag); err != nil {
		return err
	}
	fmt.Fprintf(w, "  ok   it runs: san_vpn version %s\n", tag)
	if err := update.Replace(exe, fresh); err != nil {
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	fmt.Fprintf(w, "  ok   replaced %s\n", exe)
	fmt.Fprintf(w, "\nsan_vpn processes already running (up, relay run) stay on %s until they restart.\n", version)
	return nil
}
