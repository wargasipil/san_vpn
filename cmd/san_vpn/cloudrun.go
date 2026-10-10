package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/setup"
	"github.com/wargasipil/san_vpn/internal/state"
	"github.com/wargasipil/san_vpn/internal/update"
)

func cloudrunCommand() *cli.Command {
	// A function, not a slice: each command gets flags of its own.
	where := func(more ...cli.Flag) []cli.Flag {
		return append([]cli.Flag{
			&cli.StringFlag{Name: "project", Usage: "Google Cloud project (default: the one setup recorded, else gcloud's configured project)"},
			&cli.StringFlag{Name: "region", Usage: "Cloud Run region (default: the one setup recorded, else " + setup.DefaultRegion + ", Jakarta)"},
			&cli.StringFlag{Name: "service", Usage: "Cloud Run service name (default: the one setup recorded, else " + setup.DefaultService + ")"},
			&cli.BoolFlag{Name: "dry-run", Usage: "look at everything, change nothing, and print the gcloud commands it would run"},
			&cli.StringFlag{Name: "relay", Sources: cli.EnvVars("SAN_VPN_RELAY"), Usage: "keep the relay under relay profile `name` (default: the current one when it is on Cloud Storage, else cloudrun)"},
		}, more...)
	}
	return &cli.Command{
		Name:        "cloudrun",
		Usage:       "run the relay on Google Cloud Run, its file in Cloud Storage, using your gcloud sign-in",
		Description: "The relay's file goes in --state when that is a gs:// location, else where its relay profile says, else in gs://<project>-san-vpn. This machine keeps it as relay profile cloudrun unless --relay names another.",
		Commands: []*cli.Command{
			{
				Name:   "setup",
				Usage:  "ready a project for the relay: APIs, bucket, service account, the relay's key, an image repository, Cloud Build (safe to rerun)",
				Flags:  where(),
				Action: runCloudRunSetup,
			},
			{
				Name:  "deploy",
				Usage: "build the relay from source with Cloud Build and run it; again after `update`, to move the relay to the new release",
				Flags: where(
					&cli.StringFlag{Name: "source", Usage: "build the san_vpn source tree in `dir` (default: this release's source from GitHub, or the checkout that go run runs in)"},
					&cli.StringFlag{Name: "image", Usage: "run this image as it is, with no build"},
					&cli.DurationFlag{Name: "timeout", Value: setup.DefaultRequestTimeout, Usage: "request timeout, and so how long a member connection lasts before it is renewed (1m to 1h)"},
				),
				Action: runCloudRunDeploy,
			},
		},
	}
}

// defaultCloudRunRelay is the relay profile a relay on Cloud Run is kept
// under when none is named.
const defaultCloudRunRelay = "cloudrun"

// cloudRunOptions are what setup and deploy share: where, and how loudly.
// The relay pick says which relay profile keeps the relay once it is made;
// its name is empty for a relay named only by --state.
func cloudRunOptions(cmd *cli.Command) (setup.CloudRunOptions, relayPick, error) {
	loc, p, err := cloudRunRelay(cmd)
	if err != nil {
		return setup.CloudRunOptions{}, relayPick{}, err
	}
	return setup.CloudRunOptions{
		Project: cmd.String("project"),
		Region:  cmd.String("region"),
		Service: cmd.String("service"),
		State:   loc,
		DryRun:  cmd.Bool("dry-run"),
		Out:     cmd.Root().Writer,
	}, p, nil
}

// cloudRunRelay picks the relay's file for a cloudrun command: --state, a
// gs:// location; else the relay profile --relay names; else the current one
// when it is on Cloud Storage; else cloudrun. loc is empty for a profile with
// no relay yet, which setup puts in gs://<project>-san-vpn.
func cloudRunRelay(cmd *cli.Command) (loc string, p relayPick, err error) {
	loc, name := cmd.String("state"), cmd.String("relay")
	if loc != "" && !state.RemoteLocation(loc) {
		return "", p, fmt.Errorf("--state %s: a relay on Cloud Run keeps its file in Cloud Storage; pass a gs:// location, or none", loc)
	}
	if loc != "" && name == "" {
		return loc, p, nil // named by its location alone, as before relay profiles
	}
	dir, err := state.RelayDir()
	if err != nil {
		return "", p, err
	}
	return cloudRunRelayIn(dir, loc, name)
}

// cloudRunRelayIn is cloudRunRelay with the relay directory dir, a gs://
// --state loc or none, and --relay name or none.
func cloudRunRelayIn(dir, loc, name string) (string, relayPick, error) {
	p := relayPick{dir: dir}
	if name == "" {
		name = cloudRunDefault(dir)
	}
	have, known, err := state.RelayLocation(dir, name)
	if err != nil {
		return "", p, err
	}
	p.name, p.known = name, known
	switch {
	case known && !state.RemoteLocation(have):
		return "", p, fmt.Errorf("relay profile %q is a relay on this machine, in %s; a relay on Cloud Run keeps its file in Cloud Storage, so name another with --relay", name, have)
	case known && loc != "" && strings.TrimRight(loc, "/") != have:
		return "", p, fmt.Errorf("relay profile %q is kept in %s, not %s", name, have, loc)
	case known:
		loc = have
	}
	p.loc = loc
	return loc, p, nil
}

// cloudRunDefault is the relay profile a cloudrun command works on when none
// is named: the current one when it is on Cloud Storage, else cloudrun.
func cloudRunDefault(dir string) string {
	if cur, err := state.CurrentRelay(dir); err == nil {
		if loc, _, err := state.RelayLocation(dir, cur); err == nil && state.RemoteLocation(loc) {
			return cur
		}
	}
	return defaultCloudRunRelay
}

// keepCloudRunRelay records the relay setup or deploy worked on under its
// relay profile.
func keepCloudRunRelay(p relayPick, res *setup.CloudRunResult) (relayPick, error) {
	if p.name == "" {
		return p, nil
	}
	if err := rememberRelay(p.dir, p.name, res.State); err != nil {
		return p, err
	}
	p.loc, p.known = res.State, true
	return p, nil
}

// cloudRunArg is what the next cloudrun command needs to find the same relay:
// nothing when it would anyway.
func cloudRunArg(p relayPick, res *setup.CloudRunResult) string {
	switch {
	case p.name == "":
		return " --state " + res.State
	case p.name == cloudRunDefault(p.dir):
		return ""
	}
	return " --relay " + p.name
}

func runCloudRunSetup(ctx context.Context, cmd *cli.Command) error {
	o, p, err := cloudRunOptions(cmd)
	if err != nil {
		return err
	}
	g, err := setup.FindGCloud()
	if err != nil {
		return err
	}
	w := cmd.Root().Writer
	if o.DryRun {
		fmt.Fprintln(w, "Dry run: looking only; the commands that would change something are listed")
	} else {
		fmt.Fprintln(w, "Readying Google Cloud Run for the relay")
	}
	res, err := setup.CloudRunSetup(ctx, g, o)
	if err != nil || o.DryRun {
		return err
	}
	if p, err = keepCloudRunRelay(p, res); err != nil {
		return err
	}
	if p.name != "" {
		fmt.Fprintf(w, "  ok   relay profile %q on this machine\n", p.name)
	}
	fmt.Fprintln(w, "\nNext, build the relay from source and run it:")
	fmt.Fprintf(w, "  san_vpn cloudrun deploy%s\n", cloudRunArg(p, res))
	return nil
}

func runCloudRunDeploy(ctx context.Context, cmd *cli.Command) error {
	o, p, err := cloudRunOptions(cmd)
	if err != nil {
		return err
	}
	o.Image = cmd.String("image")
	o.Timeout = cmd.Duration("timeout")
	if o.Image == "" {
		var done func()
		if o.Tag, o.Source, done, err = deploySource(cmd); err != nil {
			return err
		}
		defer done()
	}
	g, err := setup.FindGCloud()
	if err != nil {
		return err
	}
	w := cmd.Root().Writer
	if o.DryRun {
		fmt.Fprintln(w, "Dry run: looking only; the commands that would change something are listed")
	} else {
		fmt.Fprintln(w, "Deploying the relay to Google Cloud Run")
	}
	res, err := setup.CloudRunDeploy(ctx, g, o)
	if err != nil || o.DryRun {
		return err
	}
	if p, err = keepCloudRunRelay(p, res); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nThe relay runs at %s\n\n", res.URL)
	printCloudRunNext(w, p, res)
	return nil
}

// printCloudRunNext says how to invite to the relay just deployed.
func printCloudRunNext(w io.Writer, p relayPick, res *setup.CloudRunResult) {
	if p.name == "" {
		fmt.Fprintln(w, "Next, from any machine signed in to gcloud:")
		fmt.Fprintf(w, "  san_vpn --state %s relay invite <name>   one invite per machine, then on that machine: san_vpn join <invite>\n", res.State)
		fmt.Fprintf(w, "  san_vpn --state %s setup check           confirms the relay, end to end\n", res.State)
		fmt.Fprintln(w, "Set SAN_VPN_STATE to that location to leave out --state.")
	} else {
		arg := relayArg(p)
		fmt.Fprintf(w, "Next, on this machine, where it is relay profile %q:\n", p.name)
		tw := tabwriter.NewWriter(w, 0, 4, 3, ' ', 0)
		fmt.Fprintf(tw, "  san_vpn relay invite%s <name>\tone invite per machine, then on that machine: san_vpn join <invite>\n", arg)
		fmt.Fprintf(tw, "  san_vpn setup check%s\tconfirms the relay, end to end\n", arg)
		_ = tw.Flush()
		if arg != "" {
			fmt.Fprintf(w, "or make it the one the relay commands use: san_vpn relay profile use %s\n", p.name)
		}
		fmt.Fprintf(w, "On another machine signed in to gcloud, name it first: san_vpn relay profile add %s %s\n", p.name, res.State)
	}
	fmt.Fprintf(w, "After `san_vpn update`, run `san_vpn cloudrun deploy%s` again to move the relay to the new release.\n", cloudRunArg(p, res))
}

func deploySource(cmd *cli.Command) (string, func(context.Context) (string, error), func(), error) {
	return pickSource(cmd.String("source"), version, cmd.Root().Writer, &update.Client{Base: update.Base})
}

// pickSource picks what deploy builds: the tree dir names, else release
// ver's source from GitHub, else the checkout `go run` runs in. A release's
// image is tagged with the release; a tree of one's own may hold anything,
// so it gets a tag of its own each time. source fetches the tree only when a
// build is needed; done removes what it fetched.
func pickSource(dir, ver string, w io.Writer, gh *update.Client) (tag string, source func(context.Context) (string, error), done func(), err error) {
	devTag := "dev-" + time.Now().UTC().Format("20060102-150405")
	done = func() {}
	if dir != "" {
		if err := sourceTree(dir); err != nil {
			return "", nil, nil, err
		}
		return devTag, func(context.Context) (string, error) { return filepath.Abs(dir) }, done, nil
	}
	if update.IsRelease(ver) {
		var tmp string
		source = func(ctx context.Context) (string, error) {
			var err error
			if tmp, err = os.MkdirTemp("", "san_vpn-source-*"); err != nil {
				return "", err
			}
			fmt.Fprintf(w, "  ..   fetching the source of %s from %s\n", ver, gh.Base)
			return tmp, gh.Source(ctx, ver, tmp)
		}
		done = func() {
			if tmp != "" {
				os.RemoveAll(tmp)
			}
		}
		return ver, source, done, nil
	}
	if wd, err := os.Getwd(); err == nil && sourceTree(wd) == nil {
		return devTag, func(context.Context) (string, error) { return wd, nil }, done, nil
	}
	return "", nil, nil, fmt.Errorf("this san_vpn is not a release (%s), so it has no published source to build; pass --source <a san_vpn checkout>, or run it from one", ver)
}

// sourceTree checks that dir holds san_vpn's source, with its Dockerfile.
func sourceTree(dir string) error {
	mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil || !strings.Contains(strings.ReplaceAll(string(mod), "\r", ""), "module github.com/wargasipil/san_vpn\n") {
		return fmt.Errorf("%s is not a san_vpn source tree (no go.mod of github.com/wargasipil/san_vpn)", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err != nil {
		return fmt.Errorf("%s has no Dockerfile to build the relay with", dir)
	}
	return nil
}
