package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/wargasipil/san_vpn/internal/setup"
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
		}, more...)
	}
	return &cli.Command{
		Name:        "cloudrun",
		Usage:       "run the relay on Google Cloud Run, its file in Cloud Storage, using your gcloud sign-in",
		Description: "The relay's file goes in --state when that is a gs:// location, else in gs://<project>-san-vpn.",
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

// cloudRunOptions are what setup and deploy share: where, and how loudly.
func cloudRunOptions(cmd *cli.Command) (setup.CloudRunOptions, error) {
	loc := cmd.String("state")
	if loc != "" && !strings.HasPrefix(loc, "gs://") {
		return setup.CloudRunOptions{}, fmt.Errorf("--state %s: a relay on Cloud Run keeps its file in Cloud Storage; pass a gs:// location, or none", loc)
	}
	return setup.CloudRunOptions{
		Project: cmd.String("project"),
		Region:  cmd.String("region"),
		Service: cmd.String("service"),
		State:   loc,
		DryRun:  cmd.Bool("dry-run"),
		Out:     cmd.Root().Writer,
	}, nil
}

func runCloudRunSetup(ctx context.Context, cmd *cli.Command) error {
	o, err := cloudRunOptions(cmd)
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
	fmt.Fprintln(w, "\nNext, build the relay from source and run it:")
	fmt.Fprintf(w, "  san_vpn%s cloudrun deploy\n", stateArg(cmd, res))
	return nil
}

func runCloudRunDeploy(ctx context.Context, cmd *cli.Command) error {
	o, err := cloudRunOptions(cmd)
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
	fmt.Fprintf(w, "\nThe relay runs at %s\n\n", res.URL)
	fmt.Fprintln(w, "Next, from any machine signed in to gcloud:")
	fmt.Fprintf(w, "  san_vpn --state %s relay invite <name>   one invite per machine, then on that machine: san_vpn join <invite>\n", res.State)
	fmt.Fprintf(w, "  san_vpn --state %s setup check           confirms the relay, end to end\n", res.State)
	fmt.Fprintln(w, "Set SAN_VPN_STATE to that location to leave out --state.")
	fmt.Fprintf(w, "After `san_vpn update`, run `san_vpn%s cloudrun deploy` again to move the relay to the new release.\n", stateArg(cmd, res))
	return nil
}

// stateArg is " --state <location>" when the relay's file is somewhere other
// than the default, for the next command to print.
func stateArg(cmd *cli.Command, res *setup.CloudRunResult) string {
	if cmd.String("state") == "" {
		return ""
	}
	return " --state " + res.State
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
