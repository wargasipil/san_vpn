package devtunnel

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// signInPoll is how often Host looks for a new sign-in once the old one has
// expired. Tests shorten it.
var signInPoll = 15 * time.Second

// Host keeps `devtunnel host <id>` running until ctx ends, restarting it with
// backoff when it exits: a dropped connection to the dev tunnels service, a
// laptop waking up. Its output goes to log.
//
// An expired sign-in is different: the CLI's login lasts only several days,
// and nothing renews it here. Host says so once and waits for someone to sign
// in again on this machine, then hosts at once, with no relay restart.
//
// The tunnel itself is persistent, so stopping the host only takes it
// offline; nothing about the tunnel's URL or access changes.
func (c *CLI) Host(ctx context.Context, id string, log *slog.Logger) {
	const minBackoff, maxBackoff = 5 * time.Second, time.Minute
	backoff := minBackoff
	for {
		start := time.Now()
		err := c.hostOnce(ctx, id, log)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 2*time.Minute {
			backoff = minBackoff
		}
		waited, ok := c.awaitSignIn(ctx, log)
		if !ok {
			return
		}
		if waited {
			backoff = minBackoff
			continue
		}
		log.Warn("devtunnel host exited; restarting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// awaitSignIn waits while the CLI is not signed in, and reports whether it
// had to; ok is false once ctx ends. A `user show` that fails says nothing
// about the sign-in (the service unreachable, say), so it does not wait.
func (c *CLI) awaitSignIn(ctx context.Context, log *slog.Logger) (waited, ok bool) {
	u, err := c.User(ctx)
	if err != nil || u.LoggedIn() {
		return false, ctx.Err() == nil
	}
	log.Error("the dev tunnel is offline: its sign-in is no longer valid; sign in again on this machine as this user with `devtunnel user login -g` (or `san_vpn setup init`), and hosting resumes by itself",
		"status", u.Status)
	for {
		select {
		case <-ctx.Done():
			return true, false
		case <-time.After(signInPoll):
		}
		if u, err := c.User(ctx); err == nil && u.LoggedIn() {
			log.Info("signed in to dev tunnels again; hosting", "user", u.Username)
			return true, true
		}
	}
}

func (c *CLI) hostOnce(ctx context.Context, id string, log *slog.Logger) error {
	cmd := exec.CommandContext(ctx, c.Path, "host", id, "--nologo")
	cmd.WaitDelay = 5 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	bindToParent(cmd)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				log.Info(line, "component", "devtunnel")
			}
		}
	}()
	err := cmd.Wait()
	_ = pw.Close()
	<-done
	return err
}
