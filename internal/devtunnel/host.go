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

// Host keeps `devtunnel host <id>` running until ctx ends, restarting it with
// backoff when it exits: a dropped connection to the dev tunnels service, an
// expired sign-in being renewed, a laptop waking up. Its output goes to log.
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
		log.Warn("devtunnel host exited; restarting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
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
