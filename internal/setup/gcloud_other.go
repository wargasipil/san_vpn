//go:build !windows

package setup

import (
	"context"
	"os/exec"
)

// gcloudCommand runs gcloud, a plain executable outside Windows.
func gcloudCommand(ctx context.Context, path string, args []string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, path, args...), nil
}
