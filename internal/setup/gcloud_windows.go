package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// gcloudCommand runs gcloud, which on Windows is gcloud.cmd, a batch file.
// Windows starts a batch file through `cmd.exe /c`, and cmd drops the first
// and last quote of the line whenever it holds more than two. With gcloud
// under C:\Users\ASUS TUF\ and a quoted argument such as --display-name
// "san_vpn relay", the path lost its quotes and cmd ran 'C:\Users\ASUS'. So a
// batch file gets cmd.exe with /s, which strips only the outer pair added
// here, and each argument quoted so that the batch file's %* passes it on.
func gcloudCommand(ctx context.Context, path string, args []string) (*exec.Cmd, error) {
	if ext := strings.ToLower(filepath.Ext(path)); ext != ".cmd" && ext != ".bat" {
		return exec.CommandContext(ctx, path, args...), nil
	}
	line := []string{cmdArg(path)}
	for _, a := range args {
		// cmd expands %VAR% even inside quotes, gcloud.cmd turns on delayed
		// expansion, which eats !, and a quote would end the quoting.
		if strings.ContainsAny(a, "\"%!\r\n") {
			return nil, fmt.Errorf("argument %q: cmd.exe cannot pass \", %%, ! or a line break on to gcloud.cmd", a)
		}
		line = append(line, cmdArg(a))
	}
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	cmd := exec.CommandContext(ctx, comspec)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: syscall.EscapeArg(comspec) + ` /d /s /c "` + strings.Join(line, " ") + `"`}
	return cmd, nil
}

// cmdArg quotes a when cmd.exe or the program's own parser would split or
// act on it.
func cmdArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t&|<>^(),;=") {
		return a
	}
	// Backslashes right before the closing quote would escape it.
	t := strings.TrimRight(a, `\`)
	return `"` + t + strings.Repeat(`\`, 2*(len(a)-len(t))) + `"`
}
