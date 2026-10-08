// Package devtunnel drives Microsoft's devtunnel CLI, so that `san_vpn setup`
// can put the relay behind a dev tunnel and `relay run` can host it.
//
// There is no Go SDK that can host a tunnel, so the CLI is the interface. It
// is driven through its machine-readable side only -- `--json --nologo`, exit
// code 1 for "already exists" and 2 for "not found" -- the same surface .NET
// Aspire's dev tunnels integration relies on, rather than by scraping the
// human output.
package devtunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Exit codes the CLI uses for the two outcomes we act on.
const (
	codeExists   = 1
	codeNotFound = 2
)

var (
	// ErrNotInstalled means no devtunnel executable was found.
	ErrNotInstalled = errors.New("devtunnel CLI is not installed")
	// ErrNotFound is a tunnel or port the service does not know.
	ErrNotFound = errors.New("devtunnel: not found")
)

// ExitError is a CLI call that failed, with what it said.
type ExitError struct {
	Args   []string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = "no output"
	}
	return fmt.Sprintf("devtunnel %s: exit %d: %s", strings.Join(e.Args, " "), e.Code, msg)
}

// Runner executes the CLI and captures its output. Tests replace it.
type Runner func(ctx context.Context, path string, args []string) (stdout, stderr []byte, code int, err error)

// Interactive runs the CLI attached to the user's terminal: sign-in opens a
// browser or prints a device code, and the user has to see it. Tests replace
// it.
type Interactive func(ctx context.Context, path string, args []string) error

// CLI is one devtunnel executable.
type CLI struct {
	Path        string
	Run         Runner
	Interactive Interactive
}

// New wraps the executable at path.
func New(path string, stdin io.Reader, stdout, stderr io.Writer) *CLI {
	return &CLI{
		Path: path,
		Run:  run,
		Interactive: func(ctx context.Context, path string, args []string) error {
			cmd := exec.CommandContext(ctx, path, args...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
			return cmd.Run()
		},
	}
}

func run(ctx context.Context, path string, args []string) ([]byte, []byte, int, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), errb.Bytes(), ee.ExitCode(), nil
	}
	if err != nil {
		return nil, nil, -1, err
	}
	return out.Bytes(), errb.Bytes(), 0, nil
}

// Find locates the CLI: on PATH, or where its installers put it. Installers
// update PATH for new terminals only -- winget adds its package folder to the
// user PATH in the registry, Microsoft's Linux script installs to ~/bin --
// so right after installing, the second half is what finds it. It also finds
// the copy Install downloads where winget is missing.
func Find() (string, error) {
	if p, err := exec.LookPath("devtunnel"); err == nil {
		return p, nil
	}
	for _, p := range installLocations() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", ErrNotInstalled
}

func installLocations() []string {
	if runtime.GOOS != "windows" {
		var out []string
		if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, "bin", "devtunnel"))
		}
		return append(out, "/usr/local/bin/devtunnel")
	}
	var out []string
	for _, dir := range registryPath() {
		out = append(out, filepath.Join(dir, "devtunnel.exe"))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		winget := filepath.Join(base, "Microsoft", "WinGet")
		out = append(out, filepath.Join(winget, "Links", "devtunnel.exe"))
		pkgs, _ := filepath.Glob(filepath.Join(winget, "Packages", "Microsoft.devtunnel_*", "devtunnel.exe"))
		out = append(out, pkgs...)
	}
	if p := downloadPath(); p != "" {
		out = append(out, p)
	}
	return out
}

var (
	wingetCommand = []string{"winget", "install", "--id", "Microsoft.devtunnel", "--exact",
		"--accept-source-agreements", "--accept-package-agreements"}
	scriptCommand = []string{"sh", "-c", "curl -sL https://aka.ms/DevTunnelCliInstall | bash"}
)

// DownloadURL is Microsoft's direct link to the Windows CLI, the way in where
// winget is missing (Windows Server, LTSC, older Windows 10) or fails. There
// is no arm64 build behind it. san_vpn ships Windows for amd64 only, and
// Windows on Arm runs both under emulation.
const DownloadURL = "https://aka.ms/TunnelsCliDownload/win-x64"

// downloadPath is where Install puts a downloaded CLI: per user, like the
// sign-in it will hold.
func downloadPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "san_vpn", "devtunnel.exe")
}

// InstallHint tells a person how to install the CLI themselves.
func InstallHint() string {
	if runtime.GOOS == "windows" {
		return strings.Join(wingetCommand[:5], " ") + ", or save " + DownloadURL + " as devtunnel.exe in a folder on PATH"
	}
	return strings.Join(scriptCommand[2:], " ")
}

// Install installs the CLI, reporting each step to w, and returns its path.
// On Windows that is winget, and where winget is missing or fails, a download
// of Microsoft's exe. Elsewhere it is Microsoft's install script. The
// installers' own output goes to stdout and stderr.
func Install(ctx context.Context, w, stdout, stderr io.Writer) (string, error) {
	if runtime.GOOS != "windows" {
		return runInstaller(ctx, w, stdout, stderr, scriptCommand)
	}
	if _, err := exec.LookPath("winget"); err != nil {
		fmt.Fprintln(w, "  ..   winget is not available")
	} else {
		p, err := runInstaller(ctx, w, stdout, stderr, wingetCommand)
		if err == nil || ctx.Err() != nil {
			return p, err
		}
		fmt.Fprintf(w, "  ..   %v\n", err)
	}
	dst := downloadPath()
	if dst == "" {
		return "", errors.New("install devtunnel: LOCALAPPDATA is not set")
	}
	fmt.Fprintf(w, "  ..   downloading the devtunnel CLI: %s -> %s\n", DownloadURL, dst)
	if err := DownloadExe(ctx, http.DefaultClient, DownloadURL, dst); err != nil {
		return "", fmt.Errorf("install devtunnel: %w", err)
	}
	return dst, nil
}

func runInstaller(ctx context.Context, w, stdout, stderr io.Writer, argv []string) (string, error) {
	fmt.Fprintf(w, "  ..   installing the devtunnel CLI: %s\n", strings.Join(argv, " "))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("install devtunnel (%s): %w", strings.Join(argv, " "), err)
	}
	return Find()
}

// DownloadExe saves the Windows executable at url as path. The file is
// replaced only once a whole executable is in: a link that is retired
// redirects to a web page, and that must not land as devtunnel.exe.
func DownloadExe(ctx context.Context, client *http.Client, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	head := make([]byte, 2)
	n, err := io.ReadFull(resp.Body, head)
	if err == nil && string(head) != "MZ" {
		err = fmt.Errorf("GET %s: not an executable (%s)", url, resp.Header.Get("Content-Type"))
	} else if err != nil {
		err = fmt.Errorf("GET %s: not an executable (%d bytes)", url, n)
	}
	if err == nil {
		_, err = tmp.Write(head)
	}
	if err == nil {
		_, err = io.Copy(tmp, resp.Body)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// jsonCall runs a command with --json --nologo and decodes its output; with
// key set, only that top-level property.
func (c *CLI) jsonCall(ctx context.Context, v any, key string, args ...string) error {
	args = append(args, "--json", "--nologo")
	out, errb, code, err := c.Run(ctx, c.Path, args)
	if err != nil {
		return fmt.Errorf("run devtunnel: %w", err)
	}
	if code != 0 {
		return &ExitError{Args: args, Code: code, Stderr: string(errb) + string(out)}
	}
	if v == nil {
		return nil
	}
	raw := bytes.TrimSpace(out)
	if key != "" {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return fmt.Errorf("devtunnel %s: unreadable output: %w", strings.Join(args, " "), err)
		}
		raw = wrap[key]
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("devtunnel %s: unreadable output: %w", strings.Join(args, " "), err)
	}
	return nil
}

func exitCode(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 0
}

// Version is the CLI's version string.
func (c *CLI) Version(ctx context.Context) (string, error) {
	out, errb, code, err := c.Run(ctx, c.Path, []string{"--version", "--nologo"})
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", &ExitError{Args: []string{"--version"}, Code: code, Stderr: string(errb)}
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "Tunnel CLI version:"); ok {
			v, _, _ = strings.Cut(strings.TrimSpace(v), "+") // drop the commit
			return v, nil
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// User is who the CLI is signed in as.
type User struct {
	Status   string `json:"status"`
	Provider string `json:"provider"`
	Username string `json:"username"`
}

// LoggedIn reports whether the CLI has a usable sign-in.
func (u User) LoggedIn() bool { return strings.EqualFold(u.Status, "Logged in") }

// User reports the current sign-in.
func (c *CLI) User(ctx context.Context) (User, error) {
	var u User
	err := c.jsonCall(ctx, &u, "", "user", "show")
	return u, err
}

// Login signs in with GitHub, in the user's terminal. deviceCode prints a code
// to enter on another device, for machines with no browser.
func (c *CLI) Login(ctx context.Context, deviceCode bool) error {
	args := []string{"user", "login", "-g"}
	if deviceCode {
		args = append(args, "-d")
	}
	return c.Interactive(ctx, c.Path, append(args, "--nologo"))
}

// Tunnel is the part of a tunnel we read.
type Tunnel struct {
	TunnelID          string `json:"tunnelId"`
	HostConnections   int    `json:"hostConnections"`
	ClientConnections int    `json:"clientConnections"`
	Ports             []Port `json:"ports"`
}

// Port is one forwarded port.
type Port struct {
	PortNumber int    `json:"portNumber"`
	Protocol   string `json:"protocol"`
	PortURI    string `json:"portUri"`
}

// Port returns the tunnel's entry for port n.
func (t Tunnel) Port(n int) (Port, bool) {
	for _, p := range t.Ports {
		if p.PortNumber == n {
			return p, true
		}
	}
	return Port{}, false
}

// Show describes a tunnel, or returns ErrNotFound.
func (c *CLI) Show(ctx context.Context, id string) (Tunnel, error) {
	var t Tunnel
	err := c.jsonCall(ctx, &t, "tunnel", "show", id)
	if exitCode(err) == codeNotFound {
		return Tunnel{}, ErrNotFound
	}
	return t, err
}

// ErrExists is a tunnel or port that already exists.
var ErrExists = errors.New("devtunnel: already exists")

// Create makes a persistent tunnel that anonymous clients may connect to.
func (c *CLI) Create(ctx context.Context, id string) (Tunnel, error) {
	var t Tunnel
	err := c.jsonCall(ctx, &t, "tunnel", "create", id, "--allow-anonymous")
	if exitCode(err) == codeExists {
		return Tunnel{}, fmt.Errorf("%w: %v", ErrExists, err)
	}
	return t, err
}

// CreatePort adds a port, forwarded as plain HTTP: the relay speaks HTTP and
// WebSocket on loopback, and the tunnel adds the TLS.
func (c *CLI) CreatePort(ctx context.Context, id string, port int) error {
	err := c.jsonCall(ctx, nil, "", "port", "create", id, "--port-number", fmt.Sprint(port), "--protocol", "http")
	if exitCode(err) == codeExists {
		return fmt.Errorf("%w: %v", ErrExists, err)
	}
	return err
}

// AccessEntry is one access control entry.
type AccessEntry struct {
	Type        string   `json:"type"`
	IsDeny      bool     `json:"isDeny"`
	IsInherited bool     `json:"isInherited"`
	Scopes      []string `json:"scopes"`
}

type accessList struct {
	Entries []AccessEntry `json:"accessControlEntries"`
}

// AllowsAnonymous reports whether anonymous clients may connect to the
// tunnel, which members need: they carry no dev tunnels sign-in.
func (c *CLI) AllowsAnonymous(ctx context.Context, id string) (bool, error) {
	var l accessList
	if err := c.jsonCall(ctx, &l, "", "access", "list", id); err != nil {
		return false, err
	}
	allow := false
	for _, e := range l.Entries {
		if !strings.EqualFold(e.Type, "Anonymous") || !hasScope(e.Scopes, "connect") {
			continue
		}
		if e.IsDeny {
			return false, nil
		}
		allow = true
	}
	return allow, nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// AllowAnonymous lets anonymous clients connect.
func (c *CLI) AllowAnonymous(ctx context.Context, id string) error {
	return c.jsonCall(ctx, nil, "", "access", "create", id, "--anonymous")
}
