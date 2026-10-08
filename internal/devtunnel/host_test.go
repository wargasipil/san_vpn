package devtunnel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The test binary doubles as a fake devtunnel: run with SAN_VPN_FAKE_DEVTUNNEL
// set, it prints a line like `devtunnel host` does and exits after the given
// time, as a host whose connection dropped would.
func TestMain(m *testing.M) {
	if d := os.Getenv("SAN_VPN_FAKE_DEVTUNNEL"); d != "" {
		fmt.Println("Hosting port 8443 at https://fake-8443.asse.devtunnels.ms/ args=" + strings.Join(os.Args[1:], " "))
		dur, _ := time.ParseDuration(d)
		time.Sleep(dur)
		os.Exit(3)
	}
	os.Exit(m.Run())
}

type lines struct {
	mu  sync.Mutex
	got []string
}

func (l *lines) Enabled(context.Context, slog.Level) bool { return true }
func (l *lines) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, r.Message)
	return nil
}
func (l *lines) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *lines) WithGroup(string) slog.Handler      { return l }

func (l *lines) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.got {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// signedIn answers `user show` with the status in *status.
func signedIn(status *atomic.Value) Runner {
	return func(context.Context, string, []string) ([]byte, []byte, int, error) {
		return []byte(`{"status": "` + status.Load().(string) + `", "provider": "github", "username": "vaziria"}`), nil, 0, nil
	}
}

// A host that exits is started again, its output is logged, and cancelling
// stops it for good.
func TestHostRestartsAndStops(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAN_VPN_FAKE_DEVTUNNEL", "50ms")
	var status atomic.Value
	status.Store("Logged in")
	cli := &CLI{Path: exe, Run: signedIn(&status)}
	l := &lines{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); cli.Host(ctx, "san-vpn-test01.asse", slog.New(l)) }()

	deadline := time.Now().Add(20 * time.Second)
	for l.count("exited; restarting") < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("no restart; log: %v", l.got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if l.count("args=host san-vpn-test01.asse --nologo") < 1 {
		t.Fatalf("host was not run as `devtunnel host <id> --nologo`; log: %v", l.got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Host did not return after cancel")
	}
}

// With the sign-in expired, the host is not restarted over and over: Host
// says so once, waits, and hosts again as soon as someone signs in.
func TestHostWaitsForSignIn(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAN_VPN_FAKE_DEVTUNNEL", "10ms")
	old := signInPoll
	signInPoll = 20 * time.Millisecond
	var status atomic.Value
	status.Store("Login token expired")
	cli := &CLI{Path: exe, Run: signedIn(&status)}
	l := &lines{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); cli.Host(ctx, "san-vpn-test01.asse", slog.New(l)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Host did not return after cancel")
		}
		signInPoll = old
	})

	waitFor := func(sub string, n int) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for l.count(sub) < n {
			if time.Now().After(deadline) {
				t.Fatalf("no %q; log: %v", sub, l.got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("sign-in is no longer valid", 1)
	time.Sleep(200 * time.Millisecond) // ten polls
	if n := l.count("sign-in is no longer valid"); n != 1 {
		t.Fatalf("said %d times that the sign-in expired; log: %v", n, l.got)
	}
	if n := l.count("args=host"); n != 1 {
		t.Fatalf("host started %d times while signed out; log: %v", n, l.got)
	}
	if n := l.count("exited; restarting"); n != 0 {
		t.Fatalf("restarted while signed out; log: %v", l.got)
	}

	status.Store("Logged in")
	waitFor("args=host", 2)
	if l.count("signed in to dev tunnels again") != 1 {
		t.Fatalf("no word that hosting resumed; log: %v", l.got)
	}
}

func TestVersionParse(t *testing.T) {
	cli := &CLI{Path: "devtunnel", Run: func(context.Context, string, []string) ([]byte, []byte, int, error) {
		return []byte("Welcome to dev tunnels!\nTunnel CLI version: 1.0.1516+9b2c1d0e\n"), nil, 0, nil
	}}
	v, err := cli.Version(context.Background())
	if err != nil || v != "1.0.1516" {
		t.Fatalf("%q, %v", v, err)
	}
}

// Exit code 2 is "not found" and 1 is "already exists"; anything else is an
// error that carries what the CLI said.
func TestExitCodes(t *testing.T) {
	code := 0
	cli := &CLI{Path: "devtunnel", Run: func(context.Context, string, []string) ([]byte, []byte, int, error) {
		return nil, []byte("the service said no"), code, nil
	}}
	ctx := context.Background()

	code = 2
	if _, err := cli.Show(ctx, "x"); err != ErrNotFound {
		t.Fatalf("show, exit 2: %v", err)
	}
	code = 1
	if _, err := cli.Create(ctx, "x"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create, exit 1: %v", err)
	}
	code = 7
	if _, err := cli.Show(ctx, "x"); err == nil || !strings.Contains(err.Error(), "the service said no") {
		t.Fatalf("show, exit 7: %v", err)
	}
}
