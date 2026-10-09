package setup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The test binary doubles as the program behind a fake gcloud.cmd: run with
// SAN_VPN_FAKE_GCLOUD set, it prints the arguments it received as JSON.
func TestMain(m *testing.M) {
	if os.Getenv("SAN_VPN_FAKE_GCLOUD") != "" {
		_ = json.NewEncoder(os.Stdout).Encode(os.Args[1:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeGCloudCmd writes a gcloud.cmd under a folder with a space, as in
// C:\Users\ASUS TUF\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin. Like
// the real one, it turns on delayed expansion and hands %* to a program.
func fakeGCloudCmd(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ASUS TUF", "Cloud SDK", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gcloud.cmd")
	script := "@echo off\r\nSETLOCAL EnableDelayedExpansion\r\n\"" + exe + "\" %*\r\n"
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAN_VPN_FAKE_GCLOUD", "1")
	return path
}

// gcloud.cmd under a path with a space, given a quoted argument, used to fail
// with "'C:\Users\ASUS' is not recognized": cmd.exe dropped the quotes around
// the path. Every argument must arrive as it was given.
func TestGCloudCmdUnderPathWithSpace(t *testing.T) {
	path := fakeGCloudCmd(t)
	args := []string{
		"iam", "service-accounts", "create", "san-vpn-relay", "--display-name", "san_vpn relay",
		"--format", "value(config.name)",
		"--env-vars-file", `C:\Users\ASUS TUF\AppData\Local\Temp\san_vpn-env.yaml`,
		"--labels", "a=b,c=d", `C:\trailing slash\`, "", "x&y|z<w>v^u",
		"--quiet",
	}
	out, errb, err := runGCloud(context.Background(), path, args)
	if err != nil {
		t.Fatalf("run: %v\nstdout: %s\nstderr: %s", err, out, errb)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if !slices.Equal(got, args) {
		t.Errorf("gcloud.cmd passed on\n%q\nwant\n%q", got, args)
	}
}

// What cmd.exe would expand is refused before anything runs.
func TestGCloudCmdRefusesExpansion(t *testing.T) {
	path := fakeGCloudCmd(t)
	for _, a := range []string{"%PATH%", "hi!", `say "x"`} {
		_, _, err := runGCloud(context.Background(), path, []string{"config", "set", "x", a})
		if err == nil || !strings.Contains(err.Error(), "cmd.exe cannot pass") {
			t.Errorf("argument %q: err = %v, want a refusal", a, err)
		}
	}
}
