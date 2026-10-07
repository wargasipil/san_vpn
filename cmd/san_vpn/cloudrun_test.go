package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
)

// The admin commands work the same on a relay kept in Cloud Storage, from
// any machine with access to the bucket: here an emulator, which
// STORAGE_EMULATOR_HOST points them at as it would gcloud's own tools.
func TestAdminFlowOnCloudStorage(t *testing.T) {
	srv := gcstest.New()
	defer srv.Close()
	t.Setenv("STORAGE_EMULATOR_HOST", srv.URL)
	const bucket = "gs://team-relay/san_vpn"

	if _, err := run(t, "--state", bucket, "relay", "list"); err == nil || !strings.Contains(err.Error(), "relay init") {
		t.Fatalf("list before init: %v, want a pointer to relay init", err)
	}
	if _, err := run(t, "--state", bucket, "relay", "invite", "home"); err == nil || !strings.Contains(err.Error(), "relay init") {
		t.Fatalf("invite before init: %v, want a pointer to relay init", err)
	}
	if srv.Object("team-relay", "san_vpn/relay.json") != nil {
		t.Fatal("a refused invite created the relay object")
	}

	out := mustRun(t, "--state", bucket, "relay", "init", "--url", "https://relay-abc-as.a.run.app")
	if !strings.Contains(out, "created relay gs://team-relay/san_vpn/relay.json") {
		t.Fatalf("relay init said:\n%s", out)
	}
	if again := mustRun(t, "--state", bucket, "relay", "init"); keyLine(out) != keyLine(again) {
		t.Fatalf("second init changed the key:\n%s\nvs\n%s", out, again)
	}

	if out := mustRun(t, "--state", bucket, "relay", "invite", "home"); !inviteRE.MatchString(out) {
		t.Fatalf("no invite in:\n%s", out)
	}
	var list struct {
		URL     string `json:"url"`
		Invites []struct {
			Name string `json:"name"`
		} `json:"invites"`
	}
	if err := json.Unmarshal([]byte(mustRun(t, "--state", bucket, "relay", "list", "--json")), &list); err != nil {
		t.Fatal(err)
	}
	if list.URL != "https://relay-abc-as.a.run.app" || len(list.Invites) != 1 || list.Invites[0].Name != "home" {
		t.Fatalf("list: %+v", list)
	}
	mustRun(t, "--state", bucket, "relay", "remove", "home")
	if out := mustRun(t, "--state", bucket, "relay", "list"); strings.Contains(out, "home") {
		t.Fatalf("home still listed after remove:\n%s", out)
	}

	// A member's key stays on its own disk, and setup init fronts a relay on
	// this machine: neither takes a bucket.
	if _, err := run(t, "--state", bucket, "status"); err == nil || !strings.Contains(err.Error(), "own disk") {
		t.Fatalf("status with a gs:// state: %v", err)
	}
	if _, err := run(t, "--state", bucket, "setup", "init", "--no-install"); err == nil || !strings.Contains(err.Error(), "not one kept in gs://") {
		t.Fatalf("setup init with a gs:// state: %v", err)
	}
}
