package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wargasipil/san_vpn/internal/gcs"
	"github.com/wargasipil/san_vpn/internal/gcs/gcstest"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// fakeGCloud is a Google Cloud project as gcloud shows it: just the parts
// `setup cloudrun` looks at and changes. It records every call.
type fakeGCloud struct {
	t     *testing.T
	calls [][]string

	apis               map[string]bool
	bucket, sa, repo   bool
	bucketMembers      []string
	service            map[string]any // the last deploy, as describe shows it
	public             bool
	url                string
	grantFailuresAfter int // add-iam-policy-binding says "does not exist" this many times after the account is created
}

func newFakeGCloud(t *testing.T, url string) *fakeGCloud {
	return &fakeGCloud{t: t, url: url, apis: map[string]bool{"storage.googleapis.com": true, "iam.googleapis.com": true}}
}

func (f *fakeGCloud) gcloud() *GCloud { return &GCloud{Path: "gcloud", Run: f.run} }

var errExit = errors.New("exit status 1")

func (f *fakeGCloud) run(_ context.Context, _ string, args []string) ([]byte, []byte, error) {
	if args[len(args)-1] != "--quiet" {
		f.t.Errorf("gcloud %v without --quiet could prompt", args)
	}
	args = args[:len(args)-1]
	f.calls = append(f.calls, args)
	cmd := strings.Join(args, " ")
	ok := func(s string) ([]byte, []byte, error) { return []byte(s), nil, nil }
	missing := func(what string) ([]byte, []byte, error) {
		return nil, []byte("ERROR: (gcloud) " + what + " not found: 404"), errExit
	}
	has := func(prefix string) bool { return strings.HasPrefix(cmd, prefix) }
	switch {
	case cmd == "config get-value account":
		return ok("me@example.com\n")
	case cmd == "config get-value project":
		return ok("proj\n")
	case has("services list --enabled"):
		var on []string
		for api := range f.apis {
			on = append(on, api)
		}
		return ok(strings.Join(on, "\n"))
	case has("services enable"):
		for _, a := range args[2:] {
			if strings.HasSuffix(a, ".googleapis.com") {
				f.apis[a] = true
			}
		}
		return ok("")
	case has("storage buckets describe"):
		if !f.bucket {
			return missing("bucket")
		}
		return ok("proj-san-vpn")
	case has("storage buckets create"):
		f.bucket = true
		return ok("")
	case has("iam service-accounts describe"):
		if !f.sa {
			return missing("service account")
		}
		return ok(args[3])
	case has("iam service-accounts create"):
		f.sa = true
		return ok("")
	case has("storage buckets get-iam-policy"):
		return ok(policy("roles/storage.objectUser", f.bucketMembers))
	case has("storage buckets add-iam-policy-binding"):
		if f.grantFailuresAfter > 0 {
			f.grantFailuresAfter--
			return nil, []byte("ERROR: Service account san-vpn-relay@proj.iam.gserviceaccount.com does not exist."), errExit
		}
		f.bucketMembers = append(f.bucketMembers, flag(args, "--member"))
		return ok("")
	case has("artifacts repositories describe"):
		if !f.repo {
			return missing("repository")
		}
		return ok("ghcr")
	case has("artifacts repositories create"):
		f.repo = true
		return ok("")
	case has("run services describe") && flag(args, "--format") == "json":
		if f.service == nil {
			return nil, []byte("ERROR: (gcloud.run.services.describe) Cannot find service [san-vpn-relay]"), errExit
		}
		b, _ := json.Marshal(f.service)
		return ok(string(b))
	case has("run services describe"):
		return ok(f.url + "\n")
	case has("run deploy"):
		f.deploy(args)
		return ok("")
	case has("run services get-iam-policy"):
		var m []string
		if f.public {
			m = []string{"allUsers"}
		}
		return ok(policy("roles/run.invoker", m))
	case has("run services add-iam-policy-binding"):
		f.public = true
		return ok("")
	}
	f.t.Errorf("unexpected gcloud %s", cmd)
	return nil, []byte("unexpected"), errExit
}

// deploy keeps what a deploy sets, in describe's shape.
func (f *fakeGCloud) deploy(args []string) {
	env := []map[string]string{}
	b, err := os.ReadFile(flag(args, "--env-vars-file"))
	if err != nil {
		f.t.Errorf("deploy without a readable env file: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(line, ": ")
		env = append(env, map[string]string{"name": k, "value": strings.Trim(v, `"`)})
	}
	f.service = map[string]any{"spec": map[string]any{"template": map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{"autoscaling.knative.dev/maxScale": flag(args, "--max-instances")}},
		"spec": map[string]any{
			"timeoutSeconds":     json.Number(flag(args, "--timeout")),
			"serviceAccountName": flag(args, "--service-account"),
			"containers":         []map[string]any{{"image": flag(args, "--image"), "env": env}},
		},
	}}}
	f.public = f.public || slices.Contains(args, "--allow-unauthenticated")
}

func flag(args []string, name string) string {
	if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func policy(role string, members []string) string {
	b, _ := json.Marshal(map[string]any{"bindings": []map[string]any{{"role": role, "members": members}}})
	return string(b)
}

// mutations are the calls that change something.
func (f *fakeGCloud) mutations() []string {
	var out []string
	for _, c := range f.calls {
		cmd := strings.Join(c, " ")
		for _, verb := range []string{" create", " enable", "run deploy", "add-iam-policy-binding"} {
			if strings.Contains(cmd, verb) {
				out = append(out, cmd)
				break
			}
		}
	}
	return out
}

// cloudRunWorld is a fake project, a fake bucket, and a real relay serving at
// the URL the fake service reports, reading its file from that bucket.
func cloudRunWorld(t *testing.T) (*fakeGCloud, *gcstest.Server, CloudRunOptions) {
	t.Helper()
	gs := gcstest.New()
	t.Cleanup(gs.Close)
	open := func(loc string) (state.Store, error) {
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(loc, "gs://"), "/")
		return &state.GCS{Client: &gcs.Client{HTTP: gs.Client(), Base: gs.URL}, Bucket: bucket, Object: strings.TrimPrefix(prefix+"/"+state.RelayFile, "/")}, nil
	}
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, _ := open("gs://proj-san-vpn")
		srv, err := relay.New(r.Context(), store, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(svc.Close)
	f := newFakeGCloud(t, svc.URL)
	return f, gs, CloudRunOptions{Version: "v0.3.0", OpenRelay: open}
}

func TestCloudRunFromScratchThenRerun(t *testing.T) {
	retryPause = time.Millisecond
	f, gs, o := cloudRunWorld(t)
	f.grantFailuresAfter = 2 // IAM has not heard of the new account yet
	var out bytes.Buffer
	o.Out = &out

	res, err := InitCloudRun(context.Background(), f.gcloud(), o)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if res.Project != "proj" || res.Region != DefaultRegion || res.State != "gs://proj-san-vpn" || res.URL == "" {
		t.Fatalf("result %+v", res)
	}
	if want := "asia-southeast2-docker.pkg.dev/proj/ghcr/wargasipil/san_vpn:v0.3.0"; res.Image != want {
		t.Fatalf("image %s, want %s", res.Image, want)
	}
	if !f.apis["run.googleapis.com"] || !f.apis["artifactregistry.googleapis.com"] || !f.bucket || !f.sa || !f.repo || !f.public {
		t.Fatalf("not everything was set up: %+v", f)
	}

	var deploy []string
	for _, c := range f.calls {
		if len(c) > 1 && c[0] == "run" && c[1] == "deploy" {
			deploy = c
		}
	}
	for _, want := range [][2]string{
		{"--max-instances", "1"}, {"--timeout", "3600"}, {"--concurrency", "1000"},
		{"--service-account", "san-vpn-relay@proj.iam.gserviceaccount.com"}, {"--region", "asia-southeast2"},
	} {
		if flag(deploy, want[0]) != want[1] {
			t.Errorf("deploy %s = %q, want %q", want[0], flag(deploy, want[0]), want[1])
		}
	}
	for _, want := range []string{"--allow-unauthenticated", "--no-cpu-throttling"} {
		if !slices.Contains(deploy, want) {
			t.Errorf("deploy without %s", want)
		}
	}
	env := fmt.Sprint(f.service)
	if !strings.Contains(env, "SAN_VPN_STATE value:gs://proj-san-vpn") || !strings.Contains(env, "SAN_VPN_SESSION_LIMIT value:1h0m0s") {
		t.Errorf("deployed env: %s", env)
	}

	var st relay.State
	if err := json.Unmarshal(gs.Object("proj-san-vpn", "relay.json"), &st); err != nil {
		t.Fatal(err)
	}
	if st.PrivateKey.IsZero() || st.URL != res.URL || st.CloudRun == nil || st.CloudRun.Service != DefaultService {
		t.Fatalf("relay file: %+v", st)
	}
	if !strings.Contains(out.String(), "WebSocket included") {
		t.Fatalf("no end-to-end check in:\n%s", out.String())
	}

	// A rerun on the working setup changes nothing and keeps the key.
	f.calls = nil
	out.Reset()
	if _, err := InitCloudRun(context.Background(), f.gcloud(), o); err != nil {
		t.Fatalf("rerun: %v\n%s", err, out.String())
	}
	if m := f.mutations(); len(m) > 0 {
		t.Fatalf("a rerun changed things:\n%s", strings.Join(m, "\n"))
	}
	var again relay.State
	_ = json.Unmarshal(gs.Object("proj-san-vpn", "relay.json"), &again)
	if again.PrivateKey != st.PrivateKey {
		t.Fatal("a rerun replaced the relay key")
	}

	// Something taken away is put back, and only that.
	f.public = false
	f.calls = nil
	if _, err := InitCloudRun(context.Background(), f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 1 || !strings.Contains(m[0], "run services add-iam-policy-binding") {
		t.Fatalf("repairing public access ran:\n%s", strings.Join(m, "\n"))
	}
}

// A dry run looks at everything and changes nothing: not the project, not
// the bucket.
func TestCloudRunDryRun(t *testing.T) {
	f, gs, o := cloudRunWorld(t)
	var out bytes.Buffer
	o.Out, o.DryRun = &out, true
	if _, err := InitCloudRun(context.Background(), f.gcloud(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if m := f.mutations(); len(m) > 0 {
		t.Fatalf("a dry run changed things:\n%s", strings.Join(m, "\n"))
	}
	if gs.Writes.Load() > 0 {
		t.Fatal("a dry run wrote to the bucket")
	}
	for _, want := range []string{"would run: gcloud services enable", "would run: gcloud storage buckets create", "would run: gcloud run deploy", "SAN_VPN_STATE=gs://proj-san-vpn"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out.String())
		}
	}
}

// A local build has no published image to run.
func TestCloudRunNeedsAReleaseOrAnImage(t *testing.T) {
	f, _, o := cloudRunWorld(t)
	o.Version = "2026.10.07-2300"
	if _, err := InitCloudRun(context.Background(), f.gcloud(), o); err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("got %v, want a pointer to --image", err)
	}
	o.Image = "asia-southeast2-docker.pkg.dev/proj/mine/san_vpn:test"
	res, err := InitCloudRun(context.Background(), f.gcloud(), o)
	if err != nil || res.Image != o.Image || f.repo {
		t.Fatalf("with --image: %+v, %v (repo created: %v)", res, err, f.repo)
	}
}
