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
// `cloudrun setup` and `cloudrun deploy` look at and change. It records every
// call.
type fakeGCloud struct {
	t     *testing.T
	calls [][]string

	apis               map[string]bool
	bucket, sa, repo   bool
	bucketMembers      []string
	projectPolicy      map[string][]string // role -> members
	images             map[string]bool     // pushed by builds
	builds             []string            // the images built, in order
	service            map[string]any      // the last deploy, as describe shows it
	public             bool
	url                string
	grantFailuresAfter int // add-iam-policy-binding says "does not exist" this many times after the account is created
}

// builder is Cloud Build's default account in a project made since mid-2024.
const builder = "123-compute@developer.gserviceaccount.com"

func newFakeGCloud(t *testing.T, url string) *fakeGCloud {
	return &fakeGCloud{t: t, url: url,
		apis:          map[string]bool{"storage.googleapis.com": true, "iam.googleapis.com": true},
		projectPolicy: map[string][]string{"roles/owner": {"user:me@example.com"}},
		images:        map[string]bool{},
	}
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
	if !strings.HasPrefix(cmd, "config ") && flag(args, "--project") != "proj" {
		f.t.Errorf("gcloud %s outside the project", cmd)
	}
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
		return ok(policy(map[string][]string{"roles/storage.objectUser": f.bucketMembers}))
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
		return ok(args[3])
	case has("artifacts repositories create"):
		if args[3] != "san-vpn" || flag(args, "--repository-format") != "docker" || slices.Contains(args, "--mode") {
			f.t.Errorf("image repository made as %s", cmd)
		}
		f.repo = true
		return ok("")
	case has("artifacts docker images describe"):
		if !f.images[args[4]] {
			return nil, []byte("ERROR: (gcloud.artifacts.docker.images.describe) NOT_FOUND: Requested entity was not found."), errExit
		}
		return ok("image_summary: ...")
	case has("builds get-default-service-account"):
		if !f.apis["cloudbuild.googleapis.com"] {
			return nil, []byte("ERROR: (gcloud.builds.get-default-service-account) PERMISSION_DENIED: Cloud Build API has not been used in project proj"), errExit
		}
		return ok("projects/proj/serviceAccounts/" + builder + "\n")
	case has("projects get-iam-policy"):
		return ok(policy(f.projectPolicy))
	case has("projects add-iam-policy-binding"):
		if flag(args, "--condition") != "None" {
			f.t.Errorf("project binding without --condition None fails on a policy with conditions: %s", cmd)
		}
		f.projectPolicy[flag(args, "--role")] = append(f.projectPolicy[flag(args, "--role")], flag(args, "--member"))
		return ok("")
	case has("builds submit"):
		f.build(args)
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
		return ok(policy(map[string][]string{"roles/run.invoker": m}))
	case has("run services add-iam-policy-binding"):
		f.public = true
		return ok("")
	}
	f.t.Errorf("unexpected gcloud %s", cmd)
	return nil, []byte("unexpected"), errExit
}

// build checks what Cloud Build would need, then "pushes" the image: the
// builder may build, the source is a folder, the recipe stamps the version.
func (f *fakeGCloud) build(args []string) {
	if !slices.ContainsFunc(f.projectPolicy[builderRole], func(m string) bool { return m == "serviceAccount:"+builder }) &&
		!slices.Contains(f.projectPolicy["roles/editor"], "serviceAccount:"+builder) {
		f.t.Errorf("build before %s may build", builder)
	}
	if fi, err := os.Stat(args[2]); err != nil || !fi.IsDir() {
		f.t.Errorf("build of %q, not a source folder: %v", args[2], err)
	}
	recipe, err := os.ReadFile(flag(args, "--config"))
	if err != nil || !strings.Contains(string(recipe), "VERSION=${_VERSION}") {
		f.t.Errorf("recipe %q: %v", recipe, err)
	}
	if !slices.Contains(args, "--suppress-logs") {
		f.t.Error("build streams its log, which the build account may not let gcloud read")
	}
	subs := map[string]string{}
	for _, kv := range strings.Split(flag(args, "--substitutions"), ",") {
		k, v, _ := strings.Cut(kv, "=")
		subs[k] = v
	}
	if !strings.HasSuffix(subs["_IMAGE"], ":"+subs["_VERSION"]) {
		f.t.Errorf("substitutions %v: the image is not tagged with its version", subs)
	}
	f.images[subs["_IMAGE"]] = true
	f.builds = append(f.builds, subs["_IMAGE"])
}

// deploy keeps what a deploy sets, in describe's shape. A missing image
// leaves a service that is not ready, as Cloud Run does.
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
	image := flag(args, "--image")
	ready := "True"
	if strings.Contains(image, "/san-vpn/") && !f.images[image] {
		f.t.Errorf("deploy of %s, which was never built", image)
		ready = "False"
	}
	f.service = map[string]any{
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{"autoscaling.knative.dev/maxScale": flag(args, "--max-instances")}},
			"spec": map[string]any{
				"timeoutSeconds":     json.Number(flag(args, "--timeout")),
				"serviceAccountName": flag(args, "--service-account"),
				"containers":         []map[string]any{{"image": image, "env": env}},
			},
		}},
		"status": map[string]any{"conditions": []map[string]string{{"type": "Ready", "status": ready}}},
	}
	f.public = f.public || slices.Contains(args, "--allow-unauthenticated")
}

func flag(args []string, name string) string {
	if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func policy(bindings map[string][]string) string {
	var bs []map[string]any
	for role, members := range bindings {
		bs = append(bs, map[string]any{"role": role, "members": members})
	}
	b, _ := json.Marshal(map[string]any{"bindings": bs})
	return string(b)
}

// mutations are the calls that change something.
func (f *fakeGCloud) mutations() []string {
	var out []string
	for _, c := range f.calls {
		cmd := strings.Join(c, " ")
		for _, verb := range []string{" create", " enable", "run deploy", "add-iam-policy-binding", "builds submit"} {
			if strings.Contains(cmd, verb) {
				out = append(out, cmd)
				break
			}
		}
	}
	return out
}

// cloudRunWorld is a fake project, a fake bucket, and a real relay serving at
// the URL the fake service reports, reading its file from that bucket. The
// options deploy release v0.4.2 from a source folder, counting how often it
// was asked for.
func cloudRunWorld(t *testing.T) (*fakeGCloud, *gcstest.Server, CloudRunOptions, *int) {
	t.Helper()
	retryPause = time.Millisecond
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
	fetched := new(int)
	src := t.TempDir()
	return f, gs, CloudRunOptions{
		Tag:       "v0.4.2",
		Source:    func(context.Context) (string, error) { *fetched++; return src, nil },
		OpenRelay: open,
	}, fetched
}

func lastCall(f *fakeGCloud, prefix ...string) []string {
	var last []string
	for _, c := range f.calls {
		if len(c) >= len(prefix) && slices.Equal(c[:len(prefix)], prefix) {
			last = c
		}
	}
	return last
}

func TestCloudRunSetupThenDeploy(t *testing.T) {
	f, gs, o, fetched := cloudRunWorld(t)
	f.grantFailuresAfter = 2 // IAM has not heard of the new account yet
	var out bytes.Buffer
	o.Out = &out
	ctx := context.Background()

	res, err := CloudRunSetup(ctx, f.gcloud(), o)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if res.Project != "proj" || res.Region != DefaultRegion || res.State != "gs://proj-san-vpn" {
		t.Fatalf("result %+v", res)
	}
	if !f.apis["run.googleapis.com"] || !f.apis["artifactregistry.googleapis.com"] || !f.apis["cloudbuild.googleapis.com"] || !f.bucket || !f.sa || !f.repo {
		t.Fatalf("not everything was set up: %+v", f)
	}
	if !slices.Contains(f.projectPolicy[builderRole], "serviceAccount:"+builder) {
		t.Fatalf("Cloud Build's account was not allowed to build: %v", f.projectPolicy)
	}
	if f.service != nil || len(f.builds) > 0 || *fetched > 0 {
		t.Fatal("setup built or deployed")
	}
	var st relay.State
	if err := json.Unmarshal(gs.Object("proj-san-vpn", "relay.json"), &st); err != nil {
		t.Fatal(err)
	}
	if st.PrivateKey.IsZero() || st.CloudRun == nil || *st.CloudRun != (relay.CloudRun{Project: "proj", Region: DefaultRegion, Service: DefaultService}) {
		t.Fatalf("relay file after setup: %+v", st)
	}

	// A rerun of setup changes nothing and keeps the key.
	f.calls = nil
	if _, err := CloudRunSetup(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) > 0 {
		t.Fatalf("a rerun of setup changed things:\n%s", strings.Join(m, "\n"))
	}

	out.Reset()
	res, err = CloudRunDeploy(ctx, f.gcloud(), o)
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, out.String())
	}
	if want := "asia-southeast2-docker.pkg.dev/proj/san-vpn/san_vpn:v0.4.2"; res.Image != want || !slices.Equal(f.builds, []string{want}) {
		t.Fatalf("image %s, builds %v, want %s built once", res.Image, f.builds, want)
	}
	deploy := lastCall(f, "run", "deploy")
	for _, want := range [][2]string{
		{"--image", res.Image}, {"--max-instances", "1"}, {"--timeout", "3600"}, {"--concurrency", "1000"},
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
	var after relay.State
	_ = json.Unmarshal(gs.Object("proj-san-vpn", "relay.json"), &after)
	if after.PrivateKey != st.PrivateKey || after.URL != res.URL || res.URL == "" {
		t.Fatalf("relay file after deploy: %+v (result %+v)", after, res)
	}
	if !strings.Contains(out.String(), "WebSocket included") {
		t.Fatalf("no end-to-end check in:\n%s", out.String())
	}

	// Deploying the same release again builds nothing, fetches no source,
	// and changes nothing.
	f.calls = nil
	if _, err := CloudRunDeploy(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) > 0 || *fetched != 1 {
		t.Fatalf("a rerun of deploy fetched the source %d times and ran:\n%s", *fetched, strings.Join(m, "\n"))
	}

	// Something taken away is put back, and only that.
	f.public = false
	f.calls = nil
	if _, err := CloudRunDeploy(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 1 || !strings.Contains(m[0], "run services add-iam-policy-binding") {
		t.Fatalf("repairing public access ran:\n%s", strings.Join(m, "\n"))
	}

	// A service whose last deploy did not come up is deployed again, even
	// though its settings match.
	f.service["status"] = map[string]any{"conditions": []map[string]string{{"type": "Ready", "status": "False"}}}
	f.calls = nil
	if _, err := CloudRunDeploy(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 1 || !strings.HasPrefix(m[0], "run deploy") {
		t.Fatalf("a service that is not ready got:\n%s", strings.Join(m, "\n"))
	}
}

// Deploy needs the relay setup made.
func TestCloudRunDeployBeforeSetup(t *testing.T) {
	f, _, o, _ := cloudRunWorld(t)
	if _, err := CloudRunDeploy(context.Background(), f.gcloud(), o); err == nil || !strings.Contains(err.Error(), "san_vpn cloudrun setup") {
		t.Fatalf("got %v, want a pointer to cloudrun setup", err)
	}
	if m := f.mutations(); len(m) > 0 {
		t.Fatalf("a refused deploy ran:\n%s", strings.Join(m, "\n"))
	}
}

// Dry runs look at everything and change nothing: not the project, not the
// bucket, and they fetch no source.
func TestCloudRunDryRuns(t *testing.T) {
	f, gs, o, fetched := cloudRunWorld(t)
	var out bytes.Buffer
	o.Out, o.DryRun = &out, true
	if _, err := CloudRunSetup(context.Background(), f.gcloud(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if m := f.mutations(); len(m) > 0 {
		t.Fatalf("a dry run changed things:\n%s", strings.Join(m, "\n"))
	}
	if gs.Writes.Load() > 0 {
		t.Fatal("a dry run wrote to the bucket")
	}
	for _, want := range []string{"would run: gcloud services enable", "cloudbuild.googleapis.com", "would run: gcloud storage buckets create",
		"would run: gcloud artifacts repositories create san-vpn", "would check that Cloud Build's account may build"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("setup dry run output lacks %q:\n%s", want, out.String())
		}
	}

	o.DryRun = false
	o.Out = &bytes.Buffer{}
	if _, err := CloudRunSetup(context.Background(), f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	out.Reset()
	o.Out, o.DryRun = &out, true
	if _, err := CloudRunDeploy(context.Background(), f.gcloud(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if m := f.mutations(); len(m) > 0 || *fetched > 0 {
		t.Fatalf("a deploy dry run fetched the source %d times and ran:\n%s", *fetched, strings.Join(m, "\n"))
	}
	for _, want := range []string{"would run: gcloud builds submit", "_VERSION=v0.4.2", "would run: gcloud run deploy", "SAN_VPN_STATE=gs://proj-san-vpn"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("deploy dry run output lacks %q:\n%s", want, out.String())
		}
	}
}

// A tree of one's own is built on every deploy, each under its own tag, and
// --image skips the build altogether.
func TestCloudRunDeployDevAndImage(t *testing.T) {
	f, _, o, fetched := cloudRunWorld(t)
	ctx := context.Background()
	if _, err := CloudRunSetup(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"dev-20261009-120000", "dev-20261009-120500"} {
		o.Tag = tag
		res, err := CloudRunDeploy(ctx, f.gcloud(), o)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(res.Image, ":"+tag) || flag(lastCall(f, "run", "deploy"), "--image") != res.Image {
			t.Fatalf("deployed %v for %s", res.Image, tag)
		}
	}
	if len(f.builds) != 2 || *fetched != 2 {
		t.Fatalf("builds %v, source fetched %d times; want 2 of each", f.builds, *fetched)
	}

	o.Image = "asia-southeast2-docker.pkg.dev/proj/mine/san_vpn:test"
	res, err := CloudRunDeploy(ctx, f.gcloud(), o)
	if err != nil || res.Image != o.Image || len(f.builds) != 2 {
		t.Fatalf("with an image: %+v, %v (builds %v)", res, err, f.builds)
	}
}

// Deploy uses the region and service setup recorded, without being told
// again.
func TestCloudRunDeployUsesWhatSetupRecorded(t *testing.T) {
	f, _, o, _ := cloudRunWorld(t)
	ctx := context.Background()
	o.Region, o.Service = "us-central1", "relay"
	if _, err := CloudRunSetup(ctx, f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	o.Region, o.Service = "", ""
	res, err := CloudRunDeploy(ctx, f.gcloud(), o)
	if err != nil {
		t.Fatal(err)
	}
	deploy := lastCall(f, "run", "deploy")
	if res.Region != "us-central1" || deploy[2] != "relay" || flag(deploy, "--region") != "us-central1" || !strings.HasPrefix(res.Image, "us-central1-docker.pkg.dev/") {
		t.Fatalf("deploy went to %v (result %+v)", deploy, res)
	}
}

// A build account that is already an editor is left as it is.
func TestCloudRunSetupLeavesAnEditorBuilderAlone(t *testing.T) {
	f, _, o, _ := cloudRunWorld(t)
	f.apis["cloudbuild.googleapis.com"] = true
	f.projectPolicy["roles/editor"] = []string{"serviceAccount:" + builder}
	if _, err := CloudRunSetup(context.Background(), f.gcloud(), o); err != nil {
		t.Fatal(err)
	}
	if lastCall(f, "projects", "add-iam-policy-binding") != nil {
		t.Fatal("granted a role to a builder that is already an editor")
	}
}
