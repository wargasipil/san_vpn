package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wargasipil/san_vpn/internal/node"
	"github.com/wargasipil/san_vpn/internal/relay"
	"github.com/wargasipil/san_vpn/internal/state"
)

// Cloud Run defaults.
const (
	// DefaultRegion is Jakarta, nearest the members this was built for.
	DefaultRegion  = "asia-southeast2"
	DefaultService = "san-vpn-relay"
	// DefaultRequestTimeout is the longest Cloud Run allows. Each member's
	// connection is one request, so it is also the relay's session limit.
	DefaultRequestTimeout = time.Hour

	// The image is built from source by Cloud Build into an Artifact Registry
	// repository of the project itself, so Cloud Run pulls nothing from
	// outside the project.
	imageRepo = "san-vpn"
	imageName = "san_vpn"

	serviceAccountID = "san-vpn-relay"

	// builderRole lets Cloud Build's account build: read the uploaded
	// source, write logs, push to Artifact Registry.
	builderRole = "roles/cloudbuild.builds.builder"
)

// CloudRunOptions configure CloudRunSetup and CloudRunDeploy.
type CloudRunOptions struct {
	// Project, Region and Service: empty uses what setup recorded in the
	// relay's file, else gcloud's configured project and the defaults.
	Project string
	Region  string
	Service string
	// State is where the relay's file goes, gs://<bucket>[/<folder>];
	// empty is gs://<project>-san-vpn.
	State string

	// Image (deploy) runs this image as it is, with no build.
	Image string
	// Tag (deploy) names the image built from source and is the version it
	// reports: a release's tag, or a dev-<time> stamp for a tree of one's own.
	Tag string
	// Source (deploy) returns the directory of the source tree to build. It
	// is called only when a build is needed.
	Source func(ctx context.Context) (string, error)
	// Timeout (deploy) is the service's request timeout, and so the session
	// limit.
	Timeout time.Duration

	// DryRun looks at everything but changes nothing, and prints the gcloud
	// commands it would run.
	DryRun bool
	Out    io.Writer
	// OpenRelay opens the relay's file at a gs:// location; nil is state.Open.
	OpenRelay  func(location string) (state.Store, error)
	HTTPClient *http.Client
}

// CloudRunResult is what CloudRunSetup or CloudRunDeploy set up.
type CloudRunResult struct {
	Project, Region, Service string
	State                    string // gs://...
	Image                    string // deploy only
	URL                      string // deploy only; empty after a dry run that would deploy
}

// retryPause is the wait while a new service account becomes usable in IAM
// policies, which takes Google a few seconds.
var retryPause = 5 * time.Second

var releaseTagRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// cloudRun is one setup or deploy against a project and the relay's file.
type cloudRun struct {
	ctx    context.Context
	g      *GCloud
	o      CloudRunOptions
	p      printer
	r      *CloudRunResult
	bucket string
	store  state.Store
	st     relay.State
	found  bool // the relay's file exists
}

// begin finds the sign-in, the relay's file and, from the options, the file
// and gcloud's configuration, the project, region and service.
func begin(ctx context.Context, g *GCloud, o CloudRunOptions) (*cloudRun, error) {
	if o.OpenRelay == nil {
		o.OpenRelay = func(loc string) (state.Store, error) { return state.Open(loc, state.RelayFile) }
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	c := &cloudRun{ctx: ctx, g: g, o: o, p: printer{o.Out}, r: &CloudRunResult{Project: o.Project, State: o.State}}

	account, err := g.call(ctx, "config", "get-value", "account")
	if err != nil {
		return nil, err
	}
	if account == "" {
		return nil, errors.New("gcloud is not signed in; run `gcloud auth login`")
	}
	configured := func() error {
		if c.r.Project, err = g.call(ctx, "config", "get-value", "project"); err != nil {
			return err
		}
		if c.r.Project == "" {
			return errors.New("no Google Cloud project; pass --project, or set one with `gcloud config set project <id>`")
		}
		return nil
	}
	if c.r.State == "" {
		if c.r.Project == "" {
			if err := configured(); err != nil {
				return nil, err
			}
		}
		c.r.State = "gs://" + c.r.Project + "-san-vpn"
	}
	bucket, _, _ := strings.Cut(strings.TrimPrefix(c.r.State, "gs://"), "/")
	if !strings.HasPrefix(c.r.State, "gs://") || bucket == "" {
		return nil, fmt.Errorf("state %q: want gs://<bucket>[/<folder>]", c.r.State)
	}
	c.bucket = bucket
	if c.store, err = o.OpenRelay(c.r.State); err != nil {
		return nil, err
	}
	// A missing bucket reads as a missing file, which setup is about to make.
	switch _, err := c.store.Read(ctx, &c.st); {
	case err == nil:
		c.found = true
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if rec := c.st.CloudRun; rec != nil {
		c.r.Project = or(c.r.Project, rec.Project)
		c.r.Region = or(o.Region, rec.Region)
		c.r.Service = or(o.Service, rec.Service)
	}
	if c.r.Project == "" {
		if err := configured(); err != nil {
			return nil, err
		}
	}
	c.r.Region = or(or(c.r.Region, o.Region), DefaultRegion)
	c.r.Service = or(or(c.r.Service, o.Service), DefaultService)
	c.p.line("ok", "gcloud signed in as %s; project %s, region %s", account, c.r.Project, c.r.Region)
	return c, nil
}

// get runs a gcloud command that only looks, in the project.
func (c *cloudRun) get(args ...string) (string, error) {
	return c.g.call(c.ctx, append(args, "--project", c.r.Project)...)
}

// act runs a gcloud command that changes something, in the project; a dry
// run prints it instead.
func (c *cloudRun) act(args ...string) error {
	args = append(args, "--project", c.r.Project)
	if c.o.DryRun {
		c.p.line("..", "would run: gcloud %s", strings.Join(args, " "))
		return nil
	}
	_, err := c.g.call(c.ctx, args...)
	return err
}

func (c *cloudRun) serviceAccount() string {
	return serviceAccountID + "@" + c.r.Project + ".iam.gserviceaccount.com"
}

// CloudRunSetup readies a project for the relay; CloudRunDeploy then builds
// and runs it. Like Init, each step looks before it acts: a rerun on a
// working setup changes nothing, and a rerun after something changed repairs
// that step. It records the project, region and service in the relay's file,
// where deploy finds them.
func CloudRunSetup(ctx context.Context, g *GCloud, o CloudRunOptions) (*CloudRunResult, error) {
	c, err := begin(ctx, g, o)
	if err != nil {
		return nil, err
	}
	r, p, o := c.r, c.p, c.o

	// APIs. Cloud Storage and IAM are on in every project; the others
	// usually are not.
	enabled, err := c.get("services", "list", "--enabled", "--format", "value(config.name)")
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, api := range []string{"run.googleapis.com", "artifactregistry.googleapis.com", "cloudbuild.googleapis.com", "iam.googleapis.com", "storage.googleapis.com"} {
		if !slices.Contains(strings.Fields(enabled), api) {
			missing = append(missing, api)
		}
	}
	if len(missing) > 0 {
		if err := c.act(append([]string{"services", "enable"}, missing...)...); err != nil {
			return nil, err
		}
	}
	p.line("ok", "APIs: Cloud Run, Artifact Registry, Cloud Build, IAM, Cloud Storage%s", when(len(missing) > 0, " (enabled "+strings.Join(missing, ", ")+")"))

	// The bucket: private, in the service's region.
	bucketMissing := false
	_, err = c.get("storage", "buckets", "describe", "gs://"+c.bucket, "--format", "value(name)")
	switch {
	case err == nil:
		p.line("ok", "bucket gs://%s", c.bucket)
	case IsNotFound(err):
		bucketMissing = true
		if err := c.act("storage", "buckets", "create", "gs://"+c.bucket, "--location", r.Region,
			"--uniform-bucket-level-access", "--public-access-prevention"); err != nil {
			return nil, err
		}
		p.line("ok", "bucket gs://%s (created; private, in %s)", c.bucket, r.Region)
	default:
		return nil, err
	}

	// The service's identity, which may read and write the bucket and
	// nothing else.
	sa := c.serviceAccount()
	saMissing := false
	_, err = c.get("iam", "service-accounts", "describe", sa, "--format", "value(email)")
	switch {
	case err == nil:
		p.line("ok", "service account %s", sa)
	case IsNotFound(err):
		saMissing = true
		if err := c.act("iam", "service-accounts", "create", serviceAccountID, "--display-name", "san_vpn relay"); err != nil {
			return nil, err
		}
		p.line("ok", "service account %s (created)", sa)
	default:
		return nil, err
	}

	member := "serviceAccount:" + sa
	const objectRole = "roles/storage.objectUser"
	granted := false
	if !bucketMissing {
		policy, err := c.get("storage", "buckets", "get-iam-policy", "gs://"+c.bucket, "--format", "json")
		if err != nil {
			return nil, err
		}
		granted = hasBinding(policy, objectRole, member)
	}
	if !granted {
		if err := retryNew(ctx, saMissing && !o.DryRun, func() error {
			return c.act("storage", "buckets", "add-iam-policy-binding", "gs://"+c.bucket, "--member", member, "--role", objectRole)
		}); err != nil {
			return nil, err
		}
	}
	p.line("ok", "the service account may read and write the bucket%s", when(!granted, " (granted)"))

	// The relay's key and network, made here with the user's own access, so
	// the key never passes through anything but the bucket. The service is
	// recorded with them, for deploy.
	rec := &relay.CloudRun{Project: r.Project, Region: r.Region, Service: r.Service}
	switch {
	case o.DryRun && !c.found:
		p.line("..", "would create the relay's key in %s", c.store)
	case o.DryRun:
		p.line("ok", "relay key %s, network %s, %d member(s)", c.st.PrivateKey.Public(), c.st.Network, len(c.st.Nodes))
	default:
		created := false
		if err := c.store.Update(ctx, &c.st, func() error {
			c.st.CloudRun = rec
			created = c.st.PrivateKey.IsZero()
			if created {
				return c.st.Init(relay.DefaultNetwork)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		p.line("ok", "relay key %s, network %s%s in %s", c.st.PrivateKey.Public(), c.st.Network, when(created, " (created)"), c.store)
	}

	// Where Cloud Build puts the images it builds.
	_, err = c.get("artifacts", "repositories", "describe", imageRepo, "--location", r.Region, "--format", "value(name)")
	switch {
	case err == nil:
		p.line("ok", "image repository %s", imageRepo)
	case IsNotFound(err):
		if err := c.act("artifacts", "repositories", "create", imageRepo, "--repository-format", "docker",
			"--location", r.Region, "--description", "san_vpn relay images, built from source"); err != nil {
			return nil, err
		}
		p.line("ok", "image repository %s (created, in %s)", imageRepo, r.Region)
	default:
		return nil, err
	}

	// Cloud Build builds as the project's default build account: in projects
	// made since mid-2024 the Compute Engine default account, which may hold
	// no role at all, else the legacy Cloud Build account.
	if o.DryRun && slices.Contains(missing, "cloudbuild.googleapis.com") {
		p.line("..", "would check that Cloud Build's account may build, once its API is on")
		return r, nil
	}
	out, err := c.get("builds", "get-default-service-account", "--format", "value(serviceAccountEmail)")
	if err != nil {
		return nil, err
	}
	builder := out[strings.LastIndex(out, "/")+1:]
	if builder == "" {
		return nil, fmt.Errorf("Cloud Build has no default service account in project %s; see https://cloud.google.com/build/docs/cloud-build-service-account", r.Project)
	}
	policy, err := c.get("projects", "get-iam-policy", r.Project, "--format", "json")
	if err != nil {
		return nil, err
	}
	bm := "serviceAccount:" + builder
	may := hasBinding(policy, builderRole, bm) || hasBinding(policy, "roles/editor", bm) || hasBinding(policy, "roles/owner", bm)
	if !may {
		// --condition None: a project policy with conditions refuses an
		// unconditional binding without it when nobody can be asked.
		if err := c.act("projects", "add-iam-policy-binding", r.Project, "--member", bm, "--role", builderRole, "--condition", "None"); err != nil {
			return nil, err
		}
	}
	p.line("ok", "Cloud Build's account %s may build%s", builder, when(!may, " (granted "+builderRole+")"))
	return r, nil
}

// CloudRunDeploy builds the relay's image from source with Cloud Build, or
// takes o.Image, and runs it as the service CloudRunSetup prepared.
//
// The service is shaped by what the relay is. Every member's packets meet in
// one process, so there is one instance at most. Each member holds one
// request open, so concurrency is high and the timeout is Cloud Run's longest;
// the relay asks members to renew before it. Members carry no Google
// identity, so the service admits anyone, and the relay admits only its own
// members' keys.
func CloudRunDeploy(ctx context.Context, g *GCloud, o CloudRunOptions) (*CloudRunResult, error) {
	c, err := begin(ctx, g, o)
	if err != nil {
		return nil, err
	}
	r, p, o := c.r, c.p, c.o
	if !c.found || c.st.PrivateKey.IsZero() {
		return nil, fmt.Errorf("no relay in %s yet; run `san_vpn cloudrun setup` first", c.store)
	}
	p.line("ok", "relay key %s, network %s, %d member(s) in %s", c.st.PrivateKey.Public(), c.st.Network, len(c.st.Nodes), c.store)
	timeout := o.Timeout
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}
	if timeout < time.Minute || timeout > time.Hour {
		return nil, fmt.Errorf("timeout %s: Cloud Run allows 1m to 1h, and the relay wants the longest", timeout)
	}

	// The image.
	r.Image = o.Image
	if r.Image == "" {
		if err := c.build(); err != nil {
			return nil, err
		}
	}

	// The service.
	sa := c.serviceAccount()
	env := [][2]string{{"SAN_VPN_STATE", r.State}, {"SAN_VPN_SESSION_LIMIT", timeout.String()}}
	desc, err := c.get("run", "services", "describe", r.Service, "--region", r.Region, "--format", "json")
	exists := err == nil
	if err != nil && !IsNotFound(err) {
		return nil, err
	}
	if exists && serviceMatches(desc, r.Image, sa, env, timeout) {
		p.line("ok", "service %s runs %s", r.Service, r.Image)
	} else {
		if err := deploy(ctx, g, o, r, sa, env, timeout); err != nil {
			return nil, err
		}
		p.line("ok", "service %s %s: %s, one instance, timeout %s", r.Service, when(exists, "updated")+when(!exists, "deployed"), r.Image, timeout)
	}

	// Members carry no Google identity: the service lets anyone in, and the
	// relay lets in only its members' keys. Deploying set this; a rerun puts
	// it back if it was taken away.
	if exists {
		policy, err := c.get("run", "services", "get-iam-policy", r.Service, "--region", r.Region, "--format", "json")
		if err != nil {
			return nil, err
		}
		if !hasBinding(policy, "roles/run.invoker", "allUsers") {
			if err := c.act("run", "services", "add-iam-policy-binding", r.Service, "--region", r.Region,
				"--member", "allUsers", "--role", "roles/run.invoker"); err != nil {
				return nil, err
			}
			p.line("ok", "anyone may connect; the relay admits only its own members' keys (turned on)")
		}
	}

	if o.DryRun && !exists {
		p.line("..", "would record the service's URL as the relay's URL, and check it")
		return r, nil
	}
	url, err := c.get("run", "services", "describe", r.Service, "--region", r.Region, "--format", "value(status.url)")
	if err != nil {
		return nil, err
	}
	if r.URL, err = node.HTTPURL(url); err != nil {
		return nil, fmt.Errorf("the service's URL %q: %w", url, err)
	}
	if o.DryRun {
		p.line("ok", "public URL %s", r.URL)
		return r, nil
	}
	old := c.st.URL
	if err := c.store.Update(ctx, &c.st, func() error {
		c.st.URL = r.URL
		c.st.CloudRun = &relay.CloudRun{Project: r.Project, Region: r.Region, Service: r.Service}
		return nil
	}); err != nil {
		return nil, err
	}
	p.line("ok", "public URL %s", r.URL)
	if old != "" && old != r.URL && len(c.st.Nodes) > 0 {
		p.line("!!", "the relay's URL was %s; members that joined before still dial it until they join again", old)
	}

	logs := fmt.Sprintf("gcloud run services logs read %s --region %s --project %s", r.Service, r.Region, r.Project)
	if err := expectRelay(ctx, o.HTTPClient, r.URL); err != nil {
		return r, fmt.Errorf("the service does not answer as a relay: %w; see %s", err, logs)
	}
	if err := expectChallenge(ctx, o.HTTPClient, r.URL); err != nil {
		return r, fmt.Errorf("the relay answers but its WebSocket fails: %w; see %s", err, logs)
	}
	p.line("ok", "relay answers at %s, WebSocket included", r.URL)
	return r, nil
}

// buildConfig is the Cloud Build recipe: the Dockerfile's build, stamped
// with the version, pushed to the project's repository. Logs go to Cloud
// Logging only, which every build account may write; the default logs
// bucket is one more permission to miss.
const buildConfig = `# Written by san_vpn cloudrun deploy.
steps:
  - name: gcr.io/cloud-builders/docker
    args: ["build", "--build-arg", "VERSION=${_VERSION}", "-t", "${_IMAGE}", "."]
images: ["${_IMAGE}"]
options:
  logging: CLOUD_LOGGING_ONLY
`

// build makes the image of o.Tag from o.Source with Cloud Build. A release's
// image that is already in the repository is not built again; a tree of
// one's own always is.
func (c *cloudRun) build() error {
	r, p, o := c.r, c.p, c.o
	if o.Tag == "" || o.Source == nil {
		return errors.New("nothing to deploy: no image, and no source to build one from")
	}
	r.Image = fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s:%s", r.Region, r.Project, imageRepo, imageName, o.Tag)
	_, err := c.get("artifacts", "repositories", "describe", imageRepo, "--location", r.Region, "--format", "value(name)")
	if IsNotFound(err) {
		return fmt.Errorf("no image repository %s in %s; run `san_vpn cloudrun setup`, which makes it", imageRepo, r.Region)
	}
	if err != nil {
		return err
	}
	if releaseTagRE.MatchString(o.Tag) {
		_, err := c.get("artifacts", "docker", "images", "describe", r.Image)
		switch {
		case err == nil:
			p.line("ok", "image %s (built before)", r.Image)
			return nil
		case !IsNotFound(err):
			return err
		}
	}

	subs := "_IMAGE=" + r.Image + ",_VERSION=" + o.Tag
	if o.DryRun {
		p.line("..", "would run: gcloud builds submit <source of %s> --config <recipe> --substitutions %s --suppress-logs --project %s", o.Tag, subs, r.Project)
		return nil
	}
	dir, err := o.Source(c.ctx)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "san_vpn-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	recipe := filepath.Join(tmp, "cloudbuild.yaml")
	if err := os.WriteFile(recipe, []byte(buildConfig), 0o644); err != nil {
		return err
	}
	p.line("..", "building %s from source with Cloud Build; this takes a few minutes", o.Tag)
	// --suppress-logs: gcloud still waits for the build, without streaming
	// a log that it may not be allowed to read.
	if _, err := c.get("builds", "submit", dir, "--config", recipe, "--substitutions", subs, "--suppress-logs"); err != nil {
		return fmt.Errorf("%w\nthe build's log: gcloud builds list --limit 1 --project %s, then gcloud builds log <ID> --project %s", err, r.Project, r.Project)
	}
	p.line("ok", "image %s (built from source)", r.Image)
	return nil
}

// deploy creates or updates the service.
func deploy(ctx context.Context, g *GCloud, o CloudRunOptions, r *CloudRunResult, sa string, env [][2]string, timeout time.Duration) error {
	args := []string{"run", "deploy", r.Service, "--image", r.Image, "--region", r.Region, "--project", r.Project,
		"--service-account", sa,
		"--allow-unauthenticated",
		// One process, or members on different instances cannot reach each other.
		"--max-instances", "1",
		"--concurrency", "1000",
		"--timeout", strconv.Itoa(int(timeout / time.Second)),
		// Members hold their connections all the time, so the instance is
		// busy all the time: instance-based billing is the cheaper kind.
		"--no-cpu-throttling",
		"--cpu", "1", "--memory", "512Mi",
		"--execution-environment", "gen2",
	}
	// An env file, not --set-env-vars: commas and equals signs survive
	// Windows' command line and gcloud's own list syntax untouched.
	var yaml strings.Builder
	for _, kv := range env {
		fmt.Fprintf(&yaml, "%s: %s\n", kv[0], strconv.Quote(kv[1]))
	}
	if o.DryRun {
		var shown []string
		for _, kv := range env {
			shown = append(shown, kv[0]+"="+kv[1])
		}
		p := printer{o.Out}
		p.line("..", "would run: gcloud %s --env-vars-file <%s>", strings.Join(args, " "), strings.Join(shown, ", "))
		return nil
	}
	f, err := os.CreateTemp("", "san_vpn-env-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(yaml.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = g.call(ctx, append(args, "--env-vars-file", f.Name())...)
	return err
}

// serviceMatches reports whether a deployed service, as `gcloud run services
// describe --format json` shows it, already runs the relay as wanted and is
// ready. Anything it cannot read counts as a mismatch, and the service is
// deployed again; so is one whose last deploy did not come up.
func serviceMatches(desc, image, sa string, env [][2]string, timeout time.Duration) bool {
	var svc struct {
		Spec struct {
			Template struct {
				Metadata struct {
					Annotations map[string]string
				}
				Spec struct {
					TimeoutSeconds     int
					ServiceAccountName string
					Containers         []struct {
						Image string
						Env   []struct{ Name, Value string }
					}
				}
			}
		}
		Status struct {
			Conditions []struct{ Type, Status string }
		}
	}
	if json.Unmarshal([]byte(desc), &svc) != nil {
		return false
	}
	ready := slices.ContainsFunc(svc.Status.Conditions, func(c struct{ Type, Status string }) bool {
		return c.Type == "Ready" && c.Status == "True"
	})
	t := svc.Spec.Template
	if !ready ||
		t.Metadata.Annotations["autoscaling.knative.dev/maxScale"] != "1" ||
		t.Spec.TimeoutSeconds != int(timeout/time.Second) ||
		t.Spec.ServiceAccountName != sa ||
		len(t.Spec.Containers) != 1 || t.Spec.Containers[0].Image != image {
		return false
	}
	have := map[string]string{}
	for _, e := range t.Spec.Containers[0].Env {
		have[e.Name] = e.Value
	}
	for _, kv := range env {
		if have[kv[0]] != kv[1] {
			return false
		}
	}
	return true
}

// hasBinding reports whether an IAM policy, as gcloud prints it in JSON,
// grants role to member.
func hasBinding(policy, role, member string) bool {
	var pol struct {
		Bindings []struct {
			Role    string
			Members []string
		}
	}
	if json.Unmarshal([]byte(policy), &pol) != nil {
		return false
	}
	for _, b := range pol.Bindings {
		if b.Role == role && slices.Contains(b.Members, member) {
			return true
		}
	}
	return false
}

// retryNew runs fn, and when the resource it refers to was only just created,
// retries for a while on "not found": IAM takes seconds to know a new service
// account.
func retryNew(ctx context.Context, justCreated bool, fn func() error) error {
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || !justCreated || !IsNotFound(err) || attempt == 11 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryPause):
		}
	}
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
