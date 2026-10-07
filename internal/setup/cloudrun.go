package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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

	// The image comes from GitHub's registry, where the release workflow
	// publishes it, through an Artifact Registry remote repository: Cloud Run
	// pulls only from Artifact Registry and Docker Hub.
	imageRepo     = "ghcr"
	imageUpstream = "https://ghcr.io"
	imageName     = "wargasipil/san_vpn"

	serviceAccountID = "san-vpn-relay"
)

// CloudRunOptions configure InitCloudRun.
type CloudRunOptions struct {
	// Project is the Google Cloud project; empty uses gcloud's configured one.
	Project string
	Region  string
	Service string
	// State is where the relay's file goes, gs://<bucket>[/<folder>];
	// empty is gs://<project>-san-vpn.
	State string
	// Image overrides the release image for Version.
	Image string
	// Version is the release whose image to run, such as v0.3.0.
	Version string
	// Timeout is the service's request timeout, and so the session limit.
	Timeout time.Duration
	// DryRun looks at everything but changes nothing, and prints the gcloud
	// commands it would run.
	DryRun bool
	Out    io.Writer
	// OpenRelay opens the relay's file at a gs:// location; nil is state.Open.
	OpenRelay  func(location string) (state.Store, error)
	HTTPClient *http.Client
}

// CloudRunResult is what InitCloudRun set up.
type CloudRunResult struct {
	Project, Region, Service string
	State                    string // gs://...
	Image                    string
	URL                      string // empty after a dry run that would deploy
}

// retryPause is the wait while a new service account becomes usable in IAM
// policies, which takes Google a few seconds.
var retryPause = 5 * time.Second

var releaseTagRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// InitCloudRun runs the relay on Cloud Run, keeping its file in Cloud Storage.
// Like Init, each step looks before it acts: a rerun on a working setup
// changes nothing, and a rerun after something changed repairs that step.
//
// The service is shaped by what the relay is. Every member's packets meet in
// one process, so there is one instance at most. Each member holds one
// request open, so concurrency is high and the timeout is Cloud Run's longest;
// the relay asks members to renew before it. Members carry no Google
// identity, so the service admits anyone, and the relay admits only its own
// members' keys.
func InitCloudRun(ctx context.Context, g *GCloud, o CloudRunOptions) (*CloudRunResult, error) {
	p := printer{o.Out}
	if o.OpenRelay == nil {
		o.OpenRelay = func(loc string) (state.Store, error) { return state.Open(loc, state.RelayFile) }
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	act := func(args ...string) error {
		if o.DryRun {
			p.line("..", "would run: gcloud %s", strings.Join(args, " "))
			return nil
		}
		_, err := g.call(ctx, args...)
		return err
	}

	account, err := g.call(ctx, "config", "get-value", "account")
	if err != nil {
		return nil, err
	}
	if account == "" {
		return nil, errors.New("gcloud is not signed in; run `gcloud auth login`")
	}
	r := &CloudRunResult{Project: o.Project, Region: o.Region, Service: o.Service, State: o.State}
	if r.Project == "" {
		if r.Project, err = g.call(ctx, "config", "get-value", "project"); err != nil {
			return nil, err
		}
		if r.Project == "" {
			return nil, errors.New("no Google Cloud project; pass --project, or set one with `gcloud config set project <id>`")
		}
	}
	r.Region = or(r.Region, DefaultRegion)
	r.Service = or(r.Service, DefaultService)
	r.State = or(r.State, "gs://"+r.Project+"-san-vpn")
	timeout := o.Timeout
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}
	if timeout < time.Minute || timeout > time.Hour {
		return nil, fmt.Errorf("timeout %s: Cloud Run allows 1m to 1h, and the relay wants the longest", timeout)
	}
	bucket, _, _ := strings.Cut(strings.TrimPrefix(r.State, "gs://"), "/")
	if !strings.HasPrefix(r.State, "gs://") || bucket == "" {
		return nil, fmt.Errorf("state %q: want gs://<bucket>[/<folder>]", r.State)
	}
	project := []string{"--project", r.Project}
	p.line("ok", "gcloud signed in as %s; project %s, region %s", account, r.Project, r.Region)

	// APIs. Cloud Storage and IAM are on in every project; Run and Artifact
	// Registry usually are not.
	enabled, err := g.call(ctx, append([]string{"services", "list", "--enabled", "--format", "value(config.name)"}, project...)...)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, api := range []string{"run.googleapis.com", "artifactregistry.googleapis.com", "iam.googleapis.com", "storage.googleapis.com"} {
		if !slices.Contains(strings.Fields(enabled), api) {
			missing = append(missing, api)
		}
	}
	if len(missing) > 0 {
		if err := act(append(append([]string{"services", "enable"}, missing...), project...)...); err != nil {
			return nil, err
		}
	}
	p.line("ok", "APIs: Cloud Run, Artifact Registry, IAM, Cloud Storage%s", when(len(missing) > 0, " (enabled "+strings.Join(missing, ", ")+")"))

	// The bucket: private, in the service's region.
	bucketMissing := false
	_, err = g.call(ctx, append([]string{"storage", "buckets", "describe", "gs://" + bucket, "--format", "value(name)"}, project...)...)
	switch {
	case err == nil:
		p.line("ok", "bucket gs://%s", bucket)
	case IsNotFound(err):
		bucketMissing = true
		if err := act(append([]string{"storage", "buckets", "create", "gs://" + bucket, "--location", r.Region,
			"--uniform-bucket-level-access", "--public-access-prevention"}, project...)...); err != nil {
			return nil, err
		}
		p.line("ok", "bucket gs://%s (created; private, in %s)", bucket, r.Region)
	default:
		return nil, err
	}

	// The service's identity, which may read and write the bucket and
	// nothing else.
	sa := serviceAccountID + "@" + r.Project + ".iam.gserviceaccount.com"
	saMissing := false
	_, err = g.call(ctx, append([]string{"iam", "service-accounts", "describe", sa, "--format", "value(email)"}, project...)...)
	switch {
	case err == nil:
		p.line("ok", "service account %s", sa)
	case IsNotFound(err):
		saMissing = true
		if err := act(append([]string{"iam", "service-accounts", "create", serviceAccountID, "--display-name", "san_vpn relay"}, project...)...); err != nil {
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
		policy, err := g.call(ctx, append([]string{"storage", "buckets", "get-iam-policy", "gs://" + bucket, "--format", "json"}, project...)...)
		if err != nil {
			return nil, err
		}
		granted = hasBinding(policy, objectRole, member)
	}
	if !granted {
		grant := append([]string{"storage", "buckets", "add-iam-policy-binding", "gs://" + bucket, "--member", member, "--role", objectRole}, project...)
		if err := retryNew(ctx, saMissing && !o.DryRun, func() error { return act(grant...) }); err != nil {
			return nil, err
		}
	}
	p.line("ok", "the service account may read and write the bucket%s", when(!granted, " (granted)"))

	// The relay's key and network, made here with the user's own access, so
	// the key never passes through anything but the bucket.
	store, err := o.OpenRelay(r.State)
	if err != nil {
		return nil, err
	}
	var st relay.State
	switch {
	case bucketMissing && o.DryRun:
		p.line("..", "would create the relay's key in %s", store)
	case o.DryRun:
		if _, err := store.Read(ctx, &st); errors.Is(err, os.ErrNotExist) {
			p.line("..", "would create the relay's key in %s", store)
		} else if err != nil {
			return nil, err
		} else {
			p.line("ok", "relay key %s, network %s, %d member(s)", st.PrivateKey.Public(), st.Network, len(st.Nodes))
		}
	default:
		created := false
		if err := store.Update(ctx, &st, func() error {
			created = st.PrivateKey.IsZero()
			if created {
				return st.Init(relay.DefaultNetwork)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		p.line("ok", "relay key %s, network %s%s in %s", st.PrivateKey.Public(), st.Network, when(created, " (created)"), store)
	}

	// The image.
	r.Image = o.Image
	if r.Image == "" {
		if !releaseTagRE.MatchString(o.Version) {
			return nil, fmt.Errorf("this san_vpn is not a release (%s), so there is no image of it to run; use a release, or pass --image", o.Version)
		}
		_, err := g.call(ctx, append([]string{"artifacts", "repositories", "describe", imageRepo, "--location", r.Region, "--format", "value(name)"}, project...)...)
		switch {
		case err == nil:
		case IsNotFound(err):
			if err := act(append([]string{"artifacts", "repositories", "create", imageRepo, "--repository-format", "docker",
				"--location", r.Region, "--mode", "remote-repository", "--remote-docker-repo", imageUpstream,
				"--description", "GitHub Container Registry, for san_vpn"}, project...)...); err != nil {
				return nil, err
			}
			p.line("ok", "image repository %s, a cache of %s (created)", imageRepo, imageUpstream)
		default:
			return nil, err
		}
		r.Image = fmt.Sprintf("%s-docker.pkg.dev/%s/%s/%s:%s", r.Region, r.Project, imageRepo, imageName, o.Version)
	}

	// The service.
	env := [][2]string{{"SAN_VPN_STATE", r.State}, {"SAN_VPN_SESSION_LIMIT", timeout.String()}}
	desc, err := g.call(ctx, append([]string{"run", "services", "describe", r.Service, "--region", r.Region, "--format", "json"}, project...)...)
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
		policy, err := g.call(ctx, append([]string{"run", "services", "get-iam-policy", r.Service, "--region", r.Region, "--format", "json"}, project...)...)
		if err != nil {
			return nil, err
		}
		if !hasBinding(policy, "roles/run.invoker", "allUsers") {
			if err := act(append([]string{"run", "services", "add-iam-policy-binding", r.Service, "--region", r.Region,
				"--member", "allUsers", "--role", "roles/run.invoker"}, project...)...); err != nil {
				return nil, err
			}
			p.line("ok", "anyone may connect; the relay admits only its own members' keys (turned on)")
		}
	}

	if o.DryRun && !exists {
		p.line("..", "would record the service's URL as the relay's URL, and check it")
		return r, nil
	}
	url, err := g.call(ctx, append([]string{"run", "services", "describe", r.Service, "--region", r.Region, "--format", "value(status.url)"}, project...)...)
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
	old := st.URL
	if err := store.Update(ctx, &st, func() error {
		st.URL = r.URL
		st.CloudRun = &relay.CloudRun{Project: r.Project, Region: r.Region, Service: r.Service}
		return nil
	}); err != nil {
		return nil, err
	}
	p.line("ok", "public URL %s", r.URL)
	if old != "" && old != r.URL && len(st.Nodes) > 0 {
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
// describe --format json` shows it, already runs the relay as wanted. Anything
// it cannot read counts as a mismatch, and the service is deployed again.
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
	}
	if json.Unmarshal([]byte(desc), &svc) != nil {
		return false
	}
	t := svc.Spec.Template
	if t.Metadata.Annotations["autoscaling.knative.dev/maxScale"] != "1" ||
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
