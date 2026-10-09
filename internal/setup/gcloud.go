package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// GCloud drives Google's gcloud CLI, the way CLI drives devtunnel: it holds
// the user's sign-in and knows every API, so the cloudrun commands need no
// Google SDK and no credentials of their own.
type GCloud struct {
	Path string
	// Run executes gcloud and captures its output. Tests replace it.
	Run func(ctx context.Context, path string, args []string) (stdout, stderr []byte, err error)
}

// FindGCloud locates gcloud on PATH (gcloud.cmd on Windows).
func FindGCloud() (*GCloud, error) {
	p, err := exec.LookPath("gcloud")
	if err != nil {
		return nil, errors.New("the gcloud CLI is not installed; get it from https://cloud.google.com/sdk/docs/install, then run `gcloud auth login`")
	}
	return &GCloud{Path: p, Run: runGCloud}, nil
}

func runGCloud(ctx context.Context, path string, args []string) ([]byte, []byte, error) {
	cmd, err := gcloudCommand(ctx, path, args)
	if err != nil {
		return nil, nil, err
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// GCloudError is a gcloud call that failed, with what it said.
type GCloudError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *GCloudError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("gcloud %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *GCloudError) Unwrap() error { return e.Err }

// notFoundRE matches how gcloud's commands report a missing resource; they do
// not agree on one wording or exit code.
var notFoundRE = regexp.MustCompile(`(?i)not[ _]found|\b404\b|cannot find|does not exist`)

// IsNotFound reports whether err is gcloud saying the resource is not there.
func IsNotFound(err error) bool {
	var ge *GCloudError
	return errors.As(err, &ge) && notFoundRE.MatchString(ge.Stderr)
}

// call runs one gcloud command without prompts and returns its stdout.
func (g *GCloud) call(ctx context.Context, args ...string) (string, error) {
	args = append(args, "--quiet")
	out, errb, err := g.Run(ctx, g.Path, args)
	if err != nil {
		return "", &GCloudError{Args: args[:len(args)-1], Stderr: string(errb), Err: err}
	}
	return strings.TrimSpace(string(out)), nil
}
