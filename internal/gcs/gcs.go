// Package gcs reads and writes single objects in Google Cloud Storage, which is
// where a relay on Cloud Run keeps its file: Cloud Run's own disk is gone after
// every restart.
//
// It speaks the JSON API directly. Three calls do not justify Google's SDK and
// the megabytes it adds to a binary that is meant to be one file to copy.
// Every write carries a generation precondition, so two writers -- the relay
// recording a join, an admin issuing an invite from a laptop -- never lose each
// other's change: the slower one is refused and starts over.
package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound is an object (or bucket) that does not exist.
	ErrNotFound = errors.New("gcs: not found")
	// ErrConflict is a write whose generation precondition failed: someone
	// else wrote the object since it was read.
	ErrConflict = errors.New("gcs: object changed since it was read")
)

// Client is a Cloud Storage JSON API client for whole small objects.
type Client struct {
	HTTP *http.Client
	// Base is https://storage.googleapis.com, or an emulator's address.
	Base string
	// Token returns an OAuth access token. Nil sends none, for an emulator.
	Token func(ctx context.Context) (string, error)
	// Forget drops a cached token after the server rejected it. May be nil.
	Forget func()
}

// FromEnv makes the client for this environment:
//
//   - STORAGE_EMULATOR_HOST set: that emulator, without credentials
//   - on Google (Cloud Run sets K_SERVICE; GCE_METADATA_HOST overrides the
//     metadata server): the service account's token from the metadata server
//   - elsewhere: the gcloud CLI's signed-in account
func FromEnv() *Client {
	c := &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Base: "https://storage.googleapis.com"}
	if h := os.Getenv("STORAGE_EMULATOR_HOST"); h != "" {
		if !strings.Contains(h, "://") {
			h = "http://" + h
		}
		c.Base = strings.TrimRight(h, "/")
		return c
	}
	var src *cached
	if OnGoogle() {
		src = &cached{fetch: metadataToken(c.HTTP)}
	} else {
		src = &cached{fetch: gcloudToken}
	}
	c.Token, c.Forget = src.get, src.forget
	return c
}

// OnGoogle reports whether a metadata server is there to ask for tokens.
func OnGoogle() bool {
	return os.Getenv("K_SERVICE") != "" || os.Getenv("GCE_METADATA_HOST") != ""
}

// Get returns an object's content and generation.
func (c *Client) Get(ctx context.Context, bucket, object string) ([]byte, int64, error) {
	u := c.objectURL(bucket, object) + "?alt=media"
	resp, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	if err := check(resp, body, "gs://"+bucket+"/"+object); err != nil {
		return nil, 0, err
	}
	gen, err := strconv.ParseInt(resp.Header.Get("X-Goog-Generation"), 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("gs://%s/%s: no generation in the response", bucket, object)
	}
	return body, gen, nil
}

// Generation returns an object's generation without its content: a cheap
// way to notice that it changed.
func (c *Client) Generation(ctx context.Context, bucket, object string) (int64, error) {
	resp, err := c.do(ctx, http.MethodGet, c.objectURL(bucket, object)+"?fields=generation", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err := check(resp, body, "gs://"+bucket+"/"+object); err != nil {
		return 0, err
	}
	var meta struct {
		Generation string `json:"generation"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return 0, fmt.Errorf("gs://%s/%s: unreadable metadata: %w", bucket, object, err)
	}
	return strconv.ParseInt(meta.Generation, 10, 64)
}

// Put writes an object if its generation is still ifGeneration (0: only if it
// does not exist yet), and returns the new generation. A failed precondition
// is ErrConflict.
func (c *Client) Put(ctx context.Context, bucket, object string, data []byte, ifGeneration int64) (int64, error) {
	q := url.Values{
		"uploadType":        {"media"},
		"name":              {object},
		"ifGenerationMatch": {strconv.FormatInt(ifGeneration, 10)},
	}
	u := c.Base + "/upload/storage/v1/b/" + url.PathEscape(bucket) + "/o?" + q.Encode()
	resp, err := c.do(ctx, http.MethodPost, u, data)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err := check(resp, body, "gs://"+bucket+"/"+object); err != nil {
		return 0, err
	}
	var meta struct {
		Generation string `json:"generation"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return 0, fmt.Errorf("gs://%s/%s: unreadable upload response: %w", bucket, object, err)
	}
	return strconv.ParseInt(meta.Generation, 10, 64)
}

func (c *Client) objectURL(bucket, object string) string {
	return c.Base + "/storage/v1/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(object)
}

// do sends one request, and once more with a fresh token if the first was
// refused as unauthenticated: a cached token can expire early.
func (c *Client) do(ctx context.Context, method, u string, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, r)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Token != nil {
			tok, err := c.Token(ctx)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && c.Forget != nil {
			resp.Body.Close()
			c.Forget()
			continue
		}
		return resp, nil
	}
}

func check(resp *http.Response, body []byte, what string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	case resp.StatusCode == http.StatusPreconditionFailed:
		return fmt.Errorf("%s: %w", what, ErrConflict)
	}
	msg := strings.TrimSpace(string(body))
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		msg = e.Error.Message
	}
	err := fmt.Errorf("%s: %s: %.200s", what, resp.Status, msg)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		err = fmt.Errorf("%w (sign in with `gcloud auth login`; the account needs read and write access to the bucket)", err)
	}
	return err
}

// cached keeps a token until shortly before it expires.
type cached struct {
	fetch func(ctx context.Context) (string, time.Duration, error)

	mu    sync.Mutex
	tok   string
	until time.Time
}

func (c *cached) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && time.Now().Before(c.until) {
		return c.tok, nil
	}
	tok, life, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	c.tok, c.until = tok, time.Now().Add(life-time.Minute)
	return tok, nil
}

func (c *cached) forget() {
	c.mu.Lock()
	c.tok = ""
	c.mu.Unlock()
}

// metadataToken asks the metadata server for the service account's token, as
// Cloud Run and Compute Engine provide it.
func metadataToken(client *http.Client) func(ctx context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		host := os.Getenv("GCE_METADATA_HOST")
		if host == "" {
			host = "metadata.google.internal"
		}
		u := "http://" + host + "/computeMetadata/v1/instance/service-accounts/default/token"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("token from the metadata server: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode != http.StatusOK {
			return "", 0, fmt.Errorf("token from the metadata server: %s: %.200s", resp.Status, body)
		}
		var t struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &t); err != nil || t.AccessToken == "" {
			return "", 0, errors.New("token from the metadata server: unreadable answer")
		}
		return t.AccessToken, time.Duration(t.ExpiresIn) * time.Second, nil
	}
}

// gcloudToken borrows the gcloud CLI's signed-in account, for admin commands
// run from a laptop. gcloud does not say when the token expires; it lasts an
// hour, so a few minutes of caching is safe.
func gcloudToken(ctx context.Context) (string, time.Duration, error) {
	cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token", "--quiet")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", 0, errors.New("a gs:// state needs the gcloud CLI, signed in (`gcloud auth login`), or must run on Google Cloud")
		}
		return "", 0, fmt.Errorf("gcloud auth print-access-token: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", 0, errors.New("gcloud auth print-access-token printed nothing; sign in with `gcloud auth login`")
	}
	return tok, 6 * time.Minute, nil
}
