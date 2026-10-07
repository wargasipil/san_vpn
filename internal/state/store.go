package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/wargasipil/san_vpn/internal/gcs"
)

// Store holds the relay's file: on local disk, or as an object in Google
// Cloud Storage, where a relay on Cloud Run keeps it because its own disk does
// not outlive a restart. Both kinds keep the promise the file always made: a
// change by one writer is never lost to another's.
type Store interface {
	// Read loads the document into v and returns its version. A missing
	// document is os.ErrNotExist.
	Read(ctx context.Context, v any) (version string, err error)
	// Update loads the document (a missing one leaves v as the caller made
	// it), calls fn, and saves v if fn succeeded. fn may run more than once,
	// each time on fresh content, when another writer got in first.
	Update(ctx context.Context, v any, fn func() error) error
	// Version is the document's current version, cheaply, for noticing that
	// it changed. A missing document is os.ErrNotExist.
	Version(ctx context.Context) (string, error)
	// String says where the document is, for messages.
	String() string
}

// Open returns the store for file inside dir, where dir is a local directory
// or a gs://bucket[/prefix] URL.
func Open(dir, file string) (Store, error) {
	rest, ok := strings.CutPrefix(dir, "gs://")
	if !ok {
		return File(filepath.Join(dir, file)), nil
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return nil, fmt.Errorf("%q: want gs://<bucket> or gs://<bucket>/<folder>", dir)
	}
	return &GCS{Client: gcs.FromEnv(), Bucket: bucket, Object: path.Join(prefix, file)}, nil
}

// Remote reports whether s lives somewhere other than this machine's disk.
func Remote(s Store) bool {
	_, local := s.(File)
	return !local
}

// File is a JSON file on local disk, changed under the lock beside it.
type File string

func (f File) String() string { return string(f) }

// Read loads the file under its lock, so it never sees a half-replaced file.
func (f File) Read(_ context.Context, v any) (string, error) {
	unlock, err := Lock(string(f))
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := Load(string(f), v); err != nil {
		return "", err
	}
	return f.version()
}

// Update is the package's Update on this file.
func (f File) Update(_ context.Context, v any, fn func() error) error {
	return Update(string(f), v, fn)
}

// Version is a hash of the file's content. The modification time is not
// enough: two quick saves of the same size can share one clock tick, Windows'
// especially. The file is a few kilobytes, so hashing it is cheap.
func (f File) Version(context.Context) (string, error) { return f.version() }

func (f File) version() (string, error) {
	b, err := os.ReadFile(string(f))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]), nil
}

// GCS is a JSON object in Cloud Storage. Its generation is its version, and
// every write is conditional on it.
type GCS struct {
	Client *gcs.Client
	Bucket string
	Object string
}

func (g *GCS) String() string { return "gs://" + g.Bucket + "/" + g.Object }

func (g *GCS) Read(ctx context.Context, v any) (string, error) {
	_, gen, err := g.load(ctx, v)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(gen, 10), nil
}

// load reads the object into v. A missing object is os.ErrNotExist.
func (g *GCS) load(ctx context.Context, v any) ([]byte, int64, error) {
	data, gen, err := g.Client.Get(ctx, g.Bucket, g.Object)
	if errors.Is(err, gcs.ErrNotFound) {
		return nil, 0, fmt.Errorf("%s: %w", g, os.ErrNotExist)
	}
	if err != nil {
		return nil, 0, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", g, err)
	}
	return data, gen, nil
}

// updateAttempts bounds how often Update starts over after losing a race. Two
// writers at once is already rare: a join and an admin command in the same
// instant. Between attempts it waits a random while, growing, so writers that
// collided do not collide again in lockstep.
const updateAttempts = 20

func (g *GCS) Update(ctx context.Context, v any, fn func() error) error {
	for attempt := 0; attempt < updateAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(rand.Int64N(int64(attempt) * int64(20*time.Millisecond)))):
			}
			// Start from the object as it is now, not from what the last try
			// made of an older version.
			reflect.ValueOf(v).Elem().SetZero()
		}
		_, gen, err := g.load(ctx, v)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := fn(); err != nil {
			return err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", g, err)
		}
		_, err = g.Client.Put(ctx, g.Bucket, g.Object, append(b, '\n'), gen)
		if errors.Is(err, gcs.ErrConflict) {
			continue
		}
		return err
	}
	return fmt.Errorf("%s: gave up after %d attempts; it keeps changing underneath", g, updateAttempts)
}

func (g *GCS) Version(ctx context.Context) (string, error) {
	gen, err := g.Client.Generation(ctx, g.Bucket, g.Object)
	if errors.Is(err, gcs.ErrNotFound) {
		return "", fmt.Errorf("%s: %w", g, os.ErrNotExist)
	}
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(gen, 10), nil
}
