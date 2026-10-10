package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Relay profiles let one machine look after several relays and choose which
// one the relay commands work on: say the dev tunnel relay it serves itself
// and the one on Cloud Run, whose file is in a bucket. Each relay is a network
// of its own, so a command that picked the wrong one would invite a machine
// into the wrong network.
//
// A relay profile is a name for where a relay's file is: a directory on this
// machine or a gs:// location. Only the names live in relays.json, and the
// files stay where they are, so a rename never moves a file from under a
// running relay. The default relay is the relay directory itself, where
// relay.json always lived, so a relay from before relay profiles is "default"
// and nothing moves. A relay made on this machine under another name gets a
// folder under relays/.
const (
	DefaultRelay = "default"
	// RelaysFile, in the relay directory, holds the relay profiles and the
	// one the relay commands use when none is named.
	RelaysFile = "relays.json"
	relaysDir  = "relays"
)

type relayIndex struct {
	Current string `json:"current,omitempty"`
	// Relays maps a name to its relay's location: relative to the relay
	// directory when inside it ("." is the directory itself), so the folder
	// can move, else an absolute path or a gs:// location.
	Relays map[string]string `json:"relays,omitempty"`
}

// RelayProfile is one relay this machine looks after.
type RelayProfile struct {
	Name string
	// Location is the directory holding the relay's relay.json, or the
	// gs://bucket[/folder] holding it.
	Location string
}

// ValidRelayName reports whether name can name a relay profile. Names follow
// member profiles: lowercase letters, digits and inner hyphens, at most 32.
func ValidRelayName(name string) error {
	if !profileRE.MatchString(name) {
		return fmt.Errorf("relay profile %q: use lowercase letters, digits and hyphens, at most 32", name)
	}
	return nil
}

// RemoteLocation reports whether loc is in Cloud Storage rather than on this
// machine's disk.
func RemoteLocation(loc string) bool { return strings.HasPrefix(loc, "gs://") }

// RelayLocation is where relay profile name keeps its relay, in the relay
// directory dir. known is false for a name no relay has yet; loc is then where
// a new relay of that name on this machine goes. The default relay is always
// known: it is dir itself, holding a relay or not.
func RelayLocation(dir, name string) (loc string, known bool, err error) {
	if err := ValidRelayName(name); err != nil {
		return "", false, err
	}
	idx, err := loadRelays(dir)
	if err != nil {
		return "", false, err
	}
	if stored, ok := idx.Relays[name]; ok {
		return resolveLocation(dir, stored), true, nil
	}
	if name == DefaultRelay {
		return dir, true, nil
	}
	return filepath.Join(dir, relaysDir, name), false, nil
}

// RelayProfiles lists the relay profiles: default first, when dir holds a
// relay that no other name took over, then the others by name.
func RelayProfiles(dir string) ([]RelayProfile, error) {
	idx, err := loadRelays(dir)
	if err != nil {
		return nil, err
	}
	var out []RelayProfile
	if _, named := idx.Relays[DefaultRelay]; !named {
		if ok, err := defaultUnnamed(dir, idx); err != nil {
			return nil, err
		} else if ok {
			out = append(out, RelayProfile{DefaultRelay, dir})
		}
	}
	names := make([]string, 0, len(idx.Relays))
	for name := range idx.Relays {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		switch {
		case a == DefaultRelay:
			return -1
		case b == DefaultRelay:
			return 1
		}
		return strings.Compare(a, b)
	})
	for _, name := range names {
		out = append(out, RelayProfile{name, resolveLocation(dir, idx.Relays[name])})
	}
	return out, nil
}

// CurrentRelay is the relay profile chosen with SetCurrentRelay, else the
// relay directory's own relay: default, or the name it was renamed to. It may
// name a profile whose relay is not made yet; callers say so.
func CurrentRelay(dir string) (string, error) {
	idx, err := loadRelays(dir)
	switch {
	case err != nil:
		return "", err
	case idx.Current == "":
		for name, stored := range idx.Relays {
			if stored == "." {
				return name, nil
			}
		}
		return DefaultRelay, nil
	case ValidRelayName(idx.Current) != nil:
		return "", fmt.Errorf("%s names no valid relay profile: %q", filepath.Join(dir, RelaysFile), idx.Current)
	}
	return idx.Current, nil
}

// SetCurrentRelay makes relay profile name the one the relay commands use
// when none is named.
func SetCurrentRelay(dir, name string) error {
	if err := ValidRelayName(name); err != nil {
		return err
	}
	return updateRelays(dir, func(idx *relayIndex) error {
		if _, ok := idx.Relays[name]; !ok && name != DefaultRelay {
			return fmt.Errorf("no relay profile %q", name)
		}
		idx.Current = name
		if name == DefaultRelay {
			idx.Current = ""
		}
		return nil
	})
}

// AddRelay names the relay at loc, a directory or a gs:// location. Naming it
// again by the same name is fine. A name or a relay that has a profile
// already is refused: one name per relay keeps the list honest.
func AddRelay(dir, name, loc string) error {
	if err := ValidRelayName(name); err != nil {
		return err
	}
	stored, err := storedLocation(dir, loc)
	if err != nil {
		return err
	}
	return updateRelays(dir, func(idx *relayIndex) error {
		if have, ok := idx.Relays[name]; ok {
			if have == stored {
				return nil
			}
			return fmt.Errorf("relay profile %q is the relay in %s already", name, resolveLocation(dir, have))
		}
		for other, have := range idx.Relays {
			if have == stored {
				return fmt.Errorf("%s is relay profile %q already", resolveLocation(dir, have), other)
			}
		}
		unnamed, err := defaultUnnamed(dir, *idx)
		if err != nil {
			return err
		}
		if stored == "." {
			if name == DefaultRelay {
				return nil
			}
			return fmt.Errorf("%s is relay profile %q already; to call it %s: san_vpn relay profile rename %s %s", dir, DefaultRelay, name, DefaultRelay, name)
		}
		if name == DefaultRelay && unnamed {
			return fmt.Errorf("relay profile %q is the relay in %s already", name, dir)
		}
		if idx.Relays == nil {
			idx.Relays = map[string]string{}
		}
		idx.Relays[name] = stored
		return nil
	})
}

// RenameRelay renames relay profile from to to, which must be free, and keeps
// the current choice pointing at it. No file moves.
func RenameRelay(dir, from, to string) error {
	for _, n := range []string{from, to} {
		if err := ValidRelayName(n); err != nil {
			return err
		}
	}
	if from == to {
		return fmt.Errorf("relay profile %q is already called that", from)
	}
	return updateRelays(dir, func(idx *relayIndex) error {
		unnamed, err := defaultUnnamed(dir, *idx)
		if err != nil {
			return err
		}
		stored, ok := idx.Relays[from]
		if !ok {
			if from != DefaultRelay || !unnamed {
				return fmt.Errorf("no relay profile %q", from)
			}
			stored = "."
		}
		if _, ok := idx.Relays[to]; ok || (to == DefaultRelay && unnamed) {
			return fmt.Errorf("relay profile %q names another relay already", to)
		}
		delete(idx.Relays, from)
		// Renamed to default, the relay directory is plain default again.
		if to != DefaultRelay || stored != "." {
			if idx.Relays == nil {
				idx.Relays = map[string]string{}
			}
			idx.Relays[to] = stored
		}
		if idx.Current == from || (idx.Current == "" && from == DefaultRelay) {
			idx.Current = to
		}
		if idx.Current == DefaultRelay {
			idx.Current = ""
		}
		return nil
	})
}

// ForgetRelay drops relay profile name and returns where its relay is, which
// stays as it was: forgetting a name never deletes a relay. The current
// choice falls back to default.
func ForgetRelay(dir, name string) (loc string, err error) {
	if err := ValidRelayName(name); err != nil {
		return "", err
	}
	err = updateRelays(dir, func(idx *relayIndex) error {
		stored, ok := idx.Relays[name]
		if !ok {
			if name == DefaultRelay {
				return fmt.Errorf("relay profile %q is the relay directory %s itself; there is no name to forget", name, dir)
			}
			return fmt.Errorf("no relay profile %q", name)
		}
		loc = resolveLocation(dir, stored)
		delete(idx.Relays, name)
		if idx.Current == name {
			idx.Current = ""
		}
		return nil
	})
	return loc, err
}

// HasRelay reports whether a relay's file is at loc. A gs:// location is
// taken on trust: looking would take a network call and a sign-in.
func HasRelay(loc string) (bool, error) {
	if RemoteLocation(loc) {
		return true, nil
	}
	_, err := os.Stat(filepath.Join(loc, RelayFile))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// defaultUnnamed reports whether dir holds a relay that is plain default:
// there is one, and no other name was given to it.
func defaultUnnamed(dir string, idx relayIndex) (bool, error) {
	for name, stored := range idx.Relays {
		if stored == "." && name != DefaultRelay {
			return false, nil
		}
	}
	return HasRelay(dir)
}

func loadRelays(dir string) (relayIndex, error) {
	var idx relayIndex
	if err := Load(filepath.Join(dir, RelaysFile), &idx); err != nil && !errors.Is(err, os.ErrNotExist) {
		return idx, err
	}
	return idx, nil
}

func updateRelays(dir string, fn func(*relayIndex) error) error {
	var idx relayIndex
	return Update(filepath.Join(dir, RelaysFile), &idx, func() error { return fn(&idx) })
}

// storedLocation is how loc is kept in relays.json.
func storedLocation(dir, loc string) (string, error) {
	if RemoteLocation(loc) {
		bucket, _, _ := strings.Cut(strings.TrimPrefix(loc, "gs://"), "/")
		if bucket == "" {
			return "", fmt.Errorf("%q: want gs://<bucket> or gs://<bucket>/<folder>", loc)
		}
		return strings.TrimRight(loc, "/"), nil
	}
	if loc == "" {
		return "", errors.New("no location for the relay")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	absLoc, err := filepath.Abs(loc)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absDir, absLoc)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel), nil
	}
	return absLoc, nil
}

func resolveLocation(dir, stored string) string {
	if RemoteLocation(stored) || filepath.IsAbs(stored) {
		return stored
	}
	return filepath.Join(dir, filepath.FromSlash(stored))
}
