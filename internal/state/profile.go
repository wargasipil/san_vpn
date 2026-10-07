package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

// Profiles let one machine belong to several networks and choose which one
// `up` brings up: say one whose relay sits behind a dev tunnel and one whose
// relay runs on Cloud Run. Each relay is a network of its own, with its own
// key and members, so a profile is a whole membership: this machine's key,
// address and relay for that network, joined with that relay's invite.
//
// The default profile is the node directory itself, where node.json always
// lived, so a machine that joined before profiles existed has one profile,
// "default", and nothing moves. Every other profile is a folder under
// profiles/, holding its own node.json and status.json.
const (
	DefaultProfile = "default"
	// ProfileFile, in the node directory, records the profile `up` uses when
	// none is named.
	ProfileFile = "profile.json"
	profilesDir = "profiles"
)

var profileRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidProfile reports whether name can name a profile. Profiles are folder
// names, so they follow node names: lowercase letters, digits and inner
// hyphens, at most 32 characters.
func ValidProfile(name string) error {
	if !profileRE.MatchString(name) {
		return fmt.Errorf("profile %q: use lowercase letters, digits and hyphens, at most 32", name)
	}
	return nil
}

// ProfileDir is the directory holding profile name's node.json and
// status.json, inside the node directory nodeDir.
func ProfileDir(nodeDir, name string) string {
	if name == DefaultProfile {
		return nodeDir
	}
	return filepath.Join(nodeDir, profilesDir, name)
}

// Joined reports whether profile name holds a membership.
func Joined(nodeDir, name string) (bool, error) {
	_, err := os.Stat(filepath.Join(ProfileDir(nodeDir, name), NodeFile))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// Profiles lists the profiles that hold a membership: default first, then the
// others by name.
func Profiles(nodeDir string) ([]string, error) {
	var out []string
	if ok, err := Joined(nodeDir, DefaultProfile); err != nil {
		return nil, err
	} else if ok {
		out = append(out, DefaultProfile)
	}
	entries, err := os.ReadDir(filepath.Join(nodeDir, profilesDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var named []string
	for _, e := range entries {
		if !e.IsDir() || ValidProfile(e.Name()) != nil || e.Name() == DefaultProfile {
			continue
		}
		if ok, err := Joined(nodeDir, e.Name()); err != nil {
			return nil, err
		} else if ok {
			named = append(named, e.Name())
		}
	}
	slices.Sort(named)
	return append(out, named...), nil
}

type profileChoice struct {
	Current string `json:"current"`
}

// CurrentProfile is the profile chosen with SetCurrentProfile, else default.
// It may name a profile that holds no membership; callers say so.
func CurrentProfile(nodeDir string) (string, error) {
	var c profileChoice
	err := Load(filepath.Join(nodeDir, ProfileFile), &c)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return DefaultProfile, nil
	case err != nil:
		return "", err
	case ValidProfile(c.Current) != nil:
		return "", fmt.Errorf("%s names no valid profile: %q", filepath.Join(nodeDir, ProfileFile), c.Current)
	}
	return c.Current, nil
}

// SetCurrentProfile makes name the profile `up` uses when none is named.
func SetCurrentProfile(nodeDir, name string) error {
	if err := ValidProfile(name); err != nil {
		return err
	}
	return Save(filepath.Join(nodeDir, ProfileFile), profileChoice{Current: name})
}

// RenameProfile moves the membership in profile from to profile to, which
// must hold none, and keeps the current choice pointing at it. A status.json
// left behind is dropped: the caller makes sure `up` is not running on from,
// so it can only be stale.
func RenameProfile(nodeDir, from, to string) error {
	for _, n := range []string{from, to} {
		if err := ValidProfile(n); err != nil {
			return err
		}
	}
	if from == to {
		return fmt.Errorf("profile %q is already called that", from)
	}
	if ok, err := Joined(nodeDir, from); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("profile %q holds no membership", from)
	}
	if ok, err := Joined(nodeDir, to); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("profile %q already holds a membership", to)
	}

	src, dst := ProfileDir(nodeDir, from), ProfileDir(nodeDir, to)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if err := os.Rename(filepath.Join(src, NodeFile), filepath.Join(dst, NodeFile)); err != nil {
		return fmt.Errorf("move %s: %w", filepath.Join(src, NodeFile), err)
	}
	_ = os.Remove(filepath.Join(src, StatusFile))
	if from != DefaultProfile {
		_ = os.Remove(src) // only if empty: leave anything else someone put there
	}

	cur, err := CurrentProfile(nodeDir)
	if err == nil && cur == from {
		return SetCurrentProfile(nodeDir, to)
	}
	return nil
}
