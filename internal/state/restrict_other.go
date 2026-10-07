//go:build !windows

package state

import "os"

// restrict tightens a directory that already existed with looser permissions;
// MkdirAll only applies its mode to directories it creates.
func restrict(dir string, _ bool) error { return os.Chmod(dir, 0o700) }
