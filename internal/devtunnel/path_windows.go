package devtunnel

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// registryPath is PATH as a new terminal would see it: the user's and the
// machine's entries from the registry, which an installer has just updated
// but our own environment predates.
func registryPath() []string {
	var dirs []string
	for _, k := range []struct {
		root registry.Key
		path string
	}{
		{registry.CURRENT_USER, `Environment`},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
	} {
		key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := key.GetStringValue("Path")
		_ = key.Close()
		if err != nil {
			continue
		}
		if expanded, err := registry.ExpandString(v); err == nil {
			v = expanded
		}
		for _, d := range strings.Split(v, ";") {
			if d = strings.TrimSpace(d); d != "" {
				dirs = append(dirs, filepath.Clean(d))
			}
		}
	}
	return dirs
}
