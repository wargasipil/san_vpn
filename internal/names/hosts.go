package names

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The hosts file block is fenced by these lines, so it can be rewritten and
// removed without touching anyone else's entries.
const (
	hostsBegin = "# san_vpn begin: written by san_vpn up, which rewrites and removes it"
	hostsEnd   = "# san_vpn end"
)

// HostsBlock is the hosts file lines for t, in address order, or "" for an
// empty table.
func HostsBlock(t *Table) string {
	if t == nil || len(t.Hosts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(hostsBegin + "\n")
	names := slices.SortedFunc(maps.Keys(t.Hosts), func(a, b string) int { return t.Hosts[a].Compare(t.Hosts[b]) })
	for _, n := range names {
		fmt.Fprintf(&b, "%s\t%s\n", t.Hosts[n], t.Name(n))
	}
	b.WriteString(hostsEnd + "\n")
	return b.String()
}

// ReplaceHostsBlock puts block in place of the san_vpn block in a hosts
// file's content: where the old one was, else at the end. An empty block
// removes it. Everything else is kept as it was. Only a whole block is
// replaced: a begin line whose end line someone deleted is dropped alone,
// never the lines after it.
func ReplaceHostsBlock(content, block string) string {
	lines := strings.SplitAfter(content, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		switch strings.TrimRight(l, "\r\n") {
		case hostsBegin:
			if begin < 0 {
				begin = i
			}
		case hostsEnd:
			if begin >= 0 && end < 0 {
				end = i
			}
		}
	}
	switch {
	case begin >= 0 && end >= 0:
		return strings.Join(lines[:begin], "") + block + strings.Join(lines[end+1:], "")
	case begin >= 0:
		lines = slices.Delete(lines, begin, begin+1)
	}
	s := strings.Join(lines, "")
	if block == "" {
		return s
	}
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s + block
}
