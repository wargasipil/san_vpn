package node

import (
	"bufio"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// peerUpdate is the WireGuard configuration (UAPI "set") that turns the peers
// in have into the peers in want.
//
// It touches only what changed. Rewriting every peer -- replace_peers=true --
// would be simpler, but it throws away every session's keys, so each member
// joining would stall traffic between all the others until they handshake
// again. Peers in reset are removed and added back, which is exactly that,
// for the peers where it is wanted.
func peerUpdate(have, want map[wire.Key]netip.Addr, reset map[wire.Key]bool) string {
	var b strings.Builder
	for _, k := range sortedKeys(have) {
		if _, ok := want[k]; !ok || reset[k] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k.Hex())
		}
	}
	for _, k := range sortedKeys(want) {
		ip := want[k]
		if old, ok := have[k]; ok && old == ip && !reset[k] {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
			k.Hex(), k.Hex(), netip.PrefixFrom(ip, ip.BitLen()))
	}
	return b.String()
}

func sortedKeys(m map[wire.Key]netip.Addr) []wire.Key {
	keys := make([]wire.Key, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b wire.Key) int { return strings.Compare(string(a[:]), string(b[:])) })
	return keys
}

// peerStats is what WireGuard reports about one peer.
type peerStats struct {
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// parseStats reads the peers out of a UAPI "get" dump.
func parseStats(dump string) map[wire.Key]peerStats {
	out := map[wire.Key]peerStats{}
	var cur *wire.Key
	var st peerStats
	var sec, nsec int64
	flush := func() {
		if cur != nil {
			if sec != 0 || nsec != 0 {
				st.LastHandshake = time.Unix(sec, nsec)
			}
			out[*cur] = st
		}
		st, sec, nsec = peerStats{}, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(dump))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key, err := wire.ParseHexKey(v)
			if err != nil {
				cur = nil
				continue
			}
			cur = &key
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}
