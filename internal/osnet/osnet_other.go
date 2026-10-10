//go:build !linux && !windows

package osnet

import (
	"errors"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/wargasipil/san_vpn/internal/names"
	"github.com/wargasipil/san_vpn/internal/wire"
)

// DefaultName is unused here; the platform is not supported.
const DefaultName = "utun"

var errUnsupported = errors.New("san_vpn up runs on Windows and Linux only")

func Elevated() bool { return os.Geteuid() == 0 }

func Create(string, int, wire.Key) (tun.Device, error) { return nil, errUnsupported }

func Configure(tun.Device, netip.Prefix, int) error { return errUnsupported }

func AllowInbound(netip.Prefix, netip.Addr) error { return nil }

func (n *Names) Set(*names.Table) (string, error) { return "", errUnsupported }

func (n *Names) Clear() error { return nil }
