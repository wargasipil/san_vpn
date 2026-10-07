package osnet

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// DefaultName is the adapter name Windows shows in its network list.
const DefaultName = "san_vpn"

// firewallRule names the inbound rule `up` keeps in place.
const firewallRule = "san_vpn"

// wintunDLL is the Wintun driver library, from wintun.net, fetched and checked
// by build.ps1 / build.sh. Embedding it keeps san_vpn one file to copy.
//
//go:embed wintun/wintun.dll
var wintunDLL []byte

// Elevated reports whether we run as an elevated administrator, which
// creating an adapter and writing the node directory both need.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Create makes (or reuses) the Wintun adapter.
//
// The adapter GUID is derived from the node's key, so it is the same on every
// start. Windows keys its network profiles by GUID: a fresh GUID each time
// would mean a new "Network 7, Network 8..." profile, each starting as Public.
func Create(name string, mtu int, key wire.Key) (tun.Device, error) {
	if err := installWintun(); err != nil {
		return nil, err
	}
	tun.WintunTunnelType = "san_vpn"
	sum := sha256.Sum256(append([]byte("san_vpn adapter\n"+name+"\n"), key[:]...))
	guid := windows.GUID{
		Data1: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3]),
		Data2: uint16(sum[4])<<8 | uint16(sum[5]),
		Data3: uint16(sum[6])<<8 | uint16(sum[7]),
	}
	copy(guid.Data4[:], sum[8:16])
	dev, err := tun.CreateTUNWithRequestedGUID(name, &guid, mtu)
	if err != nil {
		return nil, fmt.Errorf("create adapter %q: %w", name, err)
	}
	return dev, nil
}

// installWintun puts wintun.dll beside the executable, which is where the
// Wintun loader looks (besides System32).
func installWintun() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, wintunDLL) {
		return nil
	}
	if err := os.WriteFile(path, wintunDLL, 0o644); err != nil {
		return fmt.Errorf("install wintun.dll beside %s: %w", exe, err)
	}
	return nil
}

// Configure gives the adapter its address and the route to the overlay.
//
// The steps mirror wireguard-windows: routes, then addresses, then the
// interface row -- no router discovery, no duplicate address detection
// delay, the MTU.
func Configure(dev tun.Device, prefix netip.Prefix, mtu int) error {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return errors.New("configure: not a Wintun adapter")
	}
	luid := winipcfg.LUID(nt.LUID())
	family := winipcfg.AddressFamily(windows.AF_INET)

	route := &winipcfg.RouteData{Destination: prefix.Masked(), NextHop: netip.IPv4Unspecified(), Metric: 0}
	if err := luid.SetRoutesForFamily(family, []*winipcfg.RouteData{route}); err != nil {
		return fmt.Errorf("set route %s: %w", prefix.Masked(), err)
	}
	err := luid.SetIPAddressesForFamily(family, []netip.Prefix{prefix})
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		// A previous run's adapter that Windows has not finished tearing
		// down can still hold the address.
		cleanupStaleAddress(family, prefix.Addr())
		err = luid.SetIPAddressesForFamily(family, []netip.Prefix{prefix})
	}
	if err != nil {
		return fmt.Errorf("set address %s: %w", prefix, err)
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	ipif.NLMTU = uint32(mtu)
	if err := ipif.Set(); err != nil {
		return fmt.Errorf("set interface mtu: %w", err)
	}
	return nil
}

func cleanupStaleAddress(family winipcfg.AddressFamily, addr netip.Addr) {
	ifaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for a := iface.FirstUnicastAddress; a != nil; a = a.Next {
			if ip, _ := netip.AddrFromSlice(a.Address.IP()); ip.Unmap() == addr {
				_ = iface.LUID.DeleteIPAddress(netip.PrefixFrom(addr, int(a.OnLinkPrefixLength)))
			}
		}
	}
}

// AllowInbound lets the other members reach this machine.
//
// A new adapter lands in the Public firewall profile, which blocks inbound
// traffic -- even ping -- so a mesh that only dials out would look broken. The
// rule is scoped to traffic from the overlay to our own overlay address, so it
// opens nothing on any other network.
func AllowInbound(network netip.Prefix, self netip.Addr) error {
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule).Run()
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRule, "dir=in", "action=allow", "protocol=any", "profile=any",
		"localip="+self.String(), "remoteip="+network.Masked().String(),
		"description=san_vpn: traffic from the other members of the VPN").CombinedOutput()
	if err != nil {
		return fmt.Errorf("add firewall rule: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
