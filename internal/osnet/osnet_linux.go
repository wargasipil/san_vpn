package osnet

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/wargasipil/san_vpn/internal/wire"
)

// DefaultName is the interface name; Linux allows at most 15 characters.
const DefaultName = "sanvpn0"

// Elevated reports whether we run as root. Creating a TUN device needs
// CAP_NET_ADMIN; root is the usual way to have it.
func Elevated() bool { return os.Geteuid() == 0 }

// Create makes the TUN device.
func Create(name string, mtu int, _ wire.Key) (tun.Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w (san_vpn up needs root or CAP_NET_ADMIN)", name, err)
	}
	return dev, nil
}

// Configure gives the device its address and brings it up. The kernel adds
// the route to the overlay itself, from the address's prefix length.
func Configure(dev tun.Device, prefix netip.Prefix, _ int) error {
	name, err := dev.Name()
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("set address %s on %s: %w", prefix, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

// AllowInbound does nothing on Linux: there is no firewall every
// distribution shares, and most servers accept inbound traffic on a new
// interface already. With ufw, `ufw allow in on sanvpn0`.
func AllowInbound(netip.Prefix, netip.Addr) error { return nil }
