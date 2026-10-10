package osnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/wargasipil/san_vpn/internal/names"
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

// hostsPath is the hosts file; a variable for tests.
var hostsPath = "/etc/hosts"

// Set makes this machine resolve t's names, and says how when it changed
// anything.
//
// With systemd-resolved in charge (Ubuntu, Fedora), the domain is routed to
// t.Server on the tunnel interface, and the setting goes away with the
// interface. Without it (Debian servers, Raspberry Pi OS, Alpine) the C
// library has no way to send one domain to its own server, so the names go
// into /etc/hosts instead, rewritten as members come and go.
func (n *Names) Set(t *names.Table) (string, error) {
	if t == nil || !t.Server.IsValid() {
		return "", n.Clear()
	}
	if resolvedInUse() {
		want := "resolved " + n.Interface + " " + t.Domain + " " + t.Server.String()
		if n.applied == want {
			return "", nil
		}
		n.applied = want
		if err := resolvectl("dns", n.Interface, t.Server.String()); err != nil {
			return "", err
		}
		if err := resolvectl("domain", n.Interface, "~"+t.Domain); err != nil {
			return "", err
		}
		// Only the domain: never the interface for every other name. Older
		// systemd lacks the command, and does not make it one anyway.
		_ = resolvectl("default-route", n.Interface, "false")
		return "systemd-resolved (resolvectl status " + n.Interface + ")", nil
	}
	block := names.HostsBlock(t)
	if n.applied == "hosts\n"+block {
		return "", nil
	}
	n.applied = "hosts\n" + block
	if err := writeHosts(block); err != nil {
		return "", err
	}
	return hostsPath, nil
}

// Clear undoes Set: the hosts file block goes; systemd-resolved's setting
// goes with the interface, but is reverted too in case the interface stays.
func (n *Names) Clear() error {
	applied := n.applied
	n.applied = ""
	switch {
	case strings.HasPrefix(applied, "resolved "):
		_ = resolvectl("revert", n.Interface)
	case strings.HasPrefix(applied, "hosts\n"):
		return writeHosts("")
	}
	return nil
}

// resolvedInUse reports whether systemd-resolved answers this machine's
// lookups: its resolvectl is installed, and resolv.conf points at its stub.
func resolvedInUse() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	return err == nil && resolvedStub.Match(b)
}

var resolvedStub = regexp.MustCompile(`(?m)^\s*nameserver\s+127\.0\.0\.53\s*$`)

func resolvectl(args ...string) error {
	out, err := exec.Command("resolvectl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("resolvectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeHosts puts block in place of san_vpn's block in the hosts file. It
// writes in place rather than renaming a new file over it: Docker
// bind-mounts /etc/hosts into containers, and that mount cannot be replaced.
// Writing in place also keeps the file's owner, mode and SELinux label.
func writeHosts(block string) error {
	old, err := os.ReadFile(hostsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := names.ReplaceHostsBlock(string(old), block)
	if content == string(old) {
		return nil
	}
	if err := os.WriteFile(hostsPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", hostsPath, err)
	}
	return nil
}

// AllowInbound does nothing on Linux: there is no firewall every
// distribution shares, and most servers accept inbound traffic on a new
// interface already. With ufw, `ufw allow in on sanvpn0`.
func AllowInbound(netip.Prefix, netip.Addr) error { return nil }
