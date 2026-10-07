// Package osnet is everything san_vpn asks of the operating system: a tunnel
// interface, an address on it, and on Windows a firewall rule so peers can
// reach this machine.
//
// It is the only code that needs administrator rights, and the only code the
// end-to-end tests cannot run; they use a userspace network stack in its
// place. Keep it thin.
package osnet

// DefaultMTU is the tunnel MTU. The relay path is TCP, so outer packets are
// never fragmented and a larger MTU would work; 1420 is WireGuard's own
// default and what every tool expects, so start there.
const DefaultMTU = 1420
