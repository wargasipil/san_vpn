# san_vpn

`san_vpn` joins machines at home, at the office and in other regions into one
private network. Every machine gets an address such as `10.77.0.2`, and every
machine can reach every other one on that address: ping, SSH, RDP, a database
port.

All traffic is WireGuard, end to end between the two machines. WireGuard
normally runs over UDP. Here it is carried over a WebSocket to a relay. Because
of that, it works anywhere outbound HTTPS works: behind carrier-grade NAT,
behind office firewalls, and through a Microsoft dev tunnel with no public IP
anywhere. The relay only forwards encrypted packets by public key. It cannot
read them, and neither can the dev tunnel in front of it.

```
 home (Windows)            office (Windows)            region (Linux VPS)
 10.77.0.2                 10.77.0.1 + relay            10.77.0.3
     │                        │    ▲                        │
     └── wss ──► dev tunnel ──┴──► relay ◄── wss ───────────┘
                (TLS)            forwards WireGuard packets by key
```

The design and the reasoning behind it live in
[`docs/external_repo/san_vpn.md`](../../../docs/external_repo/san_vpn.md)
in the parent repository.

## Download

Each [release](https://github.com/wargasipil/san_vpn/releases) has one file
per OS, plus `SHA256SUMS`:

```sh
# Linux
curl -fsSLo san_vpn https://github.com/wargasipil/san_vpn/releases/latest/download/san_vpn-linux-amd64
chmod +x san_vpn
```

```powershell
# Windows
Invoke-WebRequest -OutFile san_vpn.exe https://github.com/wargasipil/san_vpn/releases/latest/download/san_vpn-windows-amd64.exe
```

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a version tag is pushed. It runs `build.sh` with the tag as the version, so
`san_vpn --version` prints the tag:

```sh
git tag -a v0.2.0 -m "san_vpn v0.2.0"
git push origin v0.2.0
```

## Build

```powershell
pwsh build.ps1      # Windows: fetch Wintun, vet, test, build bin/san_vpn.exe and bin/san_vpn
bash build.sh       # Linux: the same
```

The Windows binary embeds `wintun.dll` (the tunnel driver from
[wintun.net](https://www.wintun.net)). The build script downloads it once into
`internal/osnet/wintun/` and checks its SHA-256. It is not checked in, so a plain
`go build` on a fresh clone fails until the script has run. At runtime,
`san_vpn up` writes the DLL next to the exe. The result is one file to copy.

## Set up with a dev tunnel

Choose one machine to run the relay, for example the office PC. It needs no
public IP.

**1. Set up the relay** (on the relay machine, in a normal terminal):

```powershell
san_vpn setup init
```

This does everything the dev tunnel needs, and each step checks before it acts:

- installs the `devtunnel` CLI if it is missing (winget on Windows,
  Microsoft's script on Linux)
- signs you in with GitHub; a browser opens. On Linux with no display it
  prints a device code instead (`--device-code` forces that)
- creates the relay's key and network
- creates a persistent tunnel with a random name (`san-vpn-xxxxxx`), allows
  anonymous clients, and forwards port 8443
- records the tunnel's public URL as the relay's URL

Run it again at any time. On a working setup it changes nothing. If something
broke, it repairs that step only: for example a tunnel the service expired
after 30 unused days, or anonymous access that was turned off.

Anonymous access is safe here. Only members with a key the relay issued an
invite for can connect, and every packet is WireGuard-encrypted. If you keep the
tunnel private instead, see `--header` below.

**2. Run the relay**, and keep it running:

```powershell
san_vpn relay run
```

It serves the relay on `127.0.0.1:8443` and runs `devtunnel host` beside it,
restarting it if it drops. Stopping the relay stops the tunnel host too, even
if the relay is killed. Use the same user account as `setup init`, because
the dev tunnels sign-in is per user.

**3. Invite each machine** (on the relay machine):

```powershell
san_vpn relay invite home
san_vpn relay invite office
san_vpn relay invite jakarta-vps
```

Each invite is a `sanvpn1_...` string. It can be used once and expires after 24
hours (`--ttl` to change). Send it the way you would send a password.

**4. Join and connect each machine.** Use an administrator terminal on Windows,
or `sudo` on Linux:

```powershell
san_vpn join sanvpn1_...
san_vpn up                    # stays in the foreground; Ctrl+C to leave
```

On the relay machine itself, join over loopback so its traffic does not go out
through the dev tunnel and back:

```powershell
san_vpn join --url http://127.0.0.1:8443 sanvpn1_...
```

**5. Check it**

```text
> san_vpn setup check
relay  (C:\Users\me\AppData\Roaming\san_vpn\relay.json)
  ok   relay key IQjHvNEp..., network 10.77.0.0/24, 3 member(s)
  ok   devtunnel CLI 1.0.2094
  ok   signed in to dev tunnels as me (github)
  ok   tunnel san-vpn-k3x9qa.asse
  ok   anonymous access
  ok   port 8443 forwarded
  ok   tunnel is hosted
  ok   relay answers on http://127.0.0.1:8443
  ok   relay answers at https://san-vpn-k3x9qa-8443.asse.devtunnels.ms
  ok   WebSocket through san-vpn-k3x9qa-8443.asse.devtunnels.ms works

member  (C:\ProgramData\san_vpn\node.json)
  ok   office at 10.77.0.1/24, via http://127.0.0.1:8443
  ok   relay accepts this machine's key
  ok   san_vpn up is connected, 2 of 2 peer(s) online
```

`setup check` runs on any machine. It checks the relay part if this machine
runs the relay, and the member part if it has joined; a member needs an
administrator terminal for that. Each failure comes with the command that fixes
it, and the exit code is 1 if anything failed. The member check makes its own
short connection with this machine's key, so a running `up` stays connected.

```text
> san_vpn status
home  10.77.0.2/24  connected to https://abc123-8443.asse.devtunnels.ms for 3m

NAME         IP         RELAY   HANDSHAKE  RX        TX
office       10.77.0.1  online  12s ago    20.2 MiB  317.5 KiB
jakarta-vps  10.77.0.3  online  1m ago     1.1 MiB   880.0 KiB

> ping 10.77.0.1
```

The `RELAY` column is the relay's view: does it have a connection from that
peer? `HANDSHAKE` is WireGuard's: when the encrypted session was last renewed.
A recent handshake proves the whole path works.

## Commands

| Command | Where | What |
|---|---|---|
| `setup init [--port P] [--tunnel ID] [--device-code] [--no-install]` | relay | Install devtunnel, sign in, and create the relay, its tunnel, anonymous access and port. Safe to rerun. |
| `setup check [--json]` | any | Check the relay and its tunnel, and/or this member, end to end. |
| `relay init [--url U] [--network N]` | relay | Create the relay key and network (default `10.77.0.0/24`). Run it again to change the URL; the key is kept. |
| `relay run [--listen A] [--no-tunnel]` | relay | Serve the relay (default `127.0.0.1:8443`), and host the dev tunnel that `setup init` made. |
| `relay invite <name> [--ttl D]` | relay | Print a one-time invite. Names are lowercase letters, digits and `-`. |
| `relay list [--json]` | relay | List members and invites still waiting. |
| `relay remove <name>` | relay | Remove a member or an invite. A running relay disconnects the member within a second, and the other members drop it. |
| `join <invite> [--url U] [--header "K: V"] [--force]` | member, admin | Generate this machine's key and join. The private key never leaves the machine. |
| `up [--interface I] [--mtu M] [--no-firewall]` | member, admin | Create the tunnel interface and stay connected, reconnecting by itself. |
| `status [--json]` | member | This machine's connection and its peers. |

The admin commands (`invite`, `remove`) change the relay's file while
`relay run` is running, and it picks up the change. There is no admin port.

Global flags: `--state <dir>` (env `SAN_VPN_STATE`) and `--log-level`
(env `SAN_VPN_LOG_LEVEL`).

## Where things live

| | Windows | Linux |
|---|---|---|
| Relay (`relay.json`) | `%AppData%\san_vpn` | `~/.config/san_vpn` |
| Member (`node.json`, `status.json`) | `C:\ProgramData\san_vpn`, SYSTEM and Administrators only | `/var/lib/san_vpn`, mode 0700 |
| Interface | `san_vpn` (Wintun) | `sanvpn0` (TUN) |

## Notes

- **Windows firewall.** A new adapter starts in the Public profile, which blocks
  inbound traffic, even ping. `up` adds one inbound rule named `san_vpn`. It
  allows traffic from the VPN range to this machine's VPN address only.
  `--no-firewall` skips it.
- **Linux firewall.** `up` does not touch it. With ufw, run
  `ufw allow in on sanvpn0`.
- **A private dev tunnel.** If you don't use `-a`, pass the token on join:
  `san_vpn join --header "X-Tunnel-Authorization: tunnel <token>" ...`, using a
  token from `devtunnel token san-vpn --scopes connect`. These tokens expire,
  so an always-on VPN is easier with an anonymous tunnel.
- **Other fronts.** The relay is plain HTTP and WebSocket, so a VPS behind
  Caddy or nginx, or Cloudflare Tunnel, works the same way. Skip `setup init`
  and set the URL with `relay init --url` instead.
- **Restarts.** If a member or the relay restarts, the others reconnect by
  themselves within a few seconds.

## Limits

- **Every packet passes through the relay.** Latency is home → relay → office,
  and the relay's bandwidth is the network's bandwidth.
  - Microsoft dev tunnels are a developer service with usage limits (reported
    as about 5 GB a month) and no SLA. That is fine for SSH, RDP and admin work.
  - For heavy transfers, move the relay to a VPS.
- **TCP inside TCP.** The WebSocket rides TCP, so on lossy links (mobile, bad
  Wi-Fi) throughput drops more than with native WireGuard.
- **No boot service yet.** `up` runs in a terminal.
- **IPv4 only, no DNS names.** Use the addresses that `status` shows.
- **Only the machines running san_vpn are on the network**, not their LANs.
- **The relay is trusted to say who the members are.** It cannot read traffic,
  but a compromised relay could add a member of its own.
