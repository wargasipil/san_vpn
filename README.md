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

Later, the binary updates itself:

```sh
san_vpn update --check        # is a newer release out?
san_vpn update                # install the latest release
san_vpn update v0.1.0         # or a given one, older ones too
```

It downloads this OS's file from the release, checks it against `SHA256SUMS`,
runs its `--version`, and only then replaces itself. A binary in a protected
folder (`/usr/local/bin`, `Program Files`) needs `sudo` or an administrator
terminal. A running `up` or `relay run` keeps the old version until it
restarts. A local build, stamped with its build time, is replaced only with
`--force`.

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml)
when a version tag is pushed. It runs `build.sh` with the tag as the version, so
`san_vpn --version` prints the tag. It also publishes the relay's container
image, built from the [`Dockerfile`](Dockerfile), as
`ghcr.io/wargasipil/san_vpn:<tag>` for Cloud Run:

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

- installs the `devtunnel` CLI if it is missing: winget on Windows, or,
  where winget is missing or fails (Windows Server, LTSC, older Windows 10),
  Microsoft's direct download into `%LocalAppData%\san_vpn`. On Linux it uses
  Microsoft's install script.
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

That sign-in lasts only several days. When it expires, the tunnel goes offline
and the relay logs `the dev tunnel is offline: its sign-in is no longer valid`.
Sign in again on the relay machine with `devtunnel user login -g` (or rerun
`san_vpn setup init`). Hosting resumes within 15 seconds; the relay keeps
running.

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

## Or run the relay on Google Cloud Run

Instead of behind a dev tunnel, the relay can run on Cloud Run. Then no
machine of yours has to stay on for the network to work, and there is no dev
tunnel usage limit. It costs money; see below.

**1. Deploy it** from any machine with the
[gcloud CLI](https://cloud.google.com/sdk/docs/install), signed in with
`gcloud auth login`:

```powershell
san_vpn setup cloudrun --dry-run    # look first: lists the gcloud commands it would run
san_vpn setup cloudrun              # --project, --region (default asia-southeast2, Jakarta)
```

Like `setup init`, each step checks before it acts, so it is safe to rerun:

- turns on the Cloud Run and Artifact Registry APIs if they are off
- creates a private bucket, `gs://<project>-san-vpn`, for the relay's file
  (`--state gs://...` picks another)
- creates a service account that may read and write that bucket, and nothing
  else
- creates the relay's key in the bucket, with your own gcloud sign-in
- creates an Artifact Registry repository that caches `ghcr.io`, where each
  release publishes the relay's image (`--image` runs another, and a local
  build needs it)
- deploys the service `san-vpn-relay`: one instance at most, a one-hour request
  timeout, open to anyone. The relay itself admits only its members' keys.
- records the service's URL as the relay's URL, and checks it, WebSocket
  included

**2. Invite each machine** from any machine signed in to gcloud. The admin
commands read and write the bucket directly:

```powershell
$env:SAN_VPN_STATE = "gs://<project>-san-vpn"
san_vpn relay invite home
san_vpn relay list
san_vpn setup check
```

Joining and `up` work as with a dev tunnel. A machine that is already in the
dev tunnel network keeps both with `san_vpn join --profile cloudrun ...`; see
[Profiles](#switch-networks-with-profiles).

How the relay fits Cloud Run:

- **Its file is in Cloud Storage**, because Cloud Run's disk does not outlive a
  restart. Every write is conditional on the file's version, so a join and an
  admin command never overwrite each other. The relay looks for changes every
  five seconds.
- **One instance.** Members meet in one process. With two instances, members on
  different ones could not reach each other. During a deploy Cloud Run may run
  two for a moment; members reconnect within seconds.
- **Hour-long connections.** Cloud Run ends every request at its timeout, at
  most an hour, and each member's connection is one request. The relay asks
  members to renew a few minutes before that (`SAN_VPN_SESSION_LIMIT`). They
  open the new connection before closing the old one, so traffic does not stop
  and WireGuard keeps its sessions.
- **Cost.** The instance is busy whenever a member is connected, so expect it to
  run all month: about US$45 a month for 1 vCPU at us-central1 prices after the
  free tier, more in Jakarta, plus internet egress for every byte the relay
  forwards. A small VPS is cheaper. Cloud Run is for when you want nothing to
  look after.

## Switch networks with profiles

A dev tunnel relay and a Cloud Run relay are two separate networks. Each has
its own key and its own members, so a machine joins each one with that relay's
own invite. A profile keeps each membership on the machine, and `up` brings up
one of them at a time:

```powershell
san_vpn join sanvpn1_...                      # the first network: profile "default"
san_vpn join --profile cloudrun sanvpn1_...   # a second one, beside it
san_vpn profile rename default tunnel         # optional: name the first after its relay
san_vpn profile use cloudrun                  # from now on, san_vpn up brings up cloudrun
san_vpn up                                    # or, just this once: san_vpn up --profile tunnel
```

```text
> san_vpn profile list
  PROFILE   MEMBER  ADDRESS       RELAY                                           STATE
* cloudrun  home    10.77.0.2/24  https://san-vpn-relay-abc123-et.a.run.app       running
  tunnel    home    10.77.0.4/24  https://san-vpn-k3x9qa-8443.asse.devtunnels.ms  stopped
```

- `--profile <name>` (env `SAN_VPN_PROFILE`) works on `join`, `up`, `status`
  and `setup check`. Without it, `join` and `up` use the current profile, the
  one `profile use` chose. `status` and `setup check` show the running
  profile, or else the current one.
- **One profile is up at a time.** Both networks are usually `10.77.0.0/24` and
  would use the same interface, so `up` refuses to start while another profile
  runs. To switch, stop `up` (Ctrl+C), then `profile use <name>` and `up`.
- **Members meet only on the same relay.** A machine on `tunnel` cannot reach
  one on `cloudrun`, so switch every machine that needs to reach the others.
- A machine's first membership becomes the current profile, whatever it is
  called. A `node.json` from before profiles existed is the profile `default`,
  and stays where it is until you rename it.
- Profiles are for members. The relay commands still pick their relay with
  `--state`: the dev tunnel relay's file on the relay machine, the Cloud Run
  relay's in `gs://<project>-san-vpn`.

## Commands

| Command | Where | What |
|---|---|---|
| `setup init [--port P] [--tunnel ID] [--device-code] [--no-install]` | relay | Install devtunnel, sign in, and create the relay, its tunnel, anonymous access and port. Safe to rerun. |
| `setup cloudrun [--project P] [--region R] [--service S] [--image I] [--timeout D] [--dry-run]` | any, with gcloud | Run the relay on Cloud Run, its file in Cloud Storage. Safe to rerun. |
| `setup check [--json] [--profile P]` | any | Check the relay and its tunnel, and/or this member, end to end. |
| `relay init [--url U] [--network N]` | relay | Create the relay key and network (default `10.77.0.0/24`). Run it again to change the URL; the key is kept. |
| `relay run [--listen A] [--no-tunnel] [--session-limit D]` | relay | Serve the relay (default `127.0.0.1:8443`, or `:$PORT` when `PORT` is set), and host the dev tunnel that `setup init` made. With `--session-limit`, members renew their connections before a front cuts them. |
| `relay invite <name> [--ttl D]` | relay | Print a one-time invite. Names are lowercase letters, digits and `-`. |
| `relay list [--json]` | relay | List members and invites still waiting. |
| `relay remove <name>` | relay | Remove a member or an invite. A running relay disconnects the member within seconds, and the other members drop it. |
| `join <invite> [--url U] [--header "K: V"] [--force] [--profile P]` | member, admin | Generate this machine's key and join. The private key never leaves the machine. With `--profile`, keep it beside the networks this machine is already in. |
| `up [--interface I] [--mtu M] [--no-firewall] [--profile P]` | member, admin | Create the tunnel interface and stay connected, reconnecting by itself. |
| `status [--json] [--profile P]` | member | This machine's connection and its peers. |
| `profile list [--json]` | member, admin | This machine's profiles: the one `up` brings up, and the one running. |
| `profile use <profile>` | member, admin | Make a profile the one `up` brings up. A running `up` switches once restarted. |
| `profile rename <old> <new>` | member, admin | Rename a profile, e.g. `default` to `tunnel`. Not while `up` runs on it. |
| `update [tag] [--check] [--force]` | any | Replace this binary with the latest release, or with release `tag`, once it matches `SHA256SUMS` and runs. |

The admin commands (`invite`, `remove`) change the relay's file while
`relay run` is running, and it picks up the change. There is no admin port.

Global flags: `--state <dir>` (env `SAN_VPN_STATE`; for the relay commands
also `gs://<bucket>[/<folder>]`) and `--log-level` (env `SAN_VPN_LOG_LEVEL`).

## Where things live

| | Windows | Linux |
|---|---|---|
| Relay (`relay.json`) | `%AppData%\san_vpn` | `~/.config/san_vpn` |
| Relay on Cloud Run | `gs://<project>-san-vpn/relay.json` | the same |
| Member (`node.json`, `status.json`) | `C:\ProgramData\san_vpn`, SYSTEM and Administrators only | `/var/lib/san_vpn`, mode 0700 |
| Other profiles (`profiles/<name>/node.json`), the current one (`profile.json`) | in the member's folder | the same |
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

- **Windows 10 or Windows Server 2016 and newer.** That is the oldest Windows
  that Go programs run on. Windows 7 and 8.1 are out.
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
  but a compromised relay could add a member of its own. On Cloud Run, the same
  goes for anyone who can write the bucket, which also holds the relay's key.
- **Cloud Run support is new.** It has been tested with a fake gcloud, and with
  the relay's image in Docker against a Cloud Storage emulator. It has not yet
  run on a real Google Cloud project.
