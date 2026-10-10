# san_vpn

`san_vpn` joins machines at home, at the office and in other regions into one
private network. Every machine gets an address such as `10.77.0.2` and a name
such as `home.vpn`, and every machine can reach every other one by either:
ping, SSH, RDP, a database port.

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
per OS and processor, plus `SHA256SUMS`:

```sh
# Linux
curl -fsSLo san_vpn https://github.com/wargasipil/san_vpn/releases/latest/download/san_vpn-linux-amd64
chmod +x san_vpn
```

```sh
# Raspberry Pi: san_vpn-linux-arm64 when `uname -m` says aarch64,
# san_vpn-linux-arm when it says armv6l or armv7l
curl -fsSLo san_vpn https://github.com/wargasipil/san_vpn/releases/latest/download/san_vpn-linux-arm64
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
`ghcr.io/wargasipil/san_vpn:<tag>`, for running the relay in Docker. Cloud Run
does not use it: `cloudrun deploy` builds the same Dockerfile from the tag's
source in your own project.

```sh
git tag -a v0.2.0 -m "san_vpn v0.2.0"
git push origin v0.2.0
```

## Build

```powershell
pwsh build.ps1      # Windows: fetch Wintun, vet, test, build bin/san_vpn.exe and bin/san_vpn
bash build.sh       # Linux: the same
```

Both also build `bin/san_vpn-linux-arm64` and `bin/san_vpn-linux-arm` for
Linux on ARM, such as a Raspberry Pi. The 32-bit one targets ARMv6, so it runs
on every Pi, the Pi 1 and Zero included.

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
  ok   office.vpn resolves to 10.77.0.1 (names answered at 10.77.0.254)
```

`setup check` runs on any machine. It checks the relay part if this machine
runs the relay, and the member part if it has joined; a member needs an
administrator terminal for that. Each failure comes with the command that fixes
it, and the exit code is 1 if anything failed. The member check makes its own
short connection with this machine's key, so a running `up` stays connected.

```text
> san_vpn status
home  10.77.0.2/24  connected to https://abc123-8443.asse.devtunnels.ms for 3m
names home.vpn and the others below, answered at 10.77.0.254

NAME             IP         RELAY   HANDSHAKE  RX        TX
office.vpn       10.77.0.1  online  12s ago    20.2 MiB  317.5 KiB
jakarta-vps.vpn  10.77.0.3  online  1m ago     1.1 MiB   880.0 KiB

> ping office.vpn
```

The `RELAY` column is the relay's view: does it have a connection from that
peer? `HANDSHAKE` is WireGuard's: when the encrypted session was last renewed.
A recent handshake proves the whole path works.

## Or run the relay on Google Cloud Run

Instead of behind a dev tunnel, the relay can run on Cloud Run. Then no
machine of yours has to stay on for the network to work, and there is no dev
tunnel usage limit. It costs money; see below.

**1. Set up and deploy it** from any machine with the
[gcloud CLI](https://cloud.google.com/sdk/docs/install), signed in with
`gcloud auth login`:

```powershell
san_vpn cloudrun setup --dry-run    # look first: lists the gcloud commands it would run
san_vpn cloudrun setup              # --project, --region (default asia-southeast2, Jakarta)
san_vpn cloudrun deploy             # builds the relay from source and runs it; takes a few minutes
```

`cloudrun setup` readies the project once. Like `setup init`, each step checks
before it acts, so it is safe to rerun:

- turns on the Cloud Run, Artifact Registry and Cloud Build APIs if they are
  off
- creates a private bucket, `gs://<project>-san-vpn`, for the relay's file
  (`--state gs://...` picks another), and names it relay profile `cloudrun`
  on this machine (`--relay` picks another name; see
  [Relay profiles](#look-after-several-relays-with-relay-profiles))
- creates a service account that may read and write that bucket, and nothing
  else
- creates the relay's key in the bucket, with your own gcloud sign-in, and
  records the project, region and service there for `cloudrun deploy`
- creates an Artifact Registry repository, `san-vpn`, for the relay's images
- lets Cloud Build's service account build, if it may not yet (projects made
  since mid-2024 build as the Compute Engine default account, which may hold
  no role)

`cloudrun deploy` builds and runs the relay:

- builds the image with Cloud Build, from the source of this release
  (downloaded from GitHub), into the `san-vpn` repository. A release already
  built there is not built again. `--source <dir>` builds a checkout of your
  own instead, as does `go run` started in one; `--image` runs an image as it
  is, with no build.
- deploys the service `san-vpn-relay`: one instance at most, a one-hour request
  timeout, open to anyone. The relay itself admits only its members' keys.
- records the service's URL as the relay's URL, and checks it, WebSocket
  included

After `san_vpn update`, run `san_vpn cloudrun deploy` again to move the relay
to the new release. Members reconnect on their own.

**2. Invite each machine** from any machine signed in to gcloud. The admin
commands read and write the bucket directly:

```powershell
san_vpn relay invite --relay cloudrun home
san_vpn relay list --relay cloudrun
san_vpn setup check --relay cloudrun
san_vpn relay profile use cloudrun      # or make it the relay these commands use without --relay
```

On another machine, name the relay first:
`san_vpn relay profile add cloudrun gs://<project>-san-vpn`. A relay set up
before relay profiles existed gets its name the same way, or by running
`cloudrun setup` again. `--state gs://...` (env `SAN_VPN_STATE`) still names
the bucket directly, as before.

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
- Profiles are for members. The relay side has its own:
  [relay profiles](#look-after-several-relays-with-relay-profiles).

## Look after several relays with relay profiles

A machine that looks after more than one relay, say the dev tunnel relay it
serves and the one on Cloud Run, names each one. The relay commands then work
on one of them at a time. An invite holds its relay's URL and key, so it joins
that relay's network and no other. A relay command that picked the wrong relay
would invite the machine into the wrong network.

```powershell
san_vpn cloudrun setup                       # the Cloud Run relay: relay profile "cloudrun"
san_vpn relay profile rename default tunnel  # optional: name the dev tunnel relay after its front
san_vpn relay invite home                    # the current relay: tunnel
san_vpn relay invite --relay cloudrun home   # or, just this once, another one
san_vpn relay profile use cloudrun           # from now on, the relay commands use cloudrun
```

```text
> san_vpn relay profile list
  RELAY     URL                                             MEMBERS  WHERE
* cloudrun  https://san-vpn-relay-abc123-et.a.run.app       2        gs://my-project-san-vpn
  tunnel    https://san-vpn-k3x9qa-8443.asse.devtunnels.ms  3        C:\Users\me\AppData\Roaming\san_vpn
```

- `--relay <name>` (env `SAN_VPN_RELAY`) works on `relay init`, `relay run`,
  `relay invite`, `relay list`, `relay remove`, `setup init`, `setup check`,
  `cloudrun setup` and `cloudrun deploy`. Without it they use the current
  relay profile, the one `relay profile use` chose. The cloudrun commands use
  the current one when it is in Cloud Storage, else `cloudrun`.
- It is `--relay`, not `--profile`: a member profile and a relay profile are
  different things, often with the same name, and `setup check` takes both.
- **A relay profile is only a name for where the relay's file is.** That is a
  folder on this machine, or a `gs://` location. `rename` and `forget` never
  move or delete a file. A relay from before relay profiles is `default`, in
  the folder it always used.
- `relay init --relay <name>` or `setup init --relay <name>` makes a new relay
  on this machine, in `relays/<name>/`. Two dev tunnel relays need different
  ports (`setup init --port`). A machine's first relay becomes the current
  one, whatever it is called.
- `relay profile add <name> <location>` names a relay made elsewhere, such as
  the Cloud Run relay on a second admin machine.
- `relay run` serves only a relay on this machine's disk. A relay in a bucket
  is served by Cloud Run, and a second copy here would split its members
  between two relays.
- `--state gs://...` still names one relay directly and takes no `--relay`.
  `--state <dir>` moves the folder that holds the relays and `relays.json`.

## Names

Every member is also reachable by name: its member name plus the network's
domain, `vpn` unless the relay sets another. `ssh office.vpn`,
`mstsc /v:home.vpn`, `http://jakarta-vps.vpn:8080`.

There is no name server to run. Each member answers for the names itself, from
the member list the relay already sends it:

- The network's last address, `10.77.0.254` in `10.77.0.0/24`, is kept for
  names, and the relay gives it to no member. `up` answers DNS queries to it
  inside the tunnel. Nothing listens on port 53, so it cannot clash with a DNS
  server the machine already runs, such as Pi-hole or dnsmasq.
- `up` points the domain, and only the domain, at that address:
  - Windows: a Name Resolution Policy Table rule (`Get-DnsClientNrptRule`),
    removed when `up` stops.
  - Linux with systemd-resolved (Ubuntu, Fedora): the domain on the `sanvpn0`
    link (`resolvectl status sanvpn0`).
  - Other Linux (Debian servers, Raspberry Pi OS, Alpine): a block in
    `/etc/hosts` between `# san_vpn begin` and `# san_vpn end`, rewritten
    as members come and go and removed when `up` stops.
- Every other name resolves exactly as before.
- `setup check` resolves this machine's own name the way programs do, so it
  checks the whole path. `nslookup office.vpn 10.77.0.254` asks the
  member's server directly.
- On Windows, plain `nslookup office.vpn` ignores the rule and asks the
  usual DNS server. Test with `ping`, `Resolve-DnsName office.vpn`, or
  `nslookup office.vpn 10.77.0.254`.

To use another domain, run `san_vpn relay init --domain corp.internal` on the
relay. Members pick it up within seconds, without a restart. Avoid `local`:

- it belongs to multicast DNS, which is how `raspberrypi.local` and
  `printer.local` work
- Linux machines with nss-mdns never send `.local` names to a DNS server
- on Windows, the rule would catch those LAN names too

`up --no-dns` turns names off on one machine. There are no names in a
network smaller than /29, which has no address to spare. There are none either
where a relay from before names already gave `.254` to a member; `up` logs
it.

## Commands

| Command | Where | What |
|---|---|---|
| `setup init [--port P] [--tunnel ID] [--device-code] [--no-install] [--relay R]` | relay | Install devtunnel, sign in, and create the relay, its tunnel, anonymous access and port. Safe to rerun. |
| `cloudrun setup [--project P] [--region R] [--service S] [--dry-run] [--relay R]` | any, with gcloud | Ready a project for the relay on Cloud Run, its file in Cloud Storage, and name it relay profile `cloudrun` (or `R`). Safe to rerun. |
| `cloudrun deploy [--source DIR] [--image I] [--timeout D] [--dry-run] [--relay R]` | any, with gcloud | Build the relay from source with Cloud Build and run it. Again after `update`, to move it to the new release. |
| `setup check [--json] [--profile P] [--relay R]` | any | Check the relay and its tunnel, and/or this member, end to end. |
| `relay init [--url U] [--network N] [--domain D] [--relay R]` | relay | Create the relay key and network (default `10.77.0.0/24`, names under `vpn`). Run it again to change the URL or the domain; the key is kept. A new `--relay` name makes another relay. |
| `relay run [--listen A] [--no-tunnel] [--session-limit D] [--relay R]` | relay | Serve the relay (default `127.0.0.1:8443`, or `:$PORT` when `PORT` is set), and host the dev tunnel that `setup init` made. With `--session-limit`, members renew their connections before a front cuts them. |
| `relay invite <name> [--ttl D] [--relay R]` | relay | Print a one-time invite, and the relay URL it is for. Names are lowercase letters, digits and `-`. |
| `relay list [--json] [--relay R]` | relay | List members and invites still waiting. |
| `relay remove <name> [--relay R]` | relay | Remove a member or an invite. A running relay disconnects the member within seconds, and the other members drop it. |
| `relay profile list [--json]` | relay | The relays this machine looks after, their URLs and members, and the one the relay commands use. |
| `relay profile use <name>` | relay | Make a relay profile the one the relay commands use without `--relay`. |
| `relay profile add <name> <dir or gs://...>` | relay | Name a relay made elsewhere, such as the Cloud Run relay on another admin machine. |
| `relay profile rename <old> <new>` | relay | Rename a relay profile, e.g. `default` to `tunnel`. No file moves. |
| `relay profile forget <name>` | relay | Drop a relay profile's name. The relay itself stays as it is. |
| `join <invite> [--url U] [--header "K: V"] [--force] [--profile P]` | member, admin | Generate this machine's key and join. The private key never leaves the machine. With `--profile`, keep it beside the networks this machine is already in. |
| `up [--interface I] [--mtu M] [--no-firewall] [--no-dns] [--profile P]` | member, admin | Create the tunnel interface, answer the members' names, and stay connected, reconnecting by itself. |
| `status [--json] [--profile P]` | member | This machine's connection and its peers. |
| `profile list [--json]` | member, admin | This machine's profiles: the one `up` brings up, and the one running. |
| `profile use <profile>` | member, admin | Make a profile the one `up` brings up. A running `up` switches once restarted. |
| `profile rename <old> <new>` | member, admin | Rename a profile, e.g. `default` to `tunnel`. Not while `up` runs on it. |
| `update [tag] [--check] [--force]` | any | Replace this binary with the latest release, or with release `tag`, once it matches `SHA256SUMS` and runs. |

The admin commands (`invite`, `remove`) change the relay's file while
`relay run` is running, and it picks up the change. There is no admin port.

Global flags: `--state <dir>` (env `SAN_VPN_STATE`; for the relay commands
also `gs://<bucket>[/<folder>]`, which names one relay directly) and
`--log-level` (env `SAN_VPN_LOG_LEVEL`).

## Where things live

| | Windows | Linux |
|---|---|---|
| Relay (`relay.json`) | `%AppData%\san_vpn` | `~/.config/san_vpn` |
| Other relays (`relays/<name>/relay.json`), the relay profiles and the current one (`relays.json`) | in the relay's folder | the same |
| Relay on Cloud Run | `gs://<project>-san-vpn/relay.json` | the same |
| Member (`node.json`, `status.json`) | `C:\ProgramData\san_vpn`, SYSTEM and Administrators only | `/var/lib/san_vpn`, mode 0700 |
| Other profiles (`profiles/<name>/node.json`), the current one (`profile.json`) | in the member's folder | the same |
| Interface | `san_vpn` (Wintun) | `sanvpn0` (TUN) |
| Names, while `up` runs | an NRPT rule with the comment `san_vpn` | systemd-resolved's setting for `sanvpn0`, else a block in `/etc/hosts` |

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
- **IPv4 only.** Names resolve to IPv4 addresses. They cover the members
  only: no reverse lookups and no other records.
- **Only the machines running san_vpn are on the network**, not their LANs.
- **The relay is trusted to say who the members are.** It cannot read traffic,
  but a compromised relay could add a member of its own. On Cloud Run, the same
  goes for anyone who can write the bucket, which also holds the relay's key.
- **Names on Windows are new.** The rule's commands and parameters are
  checked, and names ran end to end on Linux with a real kernel, but the rule
  has not yet been added on a real Windows machine.
- **Cloud Run support is new.** It has been tested with a fake gcloud, and with
  the relay's image in Docker against a Cloud Storage emulator. It has not yet
  run on a real Google Cloud project.
