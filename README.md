# Tincan

Tincan is a small mesh-VPN orchestration tool for WireGuard. It keeps an
encrypted, signed directory of node public keys, tunnel IPs, and endpoints in a
**dead-drop** backend, then syncs that directory onto Linux WireGuard
interfaces.

It is intended to sit between full-fat coordination services like
Tailscale/Netbird/Nebula and a fully manual `wg`/`wg-quick` deployment: you keep
running your own infrastructure, but you no longer have to touch every node when
membership changes.

## How it works

- An **admin node** holds the publisher signing key and writes a signed,
  age-encrypted directory blob to a shared dead-drop.
- Every node has its **own age keypair**. The directory is encrypted to the
  recipients of all current members, so each node decrypts the blob with its
  own identity. A client pulls the blob, verifies the publisher's signature,
  decrypts it, and reconciles its WireGuard interface against the peer list.
- Membership is **cryptographically revocable without a control plane**:
  `remove-node` drops a node's recipient, and the next `publish` re-encrypts to
  the remaining members only. The removed node keeps its key but can no longer
  decrypt new directories — no shared secret to rotate across the fleet.
- Nodes that don't run Tincan can still participate as plain WireGuard peers —
  they just won't auto-update when membership changes (and aren't recipients).

The directory blob carries a monotonic `serial`; clients refuse to apply blobs
older than the one they already cached, which protects against rollback. The
serial guards against an *older* directory, not a drop frozen at the current
one; set `[sync] max_directory_age` to also warn when the directory's
`CreatedAt` falls behind (see the configuration reference).

## Features (MVP)

- Single Go binary: `tincan`
- Linux client/admin support
- Dead-drop backends: S3-compatible object storage, HTTP (read-only for
  clients), DNS TXT records (Linode, DigitalOcean, Cloudflare, deSEC, or OVH), and local
  filesystem (e.g. shared NFS/SMB mount)
- Signed (Ed25519) and age-encrypted directory blobs
- Full-mesh WireGuard peer configuration via `wgctrl`/netlink (no `wg-quick`)
- Explicit `up` / `down` / `sync` lifecycle, plus a daemon mode that reconciles
  continuously with SIGHUP-triggered reload
- Network and node bootstrap files for one-shot client onboarding
- Local cache + serial file so the network stays up if the dead-drop is
  temporarily unreachable
- Optional endpoint discovery: an admin node can observe NAT'd peers'
  source endpoints and republish them so NAT'd peers can reach each other
  directly (UDP hole punching). See [Endpoint discovery](#endpoint-discovery).
- Automatic relay fallback: when a NAT'd peer-to-peer path can't be
  established (symmetric NAT, same-LAN hairpin, etc.) clients route the
  affected peer's traffic through the admin node and continue to re-probe
  the direct path on network changes. See [Relay fallback](#relay-fallback).
- Optional VPN DNS names: set a network domain (`tincan set-domain vpn`)
  and every node resolves as `<name>.<domain>` — members via a managed
  `/etc/hosts` block, plain-WireGuard spokes via a small DNS server on the
  hub. See [VPN DNS names](#vpn-dns-names).

## Requirements

- Linux with the `wireguard` kernel module (or `wireguard-go`) available
- `CAP_NET_ADMIN` to manage the tunnel interface — in practice, run
  `tincan up` as root or under a systemd unit with the capability granted
- Go 1.24+ to build from source

## Build

```sh
go build -o ./bin/tincan ./cmd/tincan
# or
make build
```

A statically-linked binary lands in `./bin/tincan`. Copy it to `/usr/local/bin`
on your nodes. Verify with `tincan version`.

## Quick start

The examples below assume an S3-compatible dead-drop. Replace the `--drop-type`
flag and the `[drop]` section with `http` or `file` for the other backends.

### 1. Bootstrap the first admin node

```sh
sudo tincan init \
  --name alice \
  --drop-type s3 \
  --endpoint 203.0.113.10:51820 \
  --cidr 10.42.0.0/24
```

`init` generates fresh material and writes `/etc/tincan/config.toml` (mode
`0600`):

- a WireGuard keypair for this node
- this node's own age keypair (its identity decrypts the directory; its
  recipient is what the directory is encrypted to)
- a publisher Ed25519 keypair (the private half is what makes this node an
  admin)
- a local "working directory" containing just this one node

It prints all the generated keys to stdout, including the secrets you need to
distribute. **Save these somewhere safe** — `init` does not.

Pass `--force` to overwrite an existing config, or `--state-dir /path` to put
the cache and its sibling state files somewhere other than the default
`/var/lib/tincan`.

By default the generated config is minimal: it lists only the fields you are
likely or required to change. Pass `--full-config` to instead write every
section and field that applies to this role, each at its default value.

Now edit `/etc/tincan/config.toml` and fill in `[drop.admin]` (where this node
writes the directory) and `[drop.client]` (how other nodes read it). For most
backends these are the same coordinates with different credentials; for HTTP,
`[drop.admin]` is the local file you write before uploading and `[drop.client]`
is the URL clients fetch from. See [Dead-drop backends](#dead-drop-backends).

Then publish the initial directory:

```sh
sudo tincan publish
```

`publish` seals the working directory, signs it with the publisher key, uploads
it to the dead-drop, and refreshes `/var/lib/tincan/netboot.json` — the network
bootstrap file you'll distribute to clients.

### 2. Add client nodes (admin side)

```sh
sudo tincan add-node --name bob --endpoint 198.51.100.7:51820 \
  --bootstrap /tmp/bob.json
```

If you don't pass `--pub-key`, Tincan generates both a WireGuard keypair and an
age keypair for the new node. Without `--bootstrap`, the **private key** and
**age identity** are printed to stdout once for you to transmit manually; with
`--bootstrap`, they're written into a JSON **node bootstrap file** that contains
everything the new node needs to come up. Transmit that file over a secure
channel and delete it after the client has joined.

If the operator has already generated their own keys locally (via
`tincan join --generate-key`), pass `--pub-key` **and** `--age-recipient` so
neither secret ever leaves their machine. The bootstrap file is still useful in
that case — it just won't contain the secrets.

`--endpoint` is optional. Omit it for nodes that sit behind NAT and dial out;
include `host:port` for nodes that are publicly reachable. The port you publish
becomes the node's WireGuard listen port: it travels in the bootstrap so `join`
binds exactly the port peers are told to reach. A mesh of endpoint-less nodes
cannot form without a relay, and `tincan status` will warn you when it sees that
situation.

Pass `--relay` (which requires `--endpoint`) to mark the node as the network's
designated relay: peers route through it when a direct path can't form. Without
any marked relay, Tincan falls back to the first node that has an endpoint, so
`--relay` is how you make the choice explicit rather than directory-order
dependent. See [Relay fallback](#relay-fallback).

Other admin commands:

```sh
sudo tincan list-nodes        # show the current directory
sudo tincan remove-node --name bob
sudo tincan publish           # re-publish the working directory
```

`add-node` and `remove-node` publish automatically; pass `--no-publish` to defer
the upload (changes are saved to the working directory). `publish` is for
re-issuing after deferred edits or to recover from a partial upload.

`remove-node` is also how you **revoke** a node: the publish that follows
re-encrypts the directory to the remaining members' recipients only, so the
removed node can no longer decrypt new directories. It keeps whatever blob it
already cached but is locked out of every future one — no fleet-wide rekey.

Before uploading, `publish` fetches the directory currently at the drop so it
never reuses an already-published serial. If that fetch fails (an empty drop
on first publish is fine), it refuses to proceed — pass `--force` to publish
anyway when you know the drop contents are older than your working directory.

### 3. Bring up a client node

On the new node, install the `tincan` binary. The fastest path is to use the
bootstrap file the admin sent in step 2:

```sh
sudo tincan join --bootstrap /tmp/bob.json
sudo tincan up
```

`join --bootstrap` populates `[directory]` (the node's own `network_identity`
and the `publisher_pubkey`), `[drop.client]`, the node's `listen_port` (when the
admin published an endpoint for it), and (if the admin generated it) the
WireGuard keypair from the bootstrap. Nothing else to edit. The bootstrap also
carries the directory serial current at enrollment, which `join` seeds as the
node's rollback floor — even the first sync refuses a directory older than the
bootstrap.

If you don't have a bootstrap file, do it manually:

```sh
sudo tincan join --name bob --drop-type s3 --generate-key
```

`join` writes a skeleton `/etc/tincan/config.toml`. `--generate-key` generates
this node's WireGuard **and** age keypairs locally and prints the WireGuard
public key and the age recipient, so the admin can run
`add-node --pub-key <key> --age-recipient <recipient>` — neither secret ever
leaves the node. Without `--generate-key`, `join` prompts for the WireGuard
private key on stdin (no echo); alternatively `--private-key-file /path/to/key`
reads it from a file, and you fill `[directory].network_identity` (this node's
age secret) by hand.

Pass `--force` to overwrite an existing config, or `--state-dir /path` to use a
non-default state directory. As with `init`, `--full-config` writes every
applicable section and field at its default instead of the minimal set.

If you joined without a node bootstrap, edit the config and fill in:

- `[directory]` — `network_identity` (this node's age secret) and
  `publisher_pubkey` (from the admin's `init` output)
- `[drop.client]` — the same backend coordinates the admin uses (read-only
  credentials are fine for clients)

Then bring the tunnel up:

```sh
sudo tincan up             # sync from the drop, then create tincan0 and apply peers
sudo tincan up --no-sync   # apply the cached directory without contacting the drop
sudo tincan up --daemon    # fork into background, continuously sync and apply
```

`sync` and `up` are split so you can refresh the local cache without touching
the interface:

```sh
sudo tincan sync           # fetch the latest directory and cache it
sudo tincan up --no-sync   # apply that cache to the interface
sudo tincan down           # tear the interface down
sudo tincan down --stop    # tear the interface down and stop the daemon too
```

### 4. Enroll a plain WireGuard client (mobile / QR)

A phone or any device running the native WireGuard app can join without the
Tincan binary. Pass `--client-type=wireguard` and `add-node` generates the
keypair, allocates a tunnel IP, and produces a standard `wg-quick` config as one
or more enrollment artifacts (pick at least one):

```sh
# scan straight off the terminal
sudo tincan add-node --name phone --client-type=wireguard --wg-qr
# or write a PNG to send, and/or a plain .conf file
sudo tincan add-node --name phone --client-type=wireguard \
  --wg-qr-png phone.png --wg-config phone.conf
```

(The default `--client-type=tincan` is the agent-running client from step 2,
where `--bootstrap` applies; the two flag sets are mutually exclusive and
`add-node --help` lists them in separate sections.)

These are **hub-and-spoke**: the client peers with one node — the network's
relay (a node marked `--relay`, else the first with a public `--endpoint`) — and
routes the whole network CIDR through it (add an endpoint-bearing node first, or
you'll get an error). Traffic toward the client works the same way: its config
knows only the hub, so every other node automatically routes the client's
tunnel IP through the hub (see [Relay fallback](#relay-fallback)). It's a
point-in-time snapshot — the device doesn't run Tincan, so it won't pick up
later directory changes (rotated keys, moved endpoints, new nodes); re-run to
refresh it.

Lost the config for a node that's already enrolled? `tincan render-node --name
phone` regenerates its `wg-quick` config from the current directory. The admin
never stores node private keys, so the rendered config carries a `PrivateKey`
placeholder unless you pass `--private-key` (validated against the node's
published key); the same `--wg-qr` / `--wg-qr-png` / `--wg-config` sinks apply
(the QR sinks need `--private-key`, since a QR must be directly scannable).

With `--wg-qr` the QR code is the only thing written to stdout, so you can
redirect it: `... --wg-qr >phone.txt`. That text round-trips only when
re-rendered in a real terminal (`cat phone.txt`) — pasted into chat or webmail
the line spacing breaks it, so prefer `--wg-qr-png` (or `--wg-config`) for
anything you transmit. Every artifact embeds the node's **private key** (the
files are written `0600`): treat them as secrets and remove them once the device
is enrolled.

### 5. Verify

```sh
sudo tincan status
```

`status` prints the local node name, tunnel IP, cache state (including the
directory's age), daemon liveness, dead-drop reachability, and the live
WireGuard peer table with last-handshake ages. `--json` emits the same data as
JSON.

`tincan status --network` instead prints a whole-directory roster — every node
with its tunnel IP, endpoint, role (`relay`/`self`), and handshake age — *as
seen from this node*. Tincan has no control plane, so it can't poll other nodes:
the handshake column reflects only this node's own WireGuard sessions (a node it
doesn't peer with reads `no session`, not "down"). Run it on the admin, which in
a full mesh talks to everyone, for the most complete picture.

## Running as a daemon

`tincan up --daemon` double-forks into the background, writes a PID file
(default `/run/tincan.pid`), and reconciles every `[sync].interval`
(default `5m`) by syncing from the drop and re-applying the directory.

Signals the daemon understands:

- `SIGHUP` — reload `config.toml` and run an iteration immediately
- `SIGTERM` / `SIGINT` — clean shutdown

`tincan down --stop` sends `SIGTERM` to the PID-file process and waits for it to
exit before tearing down the interface, so the daemon can't re-apply the
directory and re-raise the link on its way out. Plain `tincan down` leaves the
daemon running (it will simply bring the interface back up on its next
reconcile).

For systemd, prefer a plain service rather than `--daemon`:

```ini
[Unit]
Description=Tincan
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tincan up
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Drop `--daemon` so the unit runs in the foreground and systemd owns the process.
(The unit above runs a single iteration and exits; switch to a `oneshot` service
with a systemd timer if you'd rather schedule it externally.)

## Logging

Tincan writes structured logs to the OS syslog (facility `daemon`, tag
`tincan`) from every state-changing command and from the daemon loop. The
human-friendly console output (`✓`, colored headlines, `tincan status`
tables) is unchanged — syslog is separate and meant for debugging,
monitoring, and log shipping.

```
May 29 18:23:01 zeroflux tincan[12345]: level=INFO msg=synced source=drop serial=76
May 29 18:23:01 zeroflux tincan[12345]: level=INFO msg="relay transition" peer=tau mode=relayed via=zf
```

Set verbosity with `TINCAN_LOG_LEVEL` (`debug`, `info`, `warn`, `error`;
default `info`). For systemd:

```ini
[Service]
Environment=TINCAN_LOG_LEVEL=debug
```

Tail the daemon's recent activity:

```sh
journalctl -t tincan -f       # systemd-journald
tail -f /var/log/daemon.log   # classic syslog
```

## Endpoint discovery

By default a NAT'd node can only reach peers whose `Endpoint` is set in the
directory (typically public hosts). Two NAT'd peers can't reach each other,
because neither has an address the other can dial.

When observation is enabled on an admin node, that admin watches its
WireGuard interface for inbound handshakes from NAT'd peers, records each
peer's apparent source `ip:port`, and republishes the directory with those
observations attached to each node. Other peers pick up the observation on
their next sync and write it into their local WireGuard config; the standard
25-second keepalive on NAT'd nodes holds the NAT mapping open long enough for
the peer-to-peer handshake to complete (UDP hole punching).

Observation is **on by default for admin nodes** — a freshly initialized admin
needs no extra configuration. To turn it off:

```toml
[observe]
enabled = false
```

The setting only takes effect on an admin node (one with a publisher key and a
`[drop.admin]`); a client that leaves it unset never observes.

The admin must already be a daemon (`tincan up --daemon` or under systemd) so
that observation runs each `[sync].interval`. No client-side configuration is
required — clients automatically prefer an operator-configured `Endpoint`,
then fall back to the admin's observation.

Hole punching works for most consumer NATs (full-cone, restricted-cone,
port-restricted). It does **not** work for symmetric NAT (some carrier-grade
NAT, some corporate firewalls) — the admin's observed port differs from the
port the peer would have to use to reach you. Two peers behind the same
residential router are similarly weak: they share the same observed public
IP and require the router to hairpin UDP traffic back inside the LAN, which
many consumer routers don't do reliably. In both cases the [relay
fallback](#relay-fallback) takes over automatically.

## Relay fallback

If the direct peer-to-peer path stays broken (no handshake for 3 minutes
while keepalives go out), each client switches that peer to **relayed**
mode. The threshold sits above WireGuard's own rekey cadence on purpose: a
healthy session re-handshakes only every ~2 minutes, so shorter thresholds
would demote working paths. On demotion, the admin's `AllowedIPs` is
widened to cover the peer's tunnel IP, so data packets flow through the
admin instead. The peer's own entry stays in the
local WireGuard config but with empty `AllowedIPs` — kernel keepalives keep
attempting handshakes to its endpoint in the background, while no actual
data routes through it. This is the **shadow peer**: a probe channel that
doesn't interrupt the working relay path.

The moment one of those background handshakes succeeds, the daemon
observes a fresh `LastHandshakeTime` via wgctrl and flips the peer back to
direct — just by reshuffling `AllowedIPs`, no peer add/remove. There are
no timed probes, no flapping; recovery happens whenever the kernel
manages to handshake. Relay state is re-evaluated every 30 seconds,
independent of `[sync].interval`: both ends of a pair judge the same
handshake evidence, so the short cadence keeps their verdicts converged —
a one-sided relay decision blocks traffic in both directions until the
other side catches up.

The relay target is the node marked `--relay` (at `init` or `add-node`), or — if
none is marked — the first node in the directory with a public `Endpoint`. The
node serving as relay must allow IP forwarding:

```sh
sysctl -w net.ipv4.ip_forward=1
# persistent:
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-tincan.conf
```

The admin daemon warns on startup if forwarding is off. There is no
client-side configuration — relay fallback is on by default for every
non-admin node.

Plain WireGuard members (`--client-type=wireguard`) skip the failure
detection entirely. A spoke's enrolled config knows only its hub, so no
other node can ever reach it directly: it never initiates handshakes to
them, and drops theirs as coming from unknown keys. Every node except the
hub therefore routes the spoke's traffic through the hub from the first
iteration — including nodes that have their own public endpoint, which
never relay tincan peers — and the spoke's shadow peer carries no endpoint
or keepalive, since a background probe could never complete.

`tincan status` shows the chosen mode per peer (`direct` or `relayed via X`).
Per-peer mode lives in daemon memory; on daemon restart all peers start in
direct mode and converge to relayed within ~3 minutes if the direct path
is broken.

### Limitations

- A single relay target is chosen: a node marked `--relay` if one exists,
  otherwise the first non-self node with an `Endpoint` set. Marking more
  than one node `--relay` just picks the first such node — multi-relay /
  failover topologies aren't supported yet.
- If the relay node itself is unreachable, relayed peers are unreachable
  too. The relay isn't a failover for the relay being down.

## LAN peer discovery

Two NAT'd peers behind the same router would otherwise route through the
relay (the home router rarely hairpins UDP). LAN discovery cuts that out:
each daemon publishes a UDP multicast beacon on the local link
advertising its WireGuard pubkey and listen port; the receiving daemon
pairs the source IP with the announced port to learn a candidate LAN
endpoint and points WireGuard at it directly.

There's no admin coordination — discovery is purely client-to-client on
the LAN. Authentication is implicit: a spoofed beacon causes one failed
handshake (the attacker doesn't have the private key) and falls back to
the relay; nothing leaks. See `spec/lan-discovery.md` for the full
protocol.

Enabled by default. Disable per-node by setting `[discovery].enabled =
false`. Status output tags LAN-direct peers with `(lan)` after their
endpoint, and `tincan status --json` exposes the learned endpoints under
`.discovery`:

```sh
tincan status --json | jq '.discovery.lan_endpoints'
```

Defaults: IPv4 group `239.255.84.67:51821`, IPv6 `[ff02::1:8443]:51821`,
30-second beacon cadence, 90-second endpoint TTL. Most networks don't
need to touch these.

### Limitations

- Multicast must propagate on the LAN. Wi-Fi access points with client
  isolation enabled (common in hotels, some corporate networks) drop
  beacons. Discovery fails silently in that case and the relay carries on.
- VLAN-segregated guest networks behind one NAT see each other as same-
  `oep` but can't reach each other on the LAN. Same fallback.
- Only one LAN endpoint per peer is tracked; multi-homed peers (Wi-Fi +
  Ethernet on the same device) settle to whichever beacon arrives first.

## VPN DNS names

Set a non-public domain for the network and every node becomes reachable by
name:

```sh
# on the admin (or at first setup: tincan init --dns-domain vpn ...)
tincan set-domain vpn
```

```sh
ping nas.vpn
ssh alice.vpn
```

The domain lives in the signed directory, so it propagates like any other
change: members pick it up within one sync interval. `tincan set-domain`
with no argument shows the current domain from any node; `--clear` turns
the feature off network-wide. Setting a domain requires every node name to
be a valid DNS label (letters, digits, hyphens; ≤63 chars) — `set-domain`
refuses with a list of offenders otherwise, and `add-node` enforces the
rule for all new names so this never regresses.

Tincan members and plain-WireGuard spokes get names through two different
(deliberately independent) mechanisms:

**Members: a managed `/etc/hosts` block.** Every member already holds the
full name → tunnel-IP mapping — it's the directory it decrypts on every
sync — so no DNS server is involved at all. The daemon maintains a marker-
delimited block after each successful apply:

```
# BEGIN tincan managed block - do not edit between markers
10.42.0.1	alice.vpn
10.42.0.3	nas.vpn
# END tincan managed block
```

Entries are FQDN-only on purpose: if your machines already map bare names
like `nas` to LAN addresses in `/etc/hosts`, tincan never shadows them.
Everything outside the markers is preserved byte-for-byte; the block is
updated atomically, only when its content actually changed, and removed on
`tincan down` or after `set-domain --clear`. Resolution works offline
(it's a file), survives daemon restarts, and needs no resolver
configuration. A symlinked `/etc/hosts` (NixOS) is detected and left
alone, with a warning.

**Spokes: DNS served by the hub.** Phones and other plain-WireGuard
clients can't run tincan, so their rendered configs (add-node /
render-node) gain a line when a domain is set:

```
DNS = 10.42.0.1, vpn
```

That's the hub's tunnel IP plus the domain as a search domain (so `nas`
works as well as `nas.vpn`). The hub's daemon serves the domain on UDP 53
of its tunnel IP, answering from its cached directory. Mobile WireGuard
apps route *all* device DNS through that server while the tunnel is up, so
the hub forwards everything outside the domain to an upstream resolver —
by default the first nameserver in its own `/etc/resolv.conf`, overridable
with `[dns] upstream`.

The listener runs automatically on hub nodes only (the `--relay` node, or
the implicit relay target spokes were enrolled against) and only in daemon
mode. Force it on or off anywhere with `[dns] serve`. If something already
occupies port 53 on the hub (Pi-hole, dnsmasq), tincan warns once and
retries each sync; point `[dns] upstream` at that resident resolver if you
want VPN queries answered by tincan and the rest by it.

### Limitations

- Spoke configs are point-in-time snapshots: a domain set, cleared, or a
  hub moved after enrollment needs a re-render (`tincan render-node`).
  Clearing the domain is the sharp edge — spokes keep sending all their
  DNS to a hub that no longer answers, so `set-domain --clear` lists the
  affected spokes loudly.
- Names map to IPv4 tunnel IPs only (AAAA queries return empty NOERROR so
  dual-stack clients fall through to A cleanly).
- The hub's listener is UDP-only; single-record answers always fit. See
  `spec/dns.md` for the full design.
- Upgrade the **admin node first**: an older admin binary republishing the
  directory (e.g. endpoint observation) doesn't know the domain field and
  would silently drop it.

## Dead-drop backends

Every config has two drop sections: `[drop.admin]` is how this node writes the
directory (admin only); `[drop.client]` is how everyone reads it. Keeping them
separate means client nodes never see admin credentials, and admins can write
locally while clients pull from HTTP/CDN.

### S3-compatible object storage

```toml
[drop.admin]
type = "s3"
endpoint = "s3.amazonaws.com"   # or your MinIO/Backblaze/etc. host
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"    # defaults to "directory.bin"
access_key = "..."              # admin's read+write key
secret_key = "..."
# tls = false                   # set to false for HTTP-only endpoints (e.g. local MinIO)

[drop.client]
type = "s3"
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"
# access_key / secret_key — omit for anonymous read, or provision read-only keys
```

> Anonymous client reads work only if the object is already public. tincan does
> not manage bucket permissions — make the object public with your provider's own
> tooling (bucket policy / console), or give `[drop.client]` a read-only key.

### HTTP (read-only for clients)

```toml
[drop.admin]
type = "file"
path = "/var/www/tincan/directory.bin"   # admin writes the file; web server serves it

[drop.client]
type = "http"
url = "https://example.com/_vpn/directory.bin"
# username = "bob"
# password = "letmein"
```

The directory blob is encrypted regardless, but `username`/`password` (or
credentials embedded in the URL) are rejected over a cleartext `http://` URL
unless the host is loopback — use `https` so the drop credentials aren't
broadcast on every poll. A dead-drop is fetched directly; tincan refuses to
follow HTTP redirects.

HTTP is download-only — admins cannot `publish` to an HTTP drop. Combine a
file `[drop.admin]` (written into a web root) with an HTTP `[drop.client]` so
clients fetch through a CDN or static host.

### Local filesystem

```toml
[drop.admin]
type = "file"
path = "/mnt/shared/tincan/directory.bin"

[drop.client]
type = "file"
path = "/mnt/shared/tincan/directory.bin"
```

Useful for testing or when every node mounts a shared filesystem (NFS, SMB,
Syncthing, etc.).

### DNS TXT records

The directory can live in a DNS zone you control as a set of TXT records.
Clients read it with an ordinary DNS lookup — **no credentials and no provider
account** — which makes this the lightest-weight backend for client nodes. Only
the admin needs provider credentials, used to write the records.

```toml
[drop.admin]
type = "dns"
provider = "digitalocean"     # or "linode", "cloudflare", "desec"
zone = "example.com"          # a DNS zone hosted at the provider
record_name = "_tincan"       # host label the TXT records live at (default "_tincan")
api_token = "..."             # provider API token with DNS write access
# ttl = 300                   # optional record TTL in seconds

[drop.client]
type = "dns"
zone = "example.com"
record_name = "_tincan"
# resolver = "1.1.1.1"        # optional: query this resolver (host[:port]) instead of the system one
```

Clients never set a `provider` or any write credentials — they just resolve
`<record_name>.<zone>`. A `[drop.admin]` without a provider is read-only (like
`http`), so admins must configure a provider to `publish`.

Supported providers and how they authenticate:

- **`linode`, `digitalocean`, `cloudflare`, `desec`** — a single `api_token`
  (shown above), scoped to DNS write access. For Cloudflare, create an API token
  with the Zone:Read and DNS:Edit permissions on the zone. deSEC uses your
  account API token and enforces a minimum TTL (3600s by default), so tincan
  defaults `ttl` to 3600 when it is unset.
- **`ovh`** — OVH signs each request with three application credentials and a
  regional endpoint rather than a bearer token:

  ```toml
  [drop.admin]
  type = "dns"
  provider = "ovh"
  endpoint = "ovh-eu"        # OVH API region: ovh-eu (default), ovh-ca, ovh-us
  zone = "example.com"
  record_name = "_tincan"
  app_key = "..."
  app_secret = "..."
  consumer_key = "..."
  # ttl = 300
  ```

  Create the keys at OVH's token page (e.g. `https://eu.api.ovh.com/createToken/`)
  and grant the consumer key `GET`/`POST`/`PUT`/`DELETE` on `/domain/zone/*`.
  The `[drop.client]` side is identical to the example above (no credentials).

The zone must already be hosted at the provider — tincan writes records into it
but does not create the zone.

The sealed directory is base64-encoded and split across multiple TXT records
(each ≤255 bytes), tagged so clients reassemble them in order and ignore any
unrelated TXT records at the same name. Publishing is not atomic: during DNS
propagation a client that reads a half-updated set fails to reassemble or verify
it, keeps its cached directory, and picks up the change on the next sync — so a
short `ttl` is worthwhile. A directory needing more than ~100 records (≈16 KB, a
large network) is rejected; use S3 or HTTP for that.

## Configuration reference

`tincan` reads `/etc/tincan/config.toml` by default; override with
`-c /path/to/config.toml`. The file is created `0600` and Tincan warns at load
time if it isn't.

```toml
[wireguard]
name = "alice"                 # node name, must be unique in the directory
public_key  = "..."            # WireGuard public key (base64)
private_key = "..."            # WireGuard private key (base64)
interface   = "tincan0"        # interface name (default tincan0)
listen_port = 51820            # optional; inferred from --endpoint host:port
mtu         = 1420             # default 1420
keepalive   = "25s"            # optional persistent-keepalive for peers

[directory]
network_identity = "AGE-SECRET-KEY-1..."   # this node's own age secret (unique per node)
publisher_pubkey = "..."                   # admin's Ed25519 public key (every node)
publisher_key    = "..."                   # admin's Ed25519 private key (admins only)

[drop.admin]    # admin-only: where this node writes the directory
type = "s3"   # or "http" / "dns" / "file" — see backend sections above
# ...backend-specific fields...

[drop.client]   # how every node reads the directory
type = "s3"
# ...backend-specific fields...

[sync]
interval          = "5m"            # daemon poll interval
state_dir         = "/var/lib/tincan" # houses cache.bin and its sibling state files
pid_file          = "/run/tincan.pid"
# max_directory_age = "48h"         # optional: warn (sync/up/status) when the directory's
                                    # CreatedAt is older than this — catches a frozen or
                                    # withheld drop. Pair with a cron'd `tincan publish`
                                    # (which always re-stamps CreatedAt) as a heartbeat.

[observe]                      # admin-only; see Endpoint discovery
enabled         = true         # default on for admins; set false to stop discovering NAT'd peer endpoints
handshake_fresh = "3m"         # how recent a peer handshake must be to count as observed

[discovery]                    # LAN peer discovery via multicast beacons
enabled         = true         # default on; set false to suppress beacon send/receive
multicast_ipv4  = "239.255.84.67:51821"
multicast_ipv6  = "[ff02::1:8443]:51821"
beacon_interval = "30s"        # steady-state cadence
beacon_ttl      = "90s"        # learned endpoint expiry (must be >= 2x beacon_interval)

[dns]                          # VPN DNS names; active only when the directory has a domain
manage_hosts = true            # default on; maintain the managed /etc/hosts block
# serve      = true            # force the DNS listener on/off; unset = auto (hubs only)
# upstream   = "192.168.1.1"   # where the hub forwards non-VPN queries (host[:port],
                               # port 53 implied; default: first resolv.conf nameserver)
# hosts_path = "/etc/hosts"    # override the hosts file (tests, exotic layouts)
```

Defaults are populated automatically; you usually only need to set
`[wireguard]`, `[directory]`, `[drop.admin]` (admin only), and `[drop.client]`.

## Files Tincan touches

- `/etc/tincan/config.toml` — primary config, mode `0600`
- `/etc/hosts` — managed block between markers, only while the directory
  carries a VPN domain (see "VPN DNS names")
- `/var/lib/tincan/cache.bin` — last successfully-applied directory
- `/var/lib/tincan/cache.serial` — monotonic serial guard against rollback
- `/var/lib/tincan/state.json` — sync metadata (last sync time, ETag)
- `/var/lib/tincan/discovery.json` — learned LAN endpoints (see "LAN peer discovery")
- `/var/lib/tincan/directory-source.bin` — admin-only working directory
- `/var/lib/tincan/netboot.json` — admin-only network bootstrap (mode `0600`)
- `/run/tincan.pid` — daemon PID file

## Development

```sh
make build              # build ./bin/tincan
make test               # unit tests
make test-race          # unit tests with the race detector
make test-integration   # integration tests (build tag: integration)
make lint               # golangci-lint
make fmt                # gofmt
```

## License

See [LICENSE](LICENSE).
