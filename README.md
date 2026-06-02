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
- Every **client node** holds the shared age identity and the publisher's public
  key. It pulls the blob from the dead-drop, verifies the signature, decrypts
  it, and reconciles its local WireGuard interface against the resulting peer
  list.
- Nodes that don't run Tincan can still participate as plain WireGuard peers —
  they just won't auto-update when membership changes.

The directory blob carries a monotonic `serial`; clients refuse to apply blobs
older than the one they already cached, which protects against rollback.

## Features (MVP)

- Single Go binary: `tincan`
- Linux client/admin support
- Dead-drop backends: S3-compatible object storage, HTTP (read-only for
  clients), and local filesystem (e.g. shared NFS/SMB mount)
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
- a shared age identity (used by every node to decrypt the directory)
- a publisher Ed25519 keypair (the private half is what makes this node an
  admin)
- a local "working directory" containing just this one node

It prints all the generated keys to stdout, including the secrets you need to
distribute. **Save these somewhere safe** — `init` does not.

Pass `--force` to overwrite an existing config, or `--cache /path` to write
the cache somewhere other than the default `/var/lib/tincan/cache.bin`.

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

If you don't pass `--pubkey`, Tincan generates a WireGuard keypair for the new
node. Without `--bootstrap`, the **private key** is printed to stdout once for
you to transmit manually; with `--bootstrap`, it's written into a JSON
**node bootstrap file** that contains everything the new node needs to come up.
Transmit that file over a secure channel and delete it after the client has
joined.

If the operator has already generated their own keys locally, pass `--pubkey`
instead so the secret never leaves their machine. The bootstrap file is still
useful in that case — it just won't contain a private key.

`--endpoint` is optional. Omit it for nodes that sit behind NAT and dial out;
include `host:port` for nodes that are publicly reachable. A mesh of
endpoint-less nodes cannot form without a relay, and `tincan status` will warn
you when it sees that situation.

Other admin commands:

```sh
sudo tincan list-nodes        # show the current directory
sudo tincan remove-node --name bob
sudo tincan publish           # re-publish the working directory
```

`add-node` and `remove-node` publish automatically; pass `--no-publish` to defer
the upload (changes are saved to the working directory). `publish` is for
re-issuing after deferred edits or to recover from a partial upload.

### 3. Bring up a client node

On the new node, install the `tincan` binary. The fastest path is to use the
bootstrap file the admin sent in step 2:

```sh
sudo tincan join --bootstrap /tmp/bob.json
sudo tincan up
```

`join --bootstrap` populates `[directory]`, `[drop.client]`, and (if the admin
generated it) the WireGuard keypair from the bootstrap. Nothing else to edit.

If you don't have a bootstrap file, do it manually:

```sh
sudo tincan join --name bob --drop-type s3
```

`join` writes a skeleton `/etc/tincan/config.toml`. By default it prompts for
the WireGuard private key on stdin; alternatively:

- `--private-key-file /path/to/key` — read it from a file
- `--generate-key` — generate a fresh keypair locally and print the public key
  so the admin can `add-node --pubkey ...`

Pass `--force` to overwrite an existing config, or `--cache /path` to use a
non-default cache location. As with `init`, `--full-config` writes every
applicable section and field at its default instead of the minimal set.

Edit the config and fill in:

- `[directory]` — `network_identity` (the age secret key) and
  `publisher_pubkey`, both from the admin's `init` output
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

### 4. Verify

```sh
sudo tincan status
```

`status` prints the local node name, tunnel IP, cache state, daemon liveness,
dead-drop reachability, and the live WireGuard peer table with last-handshake
ages. `--json` emits the same data as JSON.

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

If the direct peer-to-peer path stays broken (no handshake for ~90s while
keepalives go out), each client switches that peer to **relayed** mode:
the admin's `AllowedIPs` is widened to cover the peer's tunnel IP, so data
packets flow through the admin instead. The peer's own entry stays in the
local WireGuard config but with empty `AllowedIPs` — kernel keepalives keep
attempting handshakes to its endpoint in the background, while no actual
data routes through it. This is the **shadow peer**: a probe channel that
doesn't interrupt the working relay path.

The moment one of those background handshakes succeeds, the daemon
observes a fresh `LastHandshakeTime` via wgctrl and flips the peer back to
direct — just by reshuffling `AllowedIPs`, no peer add/remove. There are
no timed probes, no flapping; recovery happens whenever the kernel
manages to handshake.

To enable the relay role, the admin node must allow IP forwarding:

```sh
sysctl -w net.ipv4.ip_forward=1
# persistent:
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-tincan.conf
```

The admin daemon warns on startup if forwarding is off. There is no
client-side configuration — relay fallback is on by default for every
non-admin node.

`tincan status` shows the chosen mode per peer (`direct` or `relayed via X`).
Per-peer mode lives in daemon memory; on daemon restart all peers start in
direct mode and converge to relayed within ~90s if the direct path is
broken.

### Limitations

- A single relay target is chosen — the first non-self node in the
  directory with an `Endpoint` set. Multi-relay topologies and explicit
  relay-role selection aren't supported yet.
- If the admin/relay node itself is unreachable, relayed peers are
  unreachable too. The relay isn't a failover for the admin being down.

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
# secure = false                # set to disable TLS (HTTP-only MinIO etc.)

[drop.client]
type = "s3"
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"
# access_key / secret_key — omit for anonymous read, or provision read-only keys
```

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
network_identity = "AGE-SECRET-KEY-1..."   # shared age secret (every node)
publisher_pubkey = "..."                   # admin's Ed25519 public key (every node)
publisher_key    = "..."                   # admin's Ed25519 private key (admins only)

[drop.admin]    # admin-only: where this node writes the directory
type = "s3"   # or "http" / "file" — see backend sections above
# ...backend-specific fields...

[drop.client]   # how every node reads the directory
type = "s3"
# ...backend-specific fields...

[sync]
interval = "5m"                # daemon poll interval
cache    = "/var/lib/tincan/cache.bin"
pid_file = "/run/tincan.pid"

[observe]                      # admin-only; see Endpoint discovery
enabled         = true         # default on for admins; set false to stop discovering NAT'd peer endpoints
handshake_fresh = "3m"         # how recent a peer handshake must be to count as observed

[discovery]                    # LAN peer discovery via multicast beacons
enabled         = true         # default on; set false to suppress beacon send/receive
multicast_ipv4  = "239.255.84.67:51821"
multicast_ipv6  = "[ff02::1:8443]:51821"
beacon_interval = "30s"        # steady-state cadence
beacon_ttl      = "90s"        # learned endpoint expiry (must be >= 2x beacon_interval)
```

Defaults are populated automatically; you usually only need to set
`[wireguard]`, `[directory]`, `[drop.admin]` (admin only), and `[drop.client]`.

## Files Tincan touches

- `/etc/tincan/config.toml` — primary config, mode `0600`
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
