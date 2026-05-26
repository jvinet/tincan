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
- One-shot and daemonized sync, with SIGHUP-triggered reload
- Local cache + serial file so the network stays up if the dead-drop is
  temporarily unreachable

## Requirements

- Linux with the `wireguard` kernel module (or `wireguard-go`) available
- `CAP_NET_ADMIN` to manage the tunnel interface — in practice, run
  `tincan sync` as root or under a systemd unit with the capability granted
- Go 1.24+ to build from source

## Build

```sh
go build -o ./bin/tincan ./cmd/tincan
# or
make build
```

A statically-linked binary lands in `./bin/tincan`. Copy it to `/usr/local/bin`
on your nodes.

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

Now edit `/etc/tincan/config.toml` and fill in the `[drop]` block (bucket name,
credentials, etc.), then publish the initial directory:

```sh
sudo tincan publish
```

`publish` seals the working directory, signs it with the publisher key, and
uploads it to the dead-drop.

### 2. Add client nodes (admin side)

```sh
sudo tincan add-node --name bob --endpoint 198.51.100.7:51820
```

If you don't pass `--pubkey`, Tincan generates a WireGuard keypair for the new
node and prints the **private key** to stdout once. Transmit it to the operator
over a secure channel, then clear your terminal. If the operator has already
generated their own keys locally, pass `--pubkey` instead so the secret never
leaves their machine.

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

`add-node` and `remove-node` publish automatically; `publish` is for re-issuing
after editing the working directory by hand or to recover from a partial upload.

### 3. Bring up a client node

On the new node, install the `tincan` binary, then run:

```sh
sudo tincan join --name bob --drop-type s3
```

`join` writes a skeleton `/etc/tincan/config.toml`. By default it prompts for
the WireGuard private key on stdin; alternatively:

- `--private-key-file /path/to/key` — read it from a file
- `--generate-key` — generate a fresh keypair locally and print the public key
  so the admin can `add-node --pubkey ...`

Edit the config and fill in:

- `[directory]` — `network_identity` (the age secret key) and
  `publisher_pubkey`, both from the admin's `init` output
- `[drop]` — the same backend coordinates the admin used (read-only credentials
  are fine for clients)

Then sync:

```sh
sudo tincan sync           # one-shot, exits after applying the directory
sudo tincan sync --daemon  # fork into background, poll periodically
sudo tincan sync --once    # alias for one-shot, useful from cron
```

### 4. Verify

```sh
sudo tincan status
```

`status` prints the local node name, tunnel IP, cache state, daemon liveness,
dead-drop reachability, and the live WireGuard peer table with last-handshake
ages. `--json` emits the same data as JSON.

## Running as a daemon

`tincan sync --daemon` double-forks into the background, writes a PID file
(default `/run/tincan.pid`), and polls the dead-drop on `[sync].interval`
(default `5m`).

Signals the daemon understands:

- `SIGHUP` — reload `config.toml` and run a sync iteration immediately
- `SIGTERM` / `SIGINT` — clean shutdown

For systemd, prefer a plain service rather than `--daemon`:

```ini
[Unit]
Description=Tincan sync
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tincan sync
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

## Dead-drop backends

All three backends store and retrieve the same opaque blob. Pick whichever is
operationally easiest.

### S3-compatible object storage

```toml
[drop]
type = "s3"
endpoint = "s3.amazonaws.com"   # or your MinIO/Backblaze/etc. host
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"    # defaults to "directory.bin"
access_key = "..."              # required on the admin
secret_key = "..."              # required on the admin
# secure = false                # set to disable TLS (HTTP-only MinIO etc.)
```

Clients can read without credentials if the bucket policy allows it; otherwise
provision read-only keys.

### HTTP (read-only)

```toml
[drop]
type = "http"
url = "https://example.com/_vpn/directory.bin"
# username = "bob"
# password = "letmein"
```

HTTP is download-only — admins cannot `publish` to an HTTP drop. Pair it with
S3/file for publishing and HTTP for clients if you want to expose the blob
through a CDN or static host.

### Local filesystem

```toml
[drop]
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

[drop]
type = "s3"   # or "http" / "file" — see backend sections above
# ...backend-specific fields...

[sync]
interval = "5m"                # daemon poll interval
cache    = "/var/lib/tincan/cache.bin"
pid_file = "/run/tincan.pid"
```

Defaults are populated automatically; you usually only need to set
`[wireguard]`, `[directory]`, and `[drop]`.

## Files Tincan touches

- `/etc/tincan/config.toml` — primary config, mode `0600`
- `/var/lib/tincan/cache.bin` — last successfully-applied directory
- `/var/lib/tincan/cache.serial` — monotonic serial guard against rollback
- `/var/lib/tincan/state.json` — sync metadata (last sync time, ETag)
- `/var/lib/tincan/directory-source.bin` — admin-only working directory
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
