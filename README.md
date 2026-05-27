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

`add-node` and `remove-node` publish automatically; `publish` is for re-issuing
after editing the working directory by hand or to recover from a partial upload.

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
```

Defaults are populated automatically; you usually only need to set
`[wireguard]`, `[directory]`, `[drop.admin]` (admin only), and `[drop.client]`.

## Files Tincan touches

- `/etc/tincan/config.toml` — primary config, mode `0600`
- `/var/lib/tincan/cache.bin` — last successfully-applied directory
- `/var/lib/tincan/cache.serial` — monotonic serial guard against rollback
- `/var/lib/tincan/state.json` — sync metadata (last sync time, ETag)
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
