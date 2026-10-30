# Tincan — MVP Implementation Plan

Status: **historical / superseded**. This is the original implementation plan,
not a description of today's system. Its shared age identity, flat `[drop]`,
`sync --daemon`, relay probing/timing, and out-of-scope feature list are obsolete.
The implementation now uses per-node recipients, separate drop roles and
sync/apply commands, shadow-peer recovery, DNS names, and additional backends.
Use the [current guides](../README.md#documentation) for supported behavior.

## Context

Tincan is a new mesh-VPN orchestration tool, being scaffolded from scratch
in `/home/jvinet/tincan-2/`. The only existing artifact is `spec.md`.

**Why build it:** the user runs Tailscale at home but their employer also
uses Tailscale on the same device under a BYOD policy — the two tailnets
can't be active simultaneously. Vendor-locked alternatives have the same
problem. Plain Wireguard solves it but is operationally painful: every
node-add forces every existing node to be reconfigured.

**What Tincan does:** maintain the canonical list of node pubkeys, tunnel
IPs, and endpoints (the "directory") encrypted at rest in a publicly-
readable "dead-drop" (S3, HTTP, filesystem). Admin nodes write new
directory blobs; clients periodically fetch, decrypt, verify, and apply.
Wireguard itself remains the data plane. Goal: simpler than Tailscale,
less painful than hand-rolled WG.

**Intended outcome:** a single Go binary `tincan` that can `init` an admin
node, `add-node` peers, and `sync` (one-shot or daemon) on clients to keep
the mesh converged. MVP targets Linux only.

---

## Decisions (locked in)

| Area                  | Choice |
|-----------------------|--------|
| Language / target     | Go 1.22+, Linux only (admin + client) |
| CLI                   | `github.com/alecthomas/kong` v1.x |
| TOML                  | `github.com/pelletier/go-toml/v2` (strict / DisallowUnknownFields) |
| Logging               | stdlib `log/slog` (text default, `--json` flag) |
| Crypto (encryption)   | `filippo.io/age` v1.3.x — shared X25519 identity (see Key model) |
| Crypto (signing)      | stdlib `crypto/ed25519` — admin publisher key (see Key model) |
| Blob serialization    | `github.com/vmihailenco/msgpack/v5` |
| WG config             | `golang.zx2c4.com/wireguard/wgctrl` (config only) |
| WG link / addr / route| `github.com/vishvananda/netlink` |
| S3 client             | `github.com/minio/minio-go/v7` (works for AWS, R2, MinIO, etc.) |
| Atomic file writes    | `github.com/google/renameio/v2` |
| Daemonization         | Hand-rolled `os.StartProcess` + env marker (`_TINCAN_DAEMON=1`), flock'd PID file — `sevlyar/go-daemon` is stale |
| Module path           | `github.com/jvinet/tincan` (user may rename) |
| Dead-drop backends    | S3 (incl. S3-compatible), HTTP (read-only client), local filesystem |
| Config default path   | `/etc/tincan/config.toml`; `--config` overrides |
| Cache / state dir     | `/var/lib/tincan/` (mode 0700) |
| PID file              | `/run/tincan.pid` (configurable) |
| Interface name        | default `tincan0`, configurable |
| IP allocation         | Admin auto-allocates next free /32 from a configured CIDR (default `10.42.0.0/24`) at `add-node` time |
| Tunnel /32 + CIDR rt  | Local addr is `tunnelIP/32`; explicit route added for `NetworkCIDR` dev `tincan0` |
| Routing model         | Full mesh; one /32 per peer; no subnet routes / exit nodes |
| Listen port           | Random ephemeral by default; required only when a node publishes an endpoint |
| Endpoints             | Either hostname:port or IP:port; re-resolved every sync iteration |
| Polling interval      | Configurable; default 5 minutes |
| Freshness             | Monotonic `serial` (uint64) inside the signed-then-encrypted blob; rollbacks rejected |
| Concurrency           | Last-write-wins; multi-admin coordination out of scope |
| Failure mode          | Cache last good directory locally; survive offline restarts; daemon never tears down WG on shutdown |
| Enrollment            | Hybrid: `add-node --pubkey <key>` accepts an existing WG pubkey, or admin generates a keypair and operator transmits the private key out-of-band |
| Verbs                 | `init`, `join`, `add-node`, `remove-node`, `list-nodes`, `publish`, `sync` (with `--daemon`), `status` |
| Name resolution / DNS | OUT OF SCOPE (no /etc/hosts, no stub resolver) |
| PSKs                  | OUT OF SCOPE (schema reserves the field for forward-compat) |

---

## Key model & crypto flow (corrects the spec)

The spec describes a single "directory keypair" with clients holding the
"public key" and decrypting with it. That doesn't match how X25519 works
— you decrypt with the private key. The interpretation we'll implement:

**Two distinct authorities:**

1. **Network membership** (read access to topology): a single shared
   age X25519 **identity** (`AGE-SECRET-KEY-1...`), held by every node
   (admin + clients). Used to decrypt blobs.
2. **Publisher authority** (write authenticity): an Ed25519 signing
   keypair, held only by admin. Public key is in every node's config.
   Used to sign each blob's plaintext before encryption.

**Each blob is**:

```
age_encrypt(
  msgpack({
    payload:   directory_msgpack,           # see schema below
    signature: ed25519_sign(admin_sk, directory_msgpack)
  }),
  recipient = age_recipient_of(network_identity)
)
```

**Publish path (admin):** marshal directory → ed25519 sign → wrap in
outer msgpack envelope → age-encrypt to network recipient → upload.

**Apply path (client):** download → age-decrypt with network identity →
parse envelope → verify ed25519 signature against admin pubkey → if both
pass and `serial >= cache.serial`, apply.

**Spec field rename:** what the spec called `[directory] public_key` on
clients is, in practice, the shared age identity. Final TOML names:

```toml
[directory]
network_identity = "AGE-SECRET-KEY-1..."   # required on every node
publisher_pubkey = "<base64-ed25519>"      # required on every node
publisher_key    = "<base64-ed25519-priv>" # admin only
```

`tincan init` generates both the network identity and the publisher
keypair, prints them, and writes them into the admin's config.
`tincan join` requires the operator to paste both `network_identity`
and `publisher_pubkey` (distributed out-of-band along with the WG private
key from `add-node`).

**Threat model:** stolen client config leaks read access to topology
only — attacker can't forge a directory (no publisher key) and can't
overwrite the drop (no write creds). Stolen admin publisher key alone
still requires drop write creds to be useful. Catastrophic case is loss
of both, which is the same risk profile as any system with an admin.

---

## Project layout

```
/home/jvinet/tincan-2/
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── spec.md                          # existing
├── Makefile                         # build / test / test-integration / lint
├── .golangci.yml
├── cmd/tincan/main.go               # kong.Parse → dispatch
└── internal/
    ├── cli/                         # one file per verb; each exports a Cmd struct with Run()
    │   ├── root.go                  # top-level kong struct, --config flag, globals
    │   ├── init.go
    │   ├── join.go
    │   ├── addnode.go
    │   ├── removenode.go
    │   ├── listnodes.go
    │   ├── publish.go
    │   ├── sync.go
    │   └── status.go
    ├── config/
    │   ├── schema.go                # types: Config, Wireguard, Directory, Drop, Sync
    │   └── config.go                # Load / Save / Default; strict-mode TOML; key-format validation
    ├── directory/
    │   ├── directory.go             # Directory, Node, Envelope types
    │   ├── codec.go                 # Marshal (sign+encrypt) / Unmarshal (decrypt+verify)
    │   ├── ipalloc.go               # NextFreeIP(cidr, taken) — host bits, skip .0 / broadcast / .1 if reserved
    │   └── serial.go                # IsRollback(newSerial, cachedSerial)
    ├── drop/
    │   ├── drop.go                  # Drop interface + factory New(cfg)
    │   ├── s3.go                    # minio-go backend (read+write)
    │   ├── http.go                  # GET/HEAD; Put → ErrReadOnly
    │   ├── file.go                  # filesystem (read+write via renameio)
    │   └── errors.go                # ErrNotFound, ErrReadOnly, ErrAuth
    ├── wg/
    │   ├── manager.go               # Manager: Ensure(self, dir) idempotent apply; Peers() snapshot
    │   ├── link.go                  # netlink link create/find/up
    │   ├── addr.go                  # idempotent /32 addr assign + CIDR route
    │   └── peers.go                 # buildPeerConfigs + endpoint resolution (operator > observed)
    ├── admin/
    │   └── observe.go               # MergeObservations: admin merges wgctrl peer state into directory
    ├── cache/
    │   └── cache.go                 # Read / Write (atomic via renameio); cache.bin, cache.serial, state.json
    ├── daemon/
    │   ├── daemon.go                # double-fork via env marker; signal loop
    │   └── pidfile.go               # flock-based PID file
    ├── keys/
    │   └── keys.go                  # WG keypair, age identity, ed25519 keypair helpers + base64 (de)serialization
    ├── log/
    │   └── log.go                   # slog setup
    └── version/
        └── version.go               # -ldflags injected
test/
├── fakedrop/fakedrop.go             # in-memory Drop for unit tests
├── integration/                     # //go:build integration — requires root + kernel
└── fixtures/
```

---

## Dependencies (go.mod)

```
require (
  filippo.io/age                            v1.3.1
  github.com/alecthomas/kong                v1.x
  github.com/google/renameio/v2             v2.0.0
  github.com/minio/minio-go/v7              v7.x
  github.com/pelletier/go-toml/v2           v2.x
  github.com/vishvananda/netlink            latest tagged
  github.com/vmihailenco/msgpack/v5         latest
  golang.zx2c4.com/wireguard/wgctrl         latest
)
```

Stdlib only: `crypto/ed25519`, `log/slog`, `net`, `net/netip`, `os`,
`os/signal`, `syscall`.

---

## Directory blob schema

`internal/directory/directory.go`:

```go
const SchemaVersion = 1

type Directory struct {
    SchemaVersion uint32    `msgpack:"v"`
    Serial        uint64    `msgpack:"s"`
    CreatedAt     time.Time `msgpack:"t"`     // UTC
    NetworkCIDR   string    `msgpack:"cidr"`  // e.g. "10.42.0.0/24" (string form for codec stability)
    Nodes         []Node    `msgpack:"nodes"`
}

type Node struct {
    Name             string    `msgpack:"n"`
    PublicKey        string    `msgpack:"pk"`               // WG pubkey, base64 (44 chars)
    TunnelIP         string    `msgpack:"ip"`               // e.g. "10.42.0.5" (no /32)
    Endpoint         string    `msgpack:"ep,omitempty"`     // operator-configured public endpoint (host:port); empty = NAT'd / roaming
    ObservedEndpoint string    `msgpack:"oep,omitempty"`    // admin-discovered NAT'd source endpoint; see Endpoint discovery
    ObservedAt       time.Time `msgpack:"oat,omitempty"`    // UTC; when ObservedEndpoint was last refreshed by the admin
    PSK              string    `msgpack:"psk,omitempty"`    // RESERVED — not used in MVP
}

// Keepalive is intentionally NOT in the directory — it's a local-node concern.
// See [wireguard].keepalive in the config and the NAT traversal section below.

// Envelope is what's actually age-encrypted.
type Envelope struct {
    Payload   []byte `msgpack:"p"`  // marshaled Directory
    Signature []byte `msgpack:"sig"` // ed25519 over Payload
}
```

Rules:
- Short msgpack tag names keep the blob compact.
- `omitempty` on every optional field — forward-compatible for older
  decoders; older clients reading newer blobs just ignore unknown fields.
- Tunnel IP & CIDR stored as strings (parsed on load) for codec stability.
- Serial monotonicity is enforced client-side. Admin sets
  `Serial = max(local, remote) + 1` on every publish.

---

## Config file schema (TOML)

```toml
[wireguard]
name        = "alice"
public_key  = "<wg pubkey base64>"
private_key = "<wg privkey base64>"        # file mode 0600
interface   = "tincan0"                     # optional; default tincan0
listen_port = 51820                         # optional; omit → ephemeral
mtu         = 1420                          # optional; default 1420
keepalive   = "25s"                         # optional; tunes the keepalive value used when this
                                            # node is NAT'd. Default 25s. Set to "0" to disable
                                            # even when NAT'd (unusual).

[directory]
network_identity = "AGE-SECRET-KEY-1..."    # required on every node
publisher_pubkey = "<base64 ed25519>"       # required on every node
publisher_key    = "<base64 ed25519 priv>"  # admin only

[drop]
type = "s3"   # one of: s3 | http | file
# Per-type fields (strict-mode rejects unknowns):

# type = "s3":
# endpoint   = "s3.amazonaws.com"   # or R2/MinIO/Wasabi endpoint
# region     = "us-east-1"
# bucket     = "my-tincan-net"
# object_key = "directory.bin"      # optional; default directory.bin
# access_key = "..."                # optional for read-only public buckets
# secret_key = "..."
# secure     = true                 # optional; default true

# type = "http":
# url      = "https://example.com/_vpn/directory"
# username = "bob"                  # optional
# password = "..."                  # optional

# type = "file":
# path = "/mnt/shared/tincan/directory.bin"

[sync]
interval = "5m"                              # time.ParseDuration; default 5m
cache    = "/var/lib/tincan/cache.bin"       # optional; shown is default
pid_file = "/run/tincan.pid"                 # optional; shown is default

[observe]                                    # admin only; opt-in endpoint discovery
enabled          = false                     # default off
handshake_fresh  = "3m"                      # peer is "fresh" if wgctrl handshake is within this window
refresh_interval = "15m"                     # refresh published ObservedAt on stable endpoints this often
```

Loading: `toml.NewDecoder(r).DisallowUnknownFields().Decode(&cfg)`.
Validate after decode: required fields, key formats (`age1` / `AGE-SECRET-KEY-1`
prefixes; WG keys base64-decode to 32 bytes; ed25519 keys to 32/64 bytes),
drop type matches per-type field set. Warn loudly if config mode is not 0600.

---

## Command flows

All eight verbs are kong subcommands. `init` and `join` run without an
existing config; everything else loads `--config` first.

**`tincan init --name <n> --drop-type <t> [--cidr 10.42.0.0/24] [--endpoint host:port]`**
1. Refuse if config exists unless `--force`.
2. Generate: WG keypair, age identity, ed25519 publisher keypair.
3. Pick admin's tunnel IP (first usable in CIDR, e.g. `10.42.0.1`).
4. Build initial in-memory `Directory{Serial: 1, ...}` with admin as the only node. If `--endpoint` was passed, set it on admin's entry. Write the **unencrypted** working copy to `/var/lib/tincan/directory-source.bin` (mode 0600).
5. Write skeleton TOML with all generated keys; `[drop]` section uses placeholder strings the operator must fill in.
6. Print to stdout: WG pub/priv, age `AGE-SECRET-KEY-1...` and `age1...`, ed25519 pub/priv, allocated IP, config path, and "next steps: edit [drop] section, then `tincan publish`".

**`tincan join --drop-type <t> --name <n> [--private-key-file <p>] [--generate-key]`**
1. Refuse if config exists unless `--force`.
2. Default: prompt for the WG private key the admin gave the operator (or read from `--private-key-file`). With `--generate-key`, generate a fresh keypair; operator must communicate the pubkey back to admin.
3. Write skeleton TOML: `[wireguard]` populated; `[directory]` and `[drop]` need to be filled with values from admin (`network_identity`, `publisher_pubkey`, drop creds/URL).
4. Print "next steps: fill `[directory]` + `[drop]`, then `tincan sync`".

**`tincan add-node --name <n> [--pubkey <k>] [--endpoint host:port]`**
1. Load config; require `publisher_key` present.
2. Fetch+decrypt+verify current directory (or use local working copy if drop unreachable; warn).
3. If `--pubkey` given, use it; else generate fresh WG keypair on the admin side.
4. Reject if name already exists.
5. Allocate IP via `NextFreeIP(cidr, takenIPs)`.
6. Append `Node{…}`; bump `Serial`; refresh `CreatedAt`.
7. Sign + encrypt; `drop.Put`.
8. Write to local cache and to `directory-source.bin`.
9. Print result. If a key was generated, print the **private key** with explicit instruction to transmit it securely and clear the terminal.

**`tincan remove-node --name <n>`**
1. Load config; require admin.
2. Fetch+decrypt+verify; refuse if name not present.
3. Remove node; bump serial; sign + encrypt; `drop.Put`.
4. Update cache and `directory-source.bin`.
5. Print freed IP. Note: removed peer remains in others' WG state until they sync.

**`tincan list-nodes`**
1. Load config.
2. `drop.Get` → decrypt with `network_identity` → verify signature with `publisher_pubkey`.
3. Render table: name, IP, pubkey-shortened, endpoint, keepalive, serial header.

**`tincan publish`**
1. Load config; require admin.
2. Load `directory-source.bin` (admin's working copy).
3. Bump serial if necessary (max(source, remote)+1); sign + encrypt; `drop.Put`.
4. Update cache.

**`tincan sync [--daemon] [--once]`**
One-shot flow:
1. Initialize `wg.Manager` for `[wireguard].interface`.
2. `drop.Get` with timeout (default 30s).
3. On Get failure: try cache; fail loudly if neither works.
4. Decrypt with `network_identity`; verify signature with `publisher_pubkey`; refuse if `Serial < cache.Serial` (rollback rejection).
5. Find self in directory by WG pubkey match; refuse if not present.
6. `wg.Manager.Ensure(self, dir)` — see WG lifecycle below.
7. Atomic-write cache (`cache.bin` + `cache.serial`) and `state.json`.
8. Exit 0.

Daemon flow:
1. Daemonize (see Daemon section).
2. Loop: run one-shot iteration; sleep `[sync].interval` between ticks; SIGHUP triggers reload + immediate iteration; SIGTERM/SIGINT triggers graceful shutdown without WG teardown.

**`tincan status [--json]`**
1. Load config + cache.
2. Print: node name + tunnel IP; WG state from `wgctrl.Device(name)` (peers, handshakes, transfer counters); cache age + serial; daemon PID + alive (`kill -0`); drop reachability (`Stat`).

---

## Daemon architecture

**Why hand-rolled, not `sevlyar/go-daemon`:** that library is unmaintained
since 2022 and its author warns against unpinned use. The double-fork
pattern is ~80 LOC.

**Sequence:**
1. Foreground (`tincan sync --daemon`): open + flock PID file (LOCK_EX|LOCK_NB); if held → another daemon running, exit non-zero with that PID. Spawn child via `os.StartProcess` with env `_TINCAN_DAEMON=1`, stdin = `/dev/null`, stdout/stderr = `/dev/null` (slog goes to journald). Parent writes child PID to PID file, releases flock, exits 0.
2. Child (`_TINCAN_DAEMON=1` set): `syscall.Setsid()`, `os.Chdir("/")`, `syscall.Umask(027)`, re-flock PID file (held for life), install signal handlers, enter polling loop.
3. Polling loop (`select` on ticker / immediate / sigCh / ctx.Done):
   - SIGTERM/SIGINT → cancel context → exit cleanly.
   - SIGHUP → reload config; re-init `wg.Manager` if interface name changed; trigger immediate sync.
   - Ticks coalesce (long iteration drains pending ticks).
   - Per-iteration timeout = `min(interval - 5s, 60s)` for the drop fetch.
   - A failing iteration logs and waits for the next tick; never crashes.
   - Iteration body: sync from drop → `manager.Ensure` → (admin-only, if `[observe].enabled`) merge wgctrl observations into source directory and republish if changed.
4. On exit: `flock(LOCK_UN)`, `os.Remove(pidFile)`.

PID file: `/run/tincan.pid`, mode 0644, ASCII PID + `\n`, advisory flock.

---

## Dead-drop interface

```go
package drop

type Metadata struct {
    Size      int64
    UpdatedAt time.Time
    ETag      string
}

type Drop interface {
    Get(ctx context.Context) ([]byte, error)
    Put(ctx context.Context, data []byte) error
    Stat(ctx context.Context) (Metadata, error)
    Name() string
}

var (
    ErrNotFound = errors.New("dead-drop: not found")
    ErrReadOnly = errors.New("dead-drop: read-only")
    ErrAuth     = errors.New("dead-drop: auth failed")
)
```

Backends:
- **`s3.go`** — minio-go with `Endpoint`/`Region`/`Secure` set from
  config. Works for AWS, Cloudflare R2, MinIO, Wasabi, Backblaze B2 S3 mode.
  `Get`/`Put`/`Stat` map directly. Empty access/secret keys → unauthenticated
  GET only (useful for public buckets).
- **`http.go`** — `Get` uses `http.Get` with optional basic auth, configurable
  timeout. `Stat` is HEAD. `Put` returns `ErrReadOnly`. Use for clients
  consuming a CDN-fronted admin-published blob.
- **`file.go`** — `os.ReadFile` / `renameio.WriteFile` / `os.Stat`. Useful
  for testing, NFS/SMB drops, or single-host multi-namespace setups.

DNS-TXT drop is out of scope for MVP.

---

## Wireguard interface lifecycle

`wgctrl` is config-only (verified). Link creation, addr, route → `netlink`.

`Manager.Ensure(self, dir)` is idempotent. Safe to call every sync iteration.

1. **Link**: `netlink.LinkByName(iface)`; if not found, `netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: {Name: iface, MTU: 1420}})`.
2. **WG config** via `wgctrl.ConfigureDevice` with `ReplacePeers: true`:
   - `PrivateKey` = self's WG key
   - `ListenPort` = `&self.ListenPort` (nil → ephemeral)
   - `Peers`: built from `dir.Nodes`, skip self; each peer has `ReplaceAllowedIPs: true`, `AllowedIPs: [tunnelIP/32]`, optional `Endpoint` (re-resolved each iteration via `net.DefaultResolver.LookupIPAddr`), `PersistentKeepaliveInterval` per NAT traversal rules below.
3. **Address**: ensure `tunnelIP/32` is on the link; remove stale addrs.
4. **Route**: ensure `NetworkCIDR dev iface scope link` exists.
5. **Link up**: `netlink.LinkSetUp(link)` if not already.

`ReplacePeers: true` + `ReplaceAllowedIPs: true` per peer = correct cleanup
when peers are removed; no explicit `Remove: true` needed.

`Teardown()` deletes the link via `netlink.LinkDel`. Not called automatically.

All `internal/wg/` files have `//go:build linux`.

### NAT traversal — PersistentKeepalive

Keepalive is a local-node concern, not a directory field. Wireguard's
`PersistentKeepalive` on a peer entry means "send a keepalive to this peer
every N seconds." It keeps the **local** node's outbound NAT mapping open;
it cannot help reach a peer that is itself NAT'd (without a published
endpoint, there's no address to send to — the NAT'd peer must initiate first).

**Rule applied in `buildPeerConfigs`:**

```go
// NAT status comes from the DIRECTORY's view of self (the network's
// authoritative view) — not from a local flag.
selfHasEndpoint := selfNode.Endpoint != ""

ka := cfg.Wireguard.Keepalive       // from [wireguard].keepalive; zero = use default
if ka == 0 && !selfHasEndpoint {
    ka = 25 * time.Second           // default for NAT'd self
}
// If selfHasEndpoint and ka was zero: leave 0 — no keepalive needed.

for _, peer := range otherPeers {
    if ka > 0 {
        peerCfg.PersistentKeepaliveInterval = &ka
    }
}
```

This means:
- A NAT'd node (no endpoint in the directory for itself) sends a 25-second
  keepalive to every peer by default — punches out, keeps NAT mappings live,
  and lets any peer reach it via the resulting flow.
- A public node (endpoint set in the directory) doesn't waste packets on
  keepalives — remote NAT'd peers do the work, and the kernel routes
  inbound naturally.
- Operators on a finicky NAT can tighten via `[wireguard].keepalive = "10s"`
  in their local config.
- Operators on a public node who *want* keepalive anyway (unusual but valid)
  can set `[wireguard].keepalive = "25s"` to force it on.

Two more notes:
- A node's NAT status is determined by the directory's view of itself, so it
  changes when admin runs `add-node --endpoint <hp>` (or `init --endpoint`).
  If a node's endpoint is later removed from the directory, that node
  automatically starts sending keepalives on its next sync.
- A NAT'd node still needs at least one peer with a public endpoint to be
  able to reach anyone. Tincan does not enforce this topologically, but
  `status` should warn if self has no endpoint AND all peers lack endpoints
  — and the warning is suppressed when at least one peer has an
  `ObservedEndpoint` (see Endpoint discovery below).

### Endpoint discovery (optional)

The keepalive rule above gets a NAT'd node *reachable* once any peer has its
endpoint, but says nothing about how a peer learns that endpoint. When both
ends are NAT'd, neither can name the other. Endpoint discovery closes that
gap by letting the admin act as a passive STUN-like coordinator.

Enabled per-admin via `[observe].enabled = true`. On each daemon iteration:

1. `admin.MergeObservations(source, dev.Peers, now, handshakeFresh, refreshInterval)`
   walks the directory and, for each node *without* an operator-configured
   `Endpoint`:
   - If the admin's `wgctrl` shows a peer entry with `LastHandshakeTime`
     within `handshakeFresh` (default 3m), record its source IP:port into
     `Node.ObservedEndpoint` and stamp `ObservedAt = now`.
   - If `ObservedEndpoint` is unchanged but `ObservedAt` is older than
     `refreshInterval` (default 15m), refresh `ObservedAt` (heartbeat so
     clients can detect a dead admin).
   - If no recent handshake exists for a peer with a prior observation,
     clear `ObservedEndpoint`/`ObservedAt` (decay).
2. If anything changed, bump serial, rewrite `directory-source.bin`, and
   publish to the drop.

Clients consume it in `buildPeerConfigs` via the precedence:

```
peer.Endpoint                               (operator's stable address — wins)
peer.ObservedEndpoint  if time.Since(ObservedAt) <= ObservedEndpointTTL
(empty — wait for the peer to initiate)
```

`ObservedEndpointTTL` is 30m in `internal/wg/peers.go`. The relationship is:

```
ObservedEndpointTTL  ≥  sync_interval + refresh_interval + headroom
              30m   ≥        5m       +       15m       +   10m
```

This guarantees a client never sees `ObservedAt` go stale just because the
admin's heartbeat was racing the client's poll cycle.

Properties:
- Works for full-cone, restricted-cone, and port-restricted NATs — the
  standard 25s keepalive holds the NAT mapping open on both ends, and the
  observed endpoint is exactly what the other side needs to send to.
- Does **not** work for symmetric NAT — the admin's observed port differs
  from the port a third peer would need to send to to reach this peer. No
  detection is built in; symmetric-NAT peers simply fail to handshake and
  fall back to "wait for the other side to initiate" (which also fails).
- Does **not** help two peers behind the same NAT (hairpin case). Same
  observed public IP for both; many consumer routers won't hairpin UDP.
  The relay fallback (below) catches this case automatically.
- Privacy note: enabling observation publishes NAT'd peers' apparent home
  IPs into the directory blob (visible to every other node with the age
  identity). The blob is still encrypted on the drop, but inside the network
  every peer learns every other peer's source IP. Default is off.

---

## NAT traversal — Relay fallback

When direct peer-to-peer can't be made to work (symmetric NAT, same-NAT
hairpin failures, or just a peer that's been offline long enough for its
mapping to expire), each client falls back to routing the affected peer's
traffic through the admin node instead. The mechanism is pure
`AllowedIPs` reshuffling — no protocol changes, no new packet types.

### Mechanism

```
# DIRECT for peer kilo:           # RELAYED for peer kilo (via admin zf):
peer zf:    AllowedIPs=10.42.0.1  peer zf:    AllowedIPs=10.42.0.1, 10.42.0.3
peer kilo:  AllowedIPs=10.42.0.3  (kilo peer omitted from local config)
```

The kernel's longest-prefix match routes 10.42.0.3 packets to `zf` instead
of `kilo`; `zf` (with `net.ipv4.ip_forward=1`) forwards them on to `kilo`
via its own WG interface. The reverse direction works the same way on
`kilo`. WireGuard handshakes complete even if forward and reverse paths
differ (one side direct, other side relayed) — sessions aren't required to
be symmetric.

### Decision lives on each client

The admin only sees handshakes against *itself*, not peer↔peer
reachability, so the decision has to be made locally. `internal/relay`
holds per-peer state across iterations:

- **DIRECT** — peer has its own /32 entry; we send to its
  Endpoint/ObservedEndpoint.
- **RELAYED** — peer's tunnel IP folded into the relay target's
  AllowedIPs; the peer entry is removed from local WG.

State machine (`relay.Decide`, pure function):

- DIRECT → RELAYED when `tx_bytes` grew (we're trying to send) AND
  `now - LastHandshakeTime > DirectFailedAfter` (90s default). A grace
  period (30s) suppresses evaluation right after entering DIRECT so a
  newly-added peer isn't misjudged as broken before the kernel has
  attempted a handshake.
- RELAYED → DIRECT on any of: probe interval elapsed (5m default), peer's
  ObservedEndpoint changed (peer moved networks; signaled by the admin's
  observation), local network changed (we moved networks; signaled by
  netlink address watcher).

State is wiped on daemon restart — peers all start DIRECT and converge to
RELAYED within ~90s if the path is dead. Acceptable; documented as a
known cost.

### Relay target selection

For v1, the relay target is the first non-self node in the directory with
a non-empty `Endpoint`. Single-admin networks (the only topology spec'd)
have exactly one such node — the admin. Multi-relay / explicit relay-role
selection (a `Role` field on `Node`) is on the out-of-scope list.

### Admin-side prerequisites

The admin must permit IPv4 forwarding (`net.ipv4.ip_forward=1`). The
daemon checks this at startup and warns; it doesn't change the sysctl
itself (managing forwarding outside the WG interface feels like overreach).

### Detection signals

- Periodic probe (5m default): catches NAT-router-rebooted transitions and
  similar passive recovery cases. At a 5m interval with 90s failure
  detection, ~30% of the recovery cycle is downtime when direct is
  genuinely broken. Geometric backoff is a deferred improvement (see
  TODO.md).
- `relay.Controller.MarkNetChanged()` — called by a Linux netlink
  `AddrSubscribe` watcher when any non-lo, non-tincan interface gets an
  address change. Triggers an immediate iteration and resets every
  RELAYED peer to probe DIRECT.
- ObservedEndpoint change — detected by comparing the directory's
  `ObservedEndpoint` for the peer against the value we stored on the
  previous iteration. Free with the existing observation feature.

`status` shows what the directory currently has for each peer in the
`ENDPOINT` column with a `(observed Xm ago)` suffix when the live wgctrl
endpoint is empty.

---

## Caching & atomic writes

`/var/lib/tincan/` (mode 0700, root-owned):
- `cache.bin` — last good plaintext msgpack `Directory` (mode 0600). Stored decrypted because (a) running WG state already exposes the same info and (b) the age identity is in `/etc/tincan/config.toml` next door, so encrypting locally adds nothing.
- `cache.serial` — ASCII serial for fast `tincan status` without deserializing.
- `directory-source.bin` — admin only; admin's working copy (plaintext msgpack), updated by `add-node`/`remove-node`/`publish`.
- `state.json` — last sync timestamp, last drop ETag.

All writes via `renameio.WriteFile` (write to `*.tmpXXXX`, fsync, rename). Same-fs rename is atomic on POSIX. Daemon and one-shot `sync` are both safe to run concurrently — wgctrl operations are kernel-arbitrated and cache writes are atomic.

---

## Test strategy

**Unit (`go test ./...`, no privileges):**
- `directory/codec` — round-trip marshal/unmarshal; sign + verify (positive & tampered); age encrypt + decrypt; bad-key rejection.
- `directory/ipalloc` — `NextFreeIP` against various CIDRs and "taken" sets; exhaustion; skip `.0`/broadcast.
- `directory/serial` — rollback rejection.
- `config` — load valid configs (admin-S3, client-http, client-file); reject unknown keys; reject malformed keys.
- `drop/file` — Put/Get/Stat round-trip in tmp dir.
- `drop/http` — against `httptest.Server`; Put → `ErrReadOnly`.
- `wg/peers` — `buildPeerConfigs(self, dir)` with fixtures; self-skip; allowed-IPs are /32.
- `cache` — atomic write + `-race`.
- `daemon/pidfile` — flock acquisition; staleness detection; concurrent attempt fails.

**Fake drop** (`test/fakedrop/`) — in-memory `Drop` with injectable `GetErr`/`PutErr`; used by sync- and publish-flow tests.

**Integration** (`//go:build integration`, requires root + WG kernel module): two netns (`ip netns add`), shared file drop in `/tmp`, run `init` → `add-node` → `publish` in netns-a, `join` → `sync` in netns-b, ping across; then `remove-node` + sync, confirm peer dropped.

`make` targets:
- `make test` — unit only, fast.
- `make test-race` — `-race`.
- `make test-integration` — privileged; CI only.

---

## Verification (end-to-end MVP)

Use two LXC containers on a host with the `wireguard` kernel module (Ubuntu
22.04+). Mount a shared host directory for a file-drop.

1. Build: `go build -o ./bin/tincan ./cmd/tincan`. Push to both containers.
2. **admin init** (container A): `tincan init --name alice --drop-type file --cidr 10.42.0.0/24`. Edit `/etc/tincan/config.toml`: `[drop].path = "/mnt/drop/directory.bin"`. Verify config mode 0600, `/var/lib/tincan` mode 0700, keys printed to stdout.
3. **first publish**: `tincan publish`. Verify the file exists on the shared mount.
4. **add bob**: `tincan add-node --name bob --endpoint <A-ip>:51820`. Capture the WG private key printed for bob.
5. **bob join** (container B): `tincan join --drop-type file --name bob`, paste bob's WG key. Edit config: `[drop].path`, `[directory].network_identity` + `publisher_pubkey` (from A's config).
6. **bob sync**: `tincan sync`. Verify `wg show tincan0` shows alice as peer; `ip a show tincan0` shows `10.42.0.2/32`; route `10.42.0.0/24 dev tincan0` exists; cache exists at `/var/lib/tincan/cache.bin`.
7. **alice sync**: `tincan sync` on A. Verify alice now lists bob.
8. **handshake**: `ping -c3 10.42.0.1` from B; `ping -c3 10.42.0.2` from A. Both succeed.
9. **propagation**: launch container C, `tincan add-node --name carol` on A; `tincan sync` on B. Verify bob's `wg show` lists carol before carol has joined.
10. **daemon**: `tincan sync --daemon` on B. Verify `/run/tincan.pid` exists, process running, `kill -HUP` triggers immediate sync (check logs), `kill -TERM` cleanly exits and removes PID file.
11. **offline cache**: block the drop (`chmod 000 /mnt/drop`), restart B's tincan, run `tincan sync`. Exit 0 with cache-used log message; WG state preserved.
12. **rollback rejection**: copy an older blob over the current one in the drop, run `tincan sync` on B. Non-zero exit with "stale serial"; WG state unchanged.
13. **remove**: `tincan remove-node --name carol` on A; sync B; carol no longer listed as peer.

---

## Critical files (all to be created)

- `/home/jvinet/tincan-2/cmd/tincan/main.go`
- `/home/jvinet/tincan-2/internal/cli/sync.go`
- `/home/jvinet/tincan-2/internal/directory/codec.go`
- `/home/jvinet/tincan-2/internal/directory/directory.go`
- `/home/jvinet/tincan-2/internal/wg/manager.go`
- `/home/jvinet/tincan-2/internal/wg/peers.go`
- `/home/jvinet/tincan-2/internal/drop/drop.go`
- `/home/jvinet/tincan-2/internal/daemon/daemon.go`
- `/home/jvinet/tincan-2/internal/config/schema.go`
- `/home/jvinet/tincan-2/internal/keys/keys.go`

The remaining files in the layout above are each small (10–80 LOC). The
spec needs a follow-up edit to correct the `[directory] public_key` →
`network_identity` + `publisher_pubkey` wording.

---

## Out of scope (MVP)

- PSKs (schema reserves the field for forward-compat).
- Name resolution (no /etc/hosts, no stub DNS resolver).
- Subnet routes / exit nodes (all peers get /32 each; no broader prefixes).
- Multi-admin coordination (last-write-wins is documented; no CAS, no leases).
  Note: `[observe]` makes the admin daemon a regular writer on top of the
  operator's explicit commands, widening the existing race window without
  adding new coordination.
- LAN candidate publishing for same-NAT peer pairs. Endpoint discovery
  surfaces the public NAT'd endpoint only; two peers behind the same router
  rely on hairpin support or fall back to relay (see "NAT traversal — Relay
  fallback"). Direct LAN-local routing for that case (a `Node.LanEndpoint`
  field plus a same-LAN heuristic) would be a follow-up optimization.
- Multi-relay / explicit relay-role topologies. Today the relay target is
  the first directory node with an `Endpoint` set — fine for single-admin
  networks. A `Role` field on `Node` would let a directory carry multiple
  relays with explicit selection (e.g. nearest by RTT).
- DNS-TXT dead-drop backend.
- Non-Linux platforms (`internal/wg/*` is `//go:build linux`).
- Tunnel IPv6 (transport IPv6 via AAAA endpoints is fine; tunnel addresses are v4).
- Self-update of the Tincan binary.
- GUI / web UI / REST API / metrics endpoint.
