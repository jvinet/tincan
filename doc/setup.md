# Setup

[← Back to overview](../README.md)

## Requirements

- Linux with kernel WireGuard support (`wireguard` module); Tincan creates
  the interface through netlink and does not launch `wireguard-go`
- `CAP_NET_ADMIN` to manage the tunnel interface — in practice, run
  `tincan up` as root or under a systemd unit with the capability granted
- Go 1.25+ to build from source

## Build

```sh
CGO_ENABLED=0 go build -o ./bin/tincan ./cmd/tincan
# or
make build
```

A statically-linked binary lands in `./bin/tincan`. Copy it to `/usr/local/bin`
on your nodes. Verify with `tincan version`.

## Quick start

The examples below assume an S3-compatible dead-drop. For other storage options,
choose the appropriate `--drop-type` and configure `[drop.admin]` and
`[drop.client]` as described in [Dead-drop backends](dead-drop-backends.md).
See the [configuration reference](configuration.md) for all directives.

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

It also prints the generated keys, including secrets, to stdout. They are saved
in the config, but **back them up somewhere safe** — `init` does not create a
separate backup. Keep the admin's private keys on the admin; clients receive
their own keys through enrollment, not the admin's age identity.

Pass `--force` to overwrite an existing config, or `--state-dir /path` to put
the cache and its sibling state files somewhere other than the default
`/var/lib/tincan`.

By default the generated config is minimal: it lists only the fields you are
likely or required to change. Pass `--full-config` to materialize defaulted
settings and common toggles for this role, including `[dns]`. Optional automatic
policies such as `[dns].serve` remain unset.

Now edit `/etc/tincan/config.toml` and fill in `[drop.admin]` (where this node
writes the directory) and `[drop.client]` (how other nodes read it). For most
backends these are the same coordinates with different credentials; for HTTP,
`[drop.admin]` is the local file you write before uploading and `[drop.client]`
is the URL clients fetch from. See [Dead-drop backends](dead-drop-backends.md#dead-drop-backends).

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
that case — it just won't contain the secrets. On the same client, finish with
`sudo tincan join --bootstrap /tmp/bob.json --force`: Tincan checks the bootstrap's
public key against the existing config and preserves both locally generated
keypairs, the state directory, and local runtime settings. Do not pass
`--generate-key` again.

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
dependent. See [Relay fallback](networking.md#relay-fallback).

Other admin commands:

```sh
sudo tincan list-nodes        # show the published directory (not deferred edits)
sudo tincan remove-node --name bob
sudo tincan publish           # re-publish the working directory
```

`add-node` and `remove-node` publish automatically; pass `--no-publish` to defer
the upload (changes accumulate in the working directory). A later automatic
publish includes those deferred edits too; use `publish` to issue them without
another mutation. Background endpoint observation pauses while edits are staged,
so it cannot publish them unexpectedly.

`remove-node` is also how you **revoke** a node: the publish that follows
re-encrypts the directory to the remaining members' recipients only, so the
removed node can no longer decrypt new directories. It keeps whatever blob it
already cached but is locked out of every future one — no fleet-wide rekey.

All publishing paths check the current remote serial and the local serial
floor before uploading. A failed remote fetch or verification refuses the
upload (an empty drop on first publish is fine). You can still stage edits
with `--no-publish`, then explicitly `publish --force` when you know the drop
contents are older than your working directory. `--force` bypasses the remote
check, not the local serial floor. Serials are reserved before upload, so a
failed upload can leave a gap in the sequence.

Local admin commands and daemon observation are serialized. Writers on different
admin machines are **not** coordinated; use one publishing machine.

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
WireGuard keypair from the bootstrap. With admin-generated secrets, nothing
else needs editing. For locally generated keys, use the existing config and
`--force` as described above; a secret-free bootstrap alone cannot supply the
node's age identity. The bootstrap also
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
non-default state directory. As with `init`, `--full-config` materializes
defaulted settings instead of writing only the minimal set.

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

For systemd services and daemon lifecycle details, see
[Operations](operations.md#running-as-a-daemon).

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
tunnel IP through the hub (see [Relay fallback](networking.md#relay-fallback)). It's a
point-in-time snapshot — the device doesn't run Tincan, so it won't pick up
later directory changes (rotated keys, moved endpoints, new nodes); use
`render-node` to refresh it.

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
