# Tincan — Original Concept

Status: **historical / superseded**. This document records the original idea,
not the current configuration, security model, or CLI. In particular, the
implemented system uses per-node age identities, `[drop.admin]` / `[drop.client]`,
and separate `sync` (cache) and `up` (apply/daemon) commands. Use the
[README](../README.md) and [current guides](../doc/setup.md) for operation.

I want to build a mesh VPN orchestration system. It will be called Tincan.

## Impetus

I currently use Tailcale at home, but my new employer also uses Tailscale, and
with the BYOD policy, I have a new problem where I cannot have both my personal
tailnet and my work tailnet active on the same device at the same time.

Rather than locking into another vendor-provided solution, I would like to
explore the idea of a simple-as-possible-but-no-simpler network that is easier
to manage than plain Wireguard and wg-quick.

## Concept

Tincan is intended to sit between Tailscale/Nebula/Netbird and a plain,
manually-configured Wireguard.

The target user is a person with a homelab or small network, who wants to
self-host and doesn't want to rely on a coordination server or any external
company for the operation of their personal VPN. This user has the knowledge and
ability to setup a Wireguard mesh VPN themselves on their devices, but they
recognize that it's operationally burdensome to add/remove nodes from the
network, as each node needs to be updated to recognize the newly-added/removed
node.

Tincan aims to remove this operational burden while still minimizing complexity
and operational overhead. It solves this question:

> How do I add a node to my network without having to update every existing
> node?

Tincan maintains a list of all nodes' public keys and endpoints. Unlike a
typical coordination server, it does not provide these to clients itself, but
rather stores them, encrypted, in a publicly-accessible place. A dead-drop, if
you will.

In client mode, Tincan can then retrieve and decrypt this data (via the shared
network age identity) and verify that it was published by an admin key in order
to assemble a Wireguard configuration for a node.
In Tincan parlance, we'll call this the network "directory".

Some ideas for dead-drop locations we could support:

- S3
- HTTP
- DNS TXT
  - TXT records are 255 bytes max, but we can store multiple and assemble them
    into the final, to-be-decrypted blob

## Nomenclature

- "directory"
  - A list of node endpoints and public keys, essentially the data required to
    assemble the network topology.
- "dead-drop"
  - A remote location (often publicly-accessible but not necessarily so) that
    provides the directory data.
- "node"
  - A device participating in the network.

## Workflow

The Tincan utility has two modes of operation: Admin and Client.

All nodes are clients, as they are all nodes in a Wireguard network. A client
can _also_ have admin privileges if it possesses the Ed25519 publisher private
key and any credentials required to write to the dead-drop. The shared age
identity gives nodes read access to the topology; the publisher private key is
what lets an admin create a signed directory blob. In this way, only admin nodes
can alter the network topology, which they do indirectly by writing a revised
directory blob.

Clients are just plain Wireguard nodes. The only extra superpower they have is
that Tincan (if it's present & configured on the node) will periodically query
the dead-drop. If a new version of the directory blob is discovered, Tincan will
download, decrypt, and apply it. Through this simple mechanism, we can achieve
our stated goal, while still keeping the network available for other OSes or
nodes that may not have Tincan.

## Technology

Tincan will be written in Go for easy deployment. The sole CLI binary is
optional for client-only nodes, though they benefit from auto-updating topology
if they have it installed and configured. The CLI binary is required for any
admin-level nodes.

There are two ways to participate in a Tincan network.

1. As a Tincan-enabled node; ie, one that has the Tincan CLI utility.
2. As a regular Wireguard node; this can be any OS that has the native Wireguard
   app and can be configured with a standard Wireguard config.

## Example Configuration

Some proposed configuration examples.

### Admin Node (S3)

```toml
[wireguard]
public_key = ...
private_key = ...
name = alice

[directory]
network_identity = "AGE-SECRET-KEY-1..."
publisher_pubkey = "..."
publisher_key = "..."

[drop]
type = s3
endpoint = s3.amazonaws.com
region = us-east-1
bucket = ...
object_key = directory.bin
access_key = ...
secret_key = ...
```

### Client Node (S3)

```toml
[wireguard]
public_key = ...
private_key = ...
name = bob

[directory]
network_identity = "AGE-SECRET-KEY-1..."
publisher_pubkey = "..."

[drop]
type = s3
endpoint = s3.amazonaws.com
region = us-east-1
bucket = ...
object_key = directory.bin
# S3 Authentication is optional but supported
```

### Admin Node (File)

```toml
[wireguard]
public_key = ...
private_key = ...
name = alice

[directory]
network_identity = "AGE-SECRET-KEY-1..."
publisher_pubkey = "..."
publisher_key = "..."

[drop]
type = file
path = /mnt/shared/tincan/directory.bin
```

### Client Node (HTTP)

```toml
[wireguard]
public_key = ...
private_key = ...
name = bob

[directory]
network_identity = "AGE-SECRET-KEY-1..."
publisher_pubkey = "..."

[drop]
type = http
url = https://example.com/_vpn/directory
username = bob
password = letmein
# HTTP Auth is optional but supported
```

## Setup

### Admin

The first admin node would run:

```bash
$ tincan init --name alice --drop-type s3
```

The command would then generate a skeleton configuration. The administrator can
then edit the file and fill in the necessary configuration items for their
dead-drop of choice.

They can then add client nodes:

```bash
$ tincan add-node --name bob
```

### Client

Once the directory has been updated to reflect the new client node, the client
machine itself can initialize their end:

```bash
$ tincan join --drop-type s3
```

As with the admin side, Tincan generates the config file and then the operator
fills in the important parts.

Once the config file is complete, they can activate the network:

```bash
$ tincan sync --daemon
```

The `sync` command retrieves the directory from the dead-drop and configures the
Wireguard interface. If `--daemon` is used, then Tincan will background itself
and poll the dead-drop every X seconds. If `--daemon` is not passed, then Tincan
exits after standing up the Wireguard interface. This gives the operator
flexibility, allowing them to run daemonless `tincan sync` via cronjob or
systemd timer.
