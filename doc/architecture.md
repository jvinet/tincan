# Architecture

[← Back to overview](../README.md)

## How it works

- An **admin node** holds the publisher signing key and writes a signed,
  age-encrypted directory blob to a shared dead-drop.
- Every node has its **own age keypair**. The directory is encrypted to the
  recipients of all current members, so each node decrypts the blob with its
  own identity. A client pulls the blob, decrypts its envelope, verifies the
  publisher's signature over the payload, then reconciles its WireGuard
  interface against the authenticated peer list.
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
`CreatedAt` falls behind (see the [configuration reference](configuration.md)).

## Implementation overview

- Single Go binary: `tincan`
- Linux client/admin support
- Dead-drop backends: S3-compatible object storage, HTTP (read-only for
  clients), DNS TXT records (Linode, DigitalOcean, Cloudflare, deSEC, Hetzner,
  Route 53, or OVH), Nostr relays, and local filesystem (e.g. shared NFS/SMB
  mount)
- Signed (Ed25519) and age-encrypted directory blobs
- Full-mesh WireGuard peer configuration via `wgctrl`/netlink (no `wg-quick`)
- Explicit `up` / `down` / `sync` lifecycle, plus a daemon mode that reconciles
  continuously with SIGHUP-triggered reload (some startup settings require a
  restart; see [Operations](operations.md#running-as-a-daemon))
- Network and node bootstrap files for one-shot client onboarding
- Local cache + serial file so the network stays up if the dead-drop is
  temporarily unreachable
- Optional endpoint discovery: an admin node can observe NAT'd peers'
  source endpoints and republish them so NAT'd peers can reach each other
  directly (UDP hole punching). See [Endpoint discovery](networking.md#endpoint-discovery).
- Automatic relay fallback: when a NAT'd peer-to-peer path can't be
  established (symmetric NAT, same-LAN hairpin, etc.) clients route the
  affected peer's traffic through the selected relay. Shadow peers keep
  probing the direct path through kernel keepalives, and a fresh handshake
  restores direct routing. See [Relay fallback](networking.md#relay-fallback).
- Optional VPN DNS names: set a network domain (`tincan set-domain vpn`)
  and every node resolves as `<name>.<domain>` — members via a managed
  `/etc/hosts` block, plain-WireGuard spokes via a small DNS server on the
  hub. See [VPN DNS names](dns.md#vpn-dns-names).
