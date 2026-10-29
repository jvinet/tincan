# Tincan

![Tincan](misc/tincan.png)

Tincan is a small, self-hosted mesh-VPN orchestration tool for WireGuard.

It does a bit more than a plain Wireguard setup, and a lot less than Tailscale,
Netbird, etc. Tincan is somewhat unique in that it does not rely on an always-on
coordination service. At least, not directly.

Instead, it keeps your nodes' public keys, tunnel IPs, and endpoints in a
signed, encrypted **directory**, which nodes fetch and apply to their WireGuard
interfaces. There is no always-on coordination service to run, but there _is_ an
admin node that needs to hold the keys necessary to encrypt and publish the
network directory.

The location of the network directory can vary. Tincan strives to keep the
directory size small, so that it will fit in more places. If you squint a bit,
these directory locations are akin to **dead drops** from your favourite spy
novel. An agent creates an encrypted message (the network directory) and leaves
in a predetermined location for another agent to pick up. In this way, the two
agents do not converse directly with each other to learn the network, but rather
through a (possibly obscure) intermediate location to provide asynchrony to
their communication.

## Drop Types

Currently, Tincan supports a few places to stash your network directory:

- HTTP
- Object storage
  - anything S3-compatible
- Local filesystem
  - useful for testing
  - also a useful escape hatch if you want to use an out-of-band process to
    acquire the directory from a location that Tincan doesn't natively support
- DNS TXT records
- Nostr relays

## Beyond manual WireGuard

With a typical `wg`/`wg-quick` setup, you maintain peer configurations on each
machine. With Tincan, an admin adds or removes a node once and publishes the
directory; the other nodes pick up the change automatically.

Tincan also handles endpoint discovery for NAT'd peers, LAN peer discovery, and
fallback through your own relay when a direct connection cannot form. Traffic
uses direct WireGuard connections wherever possible.

## Less infrastructure than Tailscale or Netbird

Instead of a full coordination stack, Tincan exchanges a directory blob through
a **dead-drop**: S3-compatible storage, a static HTTP server, DNS TXT records,
Nostr relays, or a shared filesystem. The backend stores the blob; it does not
decide who belongs to the network or need access to its plaintext contents.

You hold the signing key and manage membership. Each node has its own decryption
key; removing a member excludes it from future directories without rotating a
fleet-wide shared secret. Nodes cache the directory, so a temporary dead-drop
outage does not take down the VPN.

The trade-off is deliberate: you operate your nodes, keys, and any needed relay,
rather than relying on a hosted control plane or managed relay fleet. Tincan
currently chooses a single relay, without relay failover.

## Where it fits

Tincan is for operators who want a small, self-managed WireGuard mesh without
hand-editing every peer or deploying a full VPN platform. It works well for my
home-net setup.

The Tincan binary runs on Linux. Phones and other devices can join with a
standard WireGuard config or QR code as hub-and-spoke peers, but those configs
do not auto-update. Optional VPN names let you reach nodes as, for example,
`nas.tc`.

## Simple enrollment

Enrolling a new node is very simple.

On the admin node:

```
[jvinet@admin ~]$ sudo tincan add-node --name groot --bootstrap groot.json
```

Then copy the bootstrap JSON file to the new client and:

```
[jvinet@client ~]$ sudo tincan join --bootstrap groot.json
[jvinet@client ~]$ sudo tincan up --daemon
```

## Documentation

- [Setup](doc/setup.md) — requirements, building, onboarding, and verification
- [Configuration](doc/configuration.md) — configuration directives and defaults
- [Dead-drop backends](doc/dead-drop-backends.md) — storage options and
  credentials
- [Networking](doc/networking.md) — endpoint discovery, relay fallback, and LAN
  discovery
- [VPN DNS names](doc/dns.md) — member names and DNS for plain WireGuard clients
- [Operations](doc/operations.md) — daemon, systemd, logging, and local files
- [Architecture](doc/architecture.md) — directory security and implementation
  overview
- [Development](doc/development.md) — build, test, and lint commands

## Provenance

This project was created using Anthropic and OpenAI models. If that offends
your sensibilities, you may want to look elsewhere. I won't be offended.

## License

See [LICENSE](LICENSE).
