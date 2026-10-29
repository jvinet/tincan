# Networking

[← Back to overview](../README.md)

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
the relay; nothing leaks. See [LAN discovery design](../spec/lan-discovery.md) for the full
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
