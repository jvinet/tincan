# Tincan — LAN Peer Discovery

## Context

Two NAT'd peers in the same physical LAN that both register with the same
Tincan network usually present identical `ObservedEndpoint` IP-portions
(the shared NAT's external address). Direct peer-to-peer between them
requires the home router to hairpin UDP, which many consumer routers
don't. The existing relay fallback (`plan.md` § "NAT traversal — Relay
fallback") catches this case correctly: traffic flows via the admin node.

That's correct but suboptimal. Two devices on the same LAN routing
through an off-site relay pays the upload-bandwidth tax of the shared
internet connection both ways, doubles RTT, and is bounded by the slowest
of {local-uplink × 2, admin's downlink, admin's uplink, local-downlink}.
The LAN itself could carry that traffic gigabit-grade for free.

The system already has every piece needed to switch to LAN-direct *if it
can learn each peer's LAN-side IP:port for the WireGuard listener*.
WireGuard endpoint roaming closes the loop on the receiver side; the
existing `DIRECT`/`RELAYED` state machine handles fallback when LAN
turns out not to work. Only the *discovery* of the LAN endpoint is
missing.

Because Tincan has no control plane (no client→admin write path; see
`spec.md` and `plan.md`), discovery cannot use the directory as a side-
channel. The two viable choices are LAN-local multicast (this spec) and
in-band negotiation over the established relay tunnel (deferred). LAN
multicast was chosen because it works without the relay being up first
and doesn't require introducing a tunnel-internal control plane.

---

## Decisions (locked in)

| Area | Choice |
|------|--------|
| Discovery mechanism | UDP multicast beacons, periodic |
| IPv4 group | `239.255.84.67` (admin-scoped block `239.255.0.0/16`) |
| IPv6 group | `ff02::1:8443` (link-local scope) |
| Beacon port | `51821` (one above WireGuard's default 51820 for memorability; distinct from any WG listener port) |
| Beacon serialization | `msgpack/v5` (already a project dep) |
| Authentication | Implicit — beacon claims a pubkey; downstream WG handshake either succeeds or doesn't |
| Pubkey filtering | Listener drops beacons whose claimed pubkey isn't in the current directory |
| Beacon cadence | 30s steady-state; initial burst of 3 over 5s on startup; on-receipt response when a known pubkey is unfamiliar (rate-limited to 1/peer/5s) |
| Egress interface(s) | Every non-loopback, non-Tincan link with at least one global-scope IPv4 or IPv6 address |
| New WG state? | **No.** LAN endpoint is just another candidate in `chooseEndpoint` precedence |
| Endpoint precedence | `Endpoint > LANEndpoint (fresh) > ObservedEndpoint > empty`; same-NAT peers retry the last-known LAN endpoint even past TTL (see below) |
| LAN endpoint TTL | 90s since last beacon (3× cadence); not enforced for same-NAT peers, whose only fallback is a hairpin address |
| Invalidation on failure | Entering `RELAYED` for a peer marks that peer's LAN endpoint as failed; next beacon re-validates. Same-NAT peers bypass the blacklist |
| Directory schema | **No change.** Discovery is purely client-local |
| Config knob | `[discovery].enabled` (default `true`); separate from `[observe]` |
| Module path | `internal/discovery/` (new) |
| Status display | `DIRECT` peers show `(lan)` suffix when active endpoint is in RFC1918 / ULA |

---

## Protocol

### Multicast group selection

**IPv4: `239.255.84.67`.** The administratively-scoped block `239.0.0.0/8`
is reserved for private deployments — guaranteed never to be assigned by
IANA. Within that, `239.255.0.0/16` is conventionally site-local scope.
The specific address `239.255.84.67` is arbitrary but stable; `84.67` =
`T,C` (Tincan) in ASCII for trivia value. No existing well-known service
uses it.

**IPv6: `ff02::1:8443`.** Scope `02` is link-local — packets to this
group are never routed beyond the L2 segment, which is exactly what we
want. The group ID `0001:8443` is arbitrary but stable for the
protocol. Reuses the same scope as mDNS (`ff02::fb`).

**Port: `51821`.** Sits beside WireGuard's default `51820` and Tincan
shouldn't ever conflict — Tincan's WG listener uses operator-configured
or ephemeral ports per `plan.md`. Easy to remember and grep for.

Multicast TTL is 1 on IPv4 (link-local emulation; never crosses a
router) and the IPv6 scope handles the equivalent constraint natively.

### Beacon format

```go
package discovery

const BeaconSchemaVersion uint32 = 1

type Beacon struct {
    V         uint32 `msgpack:"v"`       // schema version, always 1 in this spec
    PublicKey string `msgpack:"pk"`      // sender's WG pubkey, base64 (44 chars)
    Port      uint16 `msgpack:"port"`    // sender's WG listen port
    Nonce     uint64 `msgpack:"n"`       // random per-beacon; reserved for future replay defense
}
```

Wire size: ~70 bytes msgpack-encoded. Well under any sane MTU.

Schema notes:
- `omitempty` not used here — every field is required for V1 beacons. A
  beacon with `V > 1` MUST be tolerated by V1 decoders (unknown fields
  ignored, all V1-known fields still parsed).
- No timestamp. Receivers stamp their local clock; sender clocks don't
  participate in the protocol.
- No signature. The pubkey is a *claim*; the downstream WG handshake
  proves possession (or fails). See § "Security considerations".

### Beacon cadence and triggers

- **Steady-state:** every 30s. Each cycle emits one beacon per eligible
  egress interface (see below).
- **Startup burst:** at daemon start, send beacons at `t = 0s, 2s, 5s`.
  Speeds convergence when two peers come up around the same time.
- **Reactive:** when a beacon arrives from a directory pubkey we haven't
  seen in the LAN store yet, send a beacon back (within the next 200ms,
  jittered). Rate-limited to 1 reactive beacon per pubkey per 5s. This
  collapses convergence to a single round-trip in the common case.
- **Triggered:** on `SIGHUP` or any wake-channel event, also send a
  beacon (rate-limited to 1 / 1s).

Beacons are *always* sent when discovery is enabled — we don't condition
sending on "directory shows a peer with matching `oep`" because the
beacon's *purpose* is to announce ourselves to anyone who cares; we
shouldn't gate that on whether *we* think we have a same-NAT peer (the
other side's information may differ from ours).

Receivers can be more selective (drop early on unknown pubkey), but
senders broadcast unconditionally.

### Egress interface selection

A "live LAN interface" is any kernel link satisfying *all* of:
1. Not loopback (`lo`).
2. Not the Tincan interface itself (default `tincan0`, per
   `cfg.Wireguard.Interface`).
3. State `UP` (per `netlink.LinkAttrs.OperState`).
4. Has at least one non-link-local, non-loopback IP address.

For each live LAN interface, the sender opens a socket with
`IP_MULTICAST_IF` (IPv4) / `IPV6_MULTICAST_IF` (IPv6) set to that
interface's index, joins the group, and writes the beacon. For IPv6,
zone IDs are honored (`ff02::1:8443%eth0`).

If a node has multiple LAN interfaces (Wi-Fi + Ethernet on a laptop),
beacons go out on every one — the peer on the other side may only be
reachable on one of them. Receiving a beacon on multiple interfaces is
treated as one logical event (deduped by pubkey + source IP).

### Receiving and processing

A single listener goroutine joins both groups (IPv4 + IPv6) on the
default port and reads beacons.

Group membership is not a join-once affair. A maintainer goroutine per
family re-enumerates the live LAN interfaces every beacon interval and
re-joins the group on each — leave first, then join, so the join is
never a kernel refcount no-op and always emits a fresh IGMP/MLD
membership report. This covers three receive-side failure modes that
produce a node that transmits beacons but never hears any (the sender
re-enumerates interfaces on every emit, so transmission survives all
three):

- an interface that qualifies only *after* the daemon started (boot race
  against DHCP / Wi-Fi association);
- an interface recreated with a new index (driver reload, USB replug);
- a snooping switch that ages the group out of its forwarding tables on
  a LAN with no IGMP querier — no local event fires for this, so only
  the periodic re-announce heals it.

For each received beacon:

1. Decode msgpack into a `Beacon`. If `V == 0` or decode fails, drop.
   Future schemas (`V > 1`) decode into the V1 struct, ignoring unknown
   fields.
2. Look up `beacon.PublicKey` in the most recent directory. If not
   found, drop (not a peer we care about, OR a beacon from another
   Tincan network sharing this LAN).
3. Extract source IP from the packet's source address. Compose the LAN
   endpoint: `srcIP:beacon.Port`. (Note: IPv6 link-local source IPs are
   not used — they'd require zone IDs to be useful to WG, and WG's
   `Endpoint` is a plain `*net.UDPAddr`. Skip beacons whose source IP is
   IPv6 link-local; the same peer should also be reachable via a global
   address.)
4. Update the LAN store: `lan[pubkey] = LANState{Endpoint: <addr>,
   LearnedAt: now}`.
5. If the LAN store *changed* (new pubkey, or endpoint differs), push
   to `wakeCh` so the next iteration applies the new endpoint
   immediately.

---

## State machine integration

The DIRECT/RELAYED state machine in `internal/relay/` is **unchanged**.
The LAN endpoint is exposed only through `chooseEndpoint` in
`internal/wg/peers.go`.

### Endpoint precedence (revised)

```
chooseEndpoint(self, node, lanStore, now):
  if node.Endpoint != ""                       -> use operator endpoint
  staleOK := sameNAT(self, node)               // admin observed both at one public IP
  if lan := lanStore.Lookup(node.PublicKey, now, staleOK); lan != "" -> use lan
  if observedFresh(node, now)                  -> use ObservedEndpoint
  return ""
```

Where `lanStore.Lookup` returns the LAN endpoint iff:
- An entry exists for `node.PublicKey`,
- `now - LearnedAt <= LANEndpointTTL` (90s default),
- `FailedAt.IsZero() || FailedAt.Before(LearnedAt)` (not blacklisted by
  a more recent failure).

With `staleOK` (peer observed behind the same public IP as self) the TTL
and blacklist checks are skipped and the most recently learned endpoint
is returned regardless of age. The fallback for such a peer is its
`ObservedEndpoint` — self's own public IP, reachable only if the router
supports NAT hairpinning, which most consumer routers don't. A stale LAN
endpoint either handshakes (recovering the direct path even when beacons
have stopped flowing — host firewall, AP multicast filtering, phone
doze) or fails harmlessly while the relay carries traffic; the same
trust model beacons already rely on.

### Working paths are never overwritten

`Apply` pushes the chosen endpoint to the kernel only when the peer's
last handshake is older than 90s (matching the relay controller's
`DirectFailedAfter`) or the peer is new. A fresh handshake proves the
kernel's current endpoint works — often one the kernel roamed to (e.g. a
same-LAN source address) that appears in no directory and no store — and
overwriting it would blackhole outbound traffic to the peer until its
next inbound packet re-roams the endpoint.

### LANState lifecycle

```go
type LANState struct {
    Endpoint  string
    LearnedAt time.Time
    FailedAt  time.Time
}
```

Three events advance the state:

- **Beacon arrives** (listener): `Endpoint`, `LearnedAt` set;
  `FailedAt` left as-is. If the new `LearnedAt > FailedAt`, the entry is
  effectively re-validated.
- **TTL expires** (next iteration after `now - LearnedAt > TTL`):
  `Lookup` returns empty; effectively unused. We don't actively delete —
  a fresh beacon revives it. Garbage-collected if the entry is older
  than `10 × TTL`.
- **RELAYED transition** (relay controller, see below): `FailedAt = now`
  is stamped for any peer that just transitioned `DIRECT → RELAYED`.
  This blacklists the LAN endpoint until the next beacon (which will
  push `LearnedAt > FailedAt` and unblock it). Same-NAT peers are exempt
  from the blacklist at lookup time: their shadow-peer probes keep
  targeting the last-known LAN endpoint, because the hairpin alternative
  can never complete a handshake.

### Why no new state in `relay.Mode`?

The state machine's job is to decide whether the peer's tunnel IP gets
its own AllowedIPs entry (DIRECT) or is folded into the relay target's
AllowedIPs (RELAYED). LAN-direct uses its own AllowedIPs entry — same
shape as DIRECT, just with a different `peer.Endpoint`. There's nothing
the state machine needs to do differently. Adding a third state would
duplicate transition logic (DIRECT↔LAN would have all the same edges as
DIRECT↔RELAYED) for no behavioral gain.

The `(lan)` label in `tincan status` is a presentation-layer detail —
status code can inspect the chosen endpoint's IP class and tag DIRECT
peers accordingly. Doesn't need a state-machine signal.

### Failure invalidation, concretely

The relay controller currently returns a `Decision` with `Relayed map[
string]bool` and `PeerStates map[string]PeerState`. We extend the
iteration in `up.go`'s `runDaemonIteration` to compare the *new*
`PeerStates` to the *previous* ones (already done for transition
logging — `prevModes` map), and for any peer transitioning
`DIRECT → RELAYED`, call `lanStore.MarkFailed(pubkey, now)`.

This is one new line in `logRelayTransitions` (or a sibling function);
no state-machine surgery.

---

## Configuration

Add a new TOML section:

```toml
[discovery]
enabled         = true                    # default; set false to disable both send and receive
multicast_ipv4  = "239.255.84.67:51821"   # default; rarely overridden
multicast_ipv6  = "[ff02::1:8443]:51821"  # default
beacon_interval = "30s"                   # default; can lower for testing
beacon_ttl      = "90s"                   # default; should be >= 2x interval
```

Required: none. All fields default. If the section is absent,
discovery is on with defaults.

Validation:
- `beacon_ttl >= 2 × beacon_interval` (else single-packet loss kills
  the endpoint between cycles); warn and clamp at load.
- Multicast addresses must be valid + actually multicast (`IsMulticast()
  == true`); fail config load with a clear error otherwise.
- IPv6 address must be link-local scope (`ff02::/16`); warn and
  proceed otherwise (operator may be doing something exotic).

CLI flag for one-off override: `tincan up --discovery=false` (mostly
for debugging).

---

## Module layout

```
internal/discovery/
├── discovery.go      # package doc, public surface (Store, Listener, Sender)
├── beacon.go         # Beacon msgpack codec + tests
├── sender.go         # sender goroutine: cadence, interface enumeration, send sockets
├── listener.go       # listener goroutine: bind, receive, parse, hand off to Store
├── store.go          # LANState, in-memory map, mutex, lookup/update/invalidate API + tests
├── iface.go          # live-LAN-interface enumeration (Linux netlink)
└── discovery_test.go # integration: pair of fake nodes on loopback multicast group
```

Public API (consumed by `internal/cli/`):

```go
type Store interface {
    Lookup(pubkey string, now time.Time) string  // "" if none
    Update(pubkey, endpoint string, now time.Time)
    MarkFailed(pubkey string, now time.Time)
    Snapshot() map[string]LANState               // for status / debugging
}

func Start(ctx context.Context, cfg Config, self directory.Node, dirSource func() directory.Directory) (Store, error)
```

`Start` launches sender and listener goroutines. `dirSource` is a
closure that returns the current directory so listener can filter
unknown pubkeys without holding a directory reference (which changes
between syncs).

---

## Daemon loop integration

Modify `runDaemonLoop` in `internal/cli/up.go`:

1. Build a `dirSource` closure that snapshots the latest directory (the
   loop already has it as `res.Directory`; wrap in `sync.Mutex` or use
   `atomic.Value`).
2. After `startNetworkWatcher`, also call
   `discovery.Start(watchCtx, cfg.Discovery, self, dirSource)` — store
   returned in a local variable.
3. Pass the store into `runDaemonIteration` alongside `controller`.
4. In `runDaemonIteration`, after `controller.Update(...)`, call
   `lanStore.MarkFailed(...)` for each peer that transitioned
   `DIRECT → RELAYED` this iteration (compare `prevModes` ↔
   `decision.PeerStates`).
5. Pass the store into `BuildPeerConfigs` (via `manager.Apply`) so
   `chooseEndpoint` can consult it.

Wake plumbing: the listener pushes to the existing `wakeCh` whenever the
store changes. Reason string: `"lan endpoint discovered"` or `"lan
endpoint updated"`.

---

## Status display

In `internal/cli/status.go`:

- For each peer with `Mode == "direct"`, inspect the active endpoint
  (from `wgctrl` snapshot). If the IP portion is RFC1918 (10/8,
  172.16/12, 192.168/16) or ULA (`fc00::/7`), append `(lan)` to the
  endpoint label.
- New row in the status output: `lan endpoints learned: N` (count
  from store snapshot).

`tincan status --json` exposes:
```json
"peers": [
  { "name": "kilo", "mode": "direct", "endpoint": "192.168.1.42:51820",
    "endpoint_source": "lan", ... }
]
```

`endpoint_source` is one of: `operator`, `lan`, `observed`, `roamed`,
`unknown`. Derived from comparing the wgctrl endpoint against the
operator/observed/lan candidates.

---

## Iteration flow (end-to-end)

```
T = 0:00   daemon starts; lan store empty
           sender burst beacon #1 emitted
T = 0:02   sender burst beacon #2 emitted
T = 0:05   sender burst beacon #3 emitted; peer kilo (also booted) receives
T = 0:05   kilo's listener: pubkey known → updates store, fires reactive beacon
T = 0:05.2 our listener: receives kilo's reactive beacon, source IP =
           192.168.1.42, port = 51820 → store["kilo"] = {192.168.1.42:51820, T+0:05.2}
           → wakeCh fires
T = 0:05.2 daemon iteration runs; BuildPeerConfigs sees lan store, sets
           peer kilo's Endpoint to 192.168.1.42:51820
T = 0:05.3 kernel attempts handshake to 192.168.1.42:51820, succeeds
T = 0:05.4 kilo's WG kernel sees handshake from our LAN IP, roams its
           Endpoint for us to our LAN address (endpoint roaming)
T = 0:30   next steady-state beacon cycle; both sides re-affirm endpoints
```

Failure flow:

```
T = 0:00   discovery as above; store["kilo"] = 192.168.1.42:51820
T = 0:00   peer kilo's Endpoint set to that; handshake attempted; fails
           (LAN firewall, isolated VLAN, whatever)
T = 1:30   relay state machine: handshake stale > 90s → DIRECT → RELAYED
T = 1:30   runDaemonIteration sees the transition → store.MarkFailed("kilo")
T = 1:30   peer kilo is now a shadow peer routed via relay
T = 0:30   next beacon from kilo arrives, store["kilo"].LearnedAt updated
           → LearnedAt > FailedAt → store entry usable again
T = 0:30.1 kernel (shadow peer) keeps probing handshakes via current peer
           Endpoint, which BuildPeerConfigs has now flipped back to LAN
           (because chooseEndpoint sees lan as usable again)
T = 0:30.1 if LAN still doesn't work, RELAYED stays; cycle repeats until
           LAN is genuinely viable or operator disables discovery
```

The cycle's correctness depends on `lan_ttl > beacon_interval` and on
`MarkFailed` only being called on the `DIRECT → RELAYED` *edge* (not
every iteration in RELAYED). Both conditions are checked in tests.

---

## Edge cases

### Peer behind same NAT, different VLAN
Beacons multicast on the LAN may not cross VLAN boundaries (depends on
the router). If they don't, discovery silently fails and relay handles
the case unchanged. No incorrect behavior.

### Peer with multiple LAN interfaces
The peer sends beacons on each interface; we receive from whichever
delivers first. We use only one endpoint at a time. If the peer roams
between interfaces (Wi-Fi → Ethernet), beacons from the new interface
arrive with a different source IP, updating the store. WG endpoint
roaming on the next handshake propagates to the kernel.

### Two Tincan networks sharing a LAN
Network A's daemon receives Network B's beacons. The pubkey filter
drops them (B's pubkeys aren't in A's directory). One round-trip of
wasted CPU per beacon; no incorrect behavior.

### IPv4 / IPv6 dual stack
Both groups are joined. A peer reachable on both will likely have two
LAN endpoints learned (one IPv4, one IPv6). The store keeps the most
recent; for predictability, we prefer IPv6 ULA/GUA over IPv4 RFC1918
when both arrive in the same cycle (lower latency at scale, no NAT
weirdness). Implementation: tie-break in `Update` by address family.

### Beacon receive on the Tincan interface
The listener binds the wildcard address, so packets can reach it on
paths that are not "a beacon multicast on the local LAN": Linux's
`IP_MULTICAST_ALL` default delivers group traffic arriving on *any*
interface (including the tunnel) to a socket that joined the group on
none of them, and plain unicast to the listen port — from the WAN, or
from a mesh member across the tunnel — lands on the wildcard bind
directly. We therefore validate ingress before decoding:

1. The packet's destination (via `IP_PKTINFO`/`IPV6_RECVPKTINFO`) must
   be the multicast group; unicast and missing-metadata packets drop.
2. The ingress interface index must not be the Tincan interface.
3. The source IP must not fall inside the network CIDR (cryptokey
   routing means tunnel-delivered packets always carry in-CIDR
   sources).

We also drop beacons whose source IP matches any of our own
non-loopback addresses (self-loopback via multicast on the same
machine).

### Network connectivity blip
DHCP renewal that changes the LAN IP would invalidate our LAN endpoint
from the peer's perspective. Three things heal this:
1. Our sender emits beacons on a 30s cycle, refreshing the peer's
   store entry with our new IP.
2. The existing `network_watch.go` deduper already handles the kernel-
   side notifications.
3. If the peer fails to handshake during the gap, it'll go RELAYED for
   ~90s and recover on the next beacon. Minor disruption, well within
   tolerance.

### Same machine, multiple Tincan daemons (testing only)
Listener and sender both bind via `SO_REUSEPORT`. Two daemons on the
same host can join the same group; each receives the other's beacons
and processes them (filter on self-source-IP drops them as expected).

### Multicast snooping switches
IGMP/MLD snooping switches will forward our multicast traffic to ports
that have a membership report. The listener's group join issues that
report on every live LAN interface, so all expected paths get the
traffic — and the membership maintainer re-issues it every beacon
interval (leave + join), so a switch that ages the group out of its
tables (typical on LANs with no IGMP querier) recovers within one
cycle. Switches without snooping flood — also fine.

### Wi-Fi AP client isolation
Some access points (especially hotels/cafés) drop client-to-client
traffic including multicast. Discovery fails silently; relay carries
on. Document this as a known limitation.

---

## Security considerations

### Authentication of beacons
A beacon claims a pubkey but doesn't prove possession. A malicious LAN
device could send `{V:1, PublicKey:<kilo's_pubkey>, Port:31337}` from
its own address. Our daemon would set peer kilo's endpoint to the
attacker's `IP:31337`. Our WG would attempt a handshake there; the
attacker doesn't have kilo's private key; handshake fails; after 90s
we flip to RELAYED; `MarkFailed` blacklists the attacker's address;
next legitimate beacon from kilo re-validates.

Net effect of attack: up to 90s of broken connectivity to kilo,
followed by recovery. No data leak (handshake never completes; no
plaintext sent). No persistent compromise.

Mitigation if 90s is too much: a future schema (`V == 2`) could
embed an Ed25519 signature over the beacon body using the sender's
identity key (separate from the WG key for forward-secrecy reasons),
with the identity pubkey added to the directory alongside `pk`. Out
of scope for V1.

### Replay
Beacons carry a `Nonce` field but it's unused in V1. A replayed beacon
just re-asserts the same endpoint; the receiver's store update is
idempotent. A future spam-flood defense could rate-limit per source IP
in the listener; V1 doesn't because beacons are cheap (~70 bytes,
trivially decoded) and a hostile LAN already has bigger attack
surface against our WG socket directly.

### Privacy / fingerprinting
The beacon reveals "this LAN has a Tincan node with pubkey X listening
on port Y." Comparable to mDNS announcing services. Disable via
`[discovery].enabled = false` if undesired.

### Cross-network leak
A beacon from one Tincan network arriving on another's LAN reveals
that network's pubkey to the other network's nodes (which then ignore
it). The pubkey isn't secret per se (any directory holder has it
already), but if two networks' admins didn't know about each other,
discovery beacons would make their coexistence visible. Minor.

---

## Test plan

### Unit (`go test ./internal/discovery/...`)
- **`beacon_test.go`** — round-trip msgpack encode/decode; reject
  malformed beacons (truncated, wrong type, unknown `V`); tolerate
  forward-compatible `V=2` payloads by ignoring unknown fields.
- **`store_test.go`** — `Update` adds an entry; `Lookup` honors TTL;
  `MarkFailed` blacklists until next `Update`; `Lookup` returns empty
  for unknown pubkey; concurrent `Update` / `Lookup` is race-free
  (`-race`).
- **`iface_test.go`** — live-LAN-interface filter against a synthetic
  netlink fixture (loopback excluded, tincan0 excluded, down links
  excluded).

### Integration (`//go:build integration`)
Two netns on the same host, joined by a `veth` pair, both running a
Tincan daemon with `[discovery].enabled = true` and a fake drop. Verify:

1. After `tincan up` on both sides, each daemon's lan store contains
   the other's pubkey within 10s.
2. WG handshake completes on the LAN endpoint (`wg show tincan0`
   shows the peer's LAN IP, not the relay).
3. Block the multicast group (e.g., `iptables -A INPUT -d 239.255.84.67
   -j DROP`) and restart one daemon; verify it goes RELAYED within 2
   minutes and `MarkFailed` is recorded.
4. Unblock multicast; verify recovery to DIRECT within 1 minute.

### Manual (three-machine setup)
`zf` (public) + `tau` and `kilo` (both NAT'd, same LAN). Validate
end-to-end on the same hardware the relay fallback was developed on:

1. With discovery disabled, confirm `tau` reaches `kilo` via `zf`.
2. Enable discovery on both; restart; confirm `tau↔kilo` becomes
   DIRECT with LAN endpoint within 1 minute.
3. `iperf3` between `tau` and `kilo`; throughput should match the LAN
   medium (≥ 100 Mbps on gigabit Ethernet), not the WAN uplink.
4. Disable Wi-Fi/Ethernet on one side, confirm fallback to relay
   within ~2 minutes; re-enable and confirm recovery.

---

## Phasing

Implementation can land in two PRs, each independently shippable:

**PR 1 — Discovery plumbing (no behavior change)**
- New `internal/discovery/` package: store, beacon codec, sender,
  listener; unit tests; integration test in netns.
- Config additions; CLI override flag.
- Daemon loop wires up `discovery.Start` but `chooseEndpoint` does NOT
  yet consult the store. Status `--json` exposes the store contents.
- Verifiable by running it and watching `tincan status --json | jq
  '.discovery'` populate with LAN endpoints without affecting routing.

**PR 2 — Activate LAN preference**
- `chooseEndpoint` consults the store between operator and observed.
- Relay iteration calls `MarkFailed` on `DIRECT → RELAYED` edges.
- Status display adds `(lan)` suffix.
- All integration / manual tests above pass.

This phasing lets PR 1 sit in production for a cycle (collecting
real-world data on what gets discovered) before flipping the behavior
switch.

---

## Out of scope (this spec)

- **Active LAN probing.** No portscanning, no ARP scans, no
  speculative-handshake-to-every-LAN-IP. Discovery is passive
  listening + opportunistic announce. If multicast is blocked, the
  relay handles it.
- **In-band negotiation over the relay tunnel.** Discussed as Option C
  in the design conversation. Could be added later as a fallback when
  multicast is blocked — uses the tunnel itself as the side-channel.
  Adds a tunnel-internal control-plane listener, which is a deliberate
  expansion of scope and worth a separate spec when needed.
- **Signed beacons (`V=2`).** Forward-compatible. V1 ships with
  pubkey-claim-only authentication (the WG handshake is the real
  authenticator).
- **Multi-LAN policy** — e.g., preferring `eth0` over `wlan0` based on
  link metrics. V1 uses whichever LAN endpoint arrives first; the
  network usually settles to a stable choice within 30s.
- **mDNS service registration** (`_tincan._udp.local`). Possible
  future enhancement; nothing in this spec depends on it.
- **Discovery across the WireGuard tunnel itself.** The Tincan
  interface is explicitly filtered out of beacon egress and listener
  ingress — we only do LAN-side discovery on physical/virtual
  hardware interfaces.
