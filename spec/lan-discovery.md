# Tincan — LAN Peer Discovery

Status: implemented design, with the current behavior summarized below.
The context and delivery proposal retain their historical motivation; API
sketches are not compatibility guarantees. See [Networking](../doc/networking.md)
for operator instructions. Privileged discovery/relay scenarios in the test
plan remain planned coverage, not claims about the existing integration test.

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
| Beacon cadence | 30s steady-state; initial burst of 3 over 5s on startup; on-receipt response when a known pubkey is unfamiliar (rate-limited globally to 1/5s) |
| Egress interface(s) | Every non-loopback, non-Tincan link with at least one global-scope IPv4 or IPv6 address |
| New WG state? | **No.** LAN endpoint is just another candidate in `chooseEndpoint` precedence |
| Endpoint precedence | `Endpoint > LANEndpoint (fresh) > ObservedEndpoint > empty`; same-NAT peers retry the last-known LAN endpoint even past TTL (see below) |
| LAN endpoint TTL | 90s since last beacon (3× cadence); not enforced for same-NAT peers, whose only fallback is a hairpin address |
| Invalidation on failure | Entering `RELAYED` for a peer marks that peer's LAN endpoint as failed; only a different advertised endpoint clears the failure. Same-NAT peers bypass the blacklist |
| Directory schema | **No change.** Discovery is purely client-local |
| Config knob | `[discovery].enabled` (default `true`); separate from `[observe]` |
| Module path | `internal/discovery/` (new) |
| Status display | Direct peers show `LAN` in the text STATUS column when the active endpoint is private or link-local |

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
- Receivers require nonzero `v`, nonempty `pk`, and nonzero `port`.
  `n` is unused and may be zero or absent. A beacon with `V > 1` is tolerated
  by V1 decoders (unknown fields ignored, all V1-known fields still parsed).
- No timestamp. Receivers stamp their local clock; sender clocks don't
  participate in the protocol.
- No signature. The pubkey is a *claim*; the downstream WG handshake
  proves possession (or fails). See § "Security considerations".

### Beacon cadence and triggers

- **Steady-state:** every 30s. Each cycle emits one beacon per eligible
  egress interface (see below).
- **Startup burst:** attempt beacons at `t = 0s, 2s, 5s`. An attempt is
  skipped until the first successful apply provides the node's key and listen
  port; a slow initial sync can therefore miss the burst.
- **Reactive:** when a beacon arrives from a directory pubkey we haven't
  seen in the LAN store yet, send a beacon back (within the next 200ms,
  jittered). Rate-limited globally to 1 reactive beacon per 5s. This
  collapses convergence to a single round-trip in the common case.
- SIGHUP and daemon wake events trigger reconciliation, not an extra beacon.
  Sender cadence and multicast sockets are startup settings; changes require
  restarting the daemon.

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
3. `net.FlagUp` is set (enumeration uses `net.Interfaces`, not netlink).
4. Has at least one non-link-local, non-loopback IP address.

The sender reuses one socket per family and selects each live LAN interface
with `IP_MULTICAST_IF` (IPv4) / `IPV6_MULTICAST_IF` (IPv6) before writing a
beacon. Receivers, not senders, join the multicast groups.

If a node has multiple LAN interfaces (Wi-Fi + Ethernet on a laptop),
beacons go out on every one — the peer on the other side may only be
reachable on one of them. Receiving a beacon on multiple interfaces is
treated as one logical event (deduped by pubkey + source IP).

### Receiving and processing

A listener goroutine per family reads beacons on the configured port.

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
  return node.ObservedEndpoint                 // no client-side observation TTL
```

Where `lanStore.Lookup` returns the LAN endpoint iff:
- An entry exists for `node.PublicKey`,
- `now - LearnedAt <= LANEndpointTTL` (90s default),
- `FailedEndpoint != Endpoint` (that specific endpoint is not blacklisted).
  Repeated beacons for the same failed address refresh its timestamp but do
  not make it usable again.

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
last handshake is older than 3 minutes (matching the relay controller's
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
    FailedEndpoint string
}
```

Three events advance the state:

- **Beacon arrives** (listener): if the pubkey is new, learn the
  endpoint. A beacon repeating the *same* endpoint refreshes `LearnedAt`
  only — it never clears a failure stamped on that same endpoint. A
  beacon advertising a *different* endpoint is accepted only when the
  current one is no longer usable (stale or failed); while the current
  endpoint is usable the change is rejected (pinning), so an
  unauthenticated beacon can't displace a working path. See "Security
  considerations § Authentication of beacons."
- **TTL expires** (next iteration after `now - LearnedAt > TTL`):
  `Lookup` returns empty; effectively unused. We don't actively delete —
  a fresh beacon revives it. Garbage-collected (`Store.GC`, called each
  daemon iteration) once the entry is older than `10 × TTL` or its
  pubkey has left the directory.
- **RELAYED transition** (relay controller, see below): `MarkFailed`
  stamps `FailedAt = now` and records `FailedEndpoint = Endpoint` for
  any peer that just transitioned `DIRECT → RELAYED`. That specific
  endpoint stays blacklisted until a beacon advertises a *different*
  one; repeating the failed address does not unblock it. Same-NAT peers
  are exempt from the blacklist at lookup time: their shadow-peer probes
  keep targeting the last-known LAN endpoint, because the hairpin
  alternative can never complete a handshake.

Wake-triggered reconciles (a beacon learning or changing an endpoint
nudges the daemon to reconverge immediately) are debounced to at most
one per 10s, so a beacon storm or a flapping dual-homed peer can't drive
back-to-back drop fetches.

### Why no new state in `relay.Mode`?

The state machine's job is to decide whether the peer's tunnel IP gets
its own AllowedIPs entry (DIRECT) or is folded into the relay target's
AllowedIPs (RELAYED). LAN-direct uses its own AllowedIPs entry — same
shape as DIRECT, just with a different `peer.Endpoint`. There's nothing
the state machine needs to do differently. Adding a third state would
duplicate transition logic (DIRECT↔LAN would have all the same edges as
DIRECT↔RELAYED) for no behavioral gain.

The `LAN` status label in `tincan status` is a presentation-layer detail —
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
  the endpoint between cycles); reject invalid configurations at load.
- Multicast addresses must be valid + actually multicast (`IsMulticast()
  == true`); fail config load with a clear error otherwise.
- IPv6 scope is not further restricted; the default group is link-local.

There is no CLI discovery override. Set `[discovery].enabled = false` and
restart the daemon to disable it.

---

## Module layout

```
internal/discovery/
├── discovery.go      # package doc, public surface (Store, Listener, Sender)
├── beacon.go         # Beacon msgpack codec + tests
├── sender.go         # sender goroutine: cadence, interface enumeration, send sockets
├── listener.go       # listener goroutine: bind, receive, parse, hand off to Store
├── store.go          # LANState, in-memory map, mutex, lookup/update/invalidate API + tests
└── iface.go          # live-LAN-interface enumeration (net.Interfaces)
```

The CLI calls `Start(ctx, cfg, dirSource, wakeCh)`, which returns `*Store`.
`Store` is a concrete, mutex-protected type. Its methods include `Lookup`,
`LookupLastKnown`, `Update` (returning `UpdateResult`), `MarkFailed`, `GC`,
`SetSelf`, and `Snapshot`; see `store.go` for their signatures.

`Start` launches sender and listener goroutines. `dirSource` yields the latest
directory for membership filtering. `wakeCh` nudges reconciliation when a
candidate changes; `SetSelf` supplies the key and live port after apply.

---

## Daemon loop integration

`runDaemonLoop` in `internal/cli/up.go` starts discovery once before polling.
The runtime exposes its latest directory through an `atomic.Pointer`-backed
`dirSource` closure and passes its store into reconciliation. Both full syncs
and the 30-second relay ticks call `markLANFailures` on DIRECT → RELAYED edges
and pass a lookup closure through `manager.Apply` to `chooseEndpoint`.

The listener sends `"lan endpoint learned"` on `wakeCh` when a candidate changes.
After a successful full apply, `SetSelf` supplies the live key and listen port;
GC and snapshot persistence run on that full-iteration cadence too.

---

## Status display

Text status labels a direct peer's private or link-local active endpoint as
`LAN` in the STATUS column. This is an IP-address classification, not an
assertion that discovery supplied the endpoint. It also reports the count
of learned LAN endpoints from the daemon's persisted snapshot.

`tincan status --json` exposes live peers under `.wireguard.peers` and learned
candidates under `.discovery.lan_endpoints`. There is no `endpoint_source`
field. Discovery snapshots are written on full reconciliations, not on every
received beacon or relay tick.

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
T > 3:00   next relay tick sees stale handshake → DIRECT → RELAYED
           store.MarkFailed("kilo") blacklists this exact LAN endpoint
           traffic now uses the relay; a Tincan shadow peer keeps probing
T = later  a beacon repeating the failed endpoint refreshes LearnedAt only
           a different advertised endpoint can clear the blacklist
           same-NAT peers bypass the blacklist and retain the LAN probe
T = later  a successful shadow handshake restores DIRECT on a relay tick
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
Both groups are joined, but the store tracks only one endpoint per peer.
The first usable endpoint is pinned until it fails or expires. There is no
address-family preference or IPv6 tie-break.

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
3. If the peer fails to handshake for over 3 minutes, it goes RELAYED on
   the next 30-second tick. A different beacon endpoint becomes a candidate;
   a successful shadow handshake, not a timer, restores direct routing.

### Same machine, multiple Tincan daemons (testing only)
The listener binds a wildcard UDP port without `SO_REUSEPORT`. A second
local daemon using that port cannot start discovery. Even with separate
ports, self-source-IP filtering excludes beacons from the same machine.

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
its own address, trying to point our WG at the attacker. Two store
rules bound the damage (`internal/discovery/store.go`):

- **Pinning.** A beacon advertising an endpoint *different* from the
  one currently stored is rejected while that stored endpoint is still
  usable (within TTL, not failed). An unsolicited beacon therefore
  cannot displace a *working* path; the incumbent must fail or age out
  first. So the attack only lands if kilo has no usable endpoint yet
  (no prior beacon) — the first beacon wins, as before.
- **Failed-endpoint memory.** When the relay machine flips kilo to
  RELAYED, `MarkFailed` records the *specific* endpoint that failed. A
  beacon repeating that same address does **not** resurrect it — only a
  beacon for a genuinely different endpoint clears the failure. A
  spoofed flood of the same bad address can no longer keep re-validating
  a dead path.

A spoof that wins the initial race can disrupt direct connectivity until
failure detection (over 3 minutes, evaluated on 30-second ticks) switches
traffic to the relay. A proven-live kernel endpoint is preserved rather
than overwritten. A persistent attacker can still delay LAN recovery by
advertising fresh bad endpoints while the real path is down.

Same-NAT peers bypass the blacklist and continue probing their stored LAN
candidate; this is a recovery heuristic, not beacon authentication. No
payload leaks to an attacker without the peer's WireGuard private key.

Full authentication needs a future schema (`V == 2`) embedding an
Ed25519 signature over the beacon body using the sender's identity key
(separate from the WG key), with the identity pubkey added to the
directory alongside `pk`. Out of scope for V1.

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
  malformed beacons (truncated, wrong type, zero `V`); tolerate
  forward-compatible `V=2` payloads by ignoring unknown fields.
- **`store_test.go`** — `Update` adds an entry; `Lookup` honors TTL;
  `MarkFailed` blacklists until a different endpoint is learned; `Lookup` returns empty
  for unknown pubkey; concurrent `Update` / `Lookup` is race-free
  (`-race`).
- **`iface_test.go`** — scope and interface filtering (loopback, the tunnel,
  and down interfaces are excluded).

### Planned discovery integration coverage (not yet automated)
Two netns on the same host, joined by a `veth` pair, both running a
Tincan daemon with `[discovery].enabled = true` and a fake drop. Verify:

1. After `tincan up --daemon` on both sides, each daemon's LAN store contains
   the other's pubkey within 10s.
2. WG handshake completes on the LAN endpoint (`wg show tincan0`
   shows the peer's LAN IP, not the relay).
3. Block the multicast group (e.g., `iptables -A INPUT -d 239.255.84.67
   -j DROP`) and interrupt the direct path; verify it goes RELAYED after
   the 3-minute stale-handshake threshold plus at most one 30-second tick,
   and `MarkFailed` is recorded. Blocking beacons alone does not invalidate
   a working WireGuard path.
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
   after roughly 3 minutes plus one relay tick; re-enable and confirm recovery.

---

## Original delivery proposal (historical)

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
- Status display adds the `LAN` label.
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
