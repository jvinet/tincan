# Tincan — VPN DNS Names

## Context

Tincan nodes referred to each other by raw tunnel IPs; name resolution was
explicitly out of scope for the MVP. This feature adds MagicDNS-style naming:
the directory defines a non-public domain (e.g. `vpn`, `vpn.home`) and every
node resolves as `<name>.<domain>`.

The design follows from one observation: unlike Tailscale, every Tincan
member already holds the complete name → tunnel-IP mapping — it is the
directory it decrypts on every sync, cached on disk. Members therefore need
no DNS server, no resolver reconfiguration, and no runtime dependency on any
other node; a managed `/etc/hosts` block is sufficient and keeps working
offline. The only clients that genuinely need a DNS *server* are
plain-WireGuard spokes (phones): no daemon, no root, no directory. They get
`DNS = <hub tunnel IP>, <domain>` in their rendered configs, and the hub —
the node they already route everything through — answers from its cached
directory.

Two small, independent mechanisms; no control plane, no new trust:

| Population | Mechanism | Failure mode |
|---|---|---|
| Members (run the daemon) | `/etc/hosts` managed block | none new — file persists offline |
| Plain-WG spokes | hub serves UDP 53 on its tunnel IP | hub down ⇒ spoke DNS down (it already carried all spoke traffic) |

## Decisions (locked in)

- **Domain in the signed payload.** `Directory.Domain` (msgpack `dom,omitempty`),
  lowercase, no trailing dot. The signed payload skips unknown msgpack keys by
  design, so pre-domain clients open domain-carrying directories untouched;
  **schema stays v2**. (The envelope stays strict — evolution belongs in the
  payload; see codec.go.)
- **Feature off when unset.** Empty domain ⇒ no hosts block, no listener, no
  DNS line in rendered configs. Existing networks see zero behavior change.
- **Conditional validation.** `Validate()` enforces domain syntax, RFC 1123
  label-ness of every node name, and case-insensitive name uniqueness *only
  when a domain is set*. Safe because the only writers of a non-empty domain
  (`init --dns-domain`, `set-domain`) pre-check all names: a published
  directory with a domain always conforms, so clients can never trip the
  check at Open. Same publish-time-strictness argument as `validateEndpoint`.
- **`add-node` requires DNS-safe names always**, domain or not — otherwise
  every name minted today is a rename `set-domain` forces tomorrow. Legacy
  names in domain-less directories remain valid.
- **Hosts entries are FQDN-only** (`10.42.0.3	nas.vpn`, lowercased, sorted).
  No bare-name aliases: machines commonly map bare names to direct LAN IPs in
  `/etc/hosts`, and the managed block must never shadow them. Spokes still get
  bare names via the search domain. All nodes are listed, including self and
  spokes.
- **Markers are sacred.** Exactly one begin/end pair, matched as whole
  trimmed lines; anything else is `ErrMalformedMarkers` and the file is left
  untouched — eating operator content out of `/etc/hosts` is the one
  unrecoverable failure mode. Symlinked hosts files (NixOS) are refused with
  `ErrSymlink` rather than replaced by a rename. Writes are atomic
  (renameio), mode-preserving, and skipped entirely when content is unchanged
  (the daemon calls this every sync interval).
- **Hosts sync is warn-don't-fail** and runs *after* a successful WireGuard
  apply — names pointing at tunnel IPs the kernel doesn't route are worse
  than no names. It also runs when the domain is empty, which strips a stale
  block exactly once after `set-domain --clear`. `down` removes the block.
  Warnings dedupe on the error's root cause.
- **The listener serves on hubs only, by default.** Auto policy: self has
  the `Relay` flag, or `RelayTarget(dir, "")` selects self — exactly the
  node `peerHub` hands to spokes at enrollment, the only clients that query.
  `[dns] serve` overrides both ways. Fleet-wide :53 binding would fight
  members' dnsmasq/Pi-hole for nothing.
- **Lifecycle is per-iteration reconcile, not start-once.** The bind address
  (self tunnel IP) and domain are only known after the first successful
  sync and can change at runtime (set-domain, renumbering, relay role
  moves). Reconcile converges the running server to the desired
  (addr, domain, upstream) tuple; EADDRINUSE warns once (deduped) and
  retries every iteration.
- **Wire codec is `golang.org/x/net/dns/dnsmessage`** — already a module
  dependency via discovery's x/net use, and the codec the Go resolver itself
  uses. Only serving logic is hand-written. UDP only.

## The critical constraint: spokes send ALL their DNS through the tunnel

A mobile WireGuard app applies the config's `DNS =` server as the device's
*only* resolver while the tunnel is up — even with split `AllowedIPs`. Every
query for every domain lands on the hub. Refusing non-VPN names would cut
the phone off from the internet, so the listener **forwards** anything
outside the domain to an upstream resolver:

- Raw byte relay, not re-resolution: EDNS options, HTTPS/SVCB (type 65,
  which iOS/Android query constantly), and DNSSEC material pass through
  untouched.
- Fresh socket per exchange: ephemeral source-port entropy plus a query-ID
  check keeps replies from crossing queries; mismatched IDs are skipped
  until deadline.
- Failures synthesize SERVFAIL (same ID/question, QR+RA set) — mobile stubs
  fail over quickly on SERVFAIL but stall on silence.
- Concurrency cap (256 in-flight); past it, queries drop and clients retry.
- Upstream default: first `/etc/resolv.conf` nameserver (loopback like
  systemd-resolved's `127.0.0.53` is correct — the proxy runs on the hub);
  `[dns] upstream` overrides; last-resort fallback `1.1.1.1:53` with a loud
  warning, because a hub that can't forward breaks all spoke DNS. An
  upstream equal to the listener's own address is rejected (forwarding
  loop).

## Authoritative behavior (rcode matrix)

| Query | Answer |
|---|---|
| A `<name>.<domain>`, name known | A record, tunnel IP, TTL 60 |
| AAAA / HTTPS / TXT / anything else, name known | **empty NOERROR** (NXDOMAIN reads as "name is dead" to dual-stack clients) |
| apex `<domain>`, any type | empty NOERROR (browsers probe it; NXDOMAIN reads as "zone dead") |
| `a.b.<domain>` (multi-label) | NXDOMAIN |
| unknown name under domain | NXDOMAIN |
| PTR, address inside `NetworkCIDR`, assigned | PTR `<name>.<domain>.` |
| PTR, inside CIDR, unassigned | NXDOMAIN (ours to deny) |
| PTR outside CIDR, `ip6.arpa` | forwarded |
| anything not under the domain | forwarded |
| non-IN class, non-QUERY opcode | forwarded |
| QR bit set (a response) | dropped — never answered or forwarded (loop bait) |
| unparsable / truncated | dropped; truncated question section ⇒ FORMERR |

Name matching is case-insensitive; the question section is echoed with the
client's original spelling (0x20 randomization compatibility). Answers carry
AA=1 and RA=1 (stubs set RD and distrust RA=0). TTL is 60 s so a removed
node's name dies within roughly a sync interval. No SOA/negative-caching
records — spoke stubs cope, and the zone has no delegation story anyway.

## Operational notes

- **Upgrade the admin first.** An older admin binary republishing (e.g.
  endpoint observation reads `directory-source.bin`, mutates, republishes)
  doesn't know `dom` and silently drops the domain. Single-curator model
  makes this a one-machine rule.
- **`set-domain --clear` strands spokes.** Their snapshot configs still
  point all device DNS at a hub that stops answering. The command prints the
  affected spoke names loudly; re-render and re-enroll them.
- **Port 53 conflicts.** A hub already running Pi-hole/dnsmasq on the tunnel
  IP keeps it: tincan warns once, retries each sync, and the operator either
  frees the port, sets `[dns] serve = false`, or points spokes' DNS at the
  resident resolver instead.
- **`status`** shows the domain, hosts-block freshness (read-only check),
  the serving policy, and a live UDP probe of `<tunnel IP>:53` — the daemon
  is a different process, so an actual query is the only honest check.

## Limitations

- IPv4 tunnel IPs only (as everywhere in tincan); AAAA is empty-NOERROR.
- UDP only, no TCP listener: authoritative answers are single records that
  always fit 512 bytes. A TC-flagged *forwarded* reply passes through
  verbatim and the client's retry-over-TCP goes... nowhere; in practice
  mobile stubs retry over UDP with EDNS and upstreams keep answers under
  the EDNS size. Revisit if a real spoke hits this.
- Single-label names only (`<name>.<domain>`); no per-node subdomains.
- No DNSSEC for the VPN zone — the directory signature already
  authenticates the data; members don't even use DNS.
- Spoke configs are snapshots; domain/hub changes need a re-render.

## Module layout

- `internal/directory/dnsname.go` — `ValidateDomain` / `ValidateLabel` /
  `NormalizeDomain`; conditional enforcement in `Validate()` (codec.go).
- `internal/hosts` — `Block` (render), `Rewrite` (pure splice), `Apply`
  (atomic write). No CLI imports; fully testable without root.
- `internal/dnsserve` — `Start`/`Close` (UDP listener), `respond` (pure
  packet → reply/forward decision), raw-relay forwarder, `DefaultUpstream`
  (resolv.conf), `Probe` (status liveness).
- `internal/cli/setdomain.go` — show/set/clear (admin mutation, follows
  remove-node's fetch → mutate → bump → publish flow).
- `internal/cli/hosts_sync.go` — warn-don't-fail syncer + `down` removal.
- `internal/cli/dns_server.go` — `dnsServerManager` per-iteration reconcile
  + `shouldServeDNS` policy.
- `internal/cli/qrconfig.go` — `DNS = <hub IP>, <domain>` line in rendered
  spoke configs.
