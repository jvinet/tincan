# Tincan — macOS Support Plan

Status: proposed; this document does not describe implemented support.

## Goals and scope

Run Tincan natively on macOS as a full directory member or admin, interoperating
with existing Linux members and plain-WireGuard spokes. Preserve directory
security, bootstrap compatibility, endpoint observation, direct/relay recovery,
LAN discovery, and VPN names without adding a coordination service.

Initial release targets:

- Apple Silicon (`darwin/arm64`) and Intel (`darwin/amd64`), initially macOS
  14+; confirm this baseline against the Go toolchain and helper during the
  spike.
- Root-operated CLI and a system-wide launchd service, not a GUI or login agent.
- The existing IPv4, split-tunnel network model; IPv6 peer endpoints remain
  usable, but IPv6 tunnel addressing and full-tunnel routing are not added.
- Both admin operations and forwarding-relay/DNS-hub roles. macOS relay support
  is not complete until forwarding and spoke interoperability are tested.

Out of scope: a Network Extension, App Store distribution, the WireGuard.app
backend, automatic firewall/PF changes, Windows support, and a new wire format.

## Current portability audit

The source, rather than older implementation plans, is the baseline:

| Area                                       | Current behavior                                              | Required work                                                                 |
| ------------------------------------------ | ------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `internal/wg/{manager,link,addr,peers}.go` | All Linux-tagged; link/address/route operations use netlink   | Share peer policy and reconciliation; introduce Darwin device/link operations |
| `internal/cli/down.go`                     | Imports netlink to recognize a missing link                   | Return a platform-neutral missing-device error from `internal/wg`             |
| `internal/cli/{status,status_network}.go`  | Query `wgctrl` using the configured interface name            | Resolve the actual Darwin device without creating one                         |
| `internal/cli/network_watch.go`            | Linux-only netlink address subscription                       | Darwin notifications and a bounded recovery fallback                          |
| `internal/cli/admin_preflight.go`          | Linux-only `/proc/sys/net/ipv4/ip_forward` check              | Darwin forwarding check and macOS-specific guidance                           |
| `internal/discovery/`                      | Already uses `net.Interfaces` and `x/net` multicast           | Test Darwin sockets/control messages; filter the actual `utun` interface      |
| `internal/config/schema.go`                | `/var/lib/tincan`, `/run/tincan.pid`, `tincan0` defaults      | Platform-specific state/runtime defaults and logical/native name distinction  |
| `internal/daemon/`                         | Re-exec detachment, Unix signals and flock-protected PID file | Test on Darwin; add foreground continuous operation for launchd               |
| `internal/hosts/`, `internal/dnsserve/`    | Managed hosts block; hub upstream from `resolv.conf`          | Verify macOS host resolution, cache behavior and upstream selection           |
| `Makefile`, `misc/tincan.service`          | GNU `install -D` and systemd service                          | BSD-compatible installation and a LaunchDaemon template                       |
| `test/integration/netns_test.go`           | Opt-in Linux network-namespace harness                        | Explicit Linux build constraint plus a separate Darwin harness                |

Keys, directory codecs, bootstrap data, dead-drop backends, cache rollback
protection, and the relay state machine should remain platform-independent. The
existing `wgctrl` dependency supports userspace control, but it does **not**
create a macOS WireGuard device. The indirect `wireguard` module dependency is
not an installed `wireguard-go` executable.

## Architecture decisions

### 1. Use a userspace WireGuard helper initially

Use the upstream `wireguard-go` executable to own the macOS `utun` device and
packet engine. Continue configuring peers and reading handshakes/counters with
`wgctrl` over WireGuard's Unix-domain UAPI socket. Do not invoke `wg-quick`,
render intermediate private-key configs, or use WireGuard.app automation.

This adds a macOS runtime dependency, but preserves an important CLI contract:
plain `tincan up` applies once and exits while the tunnel continues carrying
traffic. An embedded packet engine would die with that process unless Tincan
also introduced a persistent tunnel-worker mode. Defer that larger redesign; it
is not necessary for the initial port.

Resolve the helper to an absolute path from the documented installation
locations (including both Homebrew prefixes), not an arbitrary command from an
untrusted working directory. Report a useful installation error if it is
missing. The service must work with launchd's minimal environment. Keys travel
through UAPI only, never argv, environment variables, or logs.

### 2. Separate logical identity from the native interface

Keep `[wireguard].interface = "tincan0"` as the logical Tincan device name on
both platforms. Darwin allocates an available `utunN`; neither `tincan0` nor a
fixed `utun0` can be assumed to be an available native interface.

- Start the helper with automatic `utun` allocation. Obtain its actual name
  through its supported name-reporting mechanism (`WG_TUN_NAME_FILE`, to be
  verified against the chosen helper version), not by diffing interface lists or
  parsing human-readable logs.
- Store the logical-to-native mapping, helper identity, expected public key, and
  owned address/route information in a root-only runtime record under
  `/var/run/tincan/`. Use atomic writes, locking, and symlink-safe handling.
- Resolve the native name consistently for UAPI, addressing, routes, teardown,
  both status modes, the network watcher, and discovery ingress/egress filters.
  A cached name alone is not proof that a device still belongs to Tincan.
- Preserve the logical `interface` field in status JSON; add `native_interface`
  and backend/helper health information rather than changing its meaning.
- Do not put native interface names or helper paths into directory/bootstrap
  payloads. A Linux-produced bootstrap must work on a Mac unchanged.

### 3. Keep platform policy behind small boundaries

Make peer construction and device reconciliation portable. Remove Linux tags
from `peers.go`, its tests, and the pure reconciliation helpers/tests currently
in `manager.go`/`manager_test.go`.

Keep `wg.Manager` as the CLI-facing API, with small platform-specific methods
for device creation/resolution, link setup, address/route reconciliation, and
teardown. Put netlink imports in Linux-only files (for example, `link_linux.go`
and `addr_linux.go`); implement Darwin equivalents separately. Expose a
read-only device snapshot/name API so status does not bypass native name
resolution or accidentally launch a helper.

Use a narrow device-reader/configurer interface around `wgctrl` where needed for
tests. Preserve the existing behavior of `ReplacePeers=false`, peer removal,
explicit keepalive resets, live-endpoint preservation, shadow peers, and
endpoint-push tracking used by admin observation. These are shared policy, not
kernel-only behavior. Avoid building an unrelated general networking framework.

## Device and route lifecycle

### Helper ownership

The helper must have a lifetime independent of the one-shot command or
reconciliation loop. Launch it in foreground-helper mode as a detached,
explicitly tracked process; Tincan, not the helper's own daemonization, manages
startup readiness and records its identity. Do not bind its lifetime to a
short-lived sync context. Drain or redirect diagnostics so inherited pipes
cannot block it; reap child processes while their parent remains alive.

Serialize create/adopt/teardown per logical device. Repeated reconciles and
concurrent commands must not create multiple helpers for the same device.

1. Validate root privileges, helper availability, and runtime directory safety
   before creating resources.
2. If an owned helper/device is healthy, reuse it. Validate its UAPI/public key
   and process identity against trusted runtime state; do not adopt an unrelated
   `utun` or another VPN's socket.
3. Otherwise remove only provably stale Tincan runtime state. Record provisional
   ownership as resources are acquired, allocate a new device, and wait with a
   timeout for both its reported name and usable UAPI. Interrupted startup must
   leave enough evidence for safe recovery, not an untracked helper.
4. Configure the device, address, MTU and route. Mark the runtime record ready
   only after setup succeeds. Roll back newly-created resources on failure,
   without destroying a previously working tunnel.
5. Detect helper exit or device loss on subsequent reconciles, log the cause,
   recreate the owned device, and update native-name consumers. During an
   offline-drop recovery, use the existing authenticated directory cache and
   retain the monotonic serial guard.

A PID alone is insufficient authority to signal a process: include a verifiable
process-start identity and cross-check the owned device/UAPI. Never kill an
arbitrary process after PID reuse. Missing/stale devices make `down` idempotent;
permission failures and uncertain ownership must remain errors, not look like
"already down."

Preserve existing lifecycle semantics: stopping only the orchestrator leaves the
data plane running; `down --stop` stops reconciliation first, then removes the
tunnel. Plain `down` may be undone by a running orchestrator's next reconcile.
Teardown stops only the owned helper, closes/removes its owned UAPI resources,
removes its routes/runtime record, and removes the managed hosts block. An
unclean helper exit must be recoverable without deleting another VPN's state.

### Darwin addressing and routing

Use macOS point-to-point `/32` interface addressing and an interface route for
`Directory.NetworkCIDR`, matching Linux's effective split-tunnel behavior. Use
native APIs or fixed absolute system tools (`/sbin/ifconfig`, `/sbin/route`)
with argument arrays and strict input validation, never shell command strings.
Prefer the system tools for the first implementation unless the spike identifies
a correctness limitation.

Reconcile idempotently rather than treating every existing route as success.
Track owned addresses/routes so renumbering, CIDR changes, helper replacement,
and teardown remove obsolete entries. Refuse conflicting routes owned by another
interface/VPN rather than replacing them. Do not alter the default route, LAN
routes, system DNS, or other `utun` interfaces. Validate MTU changes and ensure
public peer endpoints remain reachable outside the tunnel.

For relays, inspect `net.inet.ip.forwarding` and warn with the macOS command
(`sudo sysctl -w net.inet.ip.forwarding=1`) and persistence instructions.
Forwarding is an operator decision: do not enable it globally or rewrite PF
rules automatically. Distinguish publishing-admin privileges from the actual
forwarding role; a non-admin relay also needs appropriate diagnostics.

## Configuration and continuous operation

Use build-tagged platform defaults, retaining all existing Linux values:

| Setting                | Linux                     | macOS                     |
| ---------------------- | ------------------------- | ------------------------- |
| Config                 | `/etc/tincan/config.toml` | `/etc/tincan/config.toml` |
| State directory        | `/var/lib/tincan`         | `/var/db/tincan`          |
| Orchestrator PID file  | `/run/tincan.pid`         | `/var/run/tincan.pid`     |
| Logical interface      | `tincan0`                 | `tincan0`                 |
| Helper runtime records | not needed                | `/var/run/tincan/`        |

Explicit configuration overrides continue to win. Audit `init`, `join`, help
text, full/minimal config generation, and tests for embedded Linux defaults.
Keep persistent cache/key material separate from disposable runtime records;
reboot must not reset `cache.serial`. Preserve config/bootstrap permissions
(`0600`) and protect runtime records/sockets from unprivileged mutation.

Add `tincan up --foreground`: acquire the same PID-file lock and run the full
continuous reconciliation loop without re-exec, `setsid`, or stdio redirection.
Make it mutually exclusive with `--daemon`; do not change plain `up` into a
continuous command. Retain `up --daemon` for manual use on both platforms. Test
SIGHUP, termination, lock contention, readiness, and startup failure on Darwin
rather than assuming all Unix daemon behavior is equivalent.

Ship `misc/tincan.plist`, installed root-owned with mode `0644` under
`/Library/LaunchDaemons/`. It should use:

- An explicit label and absolute binary/config paths.
- `ProgramArguments` running `tincan up --foreground`, never `--daemon`.
- `RunAtLoad`, a suitable `KeepAlive` policy, and restart throttling.
- A deliberate helper search environment and usable stdout/stderr logging.

Document `launchctl bootstrap`, `bootout`, and `kickstart`. A KeepAlive service
can restart after `down --stop`; service shutdown/uninstallation must first
unload it with `bootout`, then tear down the tunnel. Boot without network access
must not permanently disable the service. Verify existing syslog integration on
macOS and provide reliable stderr/file diagnostics when syslog is unavailable;
do not discard fallback logs into `/dev/null`.

## Network changes and LAN discovery

Implement `network_watch_darwin.go` using a routing socket (`AF_ROUTE`/
`PF_ROUTE`, with `golang.org/x/net/route` parsing). Observe meaningful address,
interface and default-route changes, normalize snapshots, and reuse the existing
wake/debounce behavior. Ignore loopback and Tincan's own native device and route
changes to avoid reconcile storms. Reconnect after watcher failures; retain
periodic snapshot reconciliation as a fallback, including after sleep/wake when
the address itself may not change. Make event normalization and deduplication
independently testable.

Discovery's interface enumeration is already portable; do not replace it with
netlink based on the older discovery spec. Instead:

- Make native tunnel exclusion dynamic, including after helper recreation; the
  current configured-name-only filter would miss `utunN`.
- Verify IPv4/IPv6 group joins, destination and ingress-interface ancillary
  metadata, per-interface sends, hop limits, and periodic membership renewal on
  real macOS sockets.
- Preserve fail-closed validation for missing metadata, unicast packets, tunnel
  ingress, tunnel-network sources, and unknown keys. Do not relax the beacon
  trust boundary to work around platform socket differences.
- If one address family is unavailable, close partial startup resources and
  degrade explicitly to the working family. If safe receive filtering is
  impossible, warn and disable that family, not the VPN or ingress checks.
- Test Wi-Fi/Ethernet changes, multicast-blocking APs, and macOS firewall or
  Local Network privacy restrictions, especially for headless LaunchDaemons.
  Document permissions accurately; do not assume root bypasses every policy.

## VPN names and DNS hub

Keep the managed hosts-block design: macOS members already hold the directory
and do not need a resolver profile or `/etc/resolver` entries. Verify atomic
writes through macOS's `/etc` layout without weakening final-file symlink
protection, marker validation, permissions, or preservation of operator content.
Test additions, removals and domain clearing with the system resolver
(`dscacheutil` and normal application lookups); `dig` alone does not test hosts
resolution. If cache invalidation is needed, perform it only after an actual
hosts change, with bounded, warn-only platform handling.

A Mac acting as a hub must serve the existing tunnel-IP DNS endpoint and forward
non-VPN queries correctly. `/etc/resolv.conf` is not a complete account of macOS
scoped DNS. Validate the current upstream selection against active system DNS
(`scutil --dns`); provide a Darwin default-upstream implementation or clearly
require `[dns].upstream` where selection is ambiguous. Preserve loop detection
and existing fallback warnings. Do not silently reconfigure system resolvers or
claim complete scoped-DNS forwarding from a single upstream. Re-evaluate the
selected upstream after network changes. Test plain-WireGuard spokes against a
Mac hub as well as Mac members against a Linux hub.

## Delivery phases and acceptance gates

### Phase 0 — Prove the Darwin backend

- [ ] On a real Mac, create an automatically allocated helper-owned `utun`,
      discover its name, configure/read it through the pinned `wgctrl`, and pass
      traffic to a Linux peer.
- [ ] Verify helper version/name reporting, UAPI paths/permissions, detached
      lifetime, process identity, teardown, MTU, route syntax and ancillary
      metadata.
- [ ] Record tested macOS/helper versions and minimum OS/toolchain requirements.

**Gate:** a reproducible two-node experiment validates the proposed APIs and
ownership model. Revise these decisions before implementing if it fails.

### Phase 1 — Portability boundaries, no Linux behavior change

- [ ] Split shared peer/reconcile logic from Linux link operations; move pure
      tests out from Linux-only constraints and normalize teardown errors.
- [ ] Route all device queries through the shared read-only resolution API.
- [ ] Add Darwin defaults, watcher/preflight implementations, and backend
      scaffolding. Keep netlink imports out of common CLI files.

**Gate:** Linux tests still pass; both Darwin architectures compile. Unsupported
backend operations must report explicit errors, not pretend to succeed.

### Phase 2 — Working Mac member and admin

- [ ] Implement helper ownership, runtime locking/mapping, read-only status,
      address/route reconciliation, recovery, and idempotent teardown.
- [ ] Exercise Linux-admin → Mac-join and Mac-admin → Linux-join bootstraps,
      publish/sync, peer changes, one-shot `up`, `up --daemon`, and
      `down --stop`.
- [ ] Verify offline-cache startup and failure rollback without changing
      directory encoding or weakening signature/serial validation.

**Gate:** bidirectional tunnel traffic, unchanged bootstrap compatibility, no
orphaned helpers after teardown, and no damage to unrelated VPN interfaces.

### Phase 3 — Continuous operation and feature parity

- [ ] Add foreground mode and LaunchDaemon lifecycle/logging.
- [ ] Finish native-name-aware discovery and network/sleep recovery.
- [ ] Validate hosts names, DNS upstream behavior, endpoint observation, and
      direct → relay → direct recovery across mixed Linux/macOS members.
- [ ] Validate a Mac forwarding relay/DNS hub, including plain-WireGuard spokes
      and disabled-forwarding/firewall diagnostics.

**Gate:** reboot, service restart, helper crash and network transitions recover
without manual runtime-file edits; every advertised role is tested.

### Phase 4 — Packaging, CI and documentation

- [ ] Replace GNU-only installation commands with `install -d`/`install -m`;
      keep Linux systemd installation and add explicit macOS service
      installation. Support staging with `DESTDIR` without loading services on
      the build host.
- [ ] Produce separate Darwin arm64/amd64 release archives with checksums and
      version metadata. Document `wireguard-go` installation and optional `wg`
      troubleshooting tools; do not imply the helper is bundled if it is not.
- [ ] Add Linux and native macOS CI jobs for build/unit/race tests, plus
      cross-build checks for both Darwin architectures. Cross-compilation is not
      a substitute for native execution or privileged/network tests.
- [ ] Update `README.md`, `doc/setup.md`, `doc/configuration.md`,
      `doc/operations.md`, `doc/networking.md`, `doc/dns.md`,
      `doc/architecture.md`, and `doc/development.md` with dependencies, paths,
      service commands, permissions, known limitations and cleanup/uninstall
      instructions.
- [ ] Document Gatekeeper/quarantine behavior for release binaries. Decide
      signing/notarization before claiming frictionless end-user installation;
      neither an App Store package nor a universal binary is required initially.

**Gate:** a clean supported Mac can follow the documentation from installation
through enrollment, boot-time operation, status inspection and complete removal.

## Validation matrix

Unit tests should use fake helper/process, device, route and event operations;
ordinary tests must not require root or mutate the developer's real network.
Cover concurrent startup, timeout/partial failure, stale/reused PID and native
name, ownership mismatch, permission errors, route conflicts, CIDR/address
changes, unchanged-route no-ops, and cleanup of only Tincan-owned resources.
Retain the existing crypto, enrollment, peer-policy and relay test suites.

Add an explicitly opt-in `darwin && integration` harness with isolated config,
state and test CIDRs. Keep the namespace harness `linux && integration`; macOS
has no Linux-style network namespaces. Use disposable Macs/VMs and a Linux peer
for privileged tests, with guaranteed teardown even when assertions fail.

Release validation must include:

| Scenario                                                | Expected result                                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Linux ↔ Mac and Mac ↔ Mac                               | Bidirectional traffic, peer add/remove, accurate handshake/counter status                  |
| Drop unavailable or serves older data                   | Authenticated cache keeps traffic flowing; rollback remains rejected                       |
| Same-LAN peers                                          | Safe multicast discovery selects LAN paths; blocked multicast still permits relay fallback |
| Failed direct path and restored connectivity            | Relay carries traffic, shadow probing restores direct routing                              |
| Wi-Fi ↔ Ethernet, DHCP/default-route change, sleep/wake | Bounded recovery, no duplicate helpers or wake storm                                       |
| Orchestrator restart, helper crash, reboot              | Correct ownership/recreation; persistent serial floor is preserved                         |
| Mac relay/hub with spokes                               | Forwarding and VPN/public DNS work; disabled forwarding produces actionable diagnostics    |
| Names/domain changed or cleared                         | System resolver reflects managed entries; unrelated hosts content survives                 |
| Another VPN uses `utun` or overlaps routes              | No accidental adoption, route replacement, signaling, or deletion                          |
| Repeated `up`, `down`, and service unload               | Idempotent lifecycle and complete owned-resource cleanup                                   |

Compilation and unprivileged CI establish portability, not working macOS VPN
support. Do not change the README's Linux-only support claim until the native,
privileged, mixed-platform acceptance gates have passed.
