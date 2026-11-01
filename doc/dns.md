# VPN DNS names

[← Back to overview](../README.md)

Set a non-public domain for the network and every node becomes reachable by
name:

```sh
# on the admin (or at first setup: tincan init --dns-domain vpn ...)
tincan set-domain vpn
```

```sh
ping nas.vpn
ssh alice.vpn
```

The domain lives in the signed directory, so it propagates like any other
change: members pick it up within one sync interval. `tincan set-domain`
with no argument shows the current domain from any node; `--clear` turns
the feature off network-wide. Setting a domain requires every node name to
be a valid DNS label (letters, digits, hyphens; ≤63 chars) — `set-domain`
refuses with a list of offenders otherwise, and `add-node` enforces the
rule for all new names so this never regresses.

Tincan members and plain-WireGuard spokes get names through two different
(deliberately independent) mechanisms:

**Members: a managed `/etc/hosts` block.** Every member already holds the
full name → tunnel-IP mapping — it's the directory it decrypts on every
sync — so no DNS server is involved at all. The daemon maintains a marker-
delimited block after each successful apply:

```
# BEGIN tincan managed block (tincan0) - do not edit between markers
10.42.0.1	alice.vpn
10.42.0.3	nas.vpn
# END tincan managed block (tincan0)
```

Entries are FQDN-only on purpose: if your machines already map bare names
like `nas` to LAN addresses in `/etc/hosts`, tincan never shadows them.
The interface in each marker identifies the network: `tincan1`, for example,
gets a separate block. Legacy markers without an interface belong to
`tincan0` and are replaced with labelled markers on its next apply.
Everything outside that interface's markers is preserved byte-for-byte,
including other networks' blocks. Updates are atomic, serialized across
Tincan processes using `/etc/hosts.tincan.lock`, and skipped when unchanged.
`tincan down` or `set-domain --clear` removes only the selected interface's
block. Never delete the lock file while daemons are running. Use different
VPN domains for different networks to avoid duplicate FQDNs; see
[Multiple networks on one host](operations.md#multiple-networks-on-one-host).
Resolution works offline (it's a file), survives daemon restarts, and needs
no resolver configuration. A symlinked `/etc/hosts` (NixOS) is detected and left
alone, with a warning.

**Spokes: DNS served by the hub.** Phones and other plain-WireGuard
clients can't run tincan, so their rendered configs (add-node /
render-node) gain a line when a domain is set:

```
DNS = 10.42.0.1, vpn
```

That's the hub's tunnel IP plus the domain as a search domain (so `nas`
works as well as `nas.vpn`). The hub's daemon serves the domain on UDP 53
of its tunnel IP, answering from its cached directory. Mobile WireGuard
apps route *all* device DNS through that server while the tunnel is up, so
the hub forwards everything outside the domain to an upstream resolver —
by default the first nameserver in its own `/etc/resolv.conf`, overridable
with `[dns] upstream`.

The listener runs automatically on hub nodes only (the `--relay` node, or
the implicit relay target spokes were enrolled against) and only in daemon
mode. Force it on or off anywhere with `[dns] serve`. If something already
occupies port 53 on the hub (Pi-hole, dnsmasq), tincan warns once and
retries each sync; point `[dns] upstream` at that resident resolver if you
want VPN queries answered by tincan and the rest by it.

## Limitations

- Spoke configs are point-in-time snapshots: a domain set, cleared, or a
  hub moved after enrollment needs a re-render (`tincan render-node`).
  Clearing the domain is the sharp edge — spokes keep sending all their
  DNS to a hub that no longer answers, so `set-domain --clear` lists the
  affected spokes loudly.
- Names map to IPv4 tunnel IPs only (AAAA queries return empty NOERROR so
  dual-stack clients fall through to A cleanly).
- The hub's listener is UDP-only; single-record answers always fit. See
  [DNS design](../spec/dns.md) for the full design.
- Upgrade the **admin node first**: an older admin binary republishing the
  directory (e.g. endpoint observation) doesn't know the domain field and
  would silently drop it.
