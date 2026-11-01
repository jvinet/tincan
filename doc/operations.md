# Operations

[← Back to overview](../README.md)

## Running as a daemon

`tincan up --daemon` re-execs a child into a detached session, writes a PID file
(default `/run/tincan.pid`), and reconciles every `[sync].interval`
(default `5m`) by syncing from the drop and re-applying the directory.

Signals the daemon understands:

- `SIGHUP` — reload `config.toml` and run an iteration immediately
- `SIGTERM` / `SIGINT` — clean shutdown

The config is also re-read on each regular reconciliation. Discovery settings
(`enabled`, multicast groups, cadence, TTL), the network watcher's interface
filter, and the daemon's PID-file lock are initialized at startup. Restart the
daemon after changing `[discovery]`, `[wireguard].interface`, or
`[sync].pid_file`; SIGHUP alone does not recreate those resources. Tear down the
old interface before switching its name, and stop the daemon using its old
PID-file setting before changing that setting.

`tincan down --stop` sends `SIGTERM` to the PID-file process and waits for it to
exit before tearing down the interface, so the daemon can't re-apply the
directory and re-raise the link on its way out. Plain `tincan down` leaves the
daemon running (it will simply bring the interface back up on its next
reconcile).

For systemd, use a forking service for continuous reconciliation:

```ini
[Unit]
Description=Tincan
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/tincan.pid
ExecStart=/usr/local/bin/tincan up --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

The unit's `PIDFile` must match `[sync].pid_file` in the
[configuration](configuration.md). Plain `tincan up` runs a single iteration
and exits; it is suitable for a `oneshot` service with a systemd timer, not a
continuous daemon. Endpoint observation, LAN discovery, relay recovery, and
the hub's DNS listener require daemon mode.

## Multiple networks on one host

Run one Tincan daemon per network, each with its own config. The defaults are
for a single network; do not share state directories or PID files between
instances. For example:

| Setting | `/etc/tincan/work.toml` | `/etc/tincan/home.toml` |
| --- | --- | --- |
| `[wireguard].interface` | `tincan0` | `tincan1` |
| `[wireguard].listen_port` | `51820` | `51830` |
| Network CIDR (chosen at `init --cidr`) | `10.42.0.0/24` | `10.43.0.0/24` |
| `[sync].state_dir` | `/var/lib/tincan/work` | `/var/lib/tincan/home` |
| `[sync].pid_file` | `/run/tincan-work.pid` | `/run/tincan-home.pid` |
| `[discovery].multicast_ipv4` | `239.255.84.67:51821` | `239.255.84.67:51831` |
| `[discovery].multicast_ipv6` | `[ff02::1:8443]:51821` | `[ff02::1:8443]:51831` |
| VPN DNS domain (optional) | `work.vpn` | `home.vpn` |

Each config also needs its own network's keys and dead-drop settings. Use
separate directory objects/paths (or Nostr slots) so publishing one network
cannot overwrite another. When initializing or joining, pass `-c` and
`--state-dir` to keep even the initial config and state separate; edit the
remaining settings before bringing the interface up.

Use non-overlapping tunnel CIDRs, also avoiding local LANs and other VPNs.
Explicit WireGuard listen ports must be distinct on the host, and published
endpoints must advertise the matching port. Discovery listeners bind their
UDP ports exclusively: use different ports for each network, consistently
on all members of that network, or set `[discovery].enabled = false`.
Changing only the multicast group without changing the port is not enough.

```sh
sudo tincan -c /etc/tincan/work.toml up --daemon
sudo tincan -c /etc/tincan/home.toml up --daemon
sudo tincan -c /etc/tincan/work.toml status
sudo tincan -c /etc/tincan/home.toml down --stop
```

Always select the config for administrative commands too, including
`add-node`, `publish`, and `set-domain`.

Both daemons can manage `/etc/hosts`: each block is identified by its
WireGuard interface, updates are serialized, and clearing a domain or
running `down` removes only that interface's block. Choose distinct DNS
domains to avoid conflicting FQDNs. Old unlabelled blocks belong to
`tincan0` and are migrated on its next apply; if an existing network used a
different interface, remove its old unlabelled block manually before
upgrading. Stop older daemons before using shared hosts management: older
binaries do not understand the new markers or participate in locking.
See [VPN DNS names](dns.md) for the marker format. Hub DNS listeners bind
their own tunnel IPs, so they can each use UDP 53 unless another service
already occupies those addresses (including a wildcard listener).

For systemd, use separate units, or a template named `tincan@.service` based
on the service above, with these substitutions:

```ini
[Service]
PIDFile=/run/tincan-%i.pid
ExecStart=/usr/local/bin/tincan -c /etc/tincan/%i.toml up --daemon
```

Keep `Type=forking` and the other service settings from the example. Match
each config's `[sync].pid_file` to its unit's `PIDFile`, then enable the
instances with `systemctl enable --now tincan@work tincan@home`. Do not also
run the default `tincan.service` against either instance's resources.

## Logging

Tincan writes structured logs to the OS syslog (facility `daemon`, tag
`tincan`) from every state-changing command and from the daemon loop. The
human-friendly console output (`✓`, colored headlines, `tincan status`
tables) is unchanged — syslog is separate and meant for debugging,
monitoring, and log shipping.

```
May 29 18:23:01 zeroflux tincan[12345]: level=INFO msg=synced source=drop serial=76
May 29 18:23:01 zeroflux tincan[12345]: level=INFO msg="relay transition" peer=tau mode=relayed via=zf
```

Set verbosity with `TINCAN_LOG_LEVEL` (`debug`, `info`, `warn`, `error`;
default `info`). For systemd:

```ini
[Service]
Environment=TINCAN_LOG_LEVEL=debug
```

Tail the daemon's recent activity:

```sh
journalctl -t tincan -f       # systemd-journald
tail -f /var/log/daemon.log   # classic syslog
```

## Files Tincan touches

- `/etc/tincan/config.toml` — primary config, mode `0600`
- `/etc/hosts` — interface-scoped managed blocks between markers, only while
  the directory carries a VPN domain (see [VPN DNS names](dns.md))
- `/etc/hosts.tincan.lock` — persistent lock file serializing Tincan hosts updates
- `/var/lib/tincan/cache.bin` — last successfully synced or published directory;
  it may not yet have been applied to WireGuard
- `/var/lib/tincan/cache.serial` — monotonic serial guard against rollback
- `/var/lib/tincan/publish.serial` — admin-only high-water mark for upload
  reservations; kept separate so failed uploads do not invalidate offline cache use
- `/var/lib/tincan/state.json` — sync metadata (last sync time, ETag)
- `/var/lib/tincan/discovery.json` — learned LAN endpoints (see [LAN peer discovery](networking.md#lan-peer-discovery))
- `/var/lib/tincan/directory-source.bin` — admin-only working directory
- `/var/lib/tincan/netboot.json` — admin-only network bootstrap (mode `0600`)
- `/var/lib/tincan/.lock` — short-lived state-file write lock
- `/var/lib/tincan/.admin.lock` — local admin transaction lock (commands and
  background observation; not cross-machine coordination)
- `/run/tincan.pid` — daemon PID file
