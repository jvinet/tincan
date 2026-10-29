# Operations

[← Back to overview](../README.md)

## Running as a daemon

`tincan up --daemon` double-forks into the background, writes a PID file
(default `/run/tincan.pid`), and reconciles every `[sync].interval`
(default `5m`) by syncing from the drop and re-applying the directory.

Signals the daemon understands:

- `SIGHUP` — reload `config.toml` and run an iteration immediately
- `SIGTERM` / `SIGINT` — clean shutdown

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
- `/etc/hosts` — managed block between markers, only while the directory
  carries a VPN domain (see [VPN DNS names](dns.md))
- `/var/lib/tincan/cache.bin` — last successfully-applied directory
- `/var/lib/tincan/cache.serial` — monotonic serial guard against rollback
- `/var/lib/tincan/state.json` — sync metadata (last sync time, ETag)
- `/var/lib/tincan/discovery.json` — learned LAN endpoints (see [LAN peer discovery](networking.md#lan-peer-discovery))
- `/var/lib/tincan/directory-source.bin` — admin-only working directory
- `/var/lib/tincan/netboot.json` — admin-only network bootstrap (mode `0600`)
- `/run/tincan.pid` — daemon PID file
