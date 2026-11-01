# Configuration reference

[← Back to overview](../README.md)

`tincan` reads `/etc/tincan/config.toml` by default; override with
`-c /path/to/config.toml`. The file is created `0600` and Tincan warns at load
time if it isn't. For concurrent networks, use one config per network with
separate interfaces, ports, state directories, and PID files; see
[Multiple networks on one host](operations.md#multiple-networks-on-one-host).

For backend-specific fields, see [Dead-drop backends](dead-drop-backends.md).
The [networking guide](networking.md) explains endpoint observation and LAN
discovery; [VPN DNS names](dns.md) covers the `[dns]` settings.

```toml
[wireguard]
name = "alice"                 # node name, must be unique in the directory
public_key  = "..."            # WireGuard public key (base64)
private_key = "..."            # WireGuard private key (base64)
interface   = "tincan0"        # interface name (default tincan0)
listen_port = 51820            # optional; inferred from --endpoint host:port
mtu         = 1420             # default 1420
keepalive   = "25s"            # optional persistent-keepalive for peers

[directory]
network_identity = "AGE-SECRET-KEY-1..."   # this node's own age secret (unique per node)
publisher_pubkey = "..."                   # admin's Ed25519 public key (every node)
publisher_key    = "..."                   # admin's Ed25519 private key (admins only)

[drop.admin]    # admin-only: where this node writes AND reads the directory
type = "s3"   # or "http" / "dns" / "nostr" / "file" — see dead-drop-backends.md
# ...backend-specific fields...

[drop.client]   # how non-admin nodes read; also exported in bootstraps
type = "s3"
# ...backend-specific fields...

[sync]
interval          = "5m"            # daemon poll interval
state_dir         = "/var/lib/tincan" # houses cache.bin and its sibling state files
pid_file          = "/run/tincan.pid"
# max_directory_age = "48h"         # optional: warn (sync/up/status) when the directory's
                                    # CreatedAt is older than this — catches a frozen or
                                    # withheld drop. Pair with a cron'd `tincan publish`
                                    # (which always re-stamps CreatedAt) as a heartbeat.

[observe]                      # admin-only; see Endpoint discovery
enabled         = true         # default on for admins; set false to stop discovering NAT'd peer endpoints
handshake_fresh = "3m"         # how recent a peer handshake must be to count as observed

[discovery]                    # LAN peer discovery; changes require a daemon restart
enabled         = true         # default on; set false to suppress beacon send/receive
multicast_ipv4  = "239.255.84.67:51821"
multicast_ipv6  = "[ff02::1:8443]:51821"
beacon_interval = "30s"        # steady-state cadence
beacon_ttl      = "90s"        # learned endpoint expiry (must be >= 2x beacon_interval)

[dns]                          # VPN DNS names; active only when the directory has a domain
manage_hosts = true            # default on; maintain this interface's /etc/hosts block
# serve      = true            # force the DNS listener on/off; unset = auto (hubs only)
# upstream   = "192.168.1.1"   # where the hub forwards non-VPN queries (host[:port],
                               # port 53 implied; default: first resolv.conf nameserver)
# hosts_path = "/etc/hosts"    # override the hosts file (tests, exotic layouts)
```

Defaults are populated automatically; you usually only need to set
`[wireguard]`, `[directory]`, `[drop.admin]` (admin only), and `[drop.client]`.

When `[drop.admin]` is present, it is also used for reads by `sync`, `status`,
and directory commands. In a file-to-HTTP setup, the admin therefore checks its
local file, not the HTTP/CDN path that clients use. See [Operations](operations.md)
for the settings that require a restart rather than SIGHUP.
