# To Do

- Mobile ergonomics
  - QR code generation
  - Automatic gateway selection
- Drops
  - DNS TXT
- Get rid of the default-on log messages
  - "time=2026-05-27T05:52:30.488Z level=WARN msg="failed to fetch remote directory before publish" error="dead-drop: not found"
- Logging
- Relay fallback
  - `[relay]` config block to opt out per-node and to tune `direct_failed_after`
    / `probe_interval` / `direct_grace_period` (currently hardcoded defaults).
  - Backoff for periodic probes (RELAYED→DIRECT). At 5min interval with 90s
    failure detection, a fully-broken direct path means ~30% downtime on the
    affected peer. Geometric backoff (5m → 10m → 20m → cap at 1h) would cut
    this dramatically once the daemon has learned the path is dead.
  - Persist per-peer relay state across daemon restart to avoid the ~90s
    rediscovery window every time the daemon is reloaded.
  - Explicit relay-role selection in the directory (`Role: "relay"` or
    similar) for multi-relay topologies; currently the relay target is
    "first non-self node with an Endpoint".
