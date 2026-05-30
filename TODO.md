# To Do

- Mobile ergonomics
  - QR code generation
  - Automatic gateway selection
- Drops
  - DNS TXT
- Relay fallback
  - `[relay]` config block to opt out per-node and to tune `direct_failed_after`
    / `direct_grace_period` (currently hardcoded defaults).
  - Persist per-peer relay state across daemon restart to avoid the ~90s
    rediscovery window every time the daemon is reloaded.
  - Explicit relay-role selection in the directory (`Role: "relay"` or
    similar) for multi-relay topologies; currently the relay target is
    "first non-self node with an Endpoint".
