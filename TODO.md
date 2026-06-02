# To Do

- Mobile ergonomics
  - QR code generation
  - Automatic gateway selection
- Relay fallback
  - `[relay]` config block to opt out per-node and to tune `direct_failed_after`
    / `direct_grace_period` (currently hardcoded defaults).
  - Persist per-peer relay state across daemon restart to avoid the ~90s
    rediscovery window every time the daemon is reloaded.
  - Explicit relay-role selection in the directory (`Role: "relay"` or
    similar) for multi-relay topologies; currently the relay target is
    "first non-self node with an Endpoint".
- Add utility command to view the raw, pretty-printed directory source
  - Loosely equivalent to `cat /var/lib/tincan/directory-source.bin | msgpack2json | jq`
- Admin seems to publish more often than is necessary
  - Just updated `oat` timestamps with no other changes?
- Replace `--cache` with `--state-dir`
