# Development

[← Back to overview](../README.md)

```sh
make build              # build ./bin/tincan
make test               # unit tests
make test-race          # unit tests with the race detector
make test-integration   # opt into privileged Linux network-namespace tests
make lint               # golangci-lint
make fmt                # gofmt
```

Builds require Go 1.25+. `make build` sets `CGO_ENABLED=0` for a static binary.

Run `make test-integration` as root on a disposable Linux host with
`CAP_NET_ADMIN`, network-namespace support, kernel WireGuard, `ip` (iproute2),
`ping`, and Go available. The target sets `TINCAN_RUN_NETNS_INTEGRATION=1`,
disables test-result caching, and fails if prerequisites are missing. Without
that explicit opt-in, `go test -tags integration ./test/integration/...` skips
the privileged test; a skipped run is not networking validation.

The harness uses isolated namespaces, temporary config/state and a file drop.
It checks bootstrap enrollment with distinct age identities, bidirectional
traffic, cache-only `sync` versus `up`, peer removal, offline-cache operation,
rollback rejection, and revocation. It does not exercise daemon multicast
convergence, NAT traversal, relay recovery, or real storage providers.
