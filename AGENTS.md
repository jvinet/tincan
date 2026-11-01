# Agent guidance

## Sandbox builds and tests

Go's default module and build caches may be outside the sandbox's writable
paths. A plain `make` can fail with
`mkdir /.../go/pkg/mod: read-only file system`; this is an environment
limitation, not a code defect.

Use writable caches for the session (the exports also reach `make`
subprocesses):

```sh
cache=$(mktemp -d /tmp/tincan-go.XXXXXX)
export GOMODCACHE="$cache/mod" GOCACHE="$cache/build"
make build
make test
```

An empty module cache requires dependency downloads. If network access is
blocked, reuse an available populated cache, or copy its contents into the
writable `GOMODCACHE`. Preserve a usable existing cache rather than replacing it
unnecessarily. `GOPROXY=off` can prevent download attempts when checking whether
cached dependencies suffice. Do not change `go.mod`, `go.sum`, or the Makefile
to work around sandbox restrictions; report blocked validation explicitly.

`make test-race` needs CGO and a working C compiler; do not carry the build
target's `CGO_ENABLED=0` into race tests.

`make test-integration` is privileged Linux networking validation: it requires
root, CAP_NET_ADMIN, network namespaces, and `ip`/`ping`. Do not expect it to
work in a locked-down sandbox, and do not run `make install` there.
