.PHONY: build test test-race test-integration lint fmt

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X 'github.com/jvinet/tincan/internal/version.Version=$(VERSION)' \
           -X 'github.com/jvinet/tincan/internal/version.Commit=$(COMMIT)' \
           -X 'github.com/jvinet/tincan/internal/version.Date=$(DATE)'

build:
	go build -ldflags "$(LDFLAGS)" -o ./bin/tincan ./cmd/tincan

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	go test -tags integration ./test/integration/...

lint:
	golangci-lint run

fmt:
	gofmt -w ./cmd ./internal ./test
