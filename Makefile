.PHONY: build clean install test test-race test-integration lint fmt

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X 'github.com/jvinet/tincan/internal/version.Version=$(VERSION)' \
           -X 'github.com/jvinet/tincan/internal/version.Commit=$(COMMIT)' \
           -X 'github.com/jvinet/tincan/internal/version.Date=$(DATE)'

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o ./bin/tincan ./cmd/tincan

clean:
	rm -f ./bin/tincan coverage.out

install: build
	install -Dm755 ./bin/tincan $(DESTDIR)/usr/local/bin/tincan
	install -Dm644 ./misc/tincan.service $(DESTDIR)/etc/systemd/system/tincan.service

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	TINCAN_RUN_NETNS_INTEGRATION=1 go test -count=1 -v -tags integration ./test/integration/...

lint:
	golangci-lint run

fmt:
	gofmt -w ./cmd ./internal ./test
