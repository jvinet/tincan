.PHONY: build test test-race test-integration lint fmt

build:
	go build -o ./bin/tincan ./cmd/tincan

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
