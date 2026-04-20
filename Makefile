.PHONY: build test lint fmt lab parity clean help

BINARY  := certigo
PKG     := github.com/ajm4n/certigo
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION)

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## build the certigo binary for the current host
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/certigo

test: ## run all unit tests
	go test -race ./...

lint: ## run golangci-lint
	golangci-lint run

fmt: ## format all Go code
	gofmt -w .
	goimports -w . 2>/dev/null || true

lab: ## spin up local ad+adcs lab (placeholder until M2)
	@echo "lab: not yet implemented (planned for M2+)"

parity: ## run certipy-vs-certigo parity diff (placeholder until M2)
	@echo "parity: not yet implemented (planned for M2+)"

clean: ## remove built artifacts
	rm -rf $(BINARY) dist/
