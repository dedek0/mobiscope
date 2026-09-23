.PHONY: build test lint fmt vet clean install-tools check docker serve

BINARY     := mobiscope
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildTime=$(BUILD_TIME)

GOFLAGS := -trimpath

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/mobiscope

test:
	go test $(GOFLAGS) -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .

vet:
	go vet ./...

clean:
	rm -rf bin/ coverage.out

GOFUMPT_VERSION       ?= v0.8.0
GOLANGCI_LINT_VERSION ?= v2.13.2

install-tools:
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

check: fmt vet lint test

test-integration:
	go test -tags integration ./...

serve: build
	./bin/$(BINARY) serve --addr 127.0.0.1:8080

docker:
	docker build -t $(BINARY) .

.DEFAULT_GOAL := build