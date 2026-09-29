.PHONY: build test lint fmt vet clean install-tools check docker serve
.PHONY: smoke smoke-apk smoke-ipa test-apk test-ipa fixtures docker-smoke

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

# ---------------------------------------------------------------------------
# Smoke tests against synthetic APK/IPA fixtures (no real app needed).
#   make smoke-apk   - Android: manifest, NSC, secrets, inventory
#   make smoke-ipa   - iOS: ATS, entitlements, Mach-O, strings
#   make smoke       - both
#   make test-apk SAMPLE=path/to/app.apk  - analyze a real APK
#   make test-ipa SAMPLE=path/to/app.ipa  - analyze a real IPA
# ---------------------------------------------------------------------------

SAMPLE ?=

test-apk: build
	@test -n "$(SAMPLE)" || { echo "usage: make test-apk SAMPLE=path/to/app.apk"; exit 2; }
	./bin/$(BINARY) analyze "$(SAMPLE)" --workdir targets/manual --verbose

test-ipa: build
	@test -n "$(SAMPLE)" || { echo "usage: make test-ipa SAMPLE=path/to/app.ipa"; exit 2; }
	./bin/$(BINARY) analyze "$(SAMPLE)" --workdir targets/manual --verbose

fixtures:
	python3 scripts/make-fixtures.py both -o .smoke-fixtures

smoke-apk: build
	scripts/smoke.sh apk

smoke-ipa: build
	scripts/smoke.sh ipa

smoke: build
	scripts/smoke.sh both

# The same smoke test, but inside the Docker image.
docker-smoke: docker
	docker run --rm -v "$(CURDIR)/.smoke-fixtures:/fx" --entrypoint sh mobiscope -c '\
		python3 -c "import zipfile,os; os.makedirs(\"/fx\", exist_ok=True)" && \
		mobiscope version && \
		gitleaks version && apktool --version && jadx --version && semgrep --version && \
		echo OK-toolchain'

serve: build
	./bin/$(BINARY) serve --addr 127.0.0.1:8080

docker:
	docker build -t $(BINARY) .

.DEFAULT_GOAL := build