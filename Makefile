SHELL := /bin/zsh

GO ?= go
PKG ?= ./...
BIN_DIR ?= bin
COVERAGE_FILE ?= coverage.out

CMD_DIRS := $(sort $(dir $(wildcard cmd/*/)))
CMD_PKGS := $(patsubst %/,%,$(CMD_DIRS))

.PHONY: help all build build-bin test test-race integration security bench coverage fmt fmt-check vet lint vuln tidy verify clean

help:
	@echo "VaultBrick Make targets:"
	@echo "  make build       - Build packages and any cmd binaries"
	@echo "  make test        - Run unit tests"
	@echo "  make test-race   - Run tests with race detector"
	@echo "  make integration - Run integration tests (build tag: integration)"
	@echo "  make security    - Run security tests (build tag: security)"
	@echo "  make bench       - Run benchmarks"
	@echo "  make coverage    - Generate coverage profile"
	@echo "  make fmt         - Format Go files"
	@echo "  make fmt-check   - Check Go formatting"
	@echo "  make vet         - Run go vet"
	@echo "  make lint        - fmt-check + vet + optional golangci-lint"
	@echo "  make vuln        - Run govulncheck if installed"
	@echo "  make tidy        - Run go mod tidy"
	@echo "  make verify      - Run go mod verify"
	@echo "  make clean       - Remove build/test artifacts"

all: build test

build: build-bin
	$(GO) build $(PKG)

build-bin:
	@mkdir -p $(BIN_DIR)
	@if [ -z "$(CMD_PKGS)" ]; then \
		echo "No cmd/* package directories found; skipping binary build."; \
	else \
		for pkg in $(CMD_PKGS); do \
			name=$${pkg##*/}; \
			echo "Building $$pkg -> $(BIN_DIR)/$$name"; \
			$(GO) build -o "$(BIN_DIR)/$$name" "./$$pkg"; \
		done; \
	fi

test:
	$(GO) test $(PKG)

test-race:
	$(GO) test -race $(PKG)

integration:
	$(GO) test -tags=integration $(PKG)

security:
	$(GO) test -tags=security $(PKG)

bench:
	$(GO) test -run='^$$' -bench=. -benchmem $(PKG)

coverage:
	$(GO) test -coverprofile=$(COVERAGE_FILE) $(PKG)
	$(GO) tool cover -func=$(COVERAGE_FILE)

fmt:
	$(GO) fmt $(PKG)

fmt-check:
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	$(GO) vet $(PKG)

lint: fmt-check vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found; skipping extra lint checks."; \
	fi

vuln:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck $(PKG); \
	else \
		echo "govulncheck not found; install with:"; \
		echo "  $(GO) install golang.org/x/vuln/cmd/govulncheck@latest"; \
		exit 1; \
	fi

tidy:
	$(GO) mod tidy

verify:
	$(GO) mod verify

clean:
	rm -rf $(BIN_DIR) $(COVERAGE_FILE)
