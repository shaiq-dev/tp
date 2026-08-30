# tp build. Cross building and packaging live in scripts/, since both are shell
# loops that read badly as make recipes and are useful to run on their own.
# Everything else is short enough to stay here. Needs only Go and a POSIX shell,
# and works with the GNU Make 3.81 that ships with macOS.

BIN     := tp
DIST    := dist
PREFIX  ?= $(HOME)/.local

# A tagged checkout gives v1.2.3, anything else gives the commit or "dev".
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

export BIN
export DIST
export VERSION

.PHONY: help
help:
	@echo "make build      build ./$(BIN) for this machine"
	@echo "make install    build and copy to $(PREFIX)/bin"
	@echo "make test       go test -race"
	@echo "make lint       golangci-lint"
	@echo "make lint-fix   golangci-lint with --fix"
	@echo "make fmt        golangci-lint fmt"
	@echo "make check      everything CI runs"
	@echo "make dist       cross build every platform into $(DIST)/"
	@echo "make manifest   rebuild $(DIST)/manifest.json from existing tarballs"
	@echo "make sign       minisign $(DIST)/manifest.json, normally done by CI"
	@echo "make clean      remove build output"
	@echo
	@echo "VERSION=$(VERSION)"

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $(BIN) .

.PHONY: install
install: build
	mkdir -p $(PREFIX)/bin
	cp $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "installed $(PREFIX)/bin/$(BIN)"
	@case ":$$PATH:" in \
	  *":$(PREFIX)/bin:"*) ;; \
	  *) echo "warning: $(PREFIX)/bin is not on your PATH" >&2 ;; \
	esac

.PHONY: test
test:
	go test -race ./...

.PHONY: lint
lint:
	go tool golangci-lint run ./...

.PHONY: lint-fix
lint-fix:
	go tool golangci-lint run --fix ./...

.PHONY: fmt
fmt:
	go tool golangci-lint fmt ./...

# golangci-lint is pinned as a module tool so every machine runs the same
# version. govulncheck is fetched on demand because it only reports and has
# nothing to pin against.
.PHONY: check
check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:" >&2; gofmt -l . >&2; exit 1; }
	go vet ./...
	go tool golangci-lint config verify
	go tool golangci-lint run ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -x install.sh scripts/*.sh; \
	else \
	  echo "shellcheck not installed, skipping the shell scripts" >&2; \
	fi
	go test -race ./...

.PHONY: dist
dist: clean
	scripts/build.sh

.PHONY: manifest
manifest:
	scripts/manifest.sh

.PHONY: sign
sign:
	minisign -Sm $(DIST)/manifest.json

.PHONY: clean
clean:
	rm -rf $(DIST) $(BIN)
