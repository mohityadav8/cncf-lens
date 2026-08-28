BINARY   := lens
PKG      := ./cmd/lens
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

export GOFLAGS := -mod=mod

.PHONY: all build install test test-race cover vet fmt lint clean plugin dist help

all: fmt vet test build

## build: compile the binary into ./bin
build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)
	@echo "built bin/$(BINARY) ($(VERSION))"

## install: install into $GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

## plugin: build the reference plugin
plugin:
	@mkdir -p bin
	go build -o bin/lens-plugin-example ./examples/plugin-example

## test: run the full suite
test:
	go test ./...

## test-race: run under the race detector
test-race:
	go test -race ./...

## cover: generate an HTML coverage report
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

## vet: run go vet
vet:
	go vet ./...

## fmt: format all sources
fmt:
	gofmt -w ./cmd ./internal ./examples

## lint: verify formatting is clean (CI-friendly, no rewrite)
lint:
	@test -z "$$(gofmt -l ./cmd ./internal ./examples)" || \
		{ echo "unformatted files:"; gofmt -l ./cmd ./internal ./examples; exit 1; }

## dist: cross-compile release binaries
dist:
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		out=dist/$(BINARY)-$$os-$$arch; \
		[ "$$os" = "windows" ] && out=$$out.exe; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	done

## clean: remove build artefacts
clean:
	rm -rf bin dist coverage.out coverage.html

## help: list targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
