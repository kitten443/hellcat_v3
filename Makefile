BINARY  := hellcat
GO      ?= go
PREFIX  ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: all build test race vet fmt check install uninstall clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w main.go config/*.go parser/*.go stressor/*.go

check: fmt vet test

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

clean:
	rm -f $(BINARY)
