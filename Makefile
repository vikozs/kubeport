VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)
BIN      = bin/kubeport

.PHONY: build test lint fmt fixtures site clean release-snapshot docs

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/kubeport

test:
	go test ./...

lint:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

fmt:
	gofmt -w .

# Run every fixture against every target family; fails only on tool errors (exit 2).
fixtures: build
	@for f in fixtures/*; do \
	  for t in k3s:1.31 k8s:1.32/eks openshift:4.19/vsphere; do \
	    $(BIN) check --to $$t --format json $$f > /dev/null; rc=$$?; \
	    if [ $$rc -eq 2 ]; then echo "tool error on $$f -> $$t"; exit 1; fi; \
	  done; \
	done; echo "fixtures ok"

docs: build
	$(BIN) rules > docs/rules.txt
	$(BIN) targets > docs/targets.txt

site:
	@echo "site/ is static; deploy with: wrangler pages deploy site --project-name kubeport"

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
