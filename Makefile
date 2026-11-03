VERSION ?= 0.4.0
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt demo clean install

build: ## Build the titra binary
	go build -ldflags "$(LDFLAGS)" -o titra .

test: ## Run the test suite
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt the tree
	gofmt -w .

demo: ## Run the local end-to-end demo (enforce mode)
	./scripts/demo.sh enforce

demo-monitor: ## Run the demo in monitor mode
	./scripts/demo.sh monitor

demo-trace: build ## Full product demo: whole-job tracing + story report (needs sudo, Linux)
	sudo ./scripts/e2e.sh

install: build ## Build and install shims into ./.titra-bin (local experiment)
	eval "$$(./titra install --dir ./.titra-bin --mode enforce)"

clean:
	rm -f titra
	rm -rf .titra-bin

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
