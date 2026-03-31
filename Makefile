# Makefile for Envoy mTLS + ext_authz POC

.PHONY: all certs deps run-ext-authz run-ext-authz-opa run-opa run-upstream run-envoy run-client stop clean help

ENVOY_IMAGE := envoyproxy/envoy:v1.37-latest
OPA_IMAGE   := openpolicyagent/opa:latest
CERT_DIR    := certs

##@ Setup

all: certs deps ## Generate certs and download deps

certs: ## Generate all TLS certs with SPIFFE SANs
	@echo "==> Generating certs..."
	@chmod +x $(CERT_DIR)/gen.sh && cd $(CERT_DIR) && ./gen.sh

deps: ## Download and tidy Go dependencies
	@echo "==> Initializing Go module..."
	@rm -f go.mod go.sum
	@go mod init poc
	@echo "==> Downloading dependencies..."
	@go get github.com/envoyproxy/go-control-plane/envoy/service/auth/v3
	@go get github.com/envoyproxy/go-control-plane/envoy/config/core/v3
	@go get github.com/envoyproxy/go-control-plane/envoy/type/v3
	@go get google.golang.org/grpc
	@go get google.golang.org/grpc/codes
	@go get google.golang.org/grpc/reflection
	@go get google.golang.org/grpc/status
	@echo "==> Tidying module..."
	@go mod tidy
	@echo "==> Done."

##@ Run (each in its own terminal, or use run-all with tmux)

run-ext-authz: ## Run the ext_authz gRPC server on :9191 (built-in allowlist)
	@echo "==> Starting ext_authz server on :9191 (built-in allowlist)"
	go run ./ext_authz/main.go

run-opa: ## Run OPA server on :8181 with the authz policy
	@echo "==> Starting OPA on :8181..."
	docker run --rm --network host \
		--name poc-opa \
		-v $(PWD)/opa:/policy \
		$(OPA_IMAGE) run --server --addr :8181 /policy/policy.rego

run-ext-authz-opa: ## Run ext_authz on :9191, delegating to OPA on :8181
	@echo "==> Starting ext_authz server on :9191 (OPA mode)"
	go run ./ext_authz/main.go -opa http://localhost:8181/v1/data/envoy/authz

run-upstream: ## Run the upstream HTTP app on :8080
	@echo "==> Starting upstream server on :8080"
	go run ./upstream/main.go

run-envoy: ## Run Envoy in Docker on :8443 (admin :9901)
	@echo "==> Starting Envoy ($(ENVOY_IMAGE))..."
	docker run --rm --network host \
		--name poc-envoy \
		-v $(PWD)/envoy.yaml:/etc/envoy/envoy.yaml \
		-v $(PWD)/$(CERT_DIR):/etc/envoy/certs \
		$(ENVOY_IMAGE) -c /etc/envoy/envoy.yaml

run-client: ## Run the Go mTLS client (sends one request)
	@echo "==> Running Go client..."
	go run ./client/main.go

##@ Tmux (runs all services in one window)

run-all: ## Launch all services in a tmux session (requires tmux)
	@which tmux > /dev/null || (echo "tmux not found — install it or run each target separately"; exit 1)
	@echo "==> Starting tmux session 'poc'..."
	@tmux new-session -d -s poc -x 220 -y 50
	@tmux rename-window -t poc:0 'services'
	@# Split into 4 panes
	@tmux split-window -h   -t poc:0
	@tmux split-window -v   -t poc:0.0
	@tmux split-window -v   -t poc:0.2
	@# Run each service in its pane
	@tmux send-keys -t poc:0.0 'make run-ext-authz' Enter
	@tmux send-keys -t poc:0.1 'make run-upstream'  Enter
	@tmux send-keys -t poc:0.2 'make run-envoy'     Enter
	@echo "==> Waiting 5s for services to be ready..."
	@sleep 5
	@tmux send-keys -t poc:0.3 'make run-client'    Enter
	@tmux attach-session -t poc

stop: ## Stop the tmux session and Envoy/OPA containers
	@echo "==> Stopping Envoy container..."
	@docker stop poc-envoy 2>/dev/null || true
	@echo "==> Stopping OPA container..."
	@docker stop poc-opa 2>/dev/null || true
	@echo "==> Killing tmux session..."
	@tmux kill-session -t poc 2>/dev/null || true

##@ Test

test-allow: ## Test allowed request (with client cert)
	@echo "==> Testing ALLOW (with client cert)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		https://localhost:8443/hello

test-deny: ## Test denied request (valid cert, disallowed path)
	@echo "==> Testing DENY (disallowed path /notallowedhere)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		https://localhost:8443/notallowedhere

test-all: test-allow test-deny ## Run both test cases

##@ Cleanup

clean: stop ## Remove certs, go.mod, go.sum, and stop services
	@echo "==> Cleaning up..."
	@rm -f $(CERT_DIR)/*.crt $(CERT_DIR)/*.key $(CERT_DIR)/*.csr \
	        $(CERT_DIR)/*.srl $(CERT_DIR)/*.cnf
	@rm -f go.mod go.sum
	@echo "==> Done."

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)