# Makefile for Envoy mTLS + ext_authz POC

.PHONY: all certs deps run-policyengine run-upstream run-envoy run-client run-connect run-mitm stop clean help \
        k8s-cluster k8s-build k8s-deploy k8s-test-allow k8s-test-deny k8s-test-body-deny k8s-test-all k8s-logs k8s-destroy \
        k8s-apply-policies k8s-delete-policies k8s-test-connect-allow k8s-test-connect-deny \
        k8s-test-mitm-allow k8s-test-mitm-deny-domain k8s-test-mitm-deny-path

ENVOY_IMAGE := envoyproxy/envoy:v1.37-latest
CERT_DIR    := certs
CLUSTER     := poc
K8S_NS      := poc

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

##@ Run (each in its own terminal)

run-policyengine: ## Run the unified policy engine on :9191 (ext_authz + ext_proc)
	@echo "==> Starting policy engine on :9191"
	go run ./policyengine/

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

stop: ## Stop the Envoy container
	@echo "==> Stopping Envoy container..."
	@docker stop poc-envoy 2>/dev/null || true

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

test-body-deny: ## Test denied request (blocked JSON body)
	@echo "==> Testing DENY (blocked body action)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		-X POST -H "Content-Type: application/json" \
		-d '{"action":"blocked"}' \
		https://localhost:8443/hello

test-all: test-allow test-deny test-body-deny ## Run all test cases

run-connect: ## Run the CONNECT tunnel client (local)
	@echo "==> CONNECT tunnel via localhost:8444..."
	go run ./connect/ -proxy localhost:8444 -target 127.0.0.1:8080

run-mitm: ## Run the MITM TLS-interception proxy on :9192 (local)
	@echo "==> Starting MITM proxy on :9192"
	go run ./mitm/

##@ Cleanup

clean: stop ## Remove certs, go.mod, go.sum, and stop services
	@echo "==> Cleaning up..."
	@rm -f $(CERT_DIR)/*.crt $(CERT_DIR)/*.key $(CERT_DIR)/*.csr \
	        $(CERT_DIR)/*.srl $(CERT_DIR)/*.cnf
	@rm -f go.mod go.sum
	@echo "==> Done."

##@ Kind / Kubernetes

k8s-cluster: ## Create a Kind cluster with port mappings
	@echo "==> Creating Kind cluster '$(CLUSTER)'..."
	kind create cluster --name $(CLUSTER) --config k8s/kind-config.yaml
	@echo "==> Cluster ready."

k8s-build: ## Build and load Docker images into Kind
	@echo "==> Building policyengine image..."
	docker build -t poc-policyengine:latest -f policyengine/Dockerfile .
	@echo "==> Building upstream image..."
	docker build -t poc-upstream:latest -f upstream/Dockerfile .
	@echo "==> Loading images into Kind..."
	kind load docker-image poc-policyengine:latest --name $(CLUSTER)
	kind load docker-image poc-upstream:latest --name $(CLUSTER)
	@echo "==> Images loaded."

k8s-deploy: certs ## Deploy all resources to the Kind cluster
	@echo "==> Creating namespace..."
	@kubectl apply -f k8s/namespace.yaml
	@echo "==> Installing CRD..."
	@kubectl apply -f k8s/crd.yaml
	@echo "==> Creating RBAC..."
	@kubectl apply -f k8s/rbac.yaml
	@echo "==> Creating secrets and configmaps..."
	@kubectl create secret generic envoy-certs \
		--namespace $(K8S_NS) \
		--from-file=ca.crt=$(CERT_DIR)/ca.crt \
		--from-file=server.crt=$(CERT_DIR)/server.crt \
		--from-file=server.key=$(CERT_DIR)/server.key \
		--dry-run=client -o yaml | kubectl apply -f -
	@kubectl create configmap envoy-config \
		--namespace $(K8S_NS) \
		--from-file=envoy.yaml=k8s/envoy.yaml \
		--dry-run=client -o yaml | kubectl apply -f -
	@kubectl create secret generic proxy-ca-certs \
		--namespace $(K8S_NS) \
		--from-file=proxy-ca.crt=$(CERT_DIR)/proxy-ca.crt \
		--from-file=proxy-ca.key=$(CERT_DIR)/proxy-ca.key \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "==> Deploying workloads..."
	@kubectl apply -f k8s/opa.yaml
	@kubectl apply -f k8s/upstream.yaml
	@kubectl apply -f k8s/policyengine.yaml
	@kubectl apply -f k8s/envoy-deploy.yaml
	@echo "==> Applying Policy CRs..."
	@kubectl apply -f k8s/policies/
	@echo "==> Waiting for pods to be ready..."
	@kubectl rollout status deployment/opa            -n $(K8S_NS) --timeout=60s
	@kubectl rollout status deployment/upstream       -n $(K8S_NS) --timeout=60s
	@kubectl rollout status deployment/policyengine   -n $(K8S_NS) --timeout=60s
	@kubectl rollout status deployment/envoy          -n $(K8S_NS) --timeout=60s
	@echo "==> All pods running. Envoy available at https://localhost:8443"

k8s-apply-policies: ## Apply Policy CRs from k8s/policies/
	@echo "==> Applying Policy CRs..."
	@kubectl apply -f k8s/policies/
	@echo "==> Current policies:"
	@kubectl get policies -n $(K8S_NS)

k8s-delete-policies: ## Delete all Policy CRs
	@echo "==> Deleting all Policy CRs..."
	@kubectl delete policies --all -n $(K8S_NS)
	@echo "==> Done."

k8s-test-allow: ## Test allowed request against Kind cluster
	@echo "==> Testing ALLOW (Kind cluster)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		https://localhost:8443/hello

k8s-test-deny: ## Test denied request against Kind cluster
	@echo "==> Testing DENY (Kind cluster)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		https://localhost:8443/notallowedhere

k8s-test-body-deny: ## Test denied body against Kind cluster
	@echo "==> Testing BODY DENY (Kind cluster)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--cacert $(CERT_DIR)/ca.crt \
		--cert   $(CERT_DIR)/client.crt \
		--key    $(CERT_DIR)/client.key \
		-X POST -H "Content-Type: application/json" \
		-d '{"action":"blocked"}' \
		https://localhost:8443/hello

k8s-test-all: k8s-test-allow k8s-test-deny k8s-test-body-deny k8s-test-connect-allow k8s-test-connect-deny k8s-test-mitm-allow k8s-test-mitm-deny-domain k8s-test-mitm-deny-path ## Run all K8s test cases

k8s-test-connect-allow: ## Test allowed CONNECT tunnel against Kind cluster
	@echo "==> Testing CONNECT ALLOW (Kind cluster)..."
	go run ./connect/ -proxy localhost:8444 -target upstream.poc.svc.cluster.local:8080

k8s-test-connect-deny: ## Test denied CONNECT destination against Kind cluster
	@echo "==> Testing CONNECT DENY (Kind cluster)..."
	@go run ./connect/ -proxy localhost:8444 -target evil.example.com:443 2>&1; \
	if [ $$? -ne 0 ]; then echo "=> Correctly denied"; fi

k8s-test-mitm-allow: ## Test MITM: allowed HTTPS URL (httpbin.org/get)
	@echo "==> Testing MITM ALLOW (httpbin.org/get)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--proxy https://localhost:8445 \
		--proxy-cacert $(CERT_DIR)/ca.crt \
		--proxy-cert   $(CERT_DIR)/client.crt \
		--proxy-key    $(CERT_DIR)/client.key \
		--cacert $(CERT_DIR)/proxy-ca.crt \
		https://httpbin.org/get

k8s-test-mitm-deny-domain: ## Test MITM: blocked domain (foxnews.com)
	@echo "==> Testing MITM DENY domain (foxnews.com)..."
	@curl -s -o - -w "\nHTTP %{http_code}\n" \
		--proxy https://localhost:8445 \
		--proxy-cacert $(CERT_DIR)/ca.crt \
		--proxy-cert   $(CERT_DIR)/client.crt \
		--proxy-key    $(CERT_DIR)/client.key \
		--cacert $(CERT_DIR)/proxy-ca.crt \
		https://foxnews.com/ || true

k8s-test-mitm-deny-path: ## Test MITM: blocked path (httpbin.org/post)
	@echo "==> Testing MITM DENY path (httpbin.org/post)..."
	curl -s -o - -w "\nHTTP %{http_code}\n" \
		--proxy https://localhost:8445 \
		--proxy-cacert $(CERT_DIR)/ca.crt \
		--proxy-cert   $(CERT_DIR)/client.crt \
		--proxy-key    $(CERT_DIR)/client.key \
		--cacert $(CERT_DIR)/proxy-ca.crt \
		https://httpbin.org/post -X POST -d 'test'

k8s-logs: ## Tail logs from all pods in the poc namespace
	@kubectl logs -n $(K8S_NS) -l app=policyengine --tail=20 --prefix
	@echo "---"
	@kubectl logs -n $(K8S_NS) -l app=envoy --tail=20 --prefix
	@echo "---"
	@kubectl logs -n $(K8S_NS) -l app=upstream --tail=20 --prefix

k8s-destroy: ## Delete the Kind cluster
	@echo "==> Deleting Kind cluster '$(CLUSTER)'..."
	@kind delete cluster --name $(CLUSTER)
	@echo "==> Cluster deleted."

##@ Help

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)