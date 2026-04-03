# Envoy mTLS Policy Engine

A proof-of-concept demonstrating a **middleware-chain policy engine** that serves as both Envoy's ext_authz and ext_proc gRPC backend from a single binary. Policies run L4–L7 checks across multiple request lifecycle phases, with **OPA** for dynamic rules, **CRD-driven hot-reload**, an **HTTP/2 CONNECT proxy** for tunneling, and a **MITM TLS-interception proxy** for full HTTPS URL-level filtering.

## Architecture

### Pods (4 total + optional SPIRE)

```
┌─────────────────────────────────────────────────────────────────────┐
│  policyengine pod                                                   │
│  ├─ :9191  gRPC  (ext_authz + ext_proc)                            │
│  └─ :9192  TCP   (MITM proxy — auto-detects TLS vs plaintext)      │
├─────────────────────────────────────────────────────────────────────┤
│  envoy pod                                                          │
│  ├─ :8443  Ingress          (direct HTTPS → upstream)               │
│  ├─ :8444  CONNECT tunnel   (plaintext inspection → origin)         │
│  └─ :8445  CONNECT tunnel   (TLS interception → origin)             │
├─────────────────────────────────────────────────────────────────────┤
│  opa pod       :8181  (REST Data API + Rego)                        │
├─────────────────────────────────────────────────────────────────────┤
│  upstream pod  :8080  (test backend)                                │
├─────────────────────────────────────────────────────────────────────┤
│  spire-server  :8081  (SPIRE Server — optional, spire-system ns)    │
│  spire-agent   (DaemonSet, SDS socket at /run/spire/sockets)        │
└─────────────────────────────────────────────────────────────────────┘
```

### Traffic Flow

#### Listener 1 — Ingress (:8443) — Direct HTTPS

Standard HTTPS ingress with full ext_authz + ext_proc policy chain.

```
Client ─── mTLS ───▶ Envoy :8443
                        │
                        ├── ext_authz ── gRPC ──▶ policyengine :9191
                        │    └─ PhaseAuthz: SPIFFE ID check → OPA path ACL
                        │
                        ├── ext_proc ── gRPC ──▶ policyengine :9191
                        │    ├─ PhaseRequestHeaders: header-inject → OPA forbidden headers
                        │    ├─ PhaseRequestBody: OPA blocked actions
                        │    └─ PhaseResponseHeaders: add x-policy-engine: processed
                        │
                        └── router ─── HTTP ──▶ upstream :8080
```

#### Listener 2 — CONNECT Tunnel (:8444) — Plaintext Inspection

The tunnel carries plaintext HTTP. The MITM proxy reads the inner request,
runs OPA URL-level policy, and forwards to the real origin.

```
Client ─── mTLS H2 CONNECT ───▶ Envoy :8444
                                   │
                                   ├── ext_authz ── gRPC ──▶ policyengine :9191
                                   │    └─ PhaseAuthz: SPIFFE check → OPA domain allowlist
                                   │       + stores clientIP→spiffeID in ConnIdentityStore
                                   │
                                   └── CONNECT tunnel ── TCP + PROXY proto v1 ──▶ policyengine :9192 (MITM)
                                                                     │
                                                           Parse PROXY protocol header
                                                           → extract real client IP
                                                           → look up SPIFFE ID from store
                                                                     │
                                                           peek first byte (not 0x16)
                                                           → plaintext HTTP detected
                                                                     │
                                                           Read full HTTP request
                                                           (method, path, headers, body)
                                                                     │
                                                           PhaseMITMURL → OPA
                                                           (domain blocklist + path blocklist
                                                            + per-SPIFFE-ID URL allowlist)
                                                                     │
                                                           Forward ── HTTP ──▶ origin
```

#### Listener 3 — MITM HTTPS Interception (:8445) — Full TLS Decryption

The tunnel carries HTTPS. The MITM proxy terminates TLS with a dynamically
generated certificate (signed by the proxy CA), inspects the decrypted
request, and re-encrypts to the real origin.

```
Client ─── mTLS H2 CONNECT ───▶ Envoy :8445
                                   │
                                   ├── ext_authz ── gRPC ──▶ policyengine :9191
                                   │    └─ PhaseAuthz: SPIFFE check → OPA domain allowlist
                                   │       + stores clientIP→spiffeID in ConnIdentityStore
                                   │
                                   └── CONNECT tunnel ── TCP + PROXY proto v1 ──▶ policyengine :9192 (MITM)
                                                                     │
                                                           Parse PROXY protocol header
                                                           → extract real client IP
                                                           → look up SPIFFE ID from store
                                                                     │
                                                           peek first byte (0x16)
                                                           → TLS ClientHello detected
                                                                     │
                                                           TLS terminate (proxy CA cert)
                                                           Generate per-domain cert on the fly
                                                                     │
                                                           Read decrypted HTTP request
                                                           (method, path, headers, body)
                                                                     │
                                                           PhaseMITMURL → OPA
                                                           (domain blocklist + path blocklist
                                                            + per-SPIFFE-ID URL allowlist)
                                                                     │
                                                           Forward ── HTTPS ──▶ real origin
                                                           (e.g., httpbin.org, cnn.com)
```

#### Detailed: HTTPS Request over H2 CONNECT Tunnel (:8445)

This is the full step-by-step sequence for an HTTPS request (e.g., `https://httpbin.org/get`)
tunneled through Envoy's H2 CONNECT listener with MITM inspection:

```
 Client                          Envoy (:8445)                    MITM Proxy (:9192)              Origin (httpbin.org)
   │                                  │                                  │                                │
   │──── 1. mTLS handshake ──────────▶│                                  │                                │
   │     (client cert + server cert)  │                                  │                                │
   │◀──── TLS established ────────────│                                  │                                │
   │                                  │                                  │                                │
   │──── 2. H2 CONNECT ──────────────▶│                                  │                                │
   │     :method=CONNECT              │                                  │                                │
   │     :authority=httpbin.org:443   │                                  │                                │
   │                                  │                                  │                                │
   │                                  │──── 3. ext_authz gRPC ──────────▶│                                │
   │                                  │     SPIFFE ID from client cert   │                                │
   │                                  │     connect_authority=           │                                │
   │                                  │       httpbin.org:443            │                                │
   │                                  │  (stores clientIP→spiffeID)      │                                │
   │                                  │◀──── ALLOW ──────────────────────│                                │
   │                                  │                                  │                                │
   │◀──── 4. 200 OK ──────────────────│                                  │                                │
   │     (tunnel is now open)         │                                  │                                │
   │                                  │                                  │                                │
   │──── 5. TLS ClientHello ─────────▶│── PROXY proto + raw bytes ──────▶│                                │
   │     (SNI=httpbin.org)            │  (PROXY TCP4 <clientIP> ...)     │                                │
   │                                  │                                  │                                │
   │                                  │                                  │── 5a. parse PROXY protocol     │
   │                                  │                                  │   → real clientIP               │
   │                                  │                                  │   → look up SPIFFE ID          │
   │                                  │                                  │                                │
   │                                  │                                  │── 6. peek first byte (0x16)    │
   │                                  │                                  │   → TLS detected               │
   │                                  │                                  │                                │
   │                                  │                                  │── 7. generate cert for         │
   │                                  │                                  │   httpbin.org signed by        │
   │                                  │                                  │   proxy CA                     │
   │                                  │                                  │                                │
   │◀──── 8. TLS handshake ──────────│◀──── proxy CA cert ───────────────│                                │
   │     (client sees proxy CA cert   │                                  │                                │
   │      for httpbin.org)            │                                  │                                │
   │                                  │                                  │                                │
   │──── 9. GET /get HTTP/1.1 ───────▶│──── encrypted bytes ────────────▶│                                │
   │     Host: httpbin.org            │                                  │── 10. decrypt, read HTTP req   │
   │                                  │                                  │   method=GET path=/get         │
   │                                  │                                  │   host=httpbin.org             │
   │                                  │                                  │                                │
   │                                  │                                  │── 11. PhaseMITMURL → engine    │
   │                                  │                                  │   OPA: domain ok? path ok?     │
   │                                  │                                  │   SPIFFE URL allowlist ok?     │
   │                                  │                                  │   → ALLOW                      │
   │                                  │                                  │                                │
   │                                  │                                  │──── 12. TLS connect ──────────▶│
   │                                  │                                  │     (real cert for             │
   │                                  │                                  │      httpbin.org)              │
   │                                  │                                  │──── GET /get ─────────────────▶│
   │                                  │                                  │                                │
   │                                  │                                  │◀──── 200 OK + body ────────────│
   │◀──── 13. response ───────────────│◀──── re-encrypt + forward ───────│                                │
   │     (encrypted with proxy CA     │                                  │                                │
   │      session key)                │                                  │                                │
```

**Three distinct TLS sessions:**

| # | Endpoints | Certificate | Purpose |
|---|-----------|-------------|---------|
| 1 | Client ↔ Envoy | Server: Envoy cert, Client: client cert (mTLS) | Authenticate client identity (SPIFFE ID) |
| 2 | Client ↔ MITM Proxy | Proxy CA–signed cert for `httpbin.org` | Decrypt tunnel traffic for inspection |
| 3 | MITM Proxy ↔ Origin | Real `httpbin.org` certificate | Forward request to actual server |

> **Note:** The client must trust **two** CAs — the main CA (for Envoy mTLS) and the proxy CA (for MITM-generated certs).
> In curl: `--cacert ca.crt --proxy-cacert proxy-ca.crt`

#### What OPA Sees at Each Stage

| Stage | Fields available | Example |
|---|---|---|
| ext_authz (all listeners) | `spiffe_id`, `method`, `path`, `connect_authority` | `spiffe://poc/go-client`, `CONNECT`, `httpbin.org:443` |
| ext_proc (:8443 only) | `spiffe_id`, `headers`, `body` | `spiffe://poc/go-client`, `x-debug` header, `{"action":"blocked"}` |
| mitm_url (:8444 + :8445) | `spiffe_id`, `host`, `method`, `path`, `headers`, `body` | `spiffe://poc/go-client`, `httpbin.org`, `GET`, `/get` |

#### SPIFFE Identity Flow (ext_authz → ext_proc)

The SPIFFE ID is extracted from the client certificate during ext_authz and injected as
a request header so ext_proc phases can make identity-aware decisions. The header is
stripped before reaching upstream to prevent leakage.

```
 Client                          Envoy                             Policyengine              Upstream
   │                                │                                    │                       │
   │── mTLS (client cert) ─────────▶│                                    │                       │
   │── GET /hello ─────────────────▶│                                    │                       │
   │                                │                                    │                       │
   │                    ┌───────────┤                                    │                       │
   │                    │ ext_authz │── Check(cert, method, path) ──────▶│                       │
   │                    │           │                                    │                       │
   │                    │           │                          Parse client cert PEM             │
   │                    │           │                          Extract URI SAN:                  │
   │                    │           │                            spiffe://poc/go-client          │
   │                    │           │                          engine.Run(PhaseAuthz) → ALLOW    │
   │                    │           │                                    │                       │
   │                    │           │◀── OK + inject headers: ───────────│                       │
   │                    │           │      x-spiffe-id: spiffe://poc/go-client                   │
   │                    │           │      x-cert-subject: CN=go-client  │                       │
   │                    └───────────┤                                    │                       │
   │                                │                                    │                       │
   │                                │  Envoy copies injected headers     │                       │
   │                                │  onto the request                  │                       │
   │                                │                                    │                       │
   │                    ┌───────────┤                                    │                       │
   │                    │ ext_proc  │── RequestHeaders(all headers) ────▶│                       │
   │                    │           │   includes x-spiffe-id,            │                       │
   │                    │           │   x-cert-subject                   │                       │
   │                    │           │                                    │                       │
   │                    │           │                          Read x-spiffe-id → rctx.SpiffeID  │
   │                    │           │                          Read x-cert-subject → rctx.Subject│
   │                    │           │                          engine.Run(PhaseRequestHeaders)   │
   │                    │           │                                    │                       │
   │                    │           │◀── HeadersResponse: ───────────────│                       │
   │                    │           │      remove: x-spiffe-id,          │                       │
   │                    │           │              x-cert-subject        │                       │
   │                    └───────────┤                                    │                       │
   │                                │                                    │                       │
   │                                │── GET /hello ─────────────────────────────────────────────▶│
   │                                │   (identity headers stripped)      │                       │
   │                                │                                                            │
   │◀── 200 OK ────────────────────│◀────────────────────────────────────────────────────────────│
```

**Key design points:**
- **Cryptographic extraction** happens once in ext_authz — the SPIFFE ID comes from the X.509 URI SAN, not from any client-supplied header
- **Header injection** bridges ext_authz and ext_proc — Envoy copies the injected headers onto the request before ext_proc sees them
- **Header stripping** in ext_proc removes `x-spiffe-id` and `x-cert-subject` before the request reaches upstream, preventing leakage and spoofing
- **Identity is trustworthy** within the filter chain because Envoy overwrites any client-supplied values with the ext_authz response headers

### Two-Layer Policy Model (CONNECT tunnels)

For CONNECT tunnels (`:8444` and `:8445`), policy enforcement happens in **two distinct layers** that fire in sequence:

**Layer 1 — Outer mTLS (ext_authz):** Before the tunnel opens. Identity is cryptographically verified from the client certificate. OPA can enforce:

| Field | Source | Example policy |
|---|---|---|
| SPIFFE ID | Client cert URI SAN | Only `spiffe://poc/admin` may CONNECT |
| Cert Subject | Client cert CN | Block `CN=untrusted` |
| Destination host | `:authority` header (before `:`) | Allow `httpbin.org`, deny `evil.com` |
| Destination port | `:authority` header (after `:`) | Only allow port `443` and `8080` |
| Source IP | `attrs.GetSource().GetAddress()` | Restrict by subnet *(not yet wired to OPA)* |

If Layer 1 denies, the tunnel never opens — the client gets a 403.

**Layer 2 — Inner HTTP request (MITM proxy):** After the tunnel opens. The MITM proxy reads the actual HTTP request (decrypting TLS if needed) and runs OPA again. This layer can enforce:

| Field | Source | Example policy |
|---|---|---|
| Domain | TLS SNI or HTTP `Host` header | Block `foxnews.com` and all subdomains |
| URL path | HTTP request line | Allow `/get`, block `/post`, `/delete` |
| HTTP method | HTTP request line | Block `DELETE` globally |
| Headers | HTTP request headers | Block requests with specific `User-Agent` |
| Body | HTTP request body (up to 1 MB) | Block JSON with `"action": "drop"` |

**What Layer 2 does NOT have (without PROXY protocol):**
- **5-tuple** — the connection is always `envoy → policyengine:9192`.

**What Layer 2 DOES have (via PROXY protocol + in-memory identity store):**
- **SPIFFE ID** — ext_authz stores `clientIP → spiffeID` on CONNECT; the MITM proxy reads the real client IP from the PROXY protocol v1 header and looks it up.
- **True source IP** — Envoy prepends PROXY protocol v1 to the TCP tunnel, carrying the original client IP.

**Example: two-layer deny**
```
Layer 1 (ext_authz):
  SPIFFE: spiffe://poc/go-client → allowed to CONNECT foxnews.com:443 ✅

Layer 2 (mitm_url):
  GET / on foxnews.com → domain is in mitm_blocked_domains ❌ → 403
```

**Key design decisions:**
- Both ext_authz and ext_proc gRPC services on the **same port / same server** — Envoy points both filters at one cluster.
- The MITM proxy runs in the **same binary** as the policy engine — no extra pod, calls the engine directly (no OPA HTTP round-trip for policy execution).
- **PROXY protocol v1** on the mitm_cluster carries the real client IP through Envoy's CONNECT tunnel, enabling SPIFFE ID lookup in the MITM proxy via a shared in-memory store (`ConnIdentityStore`).
- Policies are driven by **Policy CRDs** — `kubectl apply` a CR and the chain + OPA rules hot-reload with zero restarts.
- OPA Rego is embedded **inline** in the Policy CR; the controller pushes it to OPA's Policy API automatically.
- Optional **SPIRE SDS** integration — Envoy can use SPIRE-issued certificates instead of static files (see `k8s/spire/`).

## Policy Chain

In CRD mode, policies are defined as individual `Policy` custom resources with an `order` field. The controller sorts by order and rebuilds the chain on every change.

Default chain (via Policy CRs):

| Order | Policy | Phase | What it does |
|-------|--------|-------|-------------|
| 10 | `spiffe-identity` | authz | Validates SPIFFE ID from client cert against allowlist |
| 15 | `header-inject` | request_headers | Injects `Agent: zappa` header into requests |
| 20 | `opa` | authz, request_headers, request_body, mitm_url | Delegates to OPA for path ACL, header validation, body inspection, CONNECT destination checks, and MITM URL filtering |

### Available Policy Types

| Type | Phases | Config |
|------|--------|--------|
| `spiffe` | authz | `allowedIDs: [...]` |
| `path-acl` | authz | `acl: { "spiffe://...": [{methods, pathPrefix}] }` |
| `header-validate` | request_headers | `requiredHeaders`, `forbiddenHeaders` |
| `header-inject` | request_headers | `set: { "header": "value" }` |
| `body-inspect` | request_body | `blockedActions: [...]` |
| `opa` | any | `url`, `phases`, `rego` (inline Rego source) |

### Policy CRD Example

```yaml
apiVersion: policy.poc.io/v1alpha1
kind: Policy
metadata:
  name: opa
  namespace: poc
spec:
  type: opa
  order: 20
  config:
    url: http://opa.poc.svc.cluster.local:8181/v1/data/envoy/authz
    phases: [authz, request_headers, request_body]
    rego: |
      package envoy.authz
      import rego.v1
      default allow := false
      # ... your Rego rules here
```

When `config.rego` is present, the controller PUTs it to OPA's Policy API on every reconcile — updating the CR hot-reloads both the chain and the Rego rules.

### Writing a Custom Policy

Implement the `Policy` interface:

```go
type Policy interface {
    Name() string
    Phases() []Phase
    Evaluate(ctx *RequestContext) (*PolicyResult, error)
}
```

Available phases: `PhaseAuthz`, `PhaseRequestHeaders`, `PhaseRequestBody`, `PhaseResponseHeaders`, `PhaseMITMURL`.

## Prerequisites

- **Go 1.21+**
- **Docker** (for Envoy and Kind)
- **OpenSSL** (for certificate generation)
- **Make**
- **Kind** + **kubectl** (for Kubernetes deployment)

## Quick Start (Local)

### 1. Generate certificates and dependencies

```sh
make certs && make deps
```

### 2. Start services (3 terminals)

```sh
# Terminal 1 — policy engine (ext_authz + ext_proc on :9191)
make run-policyengine

# Terminal 2 — upstream app (:8080)
make run-upstream

# Terminal 3 — Envoy (:8443 ingress + :8444/:8445 CONNECT)
make run-envoy
```

### 3. Test

```sh
make test-allow        # GET /hello → 200
make test-deny         # GET /notallowedhere → 403
make test-body-deny    # POST /hello with blocked body → 403
make run-connect       # CONNECT tunnel to upstream via :8444
make run-mitm          # Run the MITM proxy locally on :9192
```

## Quick Start (Kubernetes / Kind)

```sh
make k8s-cluster       # create Kind cluster (ports 8443 + 8444 + 8445)
make k8s-build         # build + load images
make k8s-deploy        # deploy everything (CRD, RBAC, OPA, policyengine, upstream, envoy)
make k8s-test-all      # run all 10 test cases
make k8s-logs          # view policy engine logs
make k8s-destroy       # tear down
```

#### With SPIRE SDS (optional)

```sh
# After k8s-deploy, add SPIRE for SDS-based certificates:
kubectl apply -f k8s/spire/spire-server.yaml
kubectl apply -f k8s/spire/spire-agent.yaml
bash k8s/spire/register-entries.sh
kubectl apply -f k8s/spire/envoy-deploy-spire.yaml
# Use spire-ca.crt for server verification:
make k8s-test-all SERVER_CA=spire-ca.crt
```

### Hot-Reload Demo

```sh
# Edit the Rego in k8s/policies/opa.yaml to allow a new path, then:
kubectl apply -f k8s/policies/opa.yaml
# No restart needed — the controller pushes new Rego to OPA immediately.

# Manage policies dynamically:
make k8s-apply-policies     # apply all Policy CRs
make k8s-delete-policies    # remove all Policy CRs
kubectl get policies -n poc # list current policies
```

## Make Targets

| Target | Description |
|---|---|
| `make certs` | Generate TLS certs with SPIFFE SANs |
| `make deps` | Download and tidy Go dependencies |
| `make run-policyengine` | Start the policy engine on :9191 |
| `make run-upstream` | Start the upstream HTTP app on :8080 |
| `make run-envoy` | Start Envoy in Docker on :8443 + :8444 + :8445 |
| `make run-client` | Run the Go mTLS client |
| `make run-connect` | Run the HTTP/2 CONNECT tunnel client |
| `make run-mitm` | Run the MITM proxy locally on :9192 |
| `make test-allow` | Test allowed request |
| `make test-deny` | Test denied path |
| `make test-body-deny` | Test denied body content |
| `make test-all` | Run all local test cases |
| `make k8s-cluster` | Create Kind cluster |
| `make k8s-build` | Build and load Docker images |
| `make k8s-deploy` | Deploy to Kind (CRD, RBAC, OPA, workloads, Policy CRs) |
| `make k8s-apply-policies` | Apply Policy CRs from `k8s/policies/` |
| `make k8s-delete-policies` | Delete all Policy CRs |
| `make k8s-test-all` | Run all K8s test cases (10 tests) |
| `make k8s-test-connect-allow` | Test allowed CONNECT tunnel |
| `make k8s-test-connect-deny` | Test denied CONNECT destination |
| `make k8s-test-mitm-allow` | Test MITM: allowed HTTPS URL |
| `make k8s-test-mitm-deny-domain` | Test MITM: blocked domain |
| `make k8s-test-mitm-deny-path` | Test MITM: blocked path |
| `make k8s-test-mitm-spiffe-allow` | Test MITM: SPIFFE-allowed URL |
| `make k8s-test-mitm-spiffe-deny` | Test MITM: SPIFFE-denied URL |
| `make k8s-logs` | Tail pod logs |
| `make k8s-destroy` | Delete Kind cluster |

## Testing

### Standard HTTPS (port 8443)

```sh
# Allowed — valid cert, allowed path
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     https://localhost:8443/hello

# Denied (path) — valid cert, disallowed path
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     https://localhost:8443/notallowedhere

# Denied (body) — valid cert, blocked JSON body
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     -X POST -H "Content-Type: application/json" -d '{"action":"blocked"}' \
     https://localhost:8443/hello
```

### HTTP/2 CONNECT Proxy (port 8444)

```sh
# Allowed destination
go run ./connect/ -proxy localhost:8444 -target upstream.poc.svc.cluster.local:8080

# Denied destination (not in OPA allowlist)
go run ./connect/ -proxy localhost:8444 -target evil.example.com:443
```

### MITM HTTPS Interception (port 8445)

```sh
# Allowed — HTTPS to httpbin.org/get
curl --proxy https://localhost:8445 \
     --proxy-cacert certs/ca.crt --proxy-cert certs/client.crt --proxy-key certs/client.key \
     --cacert certs/proxy-ca.crt \
     https://httpbin.org/get

# Denied (blocked domain) — foxnews.com
curl --proxy https://localhost:8445 \
     --proxy-cacert certs/ca.crt --proxy-cert certs/client.crt --proxy-key certs/client.key \
     --cacert certs/proxy-ca.crt \
     https://foxnews.com/

# Denied (blocked path) — httpbin.org/post
curl --proxy https://localhost:8445 \
     --proxy-cacert certs/ca.crt --proxy-cert certs/client.crt --proxy-key certs/client.key \
     --cacert certs/proxy-ca.crt \
     https://httpbin.org/post -X POST -d 'test'
```

## Project Structure

```
├── Makefile                  # Build, run, test, and deploy targets
├── envoy.yaml                # Envoy config (local — ingress + CONNECT listeners)
├── go.mod
├── certs/
│   ├── gen.sh                # Certificate generation script
│   ├── server-ext.cnf        # Server cert extensions (SPIFFE + DNS SANs)
│   └── client-ext.cnf        # Client cert extensions (SPIFFE SAN)
├── policyengine/             # ★ Unified policy engine
│   ├── main.go               # Server setup, --crd / --mitm-ca-cert flags
│   ├── engine.go             # Middleware chain runner (thread-safe)
│   ├── authz.go              # ext_authz gRPC handler
│   ├── extproc.go            # ext_proc gRPC handler
│   ├── mitm.go               # MITM proxy (auto-detects TLS vs plaintext, PROXY protocol)
│   ├── connidentity.go       # Shared in-memory SPIFFE ID store (ext_authz → MITM)
│   ├── accesslog.go          # Structured JSON access logging
│   ├── controller.go         # CRD controller — watches Policy CRs, rebuilds chain
│   ├── factory.go            # Converts CRD spec → concrete Policy instances
│   ├── policy_spiffe.go      # L4: SPIFFE identity validation
│   ├── policy_pathacl.go     # L7: Path-based access control
│   ├── policy_headers.go     # L7: Header validation
│   ├── policy_headerinject.go # L7: Inject request headers
│   ├── policy_body.go        # L7: Body content inspection
│   ├── policy_opa.go         # Delegates to OPA + pushes inline Rego
│   └── Dockerfile
├── opa/
│   └── policy.rego           # Reference Rego policy (also embedded in Policy CR)
├── connect/
│   └── main.go               # HTTP/2 CONNECT tunnel client
├── k8s/
│   ├── kind-config.yaml      # Kind cluster (ports 30443→8443, 30444→8444, 30445→8445)
│   ├── namespace.yaml        # poc namespace
│   ├── crd.yaml              # Policy CRD definition
│   ├── rbac.yaml             # ServiceAccount + ClusterRole for controller
│   ├── envoy.yaml            # Envoy config for K8s (3 listeners, static certs)
│   ├── envoy-deploy.yaml     # Envoy Deployment + NodePort Service
│   ├── policyengine.yaml     # Policy engine Deployment (--crd + --mitm) + Service
│   ├── opa.yaml              # OPA Deployment + Service
│   ├── upstream.yaml         # Upstream Deployment + Service
│   ├── policies/             # Policy CRs applied on deploy
│   │   ├── spiffe.yaml       # SPIFFE identity policy (order 10)
│   │   ├── header-inject.yaml # Header injection policy (order 15)
│   │   └── opa.yaml          # OPA policy with inline Rego (order 20)
│   └── spire/                # SPIRE integration (optional SDS-based certs)
│       ├── spire-server.yaml # SPIRE server StatefulSet
│       ├── spire-agent.yaml  # SPIRE agent DaemonSet
│       ├── register-entries.sh # Register SPIFFE identities
│       ├── envoy-spire.yaml  # Envoy config using SPIRE SDS
│       └── envoy-deploy-spire.yaml # Envoy Deployment with SPIRE socket
├── upstream/
│   ├── main.go               # Simple HTTP upstream app
│   └── Dockerfile
└── client/
    └── main.go               # Go mTLS test client
```

## How It Works

### Envoy Configuration

Two listeners, one policy cluster:

**Ingress listener (:8443)** — standard HTTPS with ext_authz + ext_proc:
```yaml
http_filters:
  - ext_authz  → policyengine_cluster   # identity + path + OPA check
  - ext_proc   → policyengine_cluster   # header + body + OPA check
  - router     → upstream_cluster
```

**CONNECT listener (:8444)** — HTTP/2 CONNECT proxy with inner-request inspection:
```yaml
http_filters:
  - ext_authz  → policyengine_cluster   # identity + destination check
  - router     → mitm_cluster           # tunnel to MITM for plaintext inspection
```

**MITM CONNECT listener (:8445)** — HTTP/2 CONNECT proxy with TLS interception:
```yaml
http_filters:
  - ext_authz  → policyengine_cluster   # identity + destination check
  - router     → mitm_cluster           # tunnel to MITM for TLS decryption
```

### CRD Controller

The policyengine runs with `--crd` in Kubernetes. On startup it:
1. Creates a dynamic informer for `policies.policy.poc.io` in the pod's namespace
2. On any add/update/delete, lists all Policy CRs, sorts by `spec.order`
3. Converts each CR to a concrete `Policy` via the factory
4. For OPA policies with `config.rego`, PUTs the Rego source to OPA's Policy API
5. Atomically swaps the engine's policy chain (thread-safe via `sync.RWMutex`)

### Policy Engine

The engine runs a middleware chain. Each policy:
1. Declares which **phases** it participates in (authz, request_headers, request_body, response_headers, mitm_url)
2. Receives a `RequestContext` with identity, method, path, host, headers, body, and connect_authority
3. Returns `Continue` (pass to next policy) or `Deny` (short-circuit with status code + message)

### MITM Proxy

The policyengine binary includes a built-in MITM proxy (enabled with `--mitm-ca-cert` and `--mitm-ca-key`). It listens on `:9192` and auto-detects TLS vs plaintext by peeking at the first byte of each tunneled connection:
- **0x16** → TLS ClientHello: terminates TLS with a dynamically generated cert, reads decrypted HTTP
- **Otherwise** → Plaintext HTTP: reads the request directly

Both paths run `PhaseMITMURL` through the engine before forwarding to the real origin.

### Certificates

All certs are signed by a single self-signed CA. The server cert has SPIFFE URI + DNS SANs. The client cert has a SPIFFE URI SAN (`spiffe://poc/go-client`).
