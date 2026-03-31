# Envoy mTLS + ext_authz with SPIFFE IDs

A proof-of-concept demonstrating mutual TLS (mTLS) authentication through Envoy, with a gRPC external authorization server that validates SPIFFE identity from client certificates.

## Architecture

```
┌────────┐  mTLS   ┌───────┐  gRPC   ┌───────────┐  HTTP   ┌───────┐
│ Client ├────────►│ Envoy ├────────►│ ext_authz ├───────►│  OPA  │
│ :Go    │  :8443  │       │  :9191  │ (authz)   │  :8181 │       │
└────────┘         │       │         └───────────┘        └───────┘
                   │       │  HTTP   ┌───────────┐
                   │       ├────────►│ upstream  │
                   └───────┘  :8080  │ (app)     │
                                     └───────────┘
```

1. **Client** presents a certificate with SPIFFE SAN `spiffe://poc/go-client` over mTLS to Envoy.
2. **Envoy** terminates TLS, validates the client cert against the CA, and forwards the request (including the peer certificate) to the ext_authz gRPC server.
3. **ext_authz** parses the client certificate, extracts the SPIFFE ID from the URI SAN, and checks it against an allowlist (or queries OPA). If allowed, it injects `x-spiffe-id` and `x-cert-subject` headers.
4. **upstream** receives the authorized request with identity headers and returns a response.

## Prerequisites

- **Go 1.21+**
- **Docker** (for running Envoy)
- **OpenSSL** (for certificate generation)
- **Make**

## Quick Start

### 1. Generate Certificates

Generates a CA, server cert (for Envoy with `spiffe://poc/envoy` SAN), and client cert (with `spiffe://poc/go-client` SAN):

```sh
make certs
```

### 2. Install Go Dependencies

```sh
make deps
```

### 3. Start the Services

Each service runs in its own terminal. Open three separate terminals:

**Terminal 1 — ext_authz server (gRPC on :9191):**

```sh
make run-ext-authz
```

**Terminal 2 — upstream app (HTTP on :8080):**

```sh
make run-upstream
```

**Terminal 3 — Envoy proxy (HTTPS on :8443, admin on :9901):**

```sh
make run-envoy
```

### 4. Send a Request

Once all three services are running, open a fourth terminal:

```sh
make run-client
```

You should see output like:

```
Status: 200 OK
Body:
Request authorized!
SPIFFE ID:    spiffe://poc/go-client
Cert Subject: CN=go-client
```

## Make Targets

| Target | Description |
|---|---|
| `make all` | Generate certs and download deps |
| `make certs` | Generate all TLS certs with SPIFFE SANs |
| `make deps` | Download and tidy Go dependencies |
| `make run-ext-authz` | Start the ext_authz gRPC server on :9191 (built-in allowlist) |
| `make run-opa` | Start OPA server on :8181 with the authz policy |
| `make run-ext-authz-opa` | Start ext_authz on :9191, delegating to OPA |
| `make run-upstream` | Start the upstream HTTP app on :8080 |
| `make run-envoy` | Start Envoy in Docker on :8443 |
| `make run-client` | Run the Go mTLS client (sends one request) |
| `make run-all` | Launch all services in a tmux session |
| `make test-allow` | Test allowed request via curl (with client cert) |
| `make test-deny` | Test denied request via curl (no client cert) |
| `make stop` | Stop the tmux session and Envoy/OPA containers |
| `make clean` | Remove certs, go.mod/go.sum, and stop services |

## Testing with curl

**Allowed request** (with client cert):

```sh
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8443/hello
```

**Denied request** (valid cert, disallowed path):

```sh
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8443/notallowedhere
```

## Project Structure

```
├── Makefile              # Build and run targets
├── envoy.yaml            # Envoy configuration (mTLS + ext_authz filter)
├── go.mod                # Go module definition
├── certs/
│   ├── gen.sh            # Certificate generation script
│   ├── server-ext.cnf    # Server cert extensions (SPIFFE + DNS SANs)
│   └── client-ext.cnf    # Client cert extensions (SPIFFE SAN)
├── opa/
│   └── policy.rego       # OPA Rego policy (SPIFFE ID + path/method ACL)
├── ext_authz/
│   └── main.go           # gRPC ext_authz server (SPIFFE ID validation)
├── upstream/
│   └── main.go           # Simple HTTP upstream app
└── client/
    └── main.go           # Go mTLS client
```

## How It Works

### Certificates

All certs are signed by a single self-signed CA (`certs/ca.crt`). The server cert includes both a SPIFFE URI SAN (`spiffe://poc/envoy`) and DNS SANs (`envoy`, `localhost`) for TLS hostname verification. The client cert has a SPIFFE URI SAN (`spiffe://poc/go-client`).

### Envoy Configuration

- Listens on `:8443` with TLS, requiring a client certificate
- Validates client certs against the CA with a SPIFFE URI prefix match (`spiffe://poc/`)
- Forwards requests to the `ext_authz` gRPC service with `include_peer_certificate: true`
- Routes authorized requests to the upstream cluster on `:8080`
- Admin interface available on `:9901`

### ext_authz Server

The ext_authz server supports two authorization modes:

- **Built-in allowlist** (default): checks the SPIFFE ID against a hardcoded Go map
- **OPA mode** (`-opa` flag): delegates authorization decisions to an OPA server via its REST API

In both modes it:
- Receives the `CheckRequest` from Envoy containing the URL-encoded PEM client certificate
- Decodes and parses the X.509 certificate
- Extracts SPIFFE IDs from URI SANs
- On success: returns OK with injected `x-spiffe-id` and `x-cert-subject` headers
- On failure: returns `PermissionDenied` with a descriptive error message

### Authorization Policy

#### Built-in Allowlist

The allowlist is defined in `ext_authz/main.go`:

```go
var allowedSPIFFEIDs = map[string]bool{
    "spiffe://poc/go-client": true,
}
```

To authorize additional identities, add their SPIFFE IDs to this map.

#### OPA Policy

When running with OPA, the policy is defined in `opa/policy.rego`. The ext_authz server sends OPA an input document with the SPIFFE ID, HTTP method, and path:

```json
{
  "input": {
    "spiffe_id": "spiffe://poc/go-client",
    "method": "GET",
    "path": "/hello"
  }
}
```

The Rego policy evaluates this against an ACL map:

```rego
acl := {
    "spiffe://poc/go-client": [
        {"methods": ["GET"], "path_prefix": "/"},
    ],
}
```

This enables fine-grained, per-identity control over which HTTP methods and paths are allowed — without recompiling the ext_authz server.

## Running with OPA

To use OPA instead of the built-in allowlist, start OPA before the ext_authz server:

**Terminal 1 — OPA (REST API on :8181):**

```sh
make run-opa
```

**Terminal 2 — ext_authz in OPA mode (gRPC on :9191):**

```sh
make run-ext-authz-opa
```

Then start upstream, Envoy, and the client as usual. The ext_authz logs will show the OPA decision reason.

To modify the policy, edit `opa/policy.rego` and restart OPA.
