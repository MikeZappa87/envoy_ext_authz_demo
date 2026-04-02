# OPA policy for the policyengine middleware chain.
#
# Input schema (sent by the OPA policy middleware):
#   {
#     "phase":     "authz" | "request_headers" | "request_body" | ...,
#     "spiffe_id": "spiffe://poc/go-client",
#     "method":    "GET",
#     "path":      "/hello",
#     "headers":   { ... },
#     "body":      "..."
#   }
#
# Decision: { "allow": true/false, "reason": "..." }

package envoy.authz

import rego.v1

default allow := false

# --- Phase: authz -----------------------------------------------------------

# Allowed SPIFFE IDs and the paths+methods they may access.
acl := {
	"spiffe://poc/go-client": [
		{"methods": ["GET", "POST"], "path_prefix": "/hello"},
	],
}

allow if {
	input.phase == "authz"
	rules := acl[input.spiffe_id]
	some rule in rules
	input.method in rule.methods
	startswith(input.path, rule.path_prefix)
}

# Allow CONNECT to whitelisted destinations.
connect_allowed_destinations := {
	"upstream.poc.svc.cluster.local:8080",
	"httpbin.org:80",
	"httpbin.org:443",
	"cnn.com:443",
	"www.cnn.com:443",
	"foxnews.com:443",
	"www.foxnews.com:443",
}

allow if {
	input.phase == "authz"
	input.method == "CONNECT"
	acl[input.spiffe_id]                           # caller must be in the ACL
	connect_allowed_destinations[input.connect_authority]
}

# --- Phase: request_headers -------------------------------------------------

# Block requests with a forbidden header.
forbidden_headers := {"x-debug"}

allow if {
	input.phase == "request_headers"
	not has_forbidden_header
}

has_forbidden_header if {
	some h in forbidden_headers
	input.headers[h]
}

# --- Phase: request_body ----------------------------------------------------

# Block JSON bodies with action="blocked" or action="drop".
blocked_actions := {"blocked", "drop"}

allow if {
	input.phase == "request_body"
	not body_has_blocked_action
}

body_has_blocked_action if {
	body := json.unmarshal(input.body)
	blocked_actions[body.action]
}

# --- Phase: response_headers (always allow) ---------------------------------

allow if {
	input.phase == "response_headers"
}

# --- Phase: mitm_url (TLS-intercepted HTTPS URL filtering) -------------------

# Completely blocked domains — all URLs denied.
mitm_blocked_domains := {"foxnews.com", "www.foxnews.com"}

# Per-domain blocked path prefixes.
mitm_blocked_paths := {
	"httpbin.org": {"/post", "/delete", "/anything"},
}

allow if {
	input.phase == "mitm_url"
	not mitm_domain_blocked
	not mitm_path_blocked
}

mitm_domain_blocked if {
	mitm_blocked_domains[input.host]
}

mitm_domain_blocked if {
	some d in mitm_blocked_domains
	endswith(input.host, concat("", [".", d]))
}

mitm_path_blocked if {
	paths := mitm_blocked_paths[input.host]
	some prefix in paths
	startswith(input.path, prefix)
}

# --- Reason ------------------------------------------------------------------

reason := msg if {
	allow
	msg := sprintf("allowed by OPA for %s phase", [input.phase])
}

reason := msg if {
	not allow
	input.method == "CONNECT"
	msg := sprintf("denied by OPA: CONNECT to %s not permitted for %s",
		[input.connect_authority, input.spiffe_id])
}

reason := msg if {
	not allow
	input.method != "CONNECT"
	input.phase != "mitm_url"
	msg := sprintf("denied by OPA: %s %s not permitted for %s (phase: %s)",
		[input.method, input.path, input.spiffe_id, input.phase])
}

reason := msg if {
	not allow
	input.phase == "mitm_url"
	mitm_domain_blocked
	msg := sprintf("denied by MITM: domain %s is blocked", [input.host])
}

reason := msg if {
	not allow
	input.phase == "mitm_url"
	not mitm_domain_blocked
	msg := sprintf("denied by MITM: %s %s on %s is blocked",
		[input.method, input.path, input.host])
}
