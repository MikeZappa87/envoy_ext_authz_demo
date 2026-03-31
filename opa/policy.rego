# OPA policy for ext_authz SPIFFE ID authorization.
#
# Input schema (sent by the ext_authz server):
#   {
#     "spiffe_id": "spiffe://poc/go-client",
#     "method":    "GET",
#     "path":      "/hello"
#   }
#
# Decision: { "allow": true/false, "reason": "..." }

package envoy.authz

import rego.v1

default allow := false

# Allowed SPIFFE IDs and the paths+methods they may access.
# In production, load this from a bundle or external data.
acl := {
	"spiffe://poc/go-client": [
		{"methods": ["GET"], "path_prefix": "/hello"},
	],
}

# Grant access when the SPIFFE ID is in the ACL and the
# request method + path match at least one rule.
allow if {
	rules := acl[input.spiffe_id]
	some rule in rules
	input.method in rule.methods
	startswith(input.path, rule.path_prefix)
}

reason := msg if {
	allow
	msg := sprintf("allowed by policy for %s", [input.spiffe_id])
}

reason := msg if {
	not allow
	msg := sprintf("denied: %s is not authorized for %s %s", [input.spiffe_id, input.method, input.path])
}
