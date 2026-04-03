// policyengine/accesslog.go
//
// Structured JSON access logging for policy decisions. Every allow/deny
// from the engine produces a single JSON line with full request context.
package main

import (
	"encoding/json"
	"log"
	"time"
)

// AccessLogEntry is the structured log written for every policy decision.
type AccessLogEntry struct {
	Timestamp        string `json:"timestamp"`
	Decision         string `json:"decision"` // "allow" or "deny"
	Phase            string `json:"phase"`
	Policy           string `json:"policy"` // which policy produced the decision
	SpiffeID         string `json:"spiffe_id,omitempty"`
	Subject          string `json:"subject,omitempty"`
	Method           string `json:"method"`
	Path             string `json:"path,omitempty"`
	Host             string `json:"host,omitempty"`
	ConnectAuthority string `json:"connect_authority,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	StatusCode       int    `json:"status_code,omitempty"` // only on deny
	Reason           string `json:"reason"`
}

// LogAccess writes a structured JSON access log line for a policy decision.
func LogAccess(ctx *RequestContext, policyName string, result *PolicyResult) {
	decision := "allow"
	if result.Action == ActionDeny {
		decision = "deny"
	}

	entry := AccessLogEntry{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Decision:         decision,
		Phase:            ctx.Phase.String(),
		Policy:           policyName,
		SpiffeID:         ctx.SpiffeID,
		Subject:          ctx.Subject,
		Method:           ctx.Method,
		Path:             ctx.Path,
		Host:             ctx.Host,
		ConnectAuthority: ctx.ConnectAuthority,
		RequestID:        ctx.RequestID,
		Reason:           result.Message,
	}

	if result.Action == ActionDeny {
		entry.StatusCode = result.StatusCode
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("accesslog: marshal error: %v", err)
		return
	}

	log.Printf("ACCESS_LOG %s", data)
}
