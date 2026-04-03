// policyengine/engine.go
//
// Core middleware-chain policy engine. Policies register for specific
// phases and are executed in order. Any policy can short-circuit the
// chain by returning a Deny action.
package main

import (
	"fmt"
	"log"
	"sync"
)

// Phase represents when a policy runs in the request lifecycle.
type Phase int

const (
	PhaseAuthz           Phase = iota // ext_authz Check — identity + coarse access
	PhaseRequestHeaders               // ext_proc request headers
	PhaseRequestBody                  // ext_proc request body
	PhaseResponseHeaders              // ext_proc response headers
	PhaseMITMURL                      // MITM proxy — decrypted HTTPS URL-level check
)

func (p Phase) String() string {
	switch p {
	case PhaseAuthz:
		return "authz"
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseMITMURL:
		return "mitm_url"
	default:
		return fmt.Sprintf("phase(%d)", int(p))
	}
}

// Action is the result of a single policy evaluation.
type Action int

const (
	ActionContinue Action = iota // pass to next policy
	ActionDeny                   // reject the request immediately
)

// RequestContext carries data accumulated across phases.
// It is created during ext_authz (Check) and carried through ext_proc.
type RequestContext struct {
	// Identity (populated during authz phase from the cert)
	SpiffeID string
	Subject  string

	// HTTP request fields
	Method           string
	Path             string
	Host             string // target domain (used by MITM phase)
	Headers          map[string]string
	Body             []byte
	ConnectAuthority string // :authority from CONNECT requests (original destination)

	// Correlation
	RequestID string // x-request-id from Envoy for log correlation

	// Current phase
	Phase Phase

	// Accumulated mutations — policies can append to these.
	SetHeaders    map[string]string
	RemoveHeaders []string
}

// PolicyResult is what a single policy returns.
type PolicyResult struct {
	Action     Action
	StatusCode int    // only used when Action == ActionDeny
	Message    string // deny reason or audit note
}

// Policy is the interface every middleware must implement.
type Policy interface {
	// Name returns a human-readable identifier for logging.
	Name() string
	// Phases returns the set of phases this policy participates in.
	Phases() []Phase
	// Evaluate runs the policy logic for the current phase.
	Evaluate(ctx *RequestContext) (*PolicyResult, error)
}

// Engine holds the ordered policy chain.
type Engine struct {
	mu       sync.RWMutex
	policies []Policy
}

// NewEngine creates an engine with the given policies (order matters).
func NewEngine(policies ...Policy) *Engine {
	return &Engine{policies: policies}
}

// SetPolicies atomically replaces the policy chain (used by the CRD controller).
func (e *Engine) SetPolicies(policies []Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies
}

// Policies returns a snapshot of the current chain (for logging).
func (e *Engine) Policies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// Run executes all policies registered for the given phase, in order.
// It returns the first Deny result, or a Continue result if all pass.
func (e *Engine) Run(ctx *RequestContext) *PolicyResult {
	e.mu.RLock()
	policies := e.policies
	e.mu.RUnlock()

	for _, p := range policies {
		if !policyMatchesPhase(p, ctx.Phase) {
			continue
		}

		result, err := p.Evaluate(ctx)
		if err != nil {
			log.Printf("engine: policy %q error: %v — denying", p.Name(), err)
			return &PolicyResult{
				Action:     ActionDeny,
				StatusCode: 500,
				Message:    fmt.Sprintf("policy %q error: %v", p.Name(), err),
			}
		}

		log.Printf("engine: phase=%s policy=%s action=%s msg=%q",
			ctx.Phase, p.Name(), actionStr(result.Action), result.Message)

		if result.Action == ActionDeny {
			LogAccess(ctx, p.Name(), result)
			return result
		}
	}

	// Log the final allow with the last policy that ran (or "none").
	allowResult := &PolicyResult{Action: ActionContinue, Message: "all policies passed"}
	LogAccess(ctx, "chain", allowResult)
	return allowResult
}

func policyMatchesPhase(p Policy, phase Phase) bool {
	for _, ph := range p.Phases() {
		if ph == phase {
			return true
		}
	}
	return false
}

func actionStr(a Action) string {
	if a == ActionDeny {
		return "DENY"
	}
	return "CONTINUE"
}
