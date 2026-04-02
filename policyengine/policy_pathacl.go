// policyengine/policy_pathacl.go
//
// L7 path-based access control — checks that the request path matches
// at least one allowed prefix for the caller's SPIFFE ID.
package main

import (
	"fmt"
	"strings"
)

// PathRule defines an allowed method + path-prefix combination.
type PathRule struct {
	Methods    []string // e.g. ["GET", "POST"]; empty = any method
	PathPrefix string   // e.g. "/hello"
}

type PathACLPolicy struct {
	// ACL maps SPIFFE ID → list of permitted rules.
	ACL map[string][]PathRule
}

func (p *PathACLPolicy) Name() string    { return "path-acl" }
func (p *PathACLPolicy) Phases() []Phase { return []Phase{PhaseAuthz} }

func (p *PathACLPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	rules, ok := p.ACL[ctx.SpiffeID]
	if !ok {
		return &PolicyResult{
			Action:     ActionDeny,
			StatusCode: 403,
			Message:    fmt.Sprintf("no ACL rules for %q", ctx.SpiffeID),
		}, nil
	}

	for _, rule := range rules {
		if matchesMethod(rule.Methods, ctx.Method) && strings.HasPrefix(ctx.Path, rule.PathPrefix) {
			return &PolicyResult{Action: ActionContinue, Message: "path ACL OK"}, nil
		}
	}

	return &PolicyResult{
		Action:     ActionDeny,
		StatusCode: 403,
		Message:    fmt.Sprintf("%s %s not allowed for %s", ctx.Method, ctx.Path, ctx.SpiffeID),
	}, nil
}

func matchesMethod(allowed []string, method string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
