// policyengine/policy_headers.go
//
// L7 header validation policy — runs during ext_proc request-headers
// phase. Can enforce required headers or block forbidden ones.
package main

import (
	"fmt"
	"strings"
)

type HeaderPolicy struct {
	// RequiredHeaders that must be present (case-insensitive key check).
	RequiredHeaders []string
	// ForbiddenHeaders that must NOT be present.
	ForbiddenHeaders []string
}

func (p *HeaderPolicy) Name() string    { return "header-validate" }
func (p *HeaderPolicy) Phases() []Phase { return []Phase{PhaseRequestHeaders} }

func (p *HeaderPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	for _, required := range p.RequiredHeaders {
		if _, ok := ctx.Headers[strings.ToLower(required)]; !ok {
			return &PolicyResult{
				Action:     ActionDeny,
				StatusCode: 400,
				Message:    fmt.Sprintf("missing required header: %s", required),
			}, nil
		}
	}

	for _, forbidden := range p.ForbiddenHeaders {
		if _, ok := ctx.Headers[strings.ToLower(forbidden)]; ok {
			return &PolicyResult{
				Action:     ActionDeny,
				StatusCode: 403,
				Message:    fmt.Sprintf("forbidden header present: %s", forbidden),
			}, nil
		}
	}

	return &PolicyResult{Action: ActionContinue, Message: "headers OK"}, nil
}
