// policyengine/policy_spiffe.go
//
// L4 identity policy — validates the SPIFFE ID extracted from the
// client certificate against an allowlist.
package main

import "fmt"

type SPIFFEPolicy struct {
	AllowedIDs map[string]bool
}

func (p *SPIFFEPolicy) Name() string    { return "spiffe-identity" }
func (p *SPIFFEPolicy) Phases() []Phase { return []Phase{PhaseAuthz} }

func (p *SPIFFEPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	if ctx.SpiffeID == "" {
		return &PolicyResult{
			Action:     ActionDeny,
			StatusCode: 403,
			Message:    "no SPIFFE ID in client certificate",
		}, nil
	}

	if !p.AllowedIDs[ctx.SpiffeID] {
		return &PolicyResult{
			Action:     ActionDeny,
			StatusCode: 403,
			Message:    fmt.Sprintf("SPIFFE ID %q is not authorized", ctx.SpiffeID),
		}, nil
	}

	// Inject identity header for downstream policies and upstream.
	ctx.SetHeaders["x-spiffe-id"] = ctx.SpiffeID
	ctx.SetHeaders["x-cert-subject"] = ctx.Subject

	return &PolicyResult{Action: ActionContinue, Message: "identity OK"}, nil
}
