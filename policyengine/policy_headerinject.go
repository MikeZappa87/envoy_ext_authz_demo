// policyengine/policy_headerinject.go
//
// Sets arbitrary headers on the request during the request_headers phase.
// Pure config — no external calls.
package main

type HeaderInjectPolicy struct {
	Set map[string]string
}

func (p *HeaderInjectPolicy) Name() string    { return "header-inject" }
func (p *HeaderInjectPolicy) Phases() []Phase { return []Phase{PhaseRequestHeaders} }

func (p *HeaderInjectPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	for k, v := range p.Set {
		ctx.SetHeaders[k] = v
	}
	return &PolicyResult{Action: ActionContinue, Message: "headers injected"}, nil
}
