// policyengine/policy_body.go
//
// L7 body inspection policy — runs during the ext_proc request-body
// phase. Parses JSON bodies and rejects payloads containing blocked
// content (e.g. "action":"blocked").
package main

import "encoding/json"

type BodyInspectPolicy struct {
	// BlockedActions is the set of "action" field values that are denied.
	BlockedActions map[string]bool
}

func (p *BodyInspectPolicy) Name() string    { return "body-inspect" }
func (p *BodyInspectPolicy) Phases() []Phase { return []Phase{PhaseRequestBody} }

func (p *BodyInspectPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	if len(ctx.Body) == 0 {
		return &PolicyResult{Action: ActionContinue, Message: "no body"}, nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(ctx.Body, &payload); err != nil {
		// Not JSON — let it through, upstream can validate.
		return &PolicyResult{Action: ActionContinue, Message: "non-JSON body, skipping"}, nil
	}

	if action, ok := payload["action"].(string); ok && p.BlockedActions[action] {
		return &PolicyResult{
			Action:     ActionDeny,
			StatusCode: 403,
			Message:    "request body contains a blocked action: " + action,
		}, nil
	}

	return &PolicyResult{Action: ActionContinue, Message: "body OK"}, nil
}
