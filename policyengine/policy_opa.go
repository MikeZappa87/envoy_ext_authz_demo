// policyengine/policy_opa.go
//
// OPA policy middleware — delegates decisions to an OPA server via its
// REST Data API. Can participate in any phase; sends the full request
// context to OPA and interprets the Rego result.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OPAPolicy queries an OPA endpoint for each registered phase.
type OPAPolicy struct {
	// URL is the OPA Data API endpoint (e.g. http://opa:8181/v1/data/envoy/authz).
	URL string
	// RegisteredPhases is the set of phases this policy participates in.
	RegisteredPhases []Phase
	// Rego is the optional inline policy source. When set, the controller
	// pushes it to OPA's Policy API on reconcile.
	Rego string
	// PolicyID identifies this policy in OPA (used as PUT /v1/policies/<id>).
	PolicyID string
}

func (p *OPAPolicy) Name() string    { return "opa" }
func (p *OPAPolicy) Phases() []Phase { return p.RegisteredPhases }

// opaInput is the JSON body sent to OPA.
type opaInput struct {
	Input opaInputData `json:"input"`
}

type opaInputData struct {
	Phase            string            `json:"phase"`
	SpiffeID         string            `json:"spiffe_id"`
	Method           string            `json:"method"`
	Path             string            `json:"path"`
	Host             string            `json:"host,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	ConnectAuthority string            `json:"connect_authority,omitempty"`
}

// opaResult is the expected shape of OPA's response.
type opaResult struct {
	Result struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	} `json:"result"`
}

var opaHTTPClient = &http.Client{Timeout: 2 * time.Second}

func (p *OPAPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	input := opaInput{
		Input: opaInputData{
			Phase:            ctx.Phase.String(),
			SpiffeID:         ctx.SpiffeID,
			Method:           ctx.Method,
			Path:             ctx.Path,
			Host:             ctx.Host,
			Headers:          ctx.Headers,
			Body:             string(ctx.Body),
			ConnectAuthority: ctx.ConnectAuthority,
		},
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal OPA input: %w", err)
	}

	resp, err := opaHTTPClient.Post(p.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OPA request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned %d: %s", resp.StatusCode, respBody)
	}

	var result opaResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal OPA response: %w", err)
	}

	if !result.Result.Allow {
		return &PolicyResult{
			Action:     ActionDeny,
			StatusCode: 403,
			Message:    result.Result.Reason,
		}, nil
	}

	return &PolicyResult{Action: ActionContinue, Message: result.Result.Reason}, nil
}
