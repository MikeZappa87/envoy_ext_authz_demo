package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ShieldClient calls the Azure Content Safety Prompt Shield API.
type ShieldClient struct {
	endpoint   string // e.g. "https://mypromptshield.cognitiveservices.azure.com"
	apiKey     string
	httpClient *http.Client
}

type PromptPolicy struct {
	RegisteredPhases []Phase
}

func (p *PromptPolicy) Name() string    { return "prompt" }
func (p *PromptPolicy) Phases() []Phase { return p.RegisteredPhases }

func (p *PromptPolicy) Evaluate(ctx *RequestContext) (*PolicyResult, error) {
	return &PolicyResult{}, nil
}

func NewShieldClient(endpoint, apiKey string) *ShieldClient {
	endpoint = strings.TrimRight(endpoint, "/")
	return &ShieldClient{
		endpoint: endpoint,
		apiKey:   apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ShieldRequest is the request body for the Prompt Shield API.
type ShieldRequest struct {
	UserPrompt string   `json:"userPrompt"`
	Documents  []string `json:"documents,omitempty"`
}

// ShieldResponse is the response from the Prompt Shield API.
type ShieldResponse struct {
	UserPromptAnalysis *PromptAnalysis  `json:"userPromptAnalysis,omitempty"`
	DocumentsAnalysis  []PromptAnalysis `json:"documentsAnalysis,omitempty"`
}

type PromptAnalysis struct {
	AttackDetected bool `json:"attackDetected"`
}

// ShieldResult is our simplified result.
type ShieldResult struct {
	AttackDetected bool
}

// ShieldPrompt calls the Prompt Shield API and returns whether an attack was detected.
func (c *ShieldClient) ShieldPrompt(ctx context.Context, userPrompt string) (*ShieldResult, error) {
	reqBody := ShieldRequest{
		UserPrompt: userPrompt,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + "/contentsafety/text:shieldPrompt?api-version=2024-09-01"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Ocp-Apim-Subscription-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Truncate error body to avoid noisy logs and potential information exposure.
		errBody := string(respBody)
		if len(errBody) > 256 {
			errBody = errBody[:256] + "...(truncated)"
		}
		return nil, fmt.Errorf("Content Safety API returned %d: %s", resp.StatusCode, errBody)
	}

	var shieldResp ShieldResponse
	if err := json.Unmarshal(respBody, &shieldResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	result := &ShieldResult{}

	// Check user prompt analysis.
	if shieldResp.UserPromptAnalysis != nil && shieldResp.UserPromptAnalysis.AttackDetected {
		result.AttackDetected = true
	}

	// Also check document analysis — an attack in any document counts.
	for _, doc := range shieldResp.DocumentsAnalysis {
		if doc.AttackDetected {
			result.AttackDetected = true
			break
		}
	}

	return result, nil
}
