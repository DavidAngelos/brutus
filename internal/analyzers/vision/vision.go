// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package vision implements Claude Vision API integration for screenshot analysis
package vision

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	DefaultModel    = "claude-3-haiku-20240307"
	DefaultEndpoint = "https://api.anthropic.com/v1/messages"
	DefaultTimeout  = 30 * time.Second
)

func init() {
	// Register the vision analyzer factory
	brutus.RegisterAnalyzer("claude-vision", func(cfg *brutus.LLMConfig) brutus.BannerAnalyzer {
		return &Client{
			APIKey: cfg.APIKey,
			Model:  cfg.Model,
		}
	})
}

// Client implements VisionAnalyzer using Claude API
type Client struct {
	APIKey   string
	Model    string
	Endpoint string        // Optional: override endpoint for testing
	Timeout  time.Duration // Optional: request timeout
}

// visionRequest is the Claude API request with image support
type visionRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []visionMessage `json:"messages"`
}

type visionMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type   string       `json:"type"`
	Text   string       `json:"text,omitempty"`
	Source *imageSource `json:"source,omitempty"`
}

type imageSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // "image/png"
	Data      string `json:"data"`       // base64 encoded image
}

type visionResponse struct {
	Content []responseContent `json:"content"`
}

type responseContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Analyze implements brutus.BannerAnalyzer (text-based analysis)
// For vision analysis, use AnalyzeScreenshot instead
func (c *Client) Analyze(ctx context.Context, banner brutus.BannerInfo) ([]string, error) {
	// Vision analyzer doesn't support text-based analysis
	// Return empty suggestions
	return []string{}, nil
}

// AnalyzeScreenshot analyzes a page screenshot using Claude Vision
func (c *Client) AnalyzeScreenshot(ctx context.Context, screenshot []byte) (*PageAnalysis, error) {
	// Build the vision prompt
	prompt := buildVisionPrompt()

	// Encode screenshot as base64
	imageData := base64.StdEncoding.EncodeToString(screenshot)

	// Create API request with image
	reqBody := visionRequest{
		Model:     c.getModel(),
		MaxTokens: 500,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []contentBlock{
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      imageData,
						},
					},
					{
						Type: "text",
						Text: prompt,
					},
				},
			},
		},
	}

	// Marshal request
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	endpoint := c.getEndpoint()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// Send request
	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude api request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claude api error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp visionResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract JSON from response
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from claude")
	}

	var analysis PageAnalysis
	if err := json.Unmarshal([]byte(apiResp.Content[0].Text), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse analysis JSON: %w", err)
	}

	return &analysis, nil
}

// VerifyLogin compares before/after screenshots to determine if login succeeded
func (c *Client) VerifyLogin(ctx context.Context, beforeScreenshot, afterScreenshot []byte) (*LoginVerification, error) {
	// Build the verification prompt
	prompt := buildVerificationPrompt()

	// Encode screenshots as base64
	beforeData := base64.StdEncoding.EncodeToString(beforeScreenshot)
	afterData := base64.StdEncoding.EncodeToString(afterScreenshot)

	// Create API request with both images
	reqBody := visionRequest{
		Model:     c.getModel(),
		MaxTokens: 300,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []contentBlock{
					{
						Type: "text",
						Text: "BEFORE login attempt (Screenshot 1):",
					},
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      beforeData,
						},
					},
					{
						Type: "text",
						Text: "AFTER login attempt (Screenshot 2):",
					},
					{
						Type: "image",
						Source: &imageSource{
							Type:      "base64",
							MediaType: "image/png",
							Data:      afterData,
						},
					},
					{
						Type: "text",
						Text: prompt,
					},
				},
			},
		},
	}

	// Marshal request
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	endpoint := c.getEndpoint()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	// Send request
	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude api request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claude api error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp visionResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract JSON from response
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from claude")
	}

	var verification LoginVerification
	if err := json.Unmarshal([]byte(apiResp.Content[0].Text), &verification); err != nil {
		return nil, fmt.Errorf("failed to parse verification JSON: %w", err)
	}

	return &verification, nil
}

// buildVerificationPrompt creates the prompt for login verification
func buildVerificationPrompt() string {
	return `Compare these two screenshots: BEFORE a login attempt and AFTER a login attempt.

Determine if the login was SUCCESSFUL or FAILED.

Signs of SUCCESS:
- Page changed to a dashboard, admin panel, or home page
- Login form is no longer visible
- Welcome message, user profile, or "Logged in as..." text appeared
- Navigation menu or settings options became available
- Logout/Sign Out button appeared

Signs of FAILURE:
- Error message visible (red text, alert box, "Invalid credentials", "Login failed")
- Login form still showing with same fields
- Page looks nearly identical to before
- Warning icons or error styling appeared

Return ONLY valid JSON in this exact format:
{
  "success": false,
  "confidence": 0.95,
  "reason": "Error message 'Invalid password' visible on the page"
}

Rules:
- success: true if login succeeded, false if it failed
- confidence: 0.0-1.0 how confident you are in this determination
- reason: brief explanation of what visual evidence led to this conclusion

NO commentary. NO explanations. ONLY the JSON object.`
}

func (c *Client) getModel() string {
	if c.Model != "" {
		return c.Model
	}
	return DefaultModel
}

func (c *Client) getEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return DefaultEndpoint
}

func (c *Client) getTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// buildVisionPrompt creates the prompt for login page analysis
func buildVisionPrompt() string {
	return `Analyze this web page screenshot for a security assessment.

Determine:
1. Is this a login page? (Look for username/password fields, login buttons)
2. What application or device is this? (Router, printer, camera, NAS, enterprise app, etc.)
3. Identify the vendor and model if visible (logos, text, title)
4. Read the VISIBLE TEXT on form elements:
   - What text is on the login/submit button?
   - What labels are next to the username field?
   - What labels are next to the password field?
5. Based on the identified device, suggest ALL known default credentials

Return ONLY valid JSON:
{
  "is_login_page": true,
  "confidence": 0.95,
  "application": {
    "type": "printer",
    "vendor": "HP",
    "model": "LaserJet Pro",
    "confidence": 0.85
  },
  "form_labels": {
    "submit_button_text": "Sign In",
    "username_label": "Username",
    "password_label": "Password"
  },
  "suggested_credentials": [
    {"username": "admin", "password": ""},
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "1234"},
    {"username": "root", "password": ""},
    {"username": "root", "password": "root"}
  ]
}

Rules:
- is_login_page: true if page has authentication form
- confidence: 0.0-1.0
- application.type: router, printer, camera, nas, enterprise, unknown
- application.vendor/model: from visible branding or empty string
- form_labels: the actual visible text you can read on the page (button text, field labels)
- suggested_credentials: ALL common default credentials for this vendor/model (aim for 5-10 pairs). Include blank passwords, numeric codes like "1111" or "1234", and vendor-specific defaults.

NO commentary. ONLY the JSON object.`
}
