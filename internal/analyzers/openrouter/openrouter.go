// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package openrouter implements credential research using OpenRouter API.
// OpenRouter provides access to multiple LLM providers through a single
// OpenAI-compatible API endpoint.
package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	DefaultEndpoint = "https://openrouter.ai/api/v1/chat/completions"
	DefaultModel    = "anthropic/claude-3-haiku" // Fast and cost-effective
	DefaultTimeout  = 60 * time.Second
)

func init() {
	brutus.RegisterAnalyzer("openrouter", func(cfg *brutus.LLMConfig) brutus.BannerAnalyzer {
		client := &Client{
			APIKey:  cfg.APIKey,
			Verbose: cfg.Verbose,
		}
		
		if model := os.Getenv("OPENROUTER_MODEL"); model != "" {
			client.Model = model
		}
		if endpoint := os.Getenv("OPENROUTER_BASE_URL"); endpoint != "" {
			client.Endpoint = endpoint
		}
		if timeoutStr := os.Getenv("OPENROUTER_TIMEOUT"); timeoutStr != "" {
			if duration, err := time.ParseDuration(timeoutStr); err == nil {
				client.Timeout = duration
			}
		}
		return client
	})
}

// Client implements credential research using OpenRouter API.
type Client struct {
	APIKey   string
	Model    string        // Optional: override model from OPENROUTER_MODEL
	Endpoint string        // Optional: override endpoint from OPENROUTER_BASE_URL
	Timeout  time.Duration // Optional: request timeout from OPENROUTER_TIMEOUT
	Verbose  bool          // Enable debug logging
}

type apiRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiResponse struct {
	Choices []choice `json:"choices"`
}

type choice struct {
	Message message `json:"message"`
}

// Credential holds a username/password pair parsed from LLM output.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source,omitempty"` // "openrouter"
}

// Analyze implements brutus.BannerAnalyzer interface.
// Extracts application info from banner JSON and researches credentials.
func (c *Client) Analyze(ctx context.Context, banner brutus.BannerInfo) ([]string, error) {
	creds, err := c.AnalyzeCredentials(ctx, banner)
	if err != nil {
		return nil, err
	}

	// Extract unique passwords
	passwords := make([]string, 0, len(creds))
	seen := make(map[string]bool)
	for _, cred := range creds {
		if !seen[cred.Password] {
			passwords = append(passwords, cred.Password)
			seen[cred.Password] = true
		}
	}

	return passwords, nil
}

// AnalyzeCredentials implements brutus.CredentialAnalyzer interface.
// Returns full credential pairs (username + password) for the identified application.
func (c *Client) AnalyzeCredentials(ctx context.Context, banner brutus.BannerInfo) ([]brutus.Credential, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("openrouter: OPENROUTER_API_KEY is required")
	}

	// Parse application info from banner (JSON format from vision analyzer)
	var bannerData struct {
		Application struct {
			Type   string `json:"type"`
			Vendor string `json:"vendor"`
			Model  string `json:"model"`
		} `json:"application"`
	}

	var creds []Credential
	var err error

	if jsonErr := json.Unmarshal([]byte(banner.Banner), &bannerData); jsonErr != nil {
		// Not JSON — extract identifiers from raw HTML/headers before sanitization truncates them
		appName, appVersion, server := extractAppIdentifiers(banner.Banner)
		if appName != "" {
			c.logDebug("Identified application from HTML: %q (version: %q, server: %q)", appName, appVersion, server)
			creds, err = c.researchCredentials(ctx, "", "", appName, appVersion)
		} else if server != "" {
			c.logDebug("No app name found, using server header: %q", server)
			creds, err = c.researchFromText(ctx, brutus.SanitizeBanner(banner.Banner))
		} else {
			c.logDebug("No identifiers found, using raw banner (truncated)")
			creds, err = c.researchFromText(ctx, brutus.SanitizeBanner(banner.Banner))
		}
	} else {
		// Research credentials for identified application
		creds, err = c.researchCredentials(ctx,
			bannerData.Application.Type,
			bannerData.Application.Vendor,
			bannerData.Application.Model,
			"", // version unknown in this path
		)
	}

	if err != nil {
		return nil, err
	}

	// Convert to brutus.Credential
	result := make([]brutus.Credential, 0, len(creds))
	for _, cred := range creds {
		result = append(result, brutus.Credential{
			Username: cred.Username,
			Password: cred.Password,
		})
	}

	return result, nil
}

const systemPrompt = `Identify the network device or web application from the data and list its known factory default credentials.

Rules:
1. Identify app name and version from Title, Headers, or Body.
2. Output ONLY 'username:password' pairs, one per line.
3. Use <NONE>:password if no default username exists.
4. No prose, markdown, or numbering.
5. List EVERY common default variation (case-sensitive) for this app/version.
6. If exact version is unknown, list all known defaults for that vendor/model.

Example Output:
admin:admin
root:toor
<NONE>:password123
admin:P@ssword1`

// researchCredentials queries OpenRouter for default credentials.
func (c *Client) researchCredentials(ctx context.Context, appType, vendor, model, version string) ([]Credential, error) {
	query := buildSearchQuery(appType, vendor, model, version)

	reqBody := apiRequest{
		Model: c.getModel(),
		Messages: []message{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: query,
			},
		},
	}

	creds, err := c.doRequest(ctx, reqBody)
	if err != nil {
		return nil, err
	}

	for i := range creds {
		creds[i].Source = "openrouter"
	}

	return creds, nil
}

// researchFromText handles plain text or HTML banner and returns credential pairs.
// Uses a system prompt to guide strict output formatting and application identification.
func (c *Client) researchFromText(ctx context.Context, text string) ([]Credential, error) {
	// Truncate to avoid blowing up context windows
	if len(text) > 2000 {
		text = text[:2000]
	}

	reqBody := apiRequest{
		Model: c.getModel(),
		Messages: []message{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Identify the application and list its default credentials:\n\n%s", text),
			},
		},
	}

	c.logDebug("OpenRouter prompt (banner length: %d chars):\n  System: [security researcher prompt]\n  User: Identify the application...\n  Banner preview: %.200s", len(text), text)

	return c.doRequest(ctx, reqBody)
}

// doRequest sends a request to the OpenRouter API and parses the response.
func (c *Client) doRequest(ctx context.Context, reqBody apiRequest) ([]Credential, error) {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("openrouter: failed to marshal request: %w", err)
	}

	endpoint := c.getEndpoint()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("openrouter: failed to create request: %w", err)
	}

	// Set headers per OpenRouter API requirements
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("HTTP-Referer", "https://github.com/praetorian-inc/brutus")
	req.Header.Set("X-Title", "Brutus Credential Testing")

	client := &http.Client{Timeout: c.getTimeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openrouter: api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openrouter: api error (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("openrouter: failed to decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		c.logDebug("OpenRouter returned 0 choices")
		return []Credential{}, nil
	}

	rawResponse := apiResp.Choices[0].Message.Content
	c.logDebug("OpenRouter raw response:\n---\n%s\n---", rawResponse)

	creds := parseCredentials(rawResponse)
	c.logDebug("Parsed %d credentials from response", len(creds))

	return creds, nil
}

func (c *Client) logDebug(format string, args ...interface{}) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
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
// extractAppIdentifiers extracts application name and server info from raw HTTP response.
// This runs on the FULL banner before SanitizeBanner truncates it, ensuring we catch
// identifiers like <title>Radarr</title> that appear deep in the HTML.
func extractAppIdentifiers(banner string) (appName, appVersion, server string) {
	// Extract Server header and optional version (e.g., "Server: Apache/2.4.41")
	serverPattern := regexp.MustCompile(`(?i)^Server:\s*(.+)$`)
	for _, line := range strings.Split(banner, "\n") {
		if m := serverPattern.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			server = strings.TrimSpace(m[1])
			if parts := strings.SplitN(server, "/", 2); len(parts) == 2 {
				appVersion = parts[1]
			}
			break
		}
	}

	// Extract <title> tag and optional version (e.g., "pfSense - Login - v2.5.2")
	titlePattern := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if m := titlePattern.FindStringSubmatch(banner); m != nil {
		title := strings.TrimSpace(m[1])
		if title != "" && len(title) < 100 {
			appName = title
			// Look for version inside title
			if vMatch := regexp.MustCompile(`(?i)\bv(\d+(?:\.\d+)*)`).FindStringSubmatch(title); vMatch != nil {
				appVersion = vMatch[1]
			}
		}
	}

	// Extract <meta name="description" content="...">
	if appName == "" {
		metaDescPattern := regexp.MustCompile(`(?i)<meta\s+name=["']description["']\s+content=["']([^"']+)["']`)
		if m := metaDescPattern.FindStringSubmatch(banner); m != nil {
			desc := strings.TrimSpace(m[1])
			if desc != "" && len(desc) < 100 {
				appName = desc
			}
		}
	}

	// Extract JS patterns (e.g., window.Radarr, window.Version)
	if appName == "" {
		jsAppPattern := regexp.MustCompile(`(?i)window\.(Radarr|Sonarr|Lidarr|Prowlarr|Readarr|Jellyfin|Plex|Grafana|Jenkins|Portainer|Nextcloud)\b`)
		if m := jsAppPattern.FindStringSubmatch(banner); m != nil {
			appName = m[1]
		}
	}

	// Hunt for version strings globally if we still don't have one
	if appVersion == "" {
		metaVerPattern := regexp.MustCompile(`(?i)<meta\s+name=["']version["']\s+content=["']([^"']+)["']`)
		if m := metaVerPattern.FindStringSubmatch(banner); m != nil {
			appVersion = strings.TrimSpace(m[1])
		} else {
			jsVerPattern := regexp.MustCompile(`(?i)window\.version\s*=\s*["']([^"']+)["']`)
			if m := jsVerPattern.FindStringSubmatch(banner); m != nil {
				appVersion = strings.TrimSpace(m[1])
			}
		}
	}

	return appName, appVersion, server
}

// buildSearchQuery creates the search query for credential research.
func buildSearchQuery(appType, vendor, model, version string) string {
	parts := []string{}

	if vendor != "" {
		parts = append(parts, vendor)
	}
	if model != "" {
		parts = append(parts, model)
	}
	if appType != "" && appType != "unknown" {
		parts = append(parts, appType)
	}

	device := strings.Join(parts, " ")
	if device == "" {
		device = "unknown device"
	}

	if version != "" {
		device = fmt.Sprintf("%s (version %s)", device, version)
	}

	return fmt.Sprintf(`Identify and list ALL factory default credentials for: %s
Strictly follow the formatting rules from the system prompt.`, device)
}

// parseCredentials extracts credential pairs from text response.
func parseCredentials(text string) []Credential {
	creds := []Credential{}
	seen := make(map[string]bool)

	lines := strings.Split(text, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.ToUpper(line) == "UNKNOWN" {
			continue
		}

		// Strip markdown list prefixes: - , * , 1. , 2. , etc.
		line = regexp.MustCompile(`^[\-\*]\s+`).ReplaceAllString(line, "")
		line = regexp.MustCompile(`^\d+\.\s+`).ReplaceAllString(line, "")
		// Strip backticks
		line = strings.ReplaceAll(line, "`", "")
		line = strings.TrimSpace(line)

		// Pattern 1: strict "username:password" on its own line (best case from good prompt)
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			user := strings.TrimSpace(parts[0])
			pass := strings.TrimSpace(parts[1])

			if strings.ToUpper(user) == "<NONE>" {
				user = ""
			}
			if strings.ToUpper(pass) == "<NONE>" {
				pass = ""
			}

			// Only accept if username looks like a real username (short, no spaces, alphanumeric) or is empty
			if (user == "" || isValidUsername(user)) && len(pass) <= 50 {
				key := user + ":" + pass
				if !seen[key] {
					creds = append(creds, Credential{Username: user, Password: pass})
					seen[key] = true
				}
				continue
			}
		}

		// Pattern 2: "username/password" format
		if parts := strings.SplitN(line, "/", 2); len(parts) == 2 {
			user := strings.TrimSpace(parts[0])
			pass := strings.TrimSpace(parts[1])

			if strings.ToUpper(user) == "<NONE>" {
				user = ""
			}
			if strings.ToUpper(pass) == "<NONE>" {
				pass = ""
			}

			if (user == "" || isValidUsername(user)) && len(pass) <= 50 && !strings.Contains(pass, " ") {
				key := user + ":" + pass
				if !seen[key] {
					creds = append(creds, Credential{Username: user, Password: pass})
					seen[key] = true
				}
				continue
			}
		}
	}

	// Pattern 3: fallback — "Username: X ... Password: Y" in prose
	userPattern := regexp.MustCompile(`(?i)username[:\s]+([a-zA-Z0-9_]+)`)
	passPattern := regexp.MustCompile(`(?i)password[:\s]+([a-zA-Z0-9_!@#$%^&*()]+)`)
	userMatches := userPattern.FindAllStringSubmatch(text, -1)
	passMatches := passPattern.FindAllStringSubmatch(text, -1)
	for i := 0; i < len(userMatches) && i < len(passMatches); i++ {
		user := strings.TrimSpace(userMatches[i][1])
		pass := strings.TrimSpace(passMatches[i][1])
		if isValidUsername(user) {
			key := user + ":" + pass
			if !seen[key] {
				creds = append(creds, Credential{Username: user, Password: pass})
				seen[key] = true
			}
		}
	}

	// Sanitize and validate
	validCreds := []Credential{}
	for _, c := range creds {
		sanitizeCredential(&c)
		if isValidCredential(c) {
			validCreds = append(validCreds, c)
		}
	}

	// Limit to reasonable number
	if len(validCreds) > 10 {
		validCreds = validCreds[:10]
	}

	return validCreds
}

// sanitizeCredential removes markdown artifacts and normalizes credentials.
func sanitizeCredential(c *Credential) {
	markdownChars := []string{"**", "*", "`", "~", "_"}
	for _, m := range markdownChars {
		c.Username = strings.ReplaceAll(c.Username, m, "")
		c.Password = strings.ReplaceAll(c.Password, m, "")
	}
	c.Username = strings.TrimSpace(c.Username)
	c.Password = strings.TrimSpace(c.Password)
}

// isValidUsername checks if a string looks like a real username.
func isValidUsername(s string) bool {
	if s == "" || len(s) > 30 {
		return false
	}
	// Must not contain spaces
	if strings.Contains(s, " ") {
		return false
	}
	// Must start with a letter or digit
	if !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= '0' && s[0] <= '9')) {
		return false
	}
	// Check against blocklist of English words / HTML / boilerplate
	return !isBlockedWord(strings.ToLower(s))
}

// isBlockedWord returns true if the word is not a plausible username.
func isBlockedWord(word string) bool {
	blocklist := map[string]bool{
		// English words / LLM boilerplate
		"the": true, "default": true, "example": true, "devices": true,
		"notes": true, "consideration": true, "important": true, "warning": true,
		"note": true, "see": true, "for": true, "more": true, "information": true,
		"details": true, "typically": true, "usually": true, "common": true,
		"standard": true, "model": true, "here": true, "are": true, "is": true,
		"based": true, "on": true, "my": true, "research": true, "these": true,
		"this": true, "that": true, "with": true, "from": true, "and": true,
		"or": true, "not": true, "no": true, "yes": true, "can": true,
		"will": true, "would": true, "should": true, "could": true,
		"sources": true, "documentation": true, "site": true, "device": true,
		"practice": true, "own": true, "credential": true, "credentials": true,
		"following": true, "list": true, "lists": true, "found": true,
		"search": true, "results": true, "unknown": true, "none": true,
		// Protocol/URL schemes
		"http": true, "https": true, "ftp": true, "ssh": true, "tcp": true,
	}
	return blocklist[word]
}

// isValidCredential checks if a credential looks reasonable.
func isValidCredential(c Credential) bool {
	// If both are empty, invalid. If we only have password, that's fine.
	if c.Username == "" && c.Password == "" {
		return false
	}

	// Password validation
	if c.Password != "" {
		// Check if empty-equivalent
		lowerPass := strings.ToLower(c.Password)
		emptyEquiv := []string{"none", "blank", "empty", "n/a", "na"}
		for _, e := range emptyEquiv {
			if lowerPass == e {
				c.Password = ""
				return true
			}
		}

		// Must contain at least one alphanumeric character
		hasAlphanumeric := false
		for _, r := range c.Password {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				hasAlphanumeric = true
				break
			}
		}
		if !hasAlphanumeric {
			return false
		}
	}

	return true
}
