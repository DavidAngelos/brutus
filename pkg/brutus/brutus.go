// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package brutus provides a modern Go library for credential brute-forcing
// with zero dependencies and library-first design.
//
// Quick Start:
//
//	config := &brutus.Config{
//	    Target:    "10.0.0.50:22",
//	    Protocol:  "ssh",
//	    Usernames: []string{"root", "admin"},
//	    Passwords: []string{"password", "admin"},
//	    Timeout:   5 * time.Second,
//	    Threads:   10,
//	}
//
//	results, err := brutus.Brute(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, r := range results {
//	    if r.Success {
//	        fmt.Printf("Valid: %s:%s\n", r.Username, r.Password)
//	    }
//	}
//
// Error Handling:
//
// Results distinguish between authentication failures (invalid credentials)
// and connection errors. Authentication failures have Success=false and Error=nil.
// Connection errors have Success=false and Error!=nil.
//
// Supported Protocols:
//
// - ssh: SSH password authentication
package brutus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/badkeys"
)

const (
	// MaxBannerLength limits banner size to prevent prompt injection
	MaxBannerLength = 500
	// MaxPasswordLength limits suggested password length
	MaxPasswordLength = 32
)

// =============================================================================
// Context Keys for TLS Mode
// =============================================================================

type contextKey string

const tlsModeContextKey contextKey = "tlsMode"

// ContextWithTLSMode adds TLSMode to the context
func ContextWithTLSMode(ctx context.Context, tlsMode string) context.Context {
	return context.WithValue(ctx, tlsModeContextKey, tlsMode)
}

// TLSModeFromContext retrieves TLSMode from the context (default: "disable")
func TLSModeFromContext(ctx context.Context) string {
	if mode, ok := ctx.Value(tlsModeContextKey).(string); ok {
		return mode
	}
	return "disable"
}

// Credential represents a pre-paired username with password or key.
// Use this instead of separate Usernames/Passwords/Keys arrays when you have
// specific credential pairs (e.g., badkeys where each key has an associated username).
type Credential struct {
	Username string // username to test
	Password string // password to test (empty for key-based auth)
	Key      []byte // SSH private key (nil for password-based auth)
}

// Config defines the configuration for a brute force attack.
type Config struct {
	Target        string        // host:port (e.g., "10.0.0.50:22")
	Protocol      string        // plugin name (e.g., "ssh")
	Usernames     []string      // usernames to test (Cartesian product with Passwords/Keys)
	Passwords     []string      // passwords to test (Cartesian product with Usernames)
	Keys          [][]byte      // SSH private keys to test (Cartesian product with Usernames)
	Credentials   []Credential  // pre-paired credentials (no Cartesian product)
	UseDefaults   bool          // load protocol-specific default credentials from embedded wordlists
	NoBadkeys     bool          // skip embedded bad SSH keys when UseDefaults is true
	Timeout       time.Duration // per-credential timeout (default: 10s)
	Threads       int           // concurrent workers (default: 10)
	StopOnSuccess bool          // stop after first valid cred (default: true)
	LLMConfig     *LLMConfig    // optional LLM-based banner analysis (nil = disabled)
	Plugin        Plugin        // optional: pre-configured plugin instance (bypasses GetPlugin)
	TLSMode       string        // TLS/SSL verification mode: "disable", "verify", "skip-verify" (default: "disable")
	RateLimit     float64       // max requests per second (0 = unlimited, default: 0)
	Jitter        time.Duration // random delay variance added to rate limiting (default: 0)
	MaxAttempts   int           // max password attempts per username (0 = unlimited)
	SprayMode     bool          // password spraying: loop users first, then passwords
}

// Result contains the outcome of testing a single credential.
type Result struct {
	Protocol string        // protocol used
	Target   string        // target tested
	Username string        // username tested
	Password string        // password tested
	Key      []byte        // SSH key (Phase 1B, nil in 1A)
	Success  bool          // authentication succeeded?
	Error    error         // connection/network error (nil for auth failure)
	Duration time.Duration // test duration

	// Banner and LLM suggestion tracking
	Banner            string   // service banner (if captured)
	LLMSuggested      bool     // was this credential suggested by LLM?
	LLMSuggestedCreds []string // all LLM suggestions for this service
}

// LLMConfig enables optional LLM-based banner analysis
type LLMConfig struct {
	Enabled  bool
	Provider string // "claude" (additional providers can be added via the plugin architecture)
	APIKey   string
	Model    string // Optional: model override
}

// BannerAnalyzer is an optional interface for intelligent credential suggestion
type BannerAnalyzer interface {
	Analyze(ctx context.Context, banner BannerInfo) ([]string, error)
}

// CredentialAnalyzer extends BannerAnalyzer to return full credential pairs
// Analyzers that implement this interface can return both username and password
type CredentialAnalyzer interface {
	BannerAnalyzer
	AnalyzeCredentials(ctx context.Context, banner BannerInfo) ([]Credential, error)
}

// BannerInfo contains service banner information
type BannerInfo struct {
	Protocol string
	Target   string
	Banner   string      // Raw banner text
	Headers  http.Header // For HTTP services (optional)
}

// AnalyzerFactory creates a new analyzer instance from configuration
type AnalyzerFactory func(cfg *LLMConfig) BannerAnalyzer

// Plugin defines the interface for authentication protocol implementations.
// Each plugin must implement credential testing for a specific protocol (SSH, FTP, etc.).
//
// Optional Key-Based Authentication:
// Plugins may optionally implement the KeyPlugin interface for key-based authentication.
// If a plugin implements KeyPlugin, the worker pool will automatically use it when
// Config.Keys is provided.
type Plugin interface {
	// Name returns the protocol name (e.g., "ssh", "ftp").
	Name() string

	// Test attempts to authenticate using the provided credentials.
	// Returns a Result indicating success or failure.
	//
	// For authentication failures (invalid credentials), Result.Success=false and Result.Error=nil.
	// For connection/network errors, Result.Success=false and Result.Error!=nil.
	//
	// The context can be used to cancel the operation early.
	// The timeout specifies the maximum duration for the authentication attempt.
	Test(ctx context.Context, target, username, password string, timeout time.Duration) *Result
}

// KeyPlugin extends Plugin with key-based authentication support.
//
// Protocols that support public key authentication (e.g., SSH) can optionally implement
// this interface. The worker pool will automatically detect and use TestKey when
// Config.Keys is provided.
type KeyPlugin interface {
	Plugin

	// TestKey attempts authentication with username and SSH private key
	TestKey(ctx context.Context, target, username string, key []byte, timeout time.Duration) *Result
}

// PluginFactory is a function that creates a new Plugin instance.
// Using a factory pattern ensures each call to Get returns a fresh instance,
// which is important for concurrent usage.
type PluginFactory func() Plugin

// =============================================================================
// Standard Banners
// =============================================================================

// standardBanners contains known standard banner patterns for each protocol
var standardBanners = map[string][]string{
	"ssh": {
		"SSH-2.0-OpenSSH",
		"SSH-2.0-libssh",
		"SSH-2.0-dropbear",
	},
	"telnet": {
		"Ubuntu",
		"Debian",
		"Linux",
		"FreeBSD",
	},
	"ftp": {
		"220 ProFTPD",
		"220 (vsFTPd",
		"220-FileZilla",
		"220 Pure-FTPd",
	},
	"mysql": {
		"MySQL 5.",
		"MySQL 8.",
		"MariaDB 10.",
		"Percona Server",
	},
	"snmp": {
		"Linux",
		"Cisco IOS",
		"Windows",
		"FreeBSD",
		"net-snmp",
		"HP ETHERNET",
		"APC",
		"Ubiquiti",
	},
}

// IsStandardBanner checks if a banner matches known standard patterns for the protocol.
// Returns true if the banner is standard (common/default), false if custom/modified.
//
// HTTP protocols (http, https, couchdb, elasticsearch, influxdb) always return false
// to enable LLM analysis, as they have application-specific banners (Grafana, Jenkins,
// Tomcat) that benefit from LLM credential suggestion.
//
// Unknown non-HTTP protocols or empty banners are assumed standard.
func IsStandardBanner(protocol, banner string) bool {
	// Empty banner - assume standard
	if banner == "" {
		return true
	}

	// HTTP protocols always need LLM analysis (application-specific banners)
	if isHTTPProtocol(protocol) {
		return false
	}

	// Get patterns for protocol
	patterns, ok := standardBanners[protocol]
	if !ok {
		// Unknown protocol - assume standard
		return true
	}

	// Check if banner matches any standard pattern
	for _, pattern := range patterns {
		if strings.Contains(banner, pattern) {
			return true
		}
	}

	// No match - custom banner
	return false
}

// =============================================================================
// Configuration Validation
// =============================================================================

// applyDefaults populates protocol-specific default credentials from embedded
// wordlists when UseDefaults is true and no credentials have been provided.
// Existing credentials are never overwritten.
func (c *Config) applyDefaults() {
	if !c.UseDefaults {
		return
	}

	hasCreds := len(c.Credentials) > 0
	hasPasswords := len(c.Passwords) > 0
	hasKeys := len(c.Keys) > 0

	// Load SSH badkeys as paired credentials when no keys/creds were provided
	if c.Protocol == "ssh" && !c.NoBadkeys && !hasCreds && !hasKeys {
		for _, k := range badkeys.GetSSHCredentials() {
			c.Credentials = append(c.Credentials, Credential{Username: k.Username, Key: k.Key})
		}
	}

	// Load wordlist defaults when no user-supplied credentials were provided
	if !hasCreds && !hasPasswords && !hasKeys {
		if defaults := DefaultCredentials(c.Protocol); len(defaults) > 0 {
			c.Credentials = append(c.Credentials, defaults...)
		}
	}
}

// validate checks the configuration and applies defaults.
func (c *Config) validate() error {
	if c.Target == "" {
		return errors.New("target is required")
	}
	if c.Protocol == "" {
		return errors.New("protocol is required")
	}

	c.applyDefaults()

	// Need either: paired Credentials OR (Usernames + Passwords/Keys)
	hasPairedCreds := len(c.Credentials) > 0
	hasUnpairedCreds := len(c.Usernames) > 0 && (len(c.Passwords) > 0 || len(c.Keys) > 0)
	if !hasPairedCreds && !hasUnpairedCreds {
		return errors.New("credentials required: use Credentials for paired, or Usernames with Passwords/Keys")
	}

	// Apply defaults
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Threads == 0 {
		c.Threads = 10
	}

	return nil
}

// =============================================================================
// Brute Force Execution
// =============================================================================

// Brute executes a brute force attack using the provided configuration.
func Brute(cfg *Config) ([]Result, error) {
	// 1. Validate configuration
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// 2. Get protocol plugin (use provided plugin if set, otherwise lookup by name)
	var plug Plugin
	if cfg.Plugin != nil {
		plug = cfg.Plugin
	} else {
		var err error
		plug, err = GetPlugin(cfg.Protocol)
		if err != nil {
			return nil, err
		}
	}

	// 3. Run worker pool
	ctx := context.Background()
	results, err := runWorkers(ctx, cfg, plug)
	if err != nil {
		return results, fmt.Errorf("brute force failed: %w", err)
	}

	return results, nil
}

// =============================================================================
// LLM Utilities
// =============================================================================

// createAnalyzer creates the appropriate LLM analyzer based on provider configuration.
// Returns nil if provider is unknown or configuration is invalid.
// Analyzers must register themselves using RegisterAnalyzer() in their init() functions.
func createAnalyzer(cfg *LLMConfig) BannerAnalyzer {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	// Get analyzer from registry
	factory := GetAnalyzerFactory(cfg.Provider)
	if factory == nil {
		return nil
	}

	return factory(cfg)
}

// BuildPrompt constructs the LLM prompt for banner analysis
func BuildPrompt(protocol, banner string) string {
	return `You are analyzing a service banner for penetration testing.

Protocol: ` + protocol + `
Banner (sanitized):
"""
` + banner + `
"""

Task: Suggest 3-4 likely default passwords for this specific service based on:
1. Vendor/product name in banner
2. Version numbers
3. Common defaults for this product

Return ONLY a JSON array of passwords, nothing else:
["password1", "password2", "password3"]

Rules:
- Passwords must be realistic defaults (not random)
- Max 32 characters each
- Alphanumeric + common symbols only
- NO commentary, NO explanations
`
}

// SanitizeBanner removes control chars and limits length to prevent prompt injection
func SanitizeBanner(banner string) string {
	// 1. Remove null bytes
	cleaned := strings.ReplaceAll(banner, "\x00", "")

	// 2. Remove ANSI escape codes
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	cleaned = ansiRegex.ReplaceAllString(cleaned, "")

	// 3. Remove triple quotes (prevent prompt escape)
	cleaned = strings.ReplaceAll(cleaned, `"""`, "")

	// 4. Limit length
	if len(cleaned) > MaxBannerLength {
		cleaned = cleaned[:MaxBannerLength]
	}

	return cleaned
}

// ValidateSuggestions ensures LLM output is safe
func ValidateSuggestions(passwords []string) []string {
	valid := []string{}

	for _, pwd := range passwords {
		// 1. Length check
		if pwd == "" || len(pwd) > MaxPasswordLength {
			continue
		}

		// 2. Character whitelist (alphanumeric + common symbols)
		if !IsValidPassword(pwd) {
			continue
		}

		valid = append(valid, pwd)
		if len(valid) >= 4 {
			break // Max 4 suggestions
		}
	}

	return valid
}

// IsValidPassword checks for safe characters
func IsValidPassword(pwd string) bool {
	// Allow: a-zA-Z0-9 and common symbols: !@#$%^&*()-_=+[]{}
	allowedPattern := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}]+$`)
	return allowedPattern.MatchString(pwd)
}
