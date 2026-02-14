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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"

	// Import plugins and analyzers to register them
	_ "github.com/praetorian-inc/brutus/internal/analyzers"
	_ "github.com/praetorian-inc/brutus/internal/plugins"
	"github.com/praetorian-inc/brutus/internal/plugins/snmp"
)

// Version info - set by ldflags during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func main() {
	// Command-line flags
	target := flag.String("target", "", "Target host:port")
	showVersion := flag.Bool("version", false, "Show version information")
	protocol := flag.String("protocol", "", "Protocol to use (auto-detected from fingerprintx)")
	usernames := flag.String("u", "root,admin", "Comma-separated usernames")
	passwords := flag.String("p", "", "Comma-separated passwords")
	passwordFile := flag.String("P", "", "Password file (one per line)")
	keyFile := flag.String("k", "", "SSH private key file")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 10*time.Second, "Per-credential timeout")
	jsonOutput := flag.Bool("json", false, "JSON output format")
	outputFile := flag.String("o", "", "Output file for JSON results (default: stdout)")
	stopOnSuccess := flag.Bool("stop-on-success", true, "Stop after first valid credential")
	snmpTier := flag.String("snmp-tier", "default", "SNMP community string tier: default (20), extended (50), full (120)")
	rateLimit := flag.Float64("rate-limit", 0, "Max requests per second (0 = unlimited)")
	jitter := flag.Duration("jitter", 0, "Random delay variance for rate limiting (e.g., 100ms)")
	stdinMode := flag.Bool("stdin", false, "Read targets from stdin (fingerprintx JSON format)")
	maxAttempts := flag.Int("max-attempts", 0, "Max password attempts per user (0 = unlimited)")
	sprayMode := flag.Bool("spray", false, "Password spraying: try each password across all users")
	showBanner := flag.Bool("banner", true, "Show ASCII banner")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	quiet := flag.Bool("q", false, "Quiet mode - only show successful credentials")
	verbose := flag.Bool("v", false, "Verbose mode - show detailed progress to stderr")
	badkeys := flag.Bool("badkeys", true, "Test embedded bad SSH keys (rapid7/ssh-badkeys, vagrant)")
	noBadkeys := flag.Bool("no-badkeys", false, "Disable embedded bad key testing")
	verifyTLS := flag.Bool("verify-tls", false, "Require strict TLS certificate verification (default: disabled)")

	// Custom usage
	flag.Usage = customUsage

	// Browser plugin flags
	browserTimeout := flag.Duration("browser-timeout", 60*time.Second, "Total timeout for browser operations")
	browserTabs := flag.Int("browser-tabs", 3, "Number of concurrent browser tabs")
	browserVisible := flag.Bool("browser-visible", false, "Show browser window (demo mode)")
	useHTTPS := flag.Bool("https", false, "Use HTTPS for browser connections")
	aiMode := flag.Bool("experimental-ai", false, "Enable AI-powered credential detection for HTTP services (experimental)")
	aiVerify := flag.Bool("experimental-ai-verify", false, "Use Claude Vision to verify login success (more accurate but slower)")

	flag.Parse()

	// Track whether -p flag was explicitly set (to support empty passwords)
	passwordFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			passwordFlagSet = true
		}
	})

	// Detect terminal and configure colors
	useColor := !*noColor && isTerminal()

	// Show version and exit
	if *showVersion {
		printVersion(useColor)
		os.Exit(0)
	}

	// Auto-detect stdin mode: if stdin has data and no target specified, use stdin mode
	useStdin := *stdinMode || (*target == "" && hasStdinData())

	// Show banner (unless in JSON mode, stdin mode, or quiet mode)
	if *showBanner && !*jsonOutput && !useStdin && !*quiet && useColor {
		printBanner(useColor)
	}

	// AI mode validation - requires ANTHROPIC_API_KEY for Claude Vision
	// PERPLEXITY_API_KEY is optional for additional web search credential research
	var aiLLMConfig *brutus.LLMConfig
	if *aiMode {
		perplexityKey := os.Getenv("PERPLEXITY_API_KEY")
		anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

		if anthropicKey == "" {
			fmt.Fprintf(os.Stderr, "Error: --experimental-ai requires ANTHROPIC_API_KEY for Claude Vision (screenshot analysis)\n")
			fmt.Fprintf(os.Stderr, "       PERPLEXITY_API_KEY is optional for additional web search\n")
			os.Exit(1)
		}

		// Create LLM config - use Perplexity if available, otherwise just enable AI mode
		if perplexityKey != "" {
			aiLLMConfig = &brutus.LLMConfig{
				Enabled:  true,
				Provider: "perplexity",
				APIKey:   perplexityKey,
			}
		} else {
			// AI mode enabled but no Perplexity - Claude Vision will suggest credentials
			aiLLMConfig = &brutus.LLMConfig{
				Enabled:  true,
				Provider: "claude-vision",
				APIKey:   anthropicKey,
			}
		}
	}

	// Determine if badkeys should be used (--no-badkeys overrides --badkeys)
	useBadkeys := *badkeys && !*noBadkeys

	// Validate: -k requires explicit -u (not default usernames)
	if *keyFile != "" && *usernames == "root,admin" {
		fmt.Fprintf(os.Stderr, "Error: -k requires -u to specify which username(s) to test with the key\n")
		fmt.Fprintf(os.Stderr, "Example: brutus --target host:22 --protocol ssh -u vagrant -k mykey.pem\n")
		os.Exit(1)
	}

	// Setup JSON output writer (file or stdout)
	var jsonWriter io.Writer = os.Stdout
	var outputFileHandle *os.File
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		outputFileHandle = f
		jsonWriter = f
		// If -o is specified, imply --json
		*jsonOutput = true
	}
	// Helper to close output file if opened
	closeOutput := func() {
		if outputFileHandle != nil {
			outputFileHandle.Close()
		}
	}

	// Prepare common config options
	baseConfig := baseConfigOptions{
		usernames:        strings.Split(*usernames, ","),
		passwords:        loadPasswords(*passwords, *passwordFile, passwordFlagSet),
		keys:             loadKey(*keyFile),
		threads:          *threads,
		timeout:          *timeout,
		stopOnSuccess:    *stopOnSuccess,
		snmpTier:         *snmpTier,
		llmConfig:        aiLLMConfig,
		browserTimeout:   *browserTimeout,
		browserTabs:      *browserTabs,
		browserVisible:   *browserVisible,
		useHTTPS:         *useHTTPS,
		useColor:         useColor,
		quiet:            *quiet,
		verbose:          *verbose,
		useBadkeys:       useBadkeys,
		protocolOverride: *protocol,
		aiMode:           *aiMode,
		aiVerify:         *aiVerify,
		tlsMode:          determineTLSMode(*verifyTLS),
		rateLimit:        *rateLimit,
		jitter:           *jitter,
		maxAttempts:      *maxAttempts,
		sprayMode:        *sprayMode,
	}

	var allResults []brutus.Result
	var hasSuccess bool

	if useStdin {
		// Read targets from stdin (fingerprintx JSON)
		allResults, hasSuccess = runFromStdin(&baseConfig, *jsonOutput)
	} else {
		// Single target mode
		if *target == "" {
			if useColor {
				fmt.Fprintf(os.Stderr, "%s%sError:%s --target is required (or pipe data to stdin)\n\n%s", ColorBold, ColorRed, ColorReset, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: --target is required (or pipe data to stdin)\n\n")
			}
			flag.Usage()
			closeOutput()
			os.Exit(1)
		}

		// Require protocol for single target mode
		proto := *protocol
		if proto == "" {
			if baseConfig.useColor {
				fmt.Fprintf(os.Stderr, "%s%sError:%s --protocol is required when using --target\n", ColorBold, ColorRed, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: --protocol is required when using --target\n")
			}
			fmt.Fprintf(os.Stderr, "Example: brutus --target %s --protocol ssh\n", *target)
			closeOutput()
			os.Exit(1)
		}

		// AI mode for single target with HTTP protocol
		if baseConfig.aiMode && (proto == "http" || proto == "https") {
			useHTTPS := proto == "https"
			authType, banner := detectHTTPAuthTypeWithBanner(*target, useHTTPS, baseConfig.timeout, baseConfig.verbose)
			if authType == "basic" {
				if baseConfig.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s uses Basic Auth, using LLM analysis\n", *target)
				}
				if baseConfig.llmConfig != nil && baseConfig.llmConfig.Enabled {
					creds := researchCredentialsWithLLM(*target, banner, baseConfig.llmConfig, baseConfig.verbose)
					if len(creds) > 0 {
						baseConfig.aiResearchedCreds = creds
						if baseConfig.verbose {
							fmt.Fprintf(os.Stderr, "[verbose] LLM researched %d credential pairs for %s\n", len(creds), *target)
						}
					}
				}
			} else {
				proto = "browser"
				if baseConfig.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s appears form-based, using browser automation\n", *target)
				}
			}
		}

		// Print target info
		if !*jsonOutput && !*quiet {
			printTargetInfo(*target, proto, &baseConfig)
		}

		results, success := runSingleTarget(*target, proto, &baseConfig)
		allResults = results
		hasSuccess = success

		// Output for single-target mode
		if *jsonOutput {
			outputJSONL(jsonWriter, results)
		} else {
			outputHuman(results, useColor, *quiet)
		}
	}

	// Final JSON output for stdin mode
	if *jsonOutput && useStdin {
		outputJSONL(jsonWriter, allResults)
	}

	// Close output file and exit with appropriate code
	closeOutput()
	if !hasSuccess {
		os.Exit(1)
	}
}

// hasStdinData checks if stdin has data available (i.e., is being piped to)
func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	// Check if stdin is a pipe or has data
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// runFromStdin reads fingerprintx JSON from stdin and tests each target
func runFromStdin(base *baseConfigOptions, jsonOut bool) ([]brutus.Result, bool) {
	var allResults []brutus.Result
	hasSuccess := false

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse fingerprintx JSON
		var fpx FingerprintxResult
		if err := json.Unmarshal([]byte(line), &fpx); err != nil {
			if base.useColor {
				fmt.Fprintf(os.Stderr, "%s%s Warning:%s failed to parse JSON: %v%s\n", ColorYellow, SymbolWarning, ColorReset, err, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON: %v\n", err)
			}
			continue
		}

		// Determine protocol: use override if specified, otherwise map from fingerprintx
		var protocol string
		if base.protocolOverride != "" {
			protocol = base.protocolOverride
		} else {
			protocol = mapServiceToProtocol(fpx.Protocol)
			if protocol == "" {
				// Unsupported service, skip
				continue
			}
		}

		// Determine TLS mode for this specific target
		targetTLSMode := base.tlsMode
		if targetTLSMode == "disable" {
			if metadata, ok := fpx.Metadata["tls"]; ok {
				// If TLS is detected in metadata, auto-upgrade to skip-verify
				if tlsEnabled, ok := metadata.(bool); ok && tlsEnabled {
					targetTLSMode = "skip-verify"
					if base.verbose {
						fmt.Fprintf(os.Stderr, "[verbose] TLS detected in fingerprintx metadata, auto-upgrading to skip-verify mode\n")
					}
				}
			}
		}

		// Build target string
		target := fmt.Sprintf("%s:%d", fpx.IP, fpx.Port)

		// AI mode: For HTTP services, detect auth type and route appropriately
		if base.aiMode && (protocol == "http" || protocol == "https") {
			useHTTPS := protocol == "https"
			authType, banner := detectHTTPAuthTypeWithBanner(target, useHTTPS, base.timeout, base.verbose)
			if authType == "basic" {
				// HTTP Basic Auth detected - use LLM to research credentials
				if base.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s uses Basic Auth, using LLM analysis\n", target)
				}

				// Research credentials using LLM
				if base.llmConfig != nil && base.llmConfig.Enabled {
					creds := researchCredentialsWithLLM(target, banner, base.llmConfig, base.verbose)
					if len(creds) > 0 {
						// Add researched credentials to base config for this target
						base.aiResearchedCreds = creds
						if base.verbose {
							fmt.Fprintf(os.Stderr, "[verbose] LLM researched %d credential pairs for %s\n", len(creds), target)
						}
					}
				}
				// Keep http/https protocol
			} else {
				// No Basic Auth - likely form-based, use browser protocol
				if base.verbose {
					fmt.Fprintf(os.Stderr, "[verbose] AI mode: %s appears form-based, using browser automation\n", target)
				}
				protocol = "browser"
			}
		}

		// Temporarily set TLS mode for this target, then restore
		originalTLSMode := base.tlsMode
		base.tlsMode = targetTLSMode

		// Run against this target
		results, success := runSingleTarget(target, protocol, base)

		// Restore original TLS mode to prevent mutation across targets
		base.tlsMode = originalTLSMode
		allResults = append(allResults, results...)
		if success {
			hasSuccess = true
		}

		// Output valid credentials immediately (streaming for large-scale scans)
		if !jsonOut {
			outputValidOnly(results, base.useColor)
		}
	}

	if err := scanner.Err(); err != nil {
		if base.useColor {
			fmt.Fprintf(os.Stderr, "%s%s Error:%s reading stdin: %v%s\n", ColorRed, SymbolError, ColorReset, err, ColorReset)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		}
	}

	return allResults, hasSuccess
}

// runSingleTarget runs brutus against a single target
func runSingleTarget(target, protocol string, base *baseConfigOptions) ([]brutus.Result, bool) {
	config := &brutus.Config{
		Target:        target,
		Protocol:      protocol,
		Usernames:     base.usernames,
		Passwords:     base.passwords,
		Keys:          base.keys,
		UseDefaults:   true,
		NoBadkeys:     !base.useBadkeys,
		Threads:       base.threads,
		Timeout:       base.timeout,
		StopOnSuccess: base.stopOnSuccess,
		LLMConfig:     base.llmConfig,
		TLSMode:       base.tlsMode,
		RateLimit:     base.rateLimit,
		Jitter:        base.jitter,
		MaxAttempts:   base.maxAttempts,
		SprayMode:     base.sprayMode,
	}

	// Handle SNMP-specific tier selection (tiers are CLI-only, not in library defaults)
	if protocol == "snmp" && len(config.Passwords) == 0 {
		if !snmp.ValidateTier(base.snmpTier) {
			if base.useColor {
				fmt.Fprintf(os.Stderr, "%s%s Error:%s invalid --snmp-tier: %s (use: default, extended, full)%s\n",
					ColorRed, SymbolError, ColorReset, base.snmpTier, ColorReset)
			} else {
				fmt.Fprintf(os.Stderr, "Error: invalid --snmp-tier: %s (use: default, extended, full)\n", base.snmpTier)
			}
			return nil, false
		}
		config.Passwords = snmp.GetCommunityStrings(snmp.Tier(base.snmpTier))
	}

	// Handle HTTP with AI-researched credentials
	if (protocol == "http" || protocol == "https") && len(base.aiResearchedCreds) > 0 {
		// Clear default usernames/passwords - use only AI-discovered paired credentials
		config.Usernames = nil
		config.Passwords = nil

		// Add AI-researched credentials
		config.Credentials = append(config.Credentials, base.aiResearchedCreds...)

		// Add admin:admin as basic fallback
		config.Credentials = append(config.Credentials, brutus.Credential{
			Username: "admin",
			Password: "admin",
		})

		if base.verbose {
			fmt.Fprintf(os.Stderr, "[verbose] Using %d AI-researched credentials for HTTP (+ admin:admin fallback)\n", len(base.aiResearchedCreds))
		}

		// Disable LLM in config to prevent duplicate analysis in brutus.go
		config.LLMConfig = nil

		// Clear researched creds so they don't leak to next target
		base.aiResearchedCreds = nil
	}

	// Handle browser-specific configuration
	// Browser protocol requires AI mode - it's the AI-powered form authentication feature
	if protocol == "browser" {
		config.Threads = base.browserTabs
		config.Timeout = base.browserTimeout

		// Clear default usernames/passwords - browser uses AI-discovered paired credentials only
		config.Usernames = nil
		config.Passwords = nil

		// Use Claude Vision + Perplexity for credential research
		// Also get the configured browser plugin to use during brute force
		aiCreds, browserPlugin := researchBrowserCredentials(target, base)
		if len(aiCreds) > 0 {
			config.Credentials = append(config.Credentials, aiCreds...)
			if base.verbose {
				fmt.Fprintf(os.Stderr, "[verbose] AI researched %d credentials for browser\n", len(aiCreds))
			}
		}
		// Pass the configured plugin to Brute (so it has VisionAnalyzer, AIVerify, etc.)
		if browserPlugin != nil {
			config.Plugin = browserPlugin
		}
	}

	// Verbose: print config summary before starting
	if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Target: %s (protocol: %s)\n", target, protocol)
		fmt.Fprintf(os.Stderr, "[verbose] Paired credentials: %d, Usernames: %d, Passwords: %d, Keys: %d\n",
			len(config.Credentials), len(config.Usernames), len(config.Passwords), len(config.Keys))
		// Calculate total attempts
		totalAttempts := len(config.Credentials)
		if len(config.Passwords) > 0 {
			totalAttempts += len(config.Usernames) * len(config.Passwords)
		}
		if len(config.Keys) > 0 {
			totalAttempts += len(config.Usernames) * len(config.Keys)
		}
		fmt.Fprintf(os.Stderr, "[verbose] Total attempts: %d, Threads: %d, Timeout: %s\n",
			totalAttempts, config.Threads, config.Timeout)
		fmt.Fprintf(os.Stderr, "[verbose] Starting brute force...\n")
	}

	// Run brute force
	results, err := brutus.Brute(config)
	if err != nil {
		if base.useColor {
			fmt.Fprintf(os.Stderr, "%s%s Error:%s testing %s: %v%s\n", ColorRed, SymbolError, ColorReset, target, err, ColorReset)
		} else {
			fmt.Fprintf(os.Stderr, "Error testing %s: %v\n", target, err)
		}
		return nil, false
	}

	// Check for success
	hasSuccess := false
	successCount := 0
	for i := range results {
		if results[i].Success {
			hasSuccess = true
			successCount++
		}
	}

	// Verbose: print completion summary
	if base.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Completed: %d results, %d successful\n", len(results), successCount)
	}

	return results, hasSuccess
}

