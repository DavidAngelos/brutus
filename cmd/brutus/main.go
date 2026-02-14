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


