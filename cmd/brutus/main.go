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

// setupAIConfig creates the LLM configuration for AI mode.
func setupAIConfig(aiMode bool, anthropicKey, perplexityKey string) *brutus.LLMConfig {
	if !aiMode {
		return nil
	}
	if anthropicKey == "" {
		fmt.Fprintf(os.Stderr, "Error: --experimental-ai requires ANTHROPIC_API_KEY for Claude Vision (screenshot analysis)\n")
		fmt.Fprintf(os.Stderr, "       PERPLEXITY_API_KEY is optional for additional web search\n")
		os.Exit(1)
	}
	if perplexityKey != "" {
		return &brutus.LLMConfig{Enabled: true, Provider: "perplexity", APIKey: perplexityKey}
	}
	return &brutus.LLMConfig{Enabled: true, Provider: "claude-vision", APIKey: anthropicKey}
}

// setupOutputWriter configures the JSON output writer and returns a cleanup function.
func setupOutputWriter(outputFile string, jsonOutput *bool) (io.Writer, func()) {
	if outputFile == "" {
		return os.Stdout, func() {}
	}
	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	*jsonOutput = true
	return f, func() { f.Close() }
}

// shouldShowBanner determines whether to display the ASCII art banner.
func shouldShowBanner(showBanner, jsonOutput, stdinMode, quiet, useColor bool) bool {
	return showBanner && !jsonOutput && !stdinMode && !quiet && useColor
}

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
	if shouldShowBanner(*showBanner, *jsonOutput, useStdin, *quiet, useColor) {
		printBanner(useColor)
	}

	// Read API keys once (used by AI mode and browser research)
	perplexityKey := os.Getenv("PERPLEXITY_API_KEY")
	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

	aiLLMConfig := setupAIConfig(*aiMode, anthropicKey, perplexityKey)

	// Determine if badkeys should be used (--no-badkeys overrides --badkeys)
	useBadkeys := *badkeys && !*noBadkeys

	// Validate: -k requires explicit -u (not default usernames)
	if *keyFile != "" && *usernames == "root,admin" {
		fmt.Fprintf(os.Stderr, "Error: -k requires -u to specify which username(s) to test with the key\n")
		fmt.Fprintf(os.Stderr, "Example: brutus --target host:22 --protocol ssh -u vagrant -k mykey.pem\n")
		os.Exit(1)
	}

	jsonWriter, closeOutput := setupOutputWriter(*outputFile, jsonOutput)

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
		anthropicKey:     anthropicKey,
		perplexityKey:    perplexityKey,
	}

	var allResults []brutus.Result
	var hasSuccess bool

	if useStdin {
		allResults, hasSuccess = runFromStdin(&baseConfig, *jsonOutput)
	} else {
		allResults, hasSuccess = runSingleTargetMode(*target, *protocol, &baseConfig, *jsonOutput, jsonWriter, closeOutput)
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

// runSingleTargetMode handles the single-target execution path.
func runSingleTargetMode(target, protocol string, baseConfig *baseConfigOptions, jsonOutput bool, jsonWriter io.Writer, closeOutput func()) ([]brutus.Result, bool) {
	if target == "" {
		errMsg(baseConfig.useColor, "--target is required (or pipe data to stdin)")
		flag.Usage()
		closeOutput()
		os.Exit(1)
	}

	if protocol == "" {
		errMsg(baseConfig.useColor, "--protocol is required when using --target")
		fmt.Fprintf(os.Stderr, "Example: brutus --target %s --protocol ssh\n", target)
		closeOutput()
		os.Exit(1)
	}

	// AI mode for single target with HTTP protocol
	var aiCreds []brutus.Credential
	if baseConfig.aiMode && (protocol == "http" || protocol == "https") {
		protocol, aiCreds = routeHTTPWithAI(target, protocol, baseConfig)
	}

	// Print target info
	if !jsonOutput && !baseConfig.quiet {
		printTargetInfo(target, protocol, baseConfig, aiCreds)
	}

	results, success := runSingleTarget(target, protocol, baseConfig.tlsMode, baseConfig, aiCreds)

	// Output for single-target mode
	if jsonOutput {
		outputJSONL(jsonWriter, results)
	} else {
		outputHuman(results, baseConfig.useColor, baseConfig.quiet)
	}

	return results, success
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


