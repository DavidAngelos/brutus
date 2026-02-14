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
	"fmt"
	"os"
	"runtime"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// ANSI Color Constants
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorDim    = "\033[2m"
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
)

// Output symbols (ASCII for compatibility)
const (
	SymbolSuccess = "[+]"
	SymbolError   = "[-]"
	SymbolWarning = "[!]"
	SymbolInfo    = "[*]"
	SymbolLLM     = "[AI]"
)

// ASCII Banner
const banner = `
    ____  ____  __  ____________  _______
   / __ )/ __ \/ / / /_  __/ / / / ___/
  / __  / /_/ / / / / / / / / / /\__ \
 / /_/ / _, _/ /_/ / / / / /_/ /___/ /
/_____/_/ |_|\____/ /_/  \____//____/

 Et tu, Brute?
 Praetorian Security, Inc.
`

// printBanner displays the ASCII art banner with color
func printBanner(useColor bool) {
	if useColor {
		fmt.Printf("%s%s%s%s\n", ColorBold, ColorRed, banner, ColorReset)
	} else {
		fmt.Printf("%s\n", banner)
	}
}

// printVersion displays version information with color
func printVersion(useColor bool) {
	switch {
	case useColor:
		fmt.Printf("%sBrutus %s%s\n", ColorBold, Version, ColorReset)
		fmt.Printf("  %sBuild time:%s %s\n", ColorCyan, ColorReset, BuildTime)
		fmt.Printf("  %sCommit:%s     %s\n", ColorCyan, ColorReset, CommitSHA)
		fmt.Printf("  %sGo version:%s %s\n", ColorCyan, ColorReset, runtime.Version())
		fmt.Printf("  %sOS/Arch:%s    %s/%s\n", ColorCyan, ColorReset, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Printf("Brutus %s\n", Version)
		fmt.Printf("  Build time: %s\n", BuildTime)
		fmt.Printf("  Commit:     %s\n", CommitSHA)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	}
}

// printTargetInfo displays target configuration details
func printTargetInfo(target, protocol string, base *baseConfigOptions, aiCreds []brutus.Credential) {
	useColor := base.useColor

	isBrowserAI := protocol == "browser"
	isHTTPAI := (protocol == "http" || protocol == "https") && base.aiMode && len(aiCreds) > 0
	isAIMode := isBrowserAI || isHTTPAI

	fmt.Printf("\n%s %s\n", dim(useColor, SymbolInfo), heading(useColor, "Target Information"))
	fmt.Printf("  Target:      %s\n", target)
	fmt.Printf("  Protocol:    %s\n", protocol)

	switch {
	case isBrowserAI:
		fmt.Printf("  Credentials: %s\n", highlight(useColor, "AI Discovery (Claude Vision + Perplexity)"))
	case isHTTPAI:
		fmt.Printf("  Credentials: %s\n", highlight(useColor, "AI Discovery (Perplexity) + admin:admin"))
	default:
		fmt.Printf("  Users:       %d\n", len(base.usernames))
		fmt.Printf("  Passwords:   %d\n", len(base.passwords))
		if len(base.keys) > 0 {
			fmt.Printf("  SSH Keys:    %d\n", len(base.keys))
		}
	}

	if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
		fmt.Printf("  LLM:         %s\n", highlight(useColor, base.llmConfig.Provider+" enabled"))
	} else if !isAIMode {
		fmt.Printf("  LLM:         %s\n", dim(useColor, "disabled"))
	}
	fmt.Printf("  Threads:     %d\n", base.threads)
	fmt.Println()
}

// logVerbose writes a formatted verbose message to stderr when verbose is true.
func logVerbose(verbose bool, format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}

// heading returns text formatted as a bold section heading.
func heading(useColor bool, text string) string {
	if useColor {
		return ColorBold + text + ColorReset
	}
	return text
}

// highlight returns text formatted with purple/highlight color.
func highlight(useColor bool, text string) string {
	if useColor {
		return ColorPurple + text + ColorReset
	}
	return text
}

// dim returns text formatted with dim/muted color.
func dim(useColor bool, text string) string {
	if useColor {
		return ColorDim + text + ColorReset
	}
	return text
}

// errMsg prints a colored error message to stderr.
func errMsg(useColor bool, format string, args ...any) {
	if useColor {
		fmt.Fprintf(os.Stderr, ColorRed+SymbolError+" Error: "+ColorReset+format+"\n", args...)
	} else {
		fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	}
}

// warnMsg prints a colored warning message to stderr.
func warnMsg(useColor bool, format string, args ...any) {
	if useColor {
		fmt.Fprintf(os.Stderr, ColorYellow+SymbolWarning+" Warning: "+ColorReset+format+"\n", args...)
	} else {
		fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
	}
}

// colorIf returns the ANSI escape code when useColor is true, empty string otherwise.
func colorIf(useColor bool, code string) string {
	if useColor {
		return code
	}
	return ""
}
