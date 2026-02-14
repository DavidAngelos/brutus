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
	"runtime"
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
func printTargetInfo(target, protocol string, base *baseConfigOptions) {
	useColor := base.useColor

	// AI discovery modes - browser uses Vision+Perplexity, HTTP uses Perplexity for Basic Auth
	isBrowserAI := protocol == "browser"
	isHTTPAI := (protocol == "http" || protocol == "https") && base.aiMode && len(base.aiResearchedCreds) > 0
	isAIMode := isBrowserAI || isHTTPAI

	switch {
	case useColor:
		fmt.Printf("\n%s%s %sTarget Information%s\n", ColorCyan, SymbolInfo, ColorBold, ColorReset)
		fmt.Printf("  %sTarget:%s      %s\n", ColorCyan, ColorReset, target)
		fmt.Printf("  %sProtocol:%s    %s\n", ColorCyan, ColorReset, protocol)
		switch {
		case isBrowserAI:
			fmt.Printf("  %sCredentials:%s %sAI Discovery (Claude Vision + Perplexity)%s\n", ColorCyan, ColorReset, ColorPurple, ColorReset)
		case isHTTPAI:
			fmt.Printf("  %sCredentials:%s %sAI Discovery (Perplexity) + admin:admin%s\n", ColorCyan, ColorReset, ColorPurple, ColorReset)
		default:
			fmt.Printf("  %sUsers:%s       %d\n", ColorCyan, ColorReset, len(base.usernames))
			fmt.Printf("  %sPasswords:%s   %d\n", ColorCyan, ColorReset, len(base.passwords))
			if len(base.keys) > 0 {
				fmt.Printf("  %sSSH Keys:%s    %d\n", ColorCyan, ColorReset, len(base.keys))
			}
		}
		if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
			fmt.Printf("  %sLLM:%s         %s%s enabled%s\n", ColorCyan, ColorReset, ColorPurple, base.llmConfig.Provider, ColorReset)
		} else if !isAIMode {
			fmt.Printf("  %sLLM:%s         %sdisabled%s\n", ColorCyan, ColorReset, ColorDim, ColorReset)
		}
		fmt.Printf("  %sThreads:%s     %d\n", ColorCyan, ColorReset, base.threads)
		fmt.Printf("\n")
	default:
		fmt.Printf("\n%s Target Information\n", SymbolInfo)
		fmt.Printf("  Target:      %s\n", target)
		fmt.Printf("  Protocol:    %s\n", protocol)
		switch {
		case isBrowserAI:
			fmt.Printf("  Credentials: AI Discovery (Claude Vision + Perplexity)\n")
		case isHTTPAI:
			fmt.Printf("  Credentials: AI Discovery (Perplexity) + admin:admin\n")
		default:
			fmt.Printf("  Users:       %d\n", len(base.usernames))
			fmt.Printf("  Passwords:   %d\n", len(base.passwords))
			if len(base.keys) > 0 {
				fmt.Printf("  SSH Keys:    %d\n", len(base.keys))
			}
		}
		if base.llmConfig != nil && base.llmConfig.Enabled && !isAIMode {
			fmt.Printf("  LLM:         %s enabled\n", base.llmConfig.Provider)
		} else if !isAIMode {
			fmt.Printf("  LLM:         disabled\n")
		}
		fmt.Printf("  Threads:     %d\n", base.threads)
		fmt.Printf("\n")
	}
}
