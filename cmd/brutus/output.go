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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func outputHuman(results []brutus.Result, useColor, quiet bool) {
	validCount := 0
	invalidCount := 0
	errorCount := 0

	for i := range results {
		r := &results[i]
		switch {
		case r.Success:
			validCount++
			if useColor {
				fmt.Printf("%s[+] VALID: %s %s:%s @ %s (%s)%s\n",
					ColorGreen, r.Protocol, r.Username, r.Password, r.Target, r.Duration, ColorReset)
				if r.LLMSuggested {
					fmt.Printf("    %s(LLM-suggested)%s\n", ColorPurple, ColorReset)
				}
			} else {
				fmt.Printf("[+] VALID: %s %s:%s @ %s (%s)\n",
					r.Protocol, r.Username, r.Password, r.Target, r.Duration)
				if r.LLMSuggested {
					fmt.Printf("    (LLM-suggested)\n")
				}
			}
		case r.Error != nil:
			errorCount++
			if !quiet && errorCount <= 5 {
				if useColor {
					fmt.Printf("%s%s ERROR:%s %s:%s @ %s - %v%s\n",
						ColorRed, SymbolError, ColorReset, r.Username, r.Password, r.Target, r.Error, ColorReset)
				} else {
					fmt.Printf("[-] ERROR: %s:%s @ %s - %v\n",
						r.Username, r.Password, r.Target, r.Error)
				}
			}
		default:
			invalidCount++
		}
	}

	// Summary (skip in quiet mode unless there are valid credentials)
	if !quiet || validCount > 0 {
		if useColor {
			fmt.Printf("\n%sResults Summary%s\n", ColorBold, ColorReset)
			if validCount > 0 {
				fmt.Printf("  %sValid:%s     %d\n", ColorGreen, ColorReset, validCount)
			}
			if invalidCount > 0 {
				fmt.Printf("  %sInvalid:%s   %d\n", ColorDim, ColorReset, invalidCount)
			}
			if errorCount > 0 {
				fmt.Printf("  %sErrors:%s    %d\n", ColorRed, ColorReset, errorCount)
			}
			fmt.Printf("  %sTotal:%s     %d\n", ColorCyan, ColorReset, len(results))
		} else {
			fmt.Printf("Results: %d valid, %d invalid, %d errors (total: %d)\n",
				validCount, invalidCount, errorCount, len(results))
		}

		if errorCount > 5 {
			if useColor {
				fmt.Printf("\n%s%s Suppressed %d additional errors%s\n", ColorYellow, SymbolWarning, errorCount-5, ColorReset)
			} else {
				fmt.Printf("(Suppressed %d additional errors)\n", errorCount-5)
			}
		}
	}
}

// outputValidOnly prints only successful credentials (for pipeline/large-scale scanning)
func outputValidOnly(results []brutus.Result, useColor bool) {
	for i := range results {
		r := &results[i]
		if r.Success {
			// Simple, parseable format: protocol username:password@target or protocol username:key@target
			cred := r.Username
			if r.Password != "" {
				cred += ":" + r.Password
			} else if len(r.Key) > 0 {
				cred += ":key"
			}
			if useColor {
				fmt.Printf("%s%s %s@%s%s\n", ColorGreen, r.Protocol, cred, r.Target, ColorReset)
			} else {
				fmt.Printf("%s %s@%s\n", r.Protocol, cred, r.Target)
			}
		}
	}
}

// outputJSONL streams successful results as JSONL (one JSON object per line)
// This matches the output format of naabu and fingerprintx for easy piping
func outputJSONL(w io.Writer, results []brutus.Result) {
	type JSONResult struct {
		Protocol     string `json:"protocol"`
		Target       string `json:"target"`
		Username     string `json:"username"`
		Password     string `json:"password,omitempty"`
		Key          bool   `json:"key,omitempty"`
		Duration     string `json:"duration"`
		Banner       string `json:"banner,omitempty"`
		LLMSuggested bool   `json:"llm_suggested,omitempty"`
	}

	enc := json.NewEncoder(w)
	for i := range results {
		r := &results[i]
		if !r.Success {
			continue // Only output successful auths
		}
		jr := JSONResult{
			Protocol:     r.Protocol,
			Target:       r.Target,
			Username:     r.Username,
			Password:     r.Password,
			Key:          len(r.Key) > 0,
			Duration:     r.Duration.String(),
			Banner:       r.Banner,
			LLMSuggested: r.LLMSuggested,
		}
		if err := enc.Encode(jr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	}
}
