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
	"fmt"
	"os"
	"strings"
)

func loadPasswords(inline, file string, inlineFlagSet bool) []string {
	var passwords []string

	// Load from inline flag
	if inlineFlagSet {
		passwords = append(passwords, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening password file: %v\n", err)
			os.Exit(1)
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			// Skip comments
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			// Support <EMPTY> marker for empty passwords
			if trimmed == "<EMPTY>" {
				passwords = append(passwords, "")
				continue
			}
			// Include all non-comment lines (empty lines = empty passwords)
			passwords = append(passwords, trimmed)
		}

		scanErr := scanner.Err()
		f.Close()

		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", scanErr)
			os.Exit(1)
		}
	}

	return passwords
}

func loadKey(keyFile string) [][]byte {
	if keyFile == "" {
		return nil
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file %s: %v\n", keyFile, err)
		os.Exit(1)
	}

	return [][]byte{key}
}
