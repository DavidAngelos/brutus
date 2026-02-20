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

func loadPasswords(inline, file string, inlineFlagSet bool) ([]string, error) {
	var passwords []string

	// Load from inline flag
	if inlineFlagSet {
		passwords = append(passwords, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("opening password file: %w", err)
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
			return nil, fmt.Errorf("reading password file: %w", scanErr)
		}
	}

	return passwords, nil
}

func loadUsernames(inline, file string, inlineFlagSet bool) ([]string, error) {
	var usernames []string

	// Load from inline flag
	if inlineFlagSet {
		usernames = append(usernames, strings.Split(inline, ",")...)
	}

	// Load from file
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("opening username file: %w", err)
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			// Skip comments and empty lines
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			usernames = append(usernames, trimmed)
		}

		scanErr := scanner.Err()
		f.Close()

		if scanErr != nil {
			return nil, fmt.Errorf("reading username file: %w", scanErr)
		}
	}

	return usernames, nil
}

func loadKey(keyFile string) ([][]byte, error) {
	if keyFile == "" {
		return nil, nil
	}

	// Check file size to prevent OOM from excessively large files
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, fmt.Errorf("accessing key file %s: %w", keyFile, err)
	}
	const maxKeyFileSize = 1 << 20 // 1MB - generous limit for SSH/TLS keys
	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("key file %s is %d bytes (max %d bytes)", keyFile, info.Size(), maxKeyFileSize)
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", keyFile, err)
	}

	return [][]byte{key}, nil
}
