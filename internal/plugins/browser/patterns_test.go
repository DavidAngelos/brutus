// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"strings"
	"testing"
)

// TestLoginErrorPatterns verifies error patterns exist and are lowercase
func TestLoginErrorPatterns(t *testing.T) {
	if len(LoginErrorPatterns) == 0 {
		t.Fatal("LoginErrorPatterns should not be empty")
	}

	// All patterns must be lowercase (for case-insensitive matching)
	for i, pattern := range LoginErrorPatterns {
		if strings.ToLower(pattern) != pattern {
			t.Errorf("Pattern %d should be lowercase: %q", i, pattern)
		}
	}

	// Verify key patterns from BOTH files are present
	mustHave := []string{
		"invalid password",
		"incorrect credentials",
		"bad credentials",
		"authentication failed",
		`class="error"`,
		`class='error'`,
		`id="error"`,
	}

	for _, required := range mustHave {
		found := false
		for _, pattern := range LoginErrorPatterns {
			if pattern == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing required error pattern: %q", required)
		}
	}
}

// TestLoginSuccessPatterns verifies success patterns exist and are lowercase
func TestLoginSuccessPatterns(t *testing.T) {
	if len(LoginSuccessPatterns) == 0 {
		t.Fatal("LoginSuccessPatterns should not be empty")
	}

	// All patterns must be lowercase
	for i, pattern := range LoginSuccessPatterns {
		if strings.ToLower(pattern) != pattern {
			t.Errorf("Pattern %d should be lowercase: %q", i, pattern)
		}
	}

	// Verify key patterns from BOTH files are present
	mustHave := []string{
		"logout",
		"dashboard",
		"welcome",
		"logged in",
		"my account",
		"configuration",
		"settings",
		"system status",
	}

	for _, required := range mustHave {
		found := false
		for _, pattern := range LoginSuccessPatterns {
			if pattern == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing required success pattern: %q", required)
		}
	}
}

// TestURLSuccessPaths verifies URL path patterns exist and start with /
func TestURLSuccessPaths(t *testing.T) {
	if len(URLSuccessPaths) == 0 {
		t.Fatal("URLSuccessPaths should not be empty")
	}

	// All paths must start with /
	for i, path := range URLSuccessPaths {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("Path %d should start with /: %q", i, path)
		}
	}

	// Verify key paths from verification.go are present
	mustHave := []string{
		"/dashboard",
		"/admin",
		"/home",
		"/main",
		"/status",
		"/welcome",
	}

	for _, required := range mustHave {
		found := false
		for _, path := range URLSuccessPaths {
			if path == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing required URL path: %q", required)
		}
	}
}

// TestPatternUnion verifies we have UNION of both files (not lost patterns)
func TestPatternUnion(t *testing.T) {
	// browser.go had "device status" - must be present
	found := false
	for _, pattern := range LoginSuccessPatterns {
		if pattern == "device status" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Lost pattern from browser.go: 'device status'")
	}

	// verification.go had "logged in" - must be present
	found = false
	for _, pattern := range LoginSuccessPatterns {
		if pattern == "logged in" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Lost pattern from verification.go: 'logged in'")
	}

	// verification.go had class="error" - must be present
	found = false
	for _, pattern := range LoginErrorPatterns {
		if pattern == `class="error"` {
			found = true
			break
		}
	}
	if !found {
		t.Error("Lost pattern from verification.go: 'class=\"error\"'")
	}
}
