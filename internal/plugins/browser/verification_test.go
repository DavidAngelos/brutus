// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"testing"
)

func TestVerifyLogin_URLChange(t *testing.T) {
	before := VerificationState{
		URL:  "http://192.168.1.1/login",
		HTML: `<input type="password">`,
	}

	after := VerificationState{
		URL:  "http://192.168.1.1/dashboard",
		HTML: `<h1>Welcome Admin</h1>`,
	}

	result := VerifyLogin(before, after)

	if !result.Success {
		t.Errorf("Expected success=true, reason: %s", result.Reason)
	}
}

func TestVerifyLogin_ErrorMessage(t *testing.T) {
	before := VerificationState{
		URL:  "http://192.168.1.1/login",
		HTML: `<input type="password">`,
	}

	after := VerificationState{
		URL:  "http://192.168.1.1/login",
		HTML: `<div class="error">Invalid password</div><input type="password">`,
	}

	result := VerifyLogin(before, after)

	if result.Success {
		t.Error("Expected success=false for error message")
	}

	if result.Reason != "error_message_detected" {
		t.Errorf("Expected reason='error_message_detected', got '%s'", result.Reason)
	}
}

func TestVerifyLogin_FormDisappeared(t *testing.T) {
	before := VerificationState{
		URL:  "http://192.168.1.1/",
		HTML: `<form><input type="password" id="pwd"></form>`,
	}

	after := VerificationState{
		URL:  "http://192.168.1.1/",
		HTML: `<h1>Dashboard</h1><p>Logged in as admin</p>`,
	}

	result := VerifyLogin(before, after)

	if !result.Success {
		t.Errorf("Expected success=true when form disappears, reason: %s", result.Reason)
	}
}

func TestVerifyLogin_SameState(t *testing.T) {
	before := VerificationState{
		URL:  "http://192.168.1.1/login",
		HTML: `<input type="password">`,
	}

	after := VerificationState{
		URL:  "http://192.168.1.1/login",
		HTML: `<input type="password">`,
	}

	result := VerifyLogin(before, after)

	if result.Success {
		t.Error("Expected success=false when state unchanged")
	}
}

func TestDetectErrorMessage(t *testing.T) {
	testCases := []struct {
		html     string
		hasError bool
	}{
		{`<div>Invalid password</div>`, true},
		{`<span class="error">Login failed</span>`, true},
		{`<p>incorrect credentials</p>`, true},
		{`<div>Authentication error</div>`, false}, // "error" alone is too common
		{`<h1>Welcome</h1>`, false},
		{`<p>Please enter password</p>`, false},
	}

	for _, tc := range testCases {
		result := detectErrorMessage(tc.html)
		if result != tc.hasError {
			t.Errorf("detectErrorMessage(%q) = %v, want %v", tc.html, result, tc.hasError)
		}
	}
}
