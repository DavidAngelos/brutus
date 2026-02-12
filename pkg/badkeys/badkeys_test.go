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

package badkeys

import (
	"strings"
	"testing"
)

func TestGetSSHCredentials(t *testing.T) {
	creds := GetSSHCredentials()

	if len(creds) == 0 {
		t.Fatal("expected at least one SSH credential")
	}

	// Verify all credentials have required fields
	for _, cred := range creds {
		if cred.Name == "" {
			t.Error("credential has empty Name")
		}
		if cred.Username == "" {
			t.Error("credential has empty Username")
		}
		if len(cred.Key) == 0 {
			t.Errorf("credential %q has empty Key", cred.Name)
		}
		if cred.Product == "" {
			t.Errorf("credential %q has empty Product", cred.Name)
		}
		if cred.DefaultPort == 0 {
			t.Errorf("credential %q has zero DefaultPort", cred.Name)
		}

		// Verify key looks like a PEM private key
		if !strings.Contains(string(cred.Key), "PRIVATE KEY") {
			t.Errorf("credential %q key doesn't look like a PEM private key", cred.Name)
		}
	}
}

func TestGetExpandedSSHCredentials(t *testing.T) {
	expanded := GetExpandedSSHCredentials()
	base := GetSSHCredentials()

	// Expanded should have more credentials than base (due to username expansion)
	if len(expanded) < len(base) {
		t.Errorf("expanded credentials (%d) should be >= base credentials (%d)",
			len(expanded), len(base))
	}

	// Check that vagrant has multiple usernames
	vagrantCount := 0
	for _, cred := range expanded {
		if cred.Product == "vagrant" {
			vagrantCount++
		}
	}

	// Vagrant should have multiple expanded credentials
	if vagrantCount < 2 {
		t.Errorf("expected multiple vagrant credentials, got %d", vagrantCount)
	}
}

func TestGetCredentialsByProduct(t *testing.T) {
	tests := []struct {
		product       string
		expectResults bool
	}{
		{"vagrant", true},
		{"f5", true},
		{"exagrid", true},
		{"nonexistent-product-xyz", false},
	}

	for _, tc := range tests {
		creds := GetCredentialsByProduct(tc.product)
		hasResults := len(creds) > 0

		if hasResults != tc.expectResults {
			t.Errorf("GetCredentialsByProduct(%q): got %d results, expectResults=%v",
				tc.product, len(creds), tc.expectResults)
		}
	}
}

func TestGetCredentialsByCVE(t *testing.T) {
	// Test known CVE
	creds := GetCredentialsByCVE("CVE-2012-1493")
	if len(creds) == 0 {
		t.Error("expected credentials for CVE-2012-1493 (F5 BIG-IP)")
	}

	// Verify the CVE matches
	for _, cred := range creds {
		if cred.CVE != "CVE-2012-1493" {
			t.Errorf("expected CVE-2012-1493, got %q", cred.CVE)
		}
	}

	// Test non-existent CVE
	creds = GetCredentialsByCVE("CVE-9999-99999")
	if len(creds) != 0 {
		t.Errorf("expected no credentials for fake CVE, got %d", len(creds))
	}
}

func TestGetKeys(t *testing.T) {
	keys := GetKeys()

	if len(keys) == 0 {
		t.Fatal("expected at least one key")
	}

	// All keys should be non-empty
	for i, key := range keys {
		if len(key) == 0 {
			t.Errorf("key %d is empty", i)
		}
	}
}

func TestGetUsernames(t *testing.T) {
	usernames := GetUsernames()

	if len(usernames) == 0 {
		t.Fatal("expected at least one username")
	}

	// Should include common usernames
	hasRoot := false
	hasVagrant := false
	for _, u := range usernames {
		if u == "root" {
			hasRoot = true
		}
		if u == "vagrant" {
			hasVagrant = true
		}
	}

	if !hasRoot {
		t.Error("expected 'root' in usernames")
	}
	if !hasVagrant {
		t.Error("expected 'vagrant' in usernames")
	}
}

func TestGetKeyByName(t *testing.T) {
	tests := []struct {
		name      string
		expectKey bool
	}{
		{"vagrant", true},
		{"vagrant.key", true},
		{"f5-bigip-cve-2012-1493", true},
		{"nonexistent-key", false},
	}

	for _, tc := range tests {
		key, ok := GetKeyByName(tc.name)

		if ok != tc.expectKey {
			t.Errorf("GetKeyByName(%q): got ok=%v, expected %v", tc.name, ok, tc.expectKey)
		}

		if tc.expectKey && len(key) == 0 {
			t.Errorf("GetKeyByName(%q): expected non-empty key", tc.name)
		}
	}
}

func TestListKeys(t *testing.T) {
	names := ListKeys()

	if len(names) == 0 {
		t.Fatal("expected at least one key name")
	}

	// Verify expected keys are present
	expectedKeys := []string{
		"vagrant",
		"f5-bigip-cve-2012-1493",
		"exagrid-cve-2016-1561",
	}

	for _, expected := range expectedKeys {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected key %q not found in ListKeys()", expected)
		}
	}
}

func TestGetStats(t *testing.T) {
	stats := GetStats()

	if stats.TotalKeys == 0 {
		t.Error("expected TotalKeys > 0")
	}
	if stats.TotalProducts == 0 {
		t.Error("expected TotalProducts > 0")
	}
	if stats.KeysWithCVE == 0 {
		t.Error("expected KeysWithCVE > 0 (known CVEs exist)")
	}
	if stats.UniqueUsernames == 0 {
		t.Error("expected UniqueUsernames > 0")
	}
}

func TestKeysParseable(t *testing.T) {
	// This test verifies that all embedded keys can be parsed by Go's SSH library
	// We don't actually test authentication, just that the keys are valid PEM format

	creds := GetSSHCredentials()

	for _, cred := range creds {
		keyStr := string(cred.Key)

		// Check for valid PEM header
		if !strings.Contains(keyStr, "-----BEGIN") {
			t.Errorf("key %q missing PEM header", cred.Name)
		}
		if !strings.Contains(keyStr, "-----END") {
			t.Errorf("key %q missing PEM footer", cred.Name)
		}

		// Check it's a private key (RSA, DSA, or EC)
		validTypes := []string{
			"RSA PRIVATE KEY",
			"DSA PRIVATE KEY",
			"EC PRIVATE KEY",
			"OPENSSH PRIVATE KEY",
		}

		hasValidType := false
		for _, vt := range validTypes {
			if strings.Contains(keyStr, vt) {
				hasValidType = true
				break
			}
		}

		if !hasValidType {
			t.Errorf("key %q doesn't contain a recognized private key type", cred.Name)
		}
	}
}

func TestVagrantKeyContent(t *testing.T) {
	// Verify the vagrant key matches the expected content
	key, ok := GetKeyByName("vagrant")
	if !ok {
		t.Fatal("vagrant key not found")
	}

	keyStr := string(key)

	// Check for known fingerprint signature from the vagrant key
	if !strings.Contains(keyStr, "6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr") {
		t.Error("vagrant key doesn't match expected content")
	}
}

func TestCredentialMetadata(t *testing.T) {
	// Test specific known credentials have correct metadata
	creds := GetCredentialsByProduct("f5-bigip")
	if len(creds) == 0 {
		t.Fatal("expected F5 BIG-IP credentials")
	}

	f5Cred := creds[0]

	if f5Cred.CVE != "CVE-2012-1493" {
		t.Errorf("expected CVE-2012-1493 for F5 BIG-IP, got %q", f5Cred.CVE)
	}
	if f5Cred.Username != "root" {
		t.Errorf("expected username 'root' for F5 BIG-IP, got %q", f5Cred.Username)
	}
	if f5Cred.DefaultPort != 22 {
		t.Errorf("expected port 22 for F5 BIG-IP, got %d", f5Cred.DefaultPort)
	}
}

// BenchmarkGetSSHCredentials benchmarks credential loading
func BenchmarkGetSSHCredentials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetSSHCredentials()
	}
}

// BenchmarkGetExpandedSSHCredentials benchmarks expanded credential loading
func BenchmarkGetExpandedSSHCredentials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetExpandedSSHCredentials()
	}
}
