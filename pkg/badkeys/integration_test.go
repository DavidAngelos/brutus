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
	"testing"
)

func TestNewSSHConfig(t *testing.T) {
	config := NewSSHConfig("10.0.0.50:22")

	if config.Target != "10.0.0.50:22" {
		t.Errorf("expected target '10.0.0.50:22', got %q", config.Target)
	}

	if config.Protocol != "ssh" {
		t.Errorf("expected protocol 'ssh', got %q", config.Protocol)
	}

	if len(config.Usernames) == 0 {
		t.Error("expected usernames to be populated")
	}

	if len(config.Keys) == 0 {
		t.Error("expected keys to be populated")
	}

	// Should include common usernames
	hasRoot := false
	hasVagrant := false
	for _, u := range config.Usernames {
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

func TestNewSSHConfigForProduct(t *testing.T) {
	config := NewSSHConfigForProduct("10.0.0.50:22", "vagrant")

	if config.Target != "10.0.0.50:22" {
		t.Errorf("expected target '10.0.0.50:22', got %q", config.Target)
	}

	if len(config.Keys) == 0 {
		t.Error("expected vagrant keys to be populated")
	}

	// Vagrant-specific usernames should be present
	hasVagrant := false
	for _, u := range config.Usernames {
		if u == "vagrant" {
			hasVagrant = true
			break
		}
	}

	if !hasVagrant {
		t.Error("expected 'vagrant' in usernames for vagrant product")
	}
}

func TestNewSSHConfigForNonexistentProduct(t *testing.T) {
	// Should fallback to all credentials
	config := NewSSHConfigForProduct("10.0.0.50:22", "nonexistent-product")

	if len(config.Keys) == 0 {
		t.Error("expected fallback to all keys for unknown product")
	}
}

func TestNewSSHConfigWithPasswords(t *testing.T) {
	usernames := []string{"testuser"}
	passwords := []string{"testpass"}

	config := NewSSHConfigWithPasswords("10.0.0.50:22", usernames, passwords)

	// Should have both provided usernames and bad key usernames
	hasTestUser := false
	hasRoot := false
	for _, u := range config.Usernames {
		if u == "testuser" {
			hasTestUser = true
		}
		if u == "root" {
			hasRoot = true
		}
	}

	if !hasTestUser {
		t.Error("expected provided 'testuser' in usernames")
	}
	if !hasRoot {
		t.Error("expected 'root' from bad keys in usernames")
	}

	// Should have passwords
	if len(config.Passwords) != 1 || config.Passwords[0] != "testpass" {
		t.Error("expected passwords to be preserved")
	}

	// Should have keys
	if len(config.Keys) == 0 {
		t.Error("expected keys to be populated")
	}
}

func TestGetSSHKeyCredentials(t *testing.T) {
	creds := GetSSHKeyCredentials()

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	for _, cred := range creds {
		if cred.Username == "" {
			t.Error("credential has empty username")
		}
		if len(cred.Key) == 0 {
			t.Error("credential has empty key")
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	config := NewSSHConfig("10.0.0.50:22")

	// Check default values
	if config.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}

	if config.Threads == 0 {
		t.Error("expected non-zero threads")
	}

	if !config.StopOnSuccess {
		t.Error("expected StopOnSuccess to be true by default")
	}
}

// TestKeyDeduplication verifies that duplicate keys are removed
func TestKeyDeduplication(t *testing.T) {
	config := NewSSHConfig("10.0.0.50:22")

	// Check for duplicates
	keySet := make(map[string]int)
	for _, key := range config.Keys {
		keyStr := string(key)
		keySet[keyStr]++
	}

	for keyStr, count := range keySet {
		if count > 1 {
			t.Errorf("found duplicate key (%d occurrences), first 50 chars: %s...",
				count, keyStr[:min(50, len(keyStr))])
		}
	}
}
