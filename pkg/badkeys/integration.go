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
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// NewSSHConfig creates a brutus.Config pre-populated with all known bad SSH keys
// and their associated usernames for comprehensive SSH key brute forcing.
//
// The target should be in host:port format (e.g., "10.0.0.50:22").
// If only using default keys, this provides username:key combinations
// from rapid7/ssh-badkeys and hashicorp/vagrant.
//
// Example:
//
//	config := badkeys.NewSSHConfig("10.0.0.50:22")
//	results, err := brutus.Brute(config)
func NewSSHConfig(target string) *brutus.Config {
	creds := GetExpandedSSHCredentials()

	// Collect unique usernames and all keys
	usernameSet := make(map[string]bool)
	var keys [][]byte

	keySet := make(map[string]bool)
	for _, cred := range creds {
		usernameSet[cred.Username] = true

		// Deduplicate keys (vagrant key appears twice)
		keyStr := string(cred.Key)
		if !keySet[keyStr] {
			keySet[keyStr] = true
			keys = append(keys, cred.Key)
		}
	}

	var usernames []string
	for u := range usernameSet {
		usernames = append(usernames, u)
	}

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     usernames,
		Keys:          keys,
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// NewSSHConfigForProduct creates a brutus.Config for a specific product's keys.
// Use this when you know the target is running a specific product
// (e.g., "vagrant", "f5-bigip", "exagrid").
//
// Example:
//
//	// Test only vagrant keys against a suspected vagrant VM
//	config := badkeys.NewSSHConfigForProduct("10.0.0.50:22", "vagrant")
//	results, err := brutus.Brute(config)
func NewSSHConfigForProduct(target, product string) *brutus.Config {
	creds := GetCredentialsByProduct(product)
	if len(creds) == 0 {
		// Fallback to all credentials
		return NewSSHConfig(target)
	}

	// Get expanded usernames for this product
	usernameSet := make(map[string]bool)
	var keys [][]byte

	for _, cred := range creds {
		// Add the primary username
		usernameSet[cred.Username] = true

		// Add additional usernames for this product
		if additional, ok := additionalUsernames[cred.Product]; ok {
			for _, u := range additional {
				usernameSet[u] = true
			}
		}

		keys = append(keys, cred.Key)
	}

	var usernames []string
	for u := range usernameSet {
		usernames = append(usernames, u)
	}

	// Use product-specific port if available
	port := 22
	if len(creds) > 0 && creds[0].DefaultPort != 0 {
		port = creds[0].DefaultPort
	}
	_ = port // Available for future use in target parsing

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     usernames,
		Keys:          keys,
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// NewSSHConfigWithPasswords creates a brutus.Config that combines bad keys
// with a list of passwords for comprehensive SSH testing.
//
// This tests both key-based and password-based authentication,
// which is useful for thorough security assessments.
//
// Example:
//
//	config := badkeys.NewSSHConfigWithPasswords(
//	    "10.0.0.50:22",
//	    []string{"root", "admin", "vagrant"},
//	    []string{"password", "admin", "root123"},
//	)
//	results, err := brutus.Brute(config)
func NewSSHConfigWithPasswords(target string, usernames, passwords []string) *brutus.Config {
	// Merge provided usernames with bad key usernames
	usernameSet := make(map[string]bool)
	for _, u := range usernames {
		usernameSet[u] = true
	}
	for _, u := range GetUsernames() {
		usernameSet[u] = true
	}

	var allUsernames []string
	for u := range usernameSet {
		allUsernames = append(allUsernames, u)
	}

	return &brutus.Config{
		Target:        target,
		Protocol:      "ssh",
		Usernames:     allUsernames,
		Passwords:     passwords,
		Keys:          GetKeys(),
		Timeout:       10 * time.Second,
		Threads:       10,
		StopOnSuccess: true,
	}
}

// SSHKeyCredential returns a username:key pair ready for direct use with
// the brutus SSH plugin's TestKey method.
type SSHKeyCredential struct {
	Username string
	Key      []byte
}

// GetSSHKeyCredentials returns all username:key pairs for direct testing.
// Unlike GetExpandedSSHCredentials, this returns a simpler structure
// focused on just the authentication data.
//
// Example:
//
//	creds := badkeys.GetSSHKeyCredentials()
//	for _, cred := range creds {
//	    result := sshPlugin.TestKey(ctx, target, cred.Username, cred.Key, timeout)
//	    if result.Success {
//	        fmt.Printf("Found valid key for %s\n", cred.Username)
//	    }
//	}
func GetSSHKeyCredentials() []SSHKeyCredential {
	expanded := GetExpandedSSHCredentials()
	creds := make([]SSHKeyCredential, len(expanded))

	for i, e := range expanded {
		creds[i] = SSHKeyCredential{
			Username: e.Username,
			Key:      e.Key,
		}
	}

	return creds
}

// BruteSSH is a convenience function that performs SSH key brute forcing
// using all known bad keys.
//
// This is the simplest way to test a target for known default SSH keys.
//
// Example:
//
//	results, err := badkeys.BruteSSH("10.0.0.50:22")
//	for _, r := range results {
//	    if r.Success {
//	        fmt.Printf("Found valid key for %s\n", r.Username)
//	    }
//	}
func BruteSSH(target string) ([]brutus.Result, error) {
	config := NewSSHConfig(target)
	return brutus.Brute(config)
}

// BruteSSHProduct is a convenience function that performs SSH key brute forcing
// using only keys for a specific product.
//
// Example:
//
//	results, err := badkeys.BruteSSHProduct("10.0.0.50:22", "f5-bigip")
func BruteSSHProduct(target, product string) ([]brutus.Result, error) {
	config := NewSSHConfigForProduct(target, product)
	return brutus.Brute(config)
}
