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

// Package badkeys provides embedded SSH private keys known to be used as defaults
// in various software and hardware products. These keys are publicly documented
// and should never be used for actual authentication, but are commonly found
// in misconfigured systems.
//
// Sources:
//   - https://github.com/rapid7/ssh-badkeys
//   - https://github.com/hashicorp/vagrant/tree/master/keys
//
// Usage:
//
//	// Get all SSH key credentials for brute forcing
//	creds := badkeys.GetSSHCredentials()
//	for _, cred := range creds {
//	    fmt.Printf("Testing %s with key %s\n", cred.Username, cred.Name)
//	}
//
//	// Get credentials for a specific product
//	vagrantCreds := badkeys.GetCredentialsByProduct("vagrant")
package badkeys

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed keys/rapid7/*.key keys/vagrant/*.key
var keysFS embed.FS

// SSHCredential represents a username:key pair with metadata about its origin.
type SSHCredential struct {
	// Name is a human-readable identifier for this key (e.g., "vagrant-default")
	Name string
	// Username is the associated default username for this key
	Username string
	// Key is the raw PEM-encoded private key
	Key []byte
	// Product identifies the software/hardware this key is associated with
	Product string
	// CVE is the CVE identifier if one exists (empty string if none)
	CVE string
	// Description provides context about where this key is typically found
	Description string
	// DefaultPort is the typical SSH port for this service (usually 22)
	DefaultPort int
}

// keyMetadata contains the username and metadata for each known key file.
var keyMetadata = map[string]struct {
	Username    string
	Product     string
	CVE         string
	Description string
	DefaultPort int
}{
	// rapid7/ssh-badkeys authorized keys
	"array-networks-vapv-vxag.key": {
		Username:    "sync",
		Product:     "array-networks",
		CVE:         "",
		Description: "Array Networks vAPV/vxAG virtual appliances use this static key for the 'sync' user",
		DefaultPort: 22,
	},
	"barracuda_load_balancer_vm.key": {
		Username:    "cluster",
		Product:     "barracuda",
		CVE:         "CVE-2014-8428",
		Description: "Barracuda Load Balancer VM uses this static key on port 8002 for cluster management",
		DefaultPort: 8002,
	},
	"ceragon-fibeair-cve-2015-0936.key": {
		Username:    "mateidu",
		Product:     "ceragon",
		CVE:         "CVE-2015-0936",
		Description: "Ceragon FibeAir wireless backhaul devices use this hardcoded key",
		DefaultPort: 22,
	},
	"exagrid-cve-2016-1561.key": {
		Username:    "root",
		Product:     "exagrid",
		CVE:         "CVE-2016-1561",
		Description: "ExaGrid backup appliances contain a backdoor SSH key for root access",
		DefaultPort: 22,
	},
	"f5-bigip-cve-2012-1493.key": {
		Username:    "root",
		Product:     "f5-bigip",
		CVE:         "CVE-2012-1493",
		Description: "F5 BIG-IP load balancers shipped with this static root SSH key",
		DefaultPort: 22,
	},
	"loadbalancer.org-enterprise-va.key": {
		Username:    "root",
		Product:     "loadbalancer-org",
		CVE:         "",
		Description: "Loadbalancer.org Enterprise VA 7.5.2 and earlier use this static key",
		DefaultPort: 22,
	},
	"monroe-dasdec-cve-2013-0137.key": {
		Username:    "root",
		Product:     "monroe-dasdec",
		CVE:         "CVE-2013-0137",
		Description: "Monroe Electronics DASDEC emergency alert systems use this hardcoded key",
		DefaultPort: 22,
	},
	"quantum-dxi-v1000.key": {
		Username:    "root",
		Product:     "quantum-dxi",
		CVE:         "",
		Description: "Quantum DXi V1000 deduplication appliances use this static root key",
		DefaultPort: 22,
	},
	"vagrant-default.key": {
		Username:    "root",
		Product:     "vagrant",
		CVE:         "",
		Description: "Vagrant default insecure key (also in rapid7 collection)",
		DefaultPort: 22,
	},
	// Hashicorp Vagrant official key
	"vagrant.key": {
		Username:    "vagrant",
		Product:     "vagrant",
		CVE:         "",
		Description: "HashiCorp Vagrant insecure private key - default for 'vagrant' user in base boxes",
		DefaultPort: 22,
	},
}

// additionalUsernames maps products to additional usernames that may work
// beyond the primary default username.
var additionalUsernames = map[string][]string{
	"vagrant":          {"vagrant", "root", "ubuntu", "centos", "ec2-user", "admin"},
	"exagrid":          {"root", "admin", "support"},
	"f5-bigip":         {"root", "admin"},
	"barracuda":        {"cluster", "root", "admin"},
	"array-networks":   {"sync", "root", "admin"},
	"ceragon":          {"mateidu", "root", "admin"},
	"loadbalancer-org": {"root", "loadbalancer", "admin"},
	"monroe-dasdec":    {"root", "dasdec", "admin"},
	"quantum-dxi":      {"root", "admin", "service"},
}

// GetSSHCredentials returns all known SSH bad key credentials.
// Each credential includes the username most likely to work with that key.
func GetSSHCredentials() []SSHCredential {
	var creds []SSHCredential

	// Walk through embedded filesystem
	walkErr := fs.WalkDir(keysFS, "keys", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".key") {
			return nil
		}

		keyData, readErr := keysFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		filename := filepath.Base(path)
		meta, ok := keyMetadata[filename]
		if !ok {
			// Unknown key file, use defaults
			meta = struct {
				Username    string
				Product     string
				CVE         string
				Description string
				DefaultPort int
			}{
				Username:    "root",
				Product:     "unknown",
				Description: "Unknown SSH key",
				DefaultPort: 22,
			}
		}

		creds = append(creds, SSHCredential{
			Name:        strings.TrimSuffix(filename, ".key"),
			Username:    meta.Username,
			Key:         keyData,
			Product:     meta.Product,
			CVE:         meta.CVE,
			Description: meta.Description,
			DefaultPort: meta.DefaultPort,
		})

		return nil
	})

	if walkErr != nil {
		return nil
	}

	return creds
}

// GetExpandedSSHCredentials returns credentials expanded with all likely usernames.
// For products with multiple possible usernames, this returns a credential
// for each username:key combination.
func GetExpandedSSHCredentials() []SSHCredential {
	baseCreds := GetSSHCredentials()
	var expanded []SSHCredential

	for _, cred := range baseCreds {
		usernames := additionalUsernames[cred.Product]
		if len(usernames) == 0 {
			// No additional usernames, use the default
			expanded = append(expanded, cred)
			continue
		}

		// Create a credential for each possible username
		for _, username := range usernames {
			expandedCred := SSHCredential{
				Name:        cred.Name,
				Username:    username,
				Key:         cred.Key,
				Product:     cred.Product,
				CVE:         cred.CVE,
				Description: cred.Description,
				DefaultPort: cred.DefaultPort,
			}
			expanded = append(expanded, expandedCred)
		}
	}

	return expanded
}

// GetCredentialsByProduct returns credentials for a specific product.
func GetCredentialsByProduct(product string) []SSHCredential {
	var creds []SSHCredential
	product = strings.ToLower(product)

	for _, cred := range GetSSHCredentials() {
		if strings.Contains(strings.ToLower(cred.Product), product) {
			creds = append(creds, cred)
		}
	}

	return creds
}

// GetCredentialsByCVE returns credentials associated with a specific CVE.
func GetCredentialsByCVE(cve string) []SSHCredential {
	var creds []SSHCredential
	cve = strings.ToUpper(cve)

	for _, cred := range GetSSHCredentials() {
		if cred.CVE == cve {
			creds = append(creds, cred)
		}
	}

	return creds
}

// GetKeys returns just the raw private keys without metadata.
// Useful for simple key-based brute forcing where you want to try
// all keys against a target.
func GetKeys() [][]byte {
	var keys [][]byte

	for _, cred := range GetSSHCredentials() {
		keys = append(keys, cred.Key)
	}

	return keys
}

// GetUsernames returns all unique usernames associated with bad keys.
func GetUsernames() []string {
	seen := make(map[string]bool)
	var usernames []string

	for _, cred := range GetExpandedSSHCredentials() {
		if !seen[cred.Username] {
			seen[cred.Username] = true
			usernames = append(usernames, cred.Username)
		}
	}

	return usernames
}

// GetKeyByName returns a specific key by its name (without .key extension).
func GetKeyByName(name string) ([]byte, bool) {
	// Try with and without .key extension
	filename := name
	if !strings.HasSuffix(filename, ".key") {
		filename = name + ".key"
	}

	// Check rapid7 directory
	data, err := keysFS.ReadFile("keys/rapid7/" + filename)
	if err == nil {
		return data, true
	}

	// Check vagrant directory
	data, err = keysFS.ReadFile("keys/vagrant/" + filename)
	if err == nil {
		return data, true
	}

	return nil, false
}

// ListKeys returns the names of all available keys.
func ListKeys() []string {
	var names []string

	walkErr := fs.WalkDir(keysFS, "keys", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".key") {
			names = append(names, strings.TrimSuffix(filepath.Base(path), ".key"))
		}
		return nil
	})

	if walkErr != nil {
		return nil
	}

	return names
}

// Stats returns statistics about the embedded key collection.
type Stats struct {
	TotalKeys       int
	TotalProducts   int
	KeysWithCVE     int
	UniqueUsernames int
}

// GetStats returns statistics about the embedded key collection.
func GetStats() Stats {
	creds := GetSSHCredentials()
	products := make(map[string]bool)
	keysWithCVE := 0

	for _, cred := range creds {
		products[cred.Product] = true
		if cred.CVE != "" {
			keysWithCVE++
		}
	}

	return Stats{
		TotalKeys:       len(creds),
		TotalProducts:   len(products),
		KeysWithCVE:     keysWithCVE,
		UniqueUsernames: len(GetUsernames()),
	}
}
