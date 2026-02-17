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

import "strings"

// FingerprintxResult represents the JSON output from fingerprintx
type FingerprintxResult struct {
	IP        string                 `json:"ip"`
	Port      int                    `json:"port"`
	Protocol  string                 `json:"protocol"`
	Transport string                 `json:"transport"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// mapServiceToProtocol maps fingerprintx service names to brutus protocol names
func mapServiceToProtocol(service string) string {
	// Normalize to lowercase
	service = strings.ToLower(service)

	// Direct mappings
	serviceMap := map[string]string{
		// Network services
		"ssh":    "ssh",
		"ftp":    "ftp",
		"telnet": "telnet",
		"vnc":    "vnc",
		"rdp":    "rdp",

		// Enterprise
		"smb":   "smb",
		"ldap":  "ldap",
		"winrm": "winrm",

		// Databases
		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"postgres":      "postgresql",
		"mssql":         "mssql",
		"mongodb":       "mongodb",
		"redis":         "redis",
		"neo4j":         "neo4j",
		"cassandra":     "cassandra",
		"couchdb":       "couchdb",
		"elasticsearch": "elasticsearch",
		"influxdb":      "influxdb",

		// Communications
		"smtp": "smtp",
		"imap": "imap",
		"pop3": "pop3",

		// SNMP
		"snmp": "snmp",

		// HTTP - map to our http basic auth plugin
		"http":  "http",
		"https": "https",

		// Browser - headless browser for form-based auth
		"browser": "browser",
	}

	if proto, ok := serviceMap[service]; ok {
		return proto
	}

	return ""
}
