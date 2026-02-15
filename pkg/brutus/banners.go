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

package brutus

import "strings"

// standardBanners contains known standard banner patterns for each protocol
var standardBanners = map[string][]string{
	"ssh": {
		"SSH-2.0-OpenSSH",
		"SSH-2.0-libssh",
		"SSH-2.0-dropbear",
	},
	"telnet": {
		"Ubuntu",
		"Debian",
		"Linux",
		"FreeBSD",
	},
	"ftp": {
		"220 ProFTPD",
		"220 (vsFTPd",
		"220-FileZilla",
		"220 Pure-FTPd",
	},
	"mysql": {
		"MySQL 5.",
		"MySQL 8.",
		"MariaDB 10.",
		"Percona Server",
	},
	"snmp": {
		"Linux",
		"Cisco IOS",
		"Windows",
		"FreeBSD",
		"net-snmp",
		"HP ETHERNET",
		"APC",
		"Ubiquiti",
	},
}

// IsStandardBanner checks if a banner matches known standard patterns for the protocol.
// Returns true if the banner is standard (common/default), false if custom/modified.
//
// HTTP protocols (http, https, couchdb, elasticsearch, influxdb) always return false
// to enable LLM analysis, as they have application-specific banners (Grafana, Jenkins,
// Tomcat) that benefit from LLM credential suggestion.
//
// Unknown non-HTTP protocols or empty banners are assumed standard.
func IsStandardBanner(protocol, banner string) bool {
	// Empty banner - assume standard
	if banner == "" {
		return true
	}

	// HTTP protocols always need LLM analysis (application-specific banners)
	if isHTTPProtocol(protocol) {
		return false
	}

	// Get patterns for protocol
	patterns, ok := standardBanners[protocol]
	if !ok {
		// Unknown protocol - assume standard
		return true
	}

	// Check if banner matches any standard pattern
	for _, pattern := range patterns {
		if strings.Contains(banner, pattern) {
			return true
		}
	}

	// No match - custom banner
	return false
}

// isHTTPProtocol returns true if the protocol uses HTTP Basic Auth
// and can benefit from LLM-based application detection.
func isHTTPProtocol(protocol string) bool {
	switch protocol {
	case "http", "https", "couchdb", "elasticsearch", "influxdb":
		return true
	default:
		return false
	}
}
