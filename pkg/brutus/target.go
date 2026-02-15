package brutus

import (
	"net"
)

// ParseTarget splits target into host and port, defaulting to defaultPort if no port is specified.
//
// Supports both IPv4 and IPv6 targets:
//   - IPv4: "example.com:5432" → ("example.com", "5432")
//   - IPv4 no port: "example.com" → ("example.com", defaultPort)
//   - IPv6: "[::1]:5432" → ("::1", "5432")
//   - IPv6 no port: "::1" → ("::1", defaultPort)
//
// Uses net.SplitHostPort for correct IPv6 bracket handling.
func ParseTarget(target, defaultPort string) (host, port string) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified (or invalid format) - use default
		return target, defaultPort
	}
	return h, p
}
