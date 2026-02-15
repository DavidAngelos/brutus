package brutus

import (
	"fmt"
	"strings"
)

// ClassifyAuthError classifies authentication errors.
//
// Returns nil if the error matches any auth failure indicator (case-insensitive).
// Returns wrapped error for connection/network errors.
//
// This function is used by plugins to distinguish:
//   - Authentication failures (wrong credentials) → return nil
//   - Connection/network errors (retry or escalate) → return wrapped error
//
// All string matching is case-insensitive to handle server implementation variations.
func ClassifyAuthError(err error, authIndicators []string) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check if error matches any auth failure indicator
	for _, indicator := range authIndicators {
		if strings.Contains(errStr, strings.ToLower(indicator)) {
			// This is an authentication failure (wrong credentials)
			// Return nil to signal "try next credential"
			return nil
		}
	}

	// All other errors are connection/network problems
	return fmt.Errorf("connection error: %w", err)
}
