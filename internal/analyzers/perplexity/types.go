// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package perplexity

import "context"

// Credential represents a username/password pair for testing
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source,omitempty"` // "perplexity" or "llm_knowledge"
}

// CredentialResearcher researches default credentials for applications
type CredentialResearcher interface {
	// ResearchCredentials finds default credentials for the identified application
	ResearchCredentials(ctx context.Context, appType, vendor, model string) ([]Credential, error)
}
