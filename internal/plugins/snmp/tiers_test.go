// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

package snmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCommunityStrings_TierSizes(t *testing.T) {
	// Tier sizes are documented in tiers.go package comment
	// Default: ~25 high-hit-rate strings, Extended: ~75 vendor-specific, Full: 200+ comprehensive
	assert.Len(t, GetCommunityStrings(TierDefault), 23, "Default tier should have 23 strings")
	assert.Len(t, GetCommunityStrings(TierExtended), 75, "Extended tier should have 75 strings")
	assert.GreaterOrEqual(t, len(GetCommunityStrings(TierFull)), 200, "Full tier should have 200+ strings")
}

func TestGetCommunityStrings_PublicFirst(t *testing.T) {
	for _, tier := range []Tier{TierDefault, TierExtended, TierFull} {
		strings := GetCommunityStrings(tier)
		assert.Equal(t, "public", strings[0], "public should be first in tier %s", tier)
	}
}

func TestGetCommunityStrings_NoDuplicates(t *testing.T) {
	for _, tier := range []Tier{TierDefault, TierExtended, TierFull} {
		strings := GetCommunityStrings(tier)
		seen := make(map[string]bool)
		for _, s := range strings {
			assert.False(t, seen[s], "Duplicate community string %q in tier %s", s, tier)
			seen[s] = true
		}
	}
}

func TestValidateTier(t *testing.T) {
	assert.True(t, ValidateTier("default"))
	assert.True(t, ValidateTier("extended"))
	assert.True(t, ValidateTier("full"))
	assert.False(t, ValidateTier("invalid"))
	assert.False(t, ValidateTier(""))
}
