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

package rdp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "rdp", p.Name())
}

func TestPlugin_Test_ConnectionError(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Invalid host should cause connection error
	result := p.Test(ctx, "invalid-host:3389", "admin", "password", 2*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.Equal(t, "invalid-host:3389", result.Target)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestPlugin_Test_Timeout(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	// Use a blackhole IP that won't respond (connection should timeout)
	result := p.Test(ctx, "192.0.2.1:3389", "admin", "password", 1*time.Second)

	assert.NotNil(t, result)
	assert.Equal(t, "rdp", result.Protocol)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "connection error")
}

func TestParseDomainUsername(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		domain   string
		username string
	}{
		{
			name:     "plain username",
			input:    "admin",
			domain:   "",
			username: "admin",
		},
		{
			name:     "domain backslash username",
			input:    "CORP\\admin",
			domain:   "CORP",
			username: "admin",
		},
		{
			name:     "empty string",
			input:    "",
			domain:   "",
			username: "",
		},
		{
			name:     "multiple backslashes",
			input:    "CORP\\SUBDOMAIN\\admin",
			domain:   "CORP",
			username: "SUBDOMAIN\\admin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain, user := parseDomainUsername(tc.input)
			assert.Equal(t, tc.domain, domain)
			assert.Equal(t, tc.username, user)
		})
	}
}
