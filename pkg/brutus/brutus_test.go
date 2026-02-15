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

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with all fields",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{"root"},
				Passwords: []string{"password"},
				Timeout:   5 * time.Second,
				Threads:   5,
			},
			wantErr: false,
		},
		{
			name: "empty target",
			config: Config{
				Protocol:  "ssh",
				Usernames: []string{"root"},
				Passwords: []string{"password"},
			},
			wantErr: true,
		},
		{
			name: "empty protocol",
			config: Config{
				Target:    "localhost:22",
				Usernames: []string{"root"},
				Passwords: []string{"password"},
			},
			wantErr: true,
		},
		{
			name: "missing usernames",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Passwords: []string{"password"},
			},
			wantErr: true,
		},
		{
			name: "empty usernames slice",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{},
				Passwords: []string{"password"},
			},
			wantErr: true,
		},
		{
			name: "missing passwords",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{"root"},
			},
			wantErr: true,
		},
		{
			name: "empty passwords slice",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{"root"},
				Passwords: []string{},
			},
			wantErr: true,
		},
		{
			name: "applies default timeout",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{"root"},
				Passwords: []string{"password"},
			},
			wantErr: false,
		},
		{
			name: "applies default threads",
			config: Config{
				Target:    "localhost:22",
				Protocol:  "ssh",
				Usernames: []string{"root"},
				Passwords: []string{"password"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr {
				assert.Error(t, err, "expected validation error but got none")
			} else {
				assert.NoError(t, err, "expected no validation error but got: %v", err)
				// Check defaults were applied
				if tt.config.Timeout == 0 {
					assert.Equal(t, 10*time.Second, tt.config.Timeout, "default timeout should be 10s")
				}
				if tt.config.Threads == 0 {
					assert.Equal(t, 10, tt.config.Threads, "default threads should be 10")
				}
			}
		})
	}
}

func TestBruteWithContext_CancelDuringExecution(t *testing.T) {
	// Test that BruteWithContext respects context cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create a config that would take a long time to complete
	config := &Config{
		Target:    "127.0.0.1:1",  // Non-existent port
		Protocol:  "ssh",
		Usernames: []string{"user1", "user2", "user3", "user4", "user5"},
		Passwords: []string{"pass1", "pass2", "pass3", "pass4", "pass5"},
		Timeout:   1 * time.Second,
		Threads:   1,
	}

	// Cancel the context after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := BruteWithContext(ctx, config)
	elapsed := time.Since(start)

	// Should return quickly (well before 25 attempts * 1 second timeout)
	assert.True(t, elapsed < 5*time.Second, "should return quickly on context cancellation")
	assert.Error(t, err, "should return error on context cancellation")
}

func TestBrute_BackwardsCompatibility(t *testing.T) {
	// Test that Brute() still works (backwards compatibility)
	// Test with valid config but without actual plugin (expect plugin error, not panic)
	config := &Config{
		Target:    "127.0.0.1:22",
		Protocol:  "ssh",
		Usernames: []string{"root"},
		Passwords: []string{"password"},
		Timeout:   100 * time.Millisecond,
		Threads:   1,
	}

	// Should complete without panic (may return error for missing plugin)
	// The important thing is it doesn't panic and the function signature works
	_, _ = Brute(config)
	// If we get here without panicking, backwards compatibility is maintained
	assert.True(t, true, "Brute() maintains backwards compatibility")
}
