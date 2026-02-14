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

func TestIsStandardBanner(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		banner   string
		want     bool
	}{
		{
			name:     "empty banner returns true",
			protocol: "ssh",
			banner:   "",
			want:     true,
		},
		{
			name:     "ssh standard banner",
			protocol: "ssh",
			banner:   "SSH-2.0-OpenSSH_8.2",
			want:     true,
		},
		{
			name:     "ssh custom banner",
			protocol: "ssh",
			banner:   "SSH-2.0-MyCustomSSH",
			want:     false,
		},
		{
			name:     "http protocol with grafana banner should return false",
			protocol: "http",
			banner:   "Grafana v8.0.0",
			want:     false,
		},
		{
			name:     "https protocol with jenkins banner should return false",
			protocol: "https",
			banner:   "Jenkins/2.303",
			want:     false,
		},
		{
			name:     "couchdb protocol with custom banner should return false",
			protocol: "couchdb",
			banner:   "CouchDB/3.1.1",
			want:     false,
		},
		{
			name:     "elasticsearch protocol should return false",
			protocol: "elasticsearch",
			banner:   "Elasticsearch 7.10.0",
			want:     false,
		},
		{
			name:     "influxdb protocol should return false",
			protocol: "influxdb",
			banner:   "InfluxDB v2.0",
			want:     false,
		},
		{
			name:     "unknown non-http protocol returns true",
			protocol: "unknown",
			banner:   "some banner",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsStandardBanner(tt.protocol, tt.banner)
			assert.Equal(t, tt.want, got, "IsStandardBanner(%q, %q) = %v, want %v",
				tt.protocol, tt.banner, got, tt.want)
		})
	}
}

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

func TestCaptureBanner_EmptyUsernames(t *testing.T) {
	// Setup: Config with only Credentials (no Usernames), HTTP protocol, LLM enabled
	cfg := &Config{
		Target:   "example.com:80",
		Protocol: "http",
		Credentials: []Credential{
			{Username: "admin", Password: "password123"},
		},
		Usernames: []string{}, // EMPTY - triggers the bug
		Timeout:   10 * time.Second,
		LLMConfig: &LLMConfig{
			Enabled:  true,
			Provider: "claude",
		},
	}

	// Create mock plugin
	mockPlugin := &mockHTTPPlugin{}

	// This should NOT panic
	ctx := context.Background()
	banner := captureBanner(ctx, cfg, mockPlugin)

	// Should return a valid BannerInfo with empty Banner (not crash)
	assert.Equal(t, "http", banner.Protocol)
	assert.Equal(t, "example.com:80", banner.Target)
	// Banner may be empty, which is fine
}

type mockHTTPPlugin struct{}

func (m *mockHTTPPlugin) Name() string { return "http" }

func (m *mockHTTPPlugin) Test(ctx context.Context, target, username, password string, timeout time.Duration) *Result {
	return &Result{
		Protocol: "http",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
		Banner:   "HTTP/1.1 401 Unauthorized",
	}
}
