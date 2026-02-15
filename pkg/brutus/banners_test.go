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
	"testing"

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
