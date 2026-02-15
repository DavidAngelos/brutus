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

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDetectHTTPAuthType_ClosesIdleConnections tests that detectHTTPAuthTypeWithBanner
// closes idle connections after each call to prevent transport goroutine leaks
func TestDetectHTTPAuthType_ClosesIdleConnections(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Test page")
	}))
	defer server.Close()

	// Count goroutines before
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	goroutinesBefore := runtime.NumGoroutine()

	// Make multiple calls (simulating stdin pipeline mode)
	target := server.URL[7:] // Remove "http://" prefix
	for i := 0; i < 50; i++ {
		detectHTTPAuthTypeWithBanner(target, false, 5*time.Second, "skip", false)
	}

	// Force garbage collection
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Count goroutines after
	goroutinesAfter := runtime.NumGoroutine()

	// With the fix (defer client.CloseIdleConnections()), goroutines should NOT grow significantly
	// Without the fix, we'd see +50 goroutines (one per transport)
	goroutineGrowth := goroutinesAfter - goroutinesBefore

	require.Less(t, goroutineGrowth, 20,
		"Expected goroutine growth < 20, got %d (before: %d, after: %d). "+
			"Transport goroutines are leaking - CloseIdleConnections() not called",
		goroutineGrowth, goroutinesBefore, goroutinesAfter)
}

// TestDetectHTTPAuthType_BasicAuth tests detection of basic authentication
func TestDetectHTTPAuthType_BasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseHeader map[string]string
		expectedAuth   string
	}{
		{
			name:           "WWW-Authenticate header present",
			responseStatus: http.StatusUnauthorized,
			responseHeader: map[string]string{"WWW-Authenticate": "Basic realm=\"test\""},
			expectedAuth:   "basic",
		},
		{
			name:           "401 without WWW-Authenticate",
			responseStatus: http.StatusUnauthorized,
			responseHeader: map[string]string{},
			expectedAuth:   "basic",
		},
		{
			name:           "Form-based (200 OK)",
			responseStatus: http.StatusOK,
			responseHeader: map[string]string{},
			expectedAuth:   "form",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.responseHeader {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.responseStatus)
			}))
			defer server.Close()

			target := server.URL[7:] // Remove "http://" prefix
			authType, _ := detectHTTPAuthTypeWithBanner(target, false, 5*time.Second, "skip", false)

			require.Equal(t, tt.expectedAuth, authType)
		})
	}
}
