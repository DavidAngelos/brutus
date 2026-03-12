// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package openrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

func TestClient_Analyze_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify required headers
		if r.Header.Get("Authorization") == "" {
			t.Error("Missing Authorization header")
		}
		if r.Header.Get("HTTP-Referer") == "" {
			t.Error("Missing HTTP-Referer header")
		}
		if r.Header.Get("X-Title") == "" {
			t.Error("Missing X-Title header")
		}

		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": `Based on my research, the default credentials are:
- admin:admin
- root:root
- admin:1234`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{
		Protocol: "http",
		Target:   "192.168.1.1:80",
		Banner:   `{"application":{"type":"router","vendor":"TP-Link","model":"Archer C7"}}`,
	}

	passwords, err := client.Analyze(context.Background(), banner)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(passwords) == 0 {
		t.Fatal("Expected at least one password")
	}

	// Verify admin password is in the result
	found := false
	for _, p := range passwords {
		if p == "admin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected 'admin' password in results: %v", passwords)
	}
}

func TestClient_AnalyzeCredentials_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": `Default credentials for Dell iDRAC:
- root:calvin
- admin:admin`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{
		Protocol: "http",
		Target:   "192.168.1.1:443",
		Banner:   `{"application":{"type":"bmc","vendor":"Dell","model":"iDRAC"}}`,
	}

	creds, err := client.AnalyzeCredentials(context.Background(), banner)
	if err != nil {
		t.Fatalf("AnalyzeCredentials failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("Expected at least one credential")
	}

	found := false
	for _, c := range creds {
		if c.Username == "root" && c.Password == "calvin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected root/calvin credential, got: %v", creds)
	}
}

func TestClient_AnalyzeCredentials_PlainTextBanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "admin:admin\nroot:toor",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{
		Protocol: "http",
		Target:   "192.168.1.1:80",
		Banner:   "HTTP/1.1 401 Unauthorized\nServer: Apache\nWWW-Authenticate: Basic realm=\"Device\"",
	}

	creds, err := client.AnalyzeCredentials(context.Background(), banner)
	if err != nil {
		t.Fatalf("AnalyzeCredentials failed: %v", err)
	}

	if len(creds) == 0 {
		t.Error("Expected credential suggestions for plain text banner")
	}
}

func TestClient_Registration(t *testing.T) {
	factory := brutus.GetAnalyzerFactory("openrouter")
	if factory == nil {
		t.Fatal("openrouter analyzer not registered")
	}

	cfg := &brutus.LLMConfig{
		Enabled:  true,
		Provider: "openrouter",
		APIKey:   "test-key",
	}

	analyzer := factory(cfg)
	if analyzer == nil {
		t.Fatal("Factory returned nil analyzer")
	}
}

func TestClient_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid API key"}}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "bad-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{Banner: "some banner text"}
	_, err := client.AnalyzeCredentials(context.Background(), banner)
	if err == nil {
		t.Fatal("Expected error for 401 response")
	}
}

func TestClient_MissingAPIKey(t *testing.T) {
	client := &Client{
		APIKey: "",
	}

	banner := brutus.BannerInfo{Banner: "some banner"}
	_, err := client.AnalyzeCredentials(context.Background(), banner)
	if err == nil {
		t.Fatal("Expected error for missing API key")
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response — context should cancel before we respond
		<-r.Context().Done()
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	banner := brutus.BannerInfo{Banner: "some banner"}
	_, err := client.AnalyzeCredentials(ctx, banner)
	if err == nil {
		t.Fatal("Expected error on cancelled context")
	}
}

func TestClient_ModelOverride(t *testing.T) {
	var capturedModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apiRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			capturedModel = req.Model
		}

		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "admin:admin",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Model:    "openai/gpt-4o-mini",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{Banner: "some banner"}
	_, _ = client.AnalyzeCredentials(context.Background(), banner)

	if capturedModel != "openai/gpt-4o-mini" {
		t.Errorf("Expected model 'openai/gpt-4o-mini', got %q", capturedModel)
	}
}

func TestClient_DefaultModel(t *testing.T) {
	var capturedModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apiRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			capturedModel = req.Model
		}

		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "admin:admin",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{Banner: "some banner"}
	_, _ = client.AnalyzeCredentials(context.Background(), banner)

	if capturedModel != DefaultModel {
		t.Errorf("Expected default model %q, got %q", DefaultModel, capturedModel)
	}
}

func TestClient_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"choices": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &Client{
		APIKey:   "test-key",
		Endpoint: server.URL,
	}

	banner := brutus.BannerInfo{Banner: "some banner"}
	creds, err := client.AnalyzeCredentials(context.Background(), banner)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(creds) != 0 {
		t.Errorf("Expected 0 credentials from empty response, got %d", len(creds))
	}
}

func TestClient_BaseURLFromConfig(t *testing.T) {
	var requestReceived bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": "admin:admin",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Test that BaseURL from LLMConfig flows through to the client
	factory := brutus.GetAnalyzerFactory("openrouter")
	if factory == nil {
		t.Fatal("openrouter analyzer not registered")
	}

	// Set environment variable to override the endpoint for this test
	os.Setenv("OPENROUTER_BASE_URL", server.URL)
	defer os.Unsetenv("OPENROUTER_BASE_URL")

	cfg := &brutus.LLMConfig{
		Enabled:  true,
		Provider: "openrouter",
		APIKey:   "test-key",
	}

	analyzer := factory(cfg)

	banner := brutus.BannerInfo{Banner: "test banner"}
	_, _ = analyzer.Analyze(context.Background(), banner)

	if !requestReceived {
		t.Error("Request was not sent to custom BaseURL endpoint")
	}
}

func TestExtractAppIdentifiers(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantVersion string
		wantServer  string
	}{
		{
			name:        "Server Header Version",
			banner:      "HTTP/1.1 200 OK\nServer: openresty/1.21.4.1\n\n<html><title>Radarr</title></html>",
			wantName:    "Radarr",
			wantVersion: "1.21.4.1",
			wantServer:  "openresty/1.21.4.1",
		},
		{
			name:        "Title Version",
			banner:      "<html><title>pfSense - Login - v2.5.2</title></html>",
			wantName:    "pfSense - Login - v2.5.2",
			wantVersion: "2.5.2",
			wantServer:  "",
		},
		{
			name:        "Meta Version",
			banner:      "<html><head><meta name=\"description\" content=\"Jellyfin\"><meta name=\"version\" content=\"10.8.10\"></head></html>",
			wantName:    "Jellyfin",
			wantVersion: "10.8.10",
			wantServer:  "",
		},
		{
			name:        "JS App and Version",
			banner:      "<html><script>window.Sonarr = {}; window.version = '3.0.9'</script></html>",
			wantName:    "Sonarr",
			wantVersion: "3.0.9",
			wantServer:  "",
		},
		{
			name:        "No Identifiers",
			banner:      "<html><body>Just some text</body></html>",
			wantName:    "",
			wantVersion: "",
			wantServer:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion, gotServer := extractAppIdentifiers(tt.banner)
			if gotName != tt.wantName {
				t.Errorf("extractAppIdentifiers() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("extractAppIdentifiers() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotServer != tt.wantServer {
				t.Errorf("extractAppIdentifiers() gotServer = %v, want %v", gotServer, tt.wantServer)
			}
		})
	}
}
