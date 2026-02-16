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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// rdpAuthIndicators defines authentication failure strings from RDP/CredSSP.
var rdpAuthIndicators = []string{
	"logon failed",
	"login failed",
	"authentication failed",
	"access denied",
	"credentials",
	"password",
	"ntlm",
	"credssp",
	"sec_e_logon_denied",
}

func init() {
	brutus.Register("rdp", func() brutus.Plugin {
		return &Plugin{}
	})
}

// Plugin implements RDP authentication testing via IronRDP WASM.
type Plugin struct{}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return "rdp"
}

// rdpConfig is the JSON config passed to the WASM connector.
type rdpConfig struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

// Test attempts RDP authentication using NLA/CredSSP via the IronRDP WASM module.
//
// Returns Result with:
// - Success=true, Error=nil: Valid credentials
// - Success=false, Error=nil: Invalid credentials (auth failure)
// - Success=false, Error!=nil: Connection/network error
func (p *Plugin) Test(ctx context.Context, target, username, password string,
	timeout time.Duration) *brutus.Result {
	start := time.Now()

	result := &brutus.Result{
		Protocol: "rdp",
		Target:   target,
		Username: username,
		Password: password,
		Success:  false,
	}

	// Parse target
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	// Parse domain\username (reuse SMB pattern)
	domain, user := parseDomainUsername(username)

	// Initialize WASM engine (singleton, first call compiles)
	eng, err := initEngine()
	if err != nil {
		result.Error = fmt.Errorf("connection error: wasm init: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Create TCP connection with timeout
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("connection error: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Create a fresh WASM instance for this Test() call (D1: per-call isolation)
	inst, err := newInstance(ctx, eng, conn)
	if err != nil {
		result.Error = fmt.Errorf("connection error: wasm instance: %w", err)
		result.Duration = time.Since(start)
		return result
	}
	defer inst.close(ctx)

	// Prepare connector config
	cfg := rdpConfig{
		Server:   addr,
		Username: user,
		Password: password,
		Domain:   domain,
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		result.Error = fmt.Errorf("connection error: marshal config: %w", err)
		result.Duration = time.Since(start)
		return result
	}

	// Run the connector state machine
	banner, err := p.runConnector(ctx, inst, configBytes)
	if err != nil {
		result.Error = classifyError(err)
		result.Duration = time.Since(start)
		result.Banner = banner
		return result
	}

	// Connection succeeded — authentication was valid
	result.Success = true
	result.Banner = banner
	result.Duration = time.Since(start)
	return result
}

// runConnector drives the IronRDP connector state machine through WASM calls.
// Returns the RDP banner (if captured) and any error.
func (p *Plugin) runConnector(ctx context.Context, inst *wasmInstance, config []byte) (string, error) {
	// Write config to WASM memory
	configPtr, configLen, err := inst.writeToWasm(ctx, config)
	if err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	defer inst.freeInWasm(ctx, configPtr, configLen)

	// Create connector
	connectorNewFn := inst.mod.ExportedFunction("connector_new")
	if connectorNewFn == nil {
		return "", fmt.Errorf("connector_new not exported")
	}

	// Use callCtx to inject instance into context for host function dispatch
	callCtx := inst.callCtx(ctx)

	results, err := connectorNewFn.Call(callCtx, uint64(configPtr), uint64(configLen))
	if err != nil {
		return "", fmt.Errorf("connector_new: %w", err)
	}
	handle := uint32(results[0])
	if handle == 0 {
		return "", fmt.Errorf("connector_new returned null handle")
	}

	// Ensure cleanup
	connectorFreeFn := inst.mod.ExportedFunction("connector_free")
	defer func() {
		if connectorFreeFn != nil {
			_, _ = connectorFreeFn.Call(callCtx, uint64(handle))
		}
	}()

	// Step through the connector state machine
	connectorStepFn := inst.mod.ExportedFunction("connector_step")
	if connectorStepFn == nil {
		return "", fmt.Errorf("connector_step not exported")
	}

	var banner string

	// Drive the state machine loop
	// The WASM connector returns states: NEED_SEND, NEED_RECV, NEED_TLS_UPGRADE, CONNECTED, ERROR
	// For the stub, this immediately returns CONNECTED.
	// For the real implementation, this loops until CONNECTED or ERROR.
	inputPtr := uint32(0)
	inputLen := uint32(0)

	for i := 0; i < 100; i++ { // Safety limit to prevent infinite loops
		// Allocate output pointer slots in WASM memory
		outPtrSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			return banner, fmt.Errorf("alloc out ptr: %w", err)
		}
		outLenSlot, _, err := inst.writeToWasm(callCtx, make([]byte, 4))
		if err != nil {
			return banner, fmt.Errorf("alloc out len: %w", err)
		}

		results, err := connectorStepFn.Call(callCtx,
			uint64(handle),
			uint64(inputPtr), uint64(inputLen),
			uint64(outPtrSlot), uint64(outLenSlot),
		)
		if err != nil {
			return banner, fmt.Errorf("connector_step: %w", err)
		}

		state := uint32(results[0])

		// Free input from previous iteration
		if inputPtr != 0 {
			inst.freeInWasm(callCtx, inputPtr, inputLen)
			inputPtr = 0
			inputLen = 0
		}

		switch state {
		case stateConnected:
			return banner, nil // Success!

		case stateError:
			return banner, fmt.Errorf("rdp authentication failed")

		case stateNeedSend:
			// Read output bytes and send to server
			// (implementation details for Phase 2)
			return banner, fmt.Errorf("connector state machine not yet implemented")

		case stateNeedRecv:
			// Read from server and pass to next step
			return banner, fmt.Errorf("connector state machine not yet implemented")

		case stateNeedTLSUpgrade:
			// TLS upgrade handled by host function
			return banner, fmt.Errorf("connector state machine not yet implemented")

		default:
			return banner, fmt.Errorf("unknown connector state: %d", state)
		}
	}

	return banner, fmt.Errorf("connector exceeded maximum iterations")
}

// parseDomainUsername splits "DOMAIN\username" into (domain, username).
// Returns empty domain if no backslash present.
// Matches SMB plugin pattern (internal/plugins/smb/smb.go:128-136).
func parseDomainUsername(username string) (domain, user string) {
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		return parts[0], parts[1]
	}
	return "", username
}

// classifyError classifies RDP errors using the shared brutus helper.
func classifyError(err error) error {
	return brutus.ClassifyAuthError(err, rdpAuthIndicators)
}
