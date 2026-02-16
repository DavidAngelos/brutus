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
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// rdpAuthIndicators defines authentication failure strings from RDP/CredSSP.
// These are matched case-insensitively by ClassifyAuthError.
var rdpAuthIndicators = []string{
	"logon failed",
	"login failed",
	"authentication failed",
	"access denied",
	"credssp",
	"sec_e_logon_denied",
	"nla",
	"ntlm",
	"wrong password",
	"invalid credentials",
	"negotiation failure",
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
//
// The state machine loop:
// 1. Call connector_step with any pending input
// 2. Check returned state code
// 3. NEED_SEND: read output bytes from WASM, send to server via TCP
// 4. NEED_RECV: read from server, write data to WASM for next step
// 5. NEED_TLS_UPGRADE: upgrade TCP to TLS
// 6. CONNECTED: success
// 7. ERROR: read error message from output
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
	inputPtr := uint32(0)
	inputLen := uint32(0)

	for i := 0; i < 100; i++ { // Safety limit to prevent infinite loops
		// Allocate output pointer slots in WASM memory (4 bytes each for u32 values)
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
			// Read any output (may contain banner info)
			bannerBytes := readOutputFromSlots(inst, outPtrSlot, outLenSlot, callCtx)
			if len(bannerBytes) > 0 {
				banner = string(bannerBytes)
			}
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return banner, nil // Success!

		case stateError:
			// Read error message from output
			errBytes := readOutputFromSlots(inst, outPtrSlot, outLenSlot, callCtx)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			errMsg := "rdp authentication failed"
			if len(errBytes) > 0 {
				errMsg = string(errBytes)
			}
			return banner, fmt.Errorf("%s", errMsg)

		case stateNeedSend:
			// Read output bytes from WASM and send to server
			sendData := readOutputFromSlots(inst, outPtrSlot, outLenSlot, callCtx)
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)

			if len(sendData) > 0 {
				_, writeErr := inst.activeConn().Write(sendData)
				if writeErr != nil {
					return banner, fmt.Errorf("connection error: tcp write: %w", writeErr)
				}
			}
			// Continue loop — next step will read the server response

		case stateNeedRecv:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)

			// Read from server
			buf := make([]byte, 16384) // 16KB buffer
			n, readErr := inst.activeConn().Read(buf)
			if readErr != nil {
				return banner, fmt.Errorf("connection error: tcp read: %w", readErr)
			}
			// Write received data to WASM for next step
			inputPtr, inputLen, err = inst.writeToWasm(callCtx, buf[:n])
			if err != nil {
				return banner, fmt.Errorf("write recv to wasm: %w", err)
			}

		case stateNeedTLSUpgrade:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)

			// Perform TLS upgrade on the connection
			tlsConf := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // RDP servers use self-signed certs
			}
			tlsConn := tls.Client(inst.conn, tlsConf)
			if tlsErr := tlsConn.HandshakeContext(ctx); tlsErr != nil {
				return banner, fmt.Errorf("connection error: tls upgrade: %w", tlsErr)
			}
			inst.tls = tlsConn
			// Continue loop — WASM will be notified via the next step call

		default:
			inst.freeInWasm(callCtx, outPtrSlot, 4)
			inst.freeInWasm(callCtx, outLenSlot, 4)
			return banner, fmt.Errorf("unknown connector state: %d", state)
		}
	}

	return banner, fmt.Errorf("connector exceeded maximum iterations")
}

// readOutputFromSlots reads the output pointer and length from WASM memory slots,
// then reads the actual output data. Returns the output bytes (may be empty).
func readOutputFromSlots(inst *wasmInstance, outPtrSlot, outLenSlot uint32, ctx context.Context) []byte {
	outPtrBytes, err := inst.readFromWasm(outPtrSlot, 4)
	if err != nil {
		return nil
	}
	outLenBytes, err := inst.readFromWasm(outLenSlot, 4)
	if err != nil {
		return nil
	}
	outPtr := binary.LittleEndian.Uint32(outPtrBytes)
	outLen := binary.LittleEndian.Uint32(outLenBytes)

	if outLen == 0 || outPtr == 0 {
		return nil
	}

	data, err := inst.readFromWasm(outPtr, outLen)
	if err != nil {
		return nil
	}
	// Free the output buffer allocated by WASM
	inst.freeInWasm(ctx, outPtr, outLen)
	return data
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
