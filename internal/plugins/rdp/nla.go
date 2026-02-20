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
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// RDP security protocol negotiation flags.
const (
	protocolRDP      = 0x00000000 // Standard RDP Security (no NLA)
	protocolSSL      = 0x00000001 // TLS/SSL (no NLA)
	protocolHybrid   = 0x00000002 // CredSSP/NLA
	protocolRDSTLS   = 0x00000004 // RDSTLS
	protocolHybridEx = 0x00000008 // Enhanced CredSSP/NLA
)

// X.224 negotiation type codes.
const (
	negTypeRequest  = 0x01
	negTypeResponse = 0x02
	negTypeFailure  = 0x03
)

// NLAResult holds the outcome of an NLA fingerprint check.
type NLAResult struct {
	Target           string `json:"target"`
	RequiresNLA      bool   `json:"requires_nla"`
	SelectedProtocol string `json:"selected_protocol"` // "rdp", "ssl", "nla", "rdstls", "nla_ex"
	ServerName       string `json:"server_name,omitempty"`
	Error            string `json:"error,omitempty"`
}

// CheckNLA performs a lightweight NLA fingerprint check without authentication.
// It sends an X.224 Connection Request offering all protocols and reads the
// server's Connection Confirm to determine the selected security protocol.
// This is a pure TCP operation — no WASM, no TLS, no credentials.
func CheckNLA(ctx context.Context, target string, timeout time.Duration) *NLAResult {
	host, port := brutus.ParseTarget(target, "3389")
	addr := net.JoinHostPort(host, port)

	result := &NLAResult{Target: target}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send X.224 Connection Request (CR TPDU) offering all security protocols.
	crPDU := buildConnectionRequest()
	if _, err := conn.Write(crPDU); err != nil {
		result.Error = fmt.Sprintf("write cr: %v", err)
		return result
	}

	// Read X.224 Connection Confirm (CC TPDU)
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		result.Error = fmt.Sprintf("read cc: %v", err)
		return result
	}
	resp = resp[:n]

	// Parse the response
	selectedProto, negType, parseErr := parseConnectionConfirm(resp)
	if parseErr != nil {
		result.Error = fmt.Sprintf("parse cc: %v", parseErr)
		return result
	}

	if negType == negTypeFailure {
		// Server rejected negotiation — likely only supports standard RDP
		result.RequiresNLA = false
		result.SelectedProtocol = "rdp"
		return result
	}

	result.SelectedProtocol = protocolName(selectedProto)
	result.RequiresNLA = selectedProto&protocolHybrid != 0 || selectedProto&protocolHybridEx != 0

	return result
}

// buildConnectionRequest constructs an X.224 Connection Request (CR) TPDU
// with an RDP Negotiation Request offering all security protocols.
func buildConnectionRequest() []byte {
	// RDP Negotiation Request: type(1) + flags(1) + length(2) + requestedProtocols(4)
	negReq := []byte{
		negTypeRequest, // type: Negotiation Request
		0x00,           // flags
		0x08, 0x00,     // length: 8 bytes (little-endian)
		0x0B, 0x00, 0x00, 0x00, // requestedProtocols: HYBRID | SSL | HYBRID_EX (0x0B = 0x02|0x01|0x08)
	}

	// X.224 CR TPDU: length indicator(1) + CR code(1) + dst_ref(2) + src_ref(2) + class(1) + cookie + negReq
	cookie := []byte("Cookie: mstshash=brutus\r\n")

	x224Len := 1 + 1 + 2 + 2 + 1 + len(cookie) + len(negReq) // length indicator field itself is NOT included
	x224 := make([]byte, 0, x224Len+1)                         // +1 for length indicator byte
	x224 = append(x224, byte(x224Len))                          // length indicator
	x224 = append(x224, 0xE0)                                   // CR TPDU code
	x224 = append(x224, 0x00, 0x00)                             // dst ref
	x224 = append(x224, 0x00, 0x00)                             // src ref
	x224 = append(x224, 0x00)                                   // class and options
	x224 = append(x224, cookie...)
	x224 = append(x224, negReq...)

	// TPKT header: version(1) + reserved(1) + length(2 big-endian)
	tpktLen := 4 + len(x224)
	tpkt := make([]byte, 4, tpktLen)
	tpkt[0] = 0x03 // version
	tpkt[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(tpktLen))
	tpkt = append(tpkt, x224...)

	return tpkt
}

// parseConnectionConfirm parses an X.224 Connection Confirm (CC) TPDU
// and extracts the selected security protocol from the RDP Negotiation Response.
// Returns (selectedProtocol, negotiationType, error).
func parseConnectionConfirm(data []byte) (uint32, byte, error) {
	// Minimum: TPKT(4) + X.224 length(1) + CC code(1) = 6 bytes
	if len(data) < 6 {
		return 0, 0, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Verify TPKT header
	if data[0] != 0x03 {
		return 0, 0, fmt.Errorf("not a TPKT: first byte 0x%02x", data[0])
	}

	tpktLen := int(binary.BigEndian.Uint16(data[2:4]))
	if tpktLen > len(data) {
		return 0, 0, fmt.Errorf("tpkt length %d > data %d", tpktLen, len(data))
	}

	// X.224 CC TPDU starts at offset 4
	x224 := data[4:]
	if len(x224) < 1 {
		return 0, 0, fmt.Errorf("empty x224")
	}
	x224LenIndicator := int(x224[0])
	if len(x224) < x224LenIndicator+1 {
		return 0, 0, fmt.Errorf("x224 truncated")
	}

	// CC code should be 0xD0
	if len(x224) < 2 || x224[1]&0xF0 != 0xD0 {
		return 0, 0, fmt.Errorf("not a CC TPDU: code 0x%02x", x224[1])
	}

	// X.224 CC fixed part: length(1) + code(1) + dst_ref(2) + src_ref(2) + class(1) = 7 bytes
	// RDP Negotiation Response follows at offset 7 (relative to x224 start)
	negStart := 7
	if len(x224) < negStart+1 {
		// No negotiation response — server only supports standard RDP
		return protocolRDP, negTypeResponse, nil
	}

	negType := x224[negStart]

	switch negType {
	case negTypeResponse:
		// Negotiation Response: type(1) + flags(1) + length(2) + selectedProtocol(4) = 8 bytes
		if len(x224) < negStart+8 {
			return 0, negType, fmt.Errorf("negotiation response truncated")
		}
		selectedProto := binary.LittleEndian.Uint32(x224[negStart+4 : negStart+8])
		return selectedProto, negType, nil

	case negTypeFailure:
		return 0, negType, nil

	default:
		return 0, negType, fmt.Errorf("unknown negotiation type: 0x%02x", negType)
	}
}

// protocolName returns a human-readable name for the selected protocol.
func protocolName(proto uint32) string {
	switch {
	case proto&protocolHybridEx != 0:
		return "nla_ex"
	case proto&protocolHybrid != 0:
		return "nla"
	case proto&protocolRDSTLS != 0:
		return "rdstls"
	case proto&protocolSSL != 0:
		return "ssl"
	default:
		return "rdp"
	}
}
