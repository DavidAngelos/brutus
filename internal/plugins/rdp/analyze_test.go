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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeStickyKeysResponse_Clean(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4

	// Both frames identical (light gray)
	baseline := make([]byte, size)
	response := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 128
		baseline[i+1] = 128
		baseline[i+2] = 128
		baseline[i+3] = 255
		response[i] = 128
		response[i+1] = 128
		response[i+2] = 128
		response[i+3] = 255
	}

	verdict, confidence, _ := analyzeStickyKeysResponse(baseline, response, w, h)
	assert.Equal(t, "clean", verdict)
	assert.LessOrEqual(t, confidence, 0.5)
}

func TestAnalyzeStickyKeysResponse_DarkRectangle(t *testing.T) {
	w, h := uint32(100), uint32(100)
	size := int(w) * int(h) * 4

	// Baseline: all light gray
	baseline := make([]byte, size)
	for i := 0; i < size; i += 4 {
		baseline[i] = 128
		baseline[i+1] = 128
		baseline[i+2] = 128
		baseline[i+3] = 255
	}

	// Response: dark rectangle in center (simulating cmd.exe window)
	response := make([]byte, size)
	copy(response, baseline)
	for y := 20; y < 80; y++ {
		for x := 20; x < 80; x++ {
			idx := (y*int(w) + x) * 4
			response[idx] = 0     // R
			response[idx+1] = 0   // G
			response[idx+2] = 0   // B
			response[idx+3] = 255 // A
		}
	}

	verdict, confidence, _ := analyzeStickyKeysResponse(baseline, response, w, h)
	assert.Contains(t, []string{"backdoor_likely", "vulnerable"}, verdict)
	assert.Greater(t, confidence, 0.0)
}

func TestBitmapDiff(t *testing.T) {
	w, h := uint32(10), uint32(10)
	size := int(w) * int(h) * 4

	a := make([]byte, size)
	b := make([]byte, size)

	// Set first pixel different
	a[0] = 100
	b[0] = 200

	diff := bitmapDiff(a, b, w, h)
	assert.NotNil(t, diff)
	assert.Equal(t, byte(100), diff[0]) // |200-100| = 100
}

func TestRgbaToPNG(t *testing.T) {
	w, h := uint32(2), uint32(2)
	rgba := make([]byte, 16) // 2x2x4
	for i := range rgba {
		rgba[i] = 128
	}

	pngData, err := rgbaToPNG(rgba, w, h)
	assert.NoError(t, err)
	assert.True(t, len(pngData) > 0)
	// PNG magic bytes
	assert.Equal(t, byte(0x89), pngData[0])
	assert.Equal(t, byte(0x50), pngData[1])
}
