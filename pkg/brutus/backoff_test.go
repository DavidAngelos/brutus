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
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackoffController_BelowThreshold(t *testing.T) {
	bc := newBackoffController(500*time.Millisecond, 30*time.Second, false)
	// Below threshold (3), should return 0
	assert.Equal(t, time.Duration(0), bc.adaptiveDelay())
	bc.recordError()
	assert.Equal(t, time.Duration(0), bc.adaptiveDelay())
	bc.recordError()
	assert.Equal(t, time.Duration(0), bc.adaptiveDelay())
}

func TestBackoffController_AboveThreshold(t *testing.T) {
	bc := newBackoffController(500*time.Millisecond, 30*time.Second, false)
	// Push above threshold
	for i := 0; i < 5; i++ {
		bc.recordError()
	}
	// Should return non-zero delay (probabilistic, but check >0 over multiple samples)
	gotNonZero := false
	for i := 0; i < 100; i++ {
		if bc.adaptiveDelay() > 0 {
			gotNonZero = true
			break
		}
	}
	assert.True(t, gotNonZero, "adaptive delay should be non-zero above threshold")
}

func TestBackoffController_ResetOnSuccess(t *testing.T) {
	bc := newBackoffController(500*time.Millisecond, 30*time.Second, false)
	for i := 0; i < 5; i++ {
		bc.recordError()
	}
	require.True(t, bc.consecutiveErrors.Load() >= 3)
	bc.recordSuccess()
	assert.Equal(t, int64(0), bc.consecutiveErrors.Load())
	assert.Equal(t, time.Duration(0), bc.adaptiveDelay())
}

func TestBackoffController_RetryDelay(t *testing.T) {
	bc := newBackoffController(100*time.Millisecond, 5*time.Second, false)
	// Attempt 0: up to 100ms, Attempt 3: up to 800ms, capped at 5s
	for attempt := 0; attempt < 5; attempt++ {
		delay := bc.retryDelay(attempt)
		maxExpected := time.Duration(float64(100*time.Millisecond) * math.Pow(2, float64(attempt)))
		if maxExpected > 5*time.Second {
			maxExpected = 5 * time.Second
		}
		assert.LessOrEqual(t, delay, maxExpected,
			"retry delay for attempt %d should be <= %v", attempt, maxExpected)
	}
}

func TestBackoffController_MaxDelayCap(t *testing.T) {
	bc := newBackoffController(100*time.Millisecond, 1*time.Second, false)
	// At high levels, delay should never exceed maxDelay
	for i := 0; i < 100; i++ {
		delay := bc.retryDelay(20) // 2^20 * 100ms = huge, but capped at 1s
		assert.LessOrEqual(t, delay, 1*time.Second)
	}
}
