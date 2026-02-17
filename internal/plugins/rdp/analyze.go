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
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

const (
	// darkThreshold: pixel brightness below this is considered "dark"
	darkThreshold = 30
	// minDarkRegionPercent: minimum percentage of new dark pixels for detection
	minDarkRegionPercent = 2.0
	// maxDarkRegionPercent: maximum percentage (above this, probably screen went black)
	maxDarkRegionPercent = 80.0
)

// bitmapDiff computes the absolute difference between two RGBA buffers.
// Returns a diff buffer of the same size where each pixel is the max channel diff.
func bitmapDiff(baseline, response []byte, width, height uint32) []byte {
	size := int(width) * int(height) * 4
	if len(baseline) < size || len(response) < size {
		return nil
	}

	diff := make([]byte, size)
	for i := 0; i < size; i += 4 {
		dr := absDiffByte(baseline[i], response[i])
		dg := absDiffByte(baseline[i+1], response[i+1])
		db := absDiffByte(baseline[i+2], response[i+2])
		maxD := maxByte(dr, maxByte(dg, db))
		diff[i] = maxD
		diff[i+1] = maxD
		diff[i+2] = maxD
		diff[i+3] = 255
	}
	return diff
}

func absDiffByte(a, b byte) byte {
	if a > b {
		return a - b
	}
	return b - a
}

func maxByte(a, b byte) byte {
	if a > b {
		return a
	}
	return b
}

// analyzeStickyKeysResponse analyzes the difference between baseline and response frames.
// Returns (verdict, confidence, description).
func analyzeStickyKeysResponse(baseline, response []byte, width, height uint32) (verdict string, confidence float64, description string) {
	totalPixels := int(width) * int(height)
	if totalPixels == 0 {
		return "clean", 0, "no pixels to analyze"
	}

	// Count new dark pixels in response that weren't dark in baseline
	newDarkPixels := 0
	for i := 0; i < totalPixels*4; i += 4 {
		if i+2 >= len(response) || i+2 >= len(baseline) {
			break
		}
		baselineBright := (int(baseline[i]) + int(baseline[i+1]) + int(baseline[i+2])) / 3
		responseBright := (int(response[i]) + int(response[i+1]) + int(response[i+2])) / 3

		if responseBright < darkThreshold && baselineBright >= darkThreshold {
			newDarkPixels++
		}
	}

	darkPercent := float64(newDarkPixels) / float64(totalPixels) * 100.0

	if darkPercent < minDarkRegionPercent {
		return "clean", 0, fmt.Sprintf("%.1f%% new dark pixels (below %.1f%% threshold)", darkPercent, minDarkRegionPercent)
	}

	if darkPercent > maxDarkRegionPercent {
		return "clean", 0, fmt.Sprintf("%.1f%% new dark pixels (screen went dark, not a window)", darkPercent)
	}

	// Check if the dark region is rectangular (characteristic of cmd.exe window)
	isRect, rectScore := detectDarkRectangle(response, width, height, baseline)

	if isRect && darkPercent > 5.0 {
		confidence := math.Min(0.85, darkPercent/20.0+rectScore*0.5)
		return "backdoor_likely", confidence,
			fmt.Sprintf("%.1f%% new dark pixels in rectangular region (rect score: %.2f)", darkPercent, rectScore)
	}

	if darkPercent > 3.0 {
		return "vulnerable", 0.3,
			fmt.Sprintf("%.1f%% new dark pixels (possibly sticky keys dialog)", darkPercent)
	}

	return "clean", 0.1, fmt.Sprintf("%.1f%% new dark pixels (minor change)", darkPercent)
}

// detectDarkRectangle checks if new dark pixels form a rectangular region.
// Returns (isRectangular, score) where score is 0-1 indicating rectangularity.
func detectDarkRectangle(response []byte, width, height uint32, baseline []byte) (isRectangular bool, score float64) {
	w := int(width)
	h := int(height)

	// Find bounding box of new dark pixels
	minX, minY := w, h
	maxX, maxY := 0, 0
	darkCount := 0

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := (y*w + x) * 4
			if idx+2 >= len(response) || idx+2 >= len(baseline) {
				continue
			}
			responseBright := (int(response[idx]) + int(response[idx+1]) + int(response[idx+2])) / 3
			baselineBright := (int(baseline[idx]) + int(baseline[idx+1]) + int(baseline[idx+2])) / 3

			if responseBright < darkThreshold && baselineBright >= darkThreshold {
				darkCount++
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}

	if darkCount == 0 || maxX <= minX || maxY <= minY {
		return false, 0
	}

	// Calculate what fraction of the bounding box is filled with dark pixels
	boundingArea := (maxX - minX + 1) * (maxY - minY + 1)
	fillRatio := float64(darkCount) / float64(boundingArea)

	// A cmd.exe window should fill its bounding box at least 60%
	isRect := fillRatio > 0.6 && boundingArea > (w*h/100) // At least 1% of screen
	return isRect, fillRatio
}

// rgbaToPNG converts RGBA pixel data to a PNG byte buffer.
func rgbaToPNG(rgba []byte, width, height uint32) ([]byte, error) {
	w := int(width)
	h := int(height)

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := (y*w + x) * 4
			if idx+3 >= len(rgba) {
				break
			}
			img.SetRGBA(x, y, color.RGBA{
				R: rgba[idx],
				G: rgba[idx+1],
				B: rgba[idx+2],
				A: rgba[idx+3],
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), nil
}

// runStickyKeysAnalysis performs the dual-check: heuristic first, then Vision API if available.
func runStickyKeysAnalysis(ctx context.Context, baseline, response []byte,
	width, height uint32, visionAPIKey string) StickyKeysResult {

	result := StickyKeysResult{Performed: true}

	// Step 1: Heuristic analysis
	verdict, confidence, description := analyzeStickyKeysResponse(baseline, response, width, height)
	result.HeuristicResult = description

	if verdict == "clean" {
		result.OverallVerdict = "clean"
		result.Confidence = confidence
		return result
	}

	// Step 2: Try Vision API for confirmation if key available
	if visionAPIKey != "" {
		pngData, err := rgbaToPNG(response, width, height)
		if err == nil {
			visionVerdict, visionDesc := analyzeStickyKeysVision(ctx, pngData, visionAPIKey)
			result.VisionResult = visionDesc

			if visionVerdict == "backdoor_confirmed" {
				result.OverallVerdict = "backdoor_confirmed"
				result.Confidence = math.Min(1.0, confidence+0.3)
				return result
			}

			if visionVerdict == "clean" && verdict == "backdoor_likely" {
				// Heuristic says backdoor, Vision says clean -- downgrade
				result.OverallVerdict = "vulnerable"
				result.Confidence = confidence * 0.5
				return result
			}
		}
	}

	// Use heuristic result as final
	result.OverallVerdict = verdict
	result.Confidence = confidence
	return result
}
