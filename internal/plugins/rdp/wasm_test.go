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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitEngine(t *testing.T) {
	eng, err := initEngine()
	require.NoError(t, err)
	assert.NotNil(t, eng)
	assert.NotNil(t, eng.runtime)
	assert.NotNil(t, eng.compiled)
}

func TestWasmAllocDealloc(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	// Create instance without a real connection (nil conn for unit test)
	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	// Test alloc
	allocFn := inst.mod.ExportedFunction("wasm_alloc")
	require.NotNil(t, allocFn, "wasm_alloc must be exported")

	results, err := allocFn.Call(ctx, 64)
	require.NoError(t, err)
	ptr := uint32(results[0])
	assert.NotZero(t, ptr, "alloc should return non-zero pointer")

	// Test dealloc (should not panic)
	deallocFn := inst.mod.ExportedFunction("wasm_dealloc")
	require.NotNil(t, deallocFn, "wasm_dealloc must be exported")

	_, err = deallocFn.Call(ctx, uint64(ptr), 64)
	assert.NoError(t, err)
}

func TestWasmMemoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	// Write data to WASM memory
	testData := []byte("hello from Go!")
	ptr, length, err := inst.writeToWasm(ctx, testData)
	require.NoError(t, err)
	assert.NotZero(t, ptr)
	assert.Equal(t, uint32(len(testData)), length)

	// Read it back
	readBack, err := inst.readFromWasm(ptr, length)
	require.NoError(t, err)
	assert.Equal(t, testData, readBack)

	// Clean up
	inst.freeInWasm(ctx, ptr, length)
}

func TestWasmConnectorNew(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	connectorNewFn := inst.mod.ExportedFunction("connector_new")
	require.NotNil(t, connectorNewFn, "connector_new must be exported")

	// Write a dummy config
	config := []byte(`{"server":"test"}`)
	ptr, length, err := inst.writeToWasm(ctx, config)
	require.NoError(t, err)

	// Call connector_new
	results, err := connectorNewFn.Call(ctx, uint64(ptr), uint64(length))
	require.NoError(t, err)
	handle := uint32(results[0])
	assert.NotZero(t, handle, "connector_new should return non-zero handle")

	// Clean up
	connectorFreeFn := inst.mod.ExportedFunction("connector_free")
	require.NotNil(t, connectorFreeFn)
	_, err = connectorFreeFn.Call(ctx, uint64(handle))
	assert.NoError(t, err)

	inst.freeInWasm(ctx, ptr, length)
}

func TestWasmConnectorNewEmptyConfig(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	connectorNewFn := inst.mod.ExportedFunction("connector_new")
	require.NotNil(t, connectorNewFn)

	// Empty config should return 0 (error)
	results, err := connectorNewFn.Call(ctx, 0, 0)
	require.NoError(t, err)
	handle := uint32(results[0])
	assert.Zero(t, handle, "connector_new with empty config should return 0")
}

func TestWasmVersion(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	versionFn := inst.mod.ExportedFunction("version")
	require.NotNil(t, versionFn, "version must be exported")

	// Allocate buffer for version string
	bufSize := uint32(64)
	ptr, _, err := inst.writeToWasm(ctx, make([]byte, bufSize))
	require.NoError(t, err)

	results, err := versionFn.Call(ctx, uint64(ptr), uint64(bufSize))
	require.NoError(t, err)
	length := uint32(results[0])
	assert.Greater(t, length, uint32(0))

	version, err := inst.readFromWasm(ptr, length)
	require.NoError(t, err)
	assert.Contains(t, string(version), "ironrdp-wasm")

	inst.freeInWasm(ctx, ptr, bufSize)
}

func TestWasmExportsExist(t *testing.T) {
	ctx := context.Background()
	eng, err := initEngine()
	require.NoError(t, err)

	inst, err := newInstance(ctx, eng, nil)
	require.NoError(t, err)
	defer inst.close(ctx)

	requiredExports := []string{
		"wasm_alloc",
		"wasm_dealloc",
		"connector_new",
		"connector_step",
		"connector_free",
		"version",
	}

	for _, name := range requiredExports {
		fn := inst.mod.ExportedFunction(name)
		assert.NotNil(t, fn, "required export %q must exist", name)
	}
}
