//! Stub IronRDP WASM module for pipeline validation.
//! This will be replaced with real IronRDP integration in Phase 2.

use std::alloc::{alloc, dealloc, Layout};

/// Allocate memory in WASM linear memory.
/// Called by Go host to write data into WASM.
#[no_mangle]
pub extern "C" fn wasm_alloc(size: u32) -> u32 {
    if size == 0 {
        return 0;
    }
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { alloc(layout) as u32 }
}

/// Free memory in WASM linear memory.
/// Called by Go host to clean up allocations.
#[no_mangle]
pub extern "C" fn wasm_dealloc(ptr: u32, size: u32) {
    if ptr == 0 || size == 0 {
        return;
    }
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) }
}

// Connector state constants returned by connector_step
const STATE_NEED_SEND: u32 = 1;
const STATE_NEED_RECV: u32 = 2;
const STATE_NEED_TLS_UPGRADE: u32 = 3;
const STATE_CONNECTED: u32 = 4;
const STATE_ERROR: u32 = 5;

/// Create a new RDP connector. Returns a handle (non-zero on success, 0 on error).
/// config_ptr/config_len: JSON config bytes in WASM memory.
/// Stub: ignores config, returns handle=1.
#[no_mangle]
pub extern "C" fn connector_new(config_ptr: u32, config_len: u32) -> u32 {
    // Stub: return a dummy handle
    if config_len == 0 {
        return 0; // Error: empty config
    }
    1 // Dummy handle
}

/// Step the connector state machine.
/// Returns: state code (see STATE_* constants).
/// output_ptr_out/output_len_out: set to point at output bytes in WASM memory.
/// Stub: immediately returns CONNECTED.
#[no_mangle]
pub extern "C" fn connector_step(
    handle: u32,
    input_ptr: u32,
    input_len: u32,
    output_ptr_out: u32,
    output_len_out: u32,
) -> u32 {
    if handle == 0 {
        return STATE_ERROR;
    }
    // Stub: write zeros to output pointers and return CONNECTED
    STATE_CONNECTED
}

/// Free a connector handle.
#[no_mangle]
pub extern "C" fn connector_free(handle: u32) {
    // Stub: nothing to free
}

/// Return the version string for diagnostics.
/// Writes version bytes to a pre-allocated buffer at ptr.
/// Returns actual length written.
#[no_mangle]
pub extern "C" fn version(ptr: u32, max_len: u32) -> u32 {
    let v = b"ironrdp-wasm-stub-0.1.0";
    let len = v.len().min(max_len as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(v.as_ptr(), ptr as *mut u8, len);
    }
    len as u32
}
