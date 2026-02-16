//! IronRDP WASM module for Brutus RDP authentication testing.
//!
//! Exports:
//! - wasm_alloc/wasm_dealloc: memory management
//! - connector_new/step/free: RDP connector state machine
//! - version: module version string

mod allocator;
mod connector;
mod host_io;

use connector::ConnectorHandle;
use std::collections::HashMap;
use std::sync::Mutex;

// Re-export allocator functions
pub use allocator::{wasm_alloc, wasm_dealloc};

/// Global handle table for connector instances.
/// Protected by mutex for safety (though WASM is single-threaded).
static HANDLES: Mutex<Option<HandleTable>> = Mutex::new(None);

struct HandleTable {
    next_id: u32,
    connectors: HashMap<u32, ConnectorHandle>,
}

impl HandleTable {
    fn new() -> Self {
        HandleTable {
            next_id: 1,
            connectors: HashMap::new(),
        }
    }

    fn insert(&mut self, handle: ConnectorHandle) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.connectors.insert(id, handle);
        id
    }

    fn get_mut(&mut self, id: u32) -> Option<&mut ConnectorHandle> {
        self.connectors.get_mut(&id)
    }

    fn remove(&mut self, id: u32) {
        self.connectors.remove(&id);
    }
}

fn with_handles<F, R>(f: F) -> R
where
    F: FnOnce(&mut HandleTable) -> R,
{
    let mut guard = HANDLES.lock().unwrap();
    let table = guard.get_or_insert_with(HandleTable::new);
    f(table)
}

/// Create a new RDP connector from JSON config.
/// Returns handle (non-zero) on success, 0 on error.
#[no_mangle]
pub extern "C" fn connector_new(config_ptr: u32, config_len: u32) -> u32 {
    if config_len == 0 {
        return 0;
    }

    let config_bytes = unsafe {
        std::slice::from_raw_parts(config_ptr as *const u8, config_len as usize)
    };

    match ConnectorHandle::new(config_bytes) {
        Ok(handle) => with_handles(|t| t.insert(handle)),
        Err(_) => 0,
    }
}

/// Step the connector state machine.
/// Returns state code (STATE_NEED_SEND, STATE_NEED_RECV, STATE_CONNECTED, STATE_ERROR).
/// Output bytes are written to WASM memory at output_ptr_out/output_len_out.
#[no_mangle]
pub extern "C" fn connector_step(
    handle: u32,
    input_ptr: u32,
    input_len: u32,
    output_ptr_out: u32,
    output_len_out: u32,
) -> u32 {
    let input = if input_len > 0 {
        unsafe { std::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) }
    } else {
        &[]
    };

    let (state, output) = with_handles(|t| match t.get_mut(handle) {
        Some(conn) => conn.step(input),
        None => (connector::STATE_ERROR, Vec::new()),
    });

    // Write output to WASM memory if there is any
    if !output.is_empty() {
        let out_ptr = wasm_alloc(output.len() as u32);
        if out_ptr != 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    output.as_ptr(),
                    out_ptr as *mut u8,
                    output.len(),
                );
                // Write pointer and length to the output slots
                std::ptr::write(output_ptr_out as *mut u32, out_ptr);
                std::ptr::write(output_len_out as *mut u32, output.len() as u32);
            }
        }
    }

    state
}

/// Free a connector handle.
#[no_mangle]
pub extern "C" fn connector_free(handle: u32) {
    with_handles(|t| t.remove(handle));
}

/// Write version string to buffer. Returns bytes written.
#[no_mangle]
pub extern "C" fn version(ptr: u32, max_len: u32) -> u32 {
    let v = b"ironrdp-wasm-0.1.0";
    let len = v.len().min(max_len as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(v.as_ptr(), ptr as *mut u8, len);
    }
    len as u32
}
