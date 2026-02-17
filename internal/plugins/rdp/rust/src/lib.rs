//! IronRDP WASM module for Brutus RDP authentication and session testing.
//!
//! Exports:
//! - wasm_alloc/wasm_dealloc: memory management
//! - connector_new/step/free: RDP connector state machine
//! - session_new/step/send_key/get_frame/free: RDP session management
//! - version: module version string

mod allocator;
mod connector;
mod host_io;
mod session;

use connector::ConnectorHandle;
use session::SessionHandle;
use std::collections::HashMap;
use std::sync::Mutex;

// Re-export allocator functions
pub use allocator::{wasm_alloc, wasm_dealloc};

/// Global handle table for connector and session instances.
/// Protected by mutex for safety (though WASM is single-threaded).
static HANDLES: Mutex<Option<HandleTable>> = Mutex::new(None);

struct HandleTable {
    next_id: u32,
    connectors: HashMap<u32, ConnectorHandle>,
    sessions: HashMap<u32, SessionHandle>,
}

impl HandleTable {
    fn new() -> Self {
        HandleTable {
            next_id: 1,
            connectors: HashMap::new(),
            sessions: HashMap::new(),
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

    fn insert_session(&mut self, handle: SessionHandle) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(id, handle);
        id
    }

    fn get_session_mut(&mut self, id: u32) -> Option<&mut SessionHandle> {
        self.sessions.get_mut(&id)
    }

    fn remove_session(&mut self, id: u32) {
        self.sessions.remove(&id);
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

// ---------------------------------------------------------------------------
// Connector WASM exports
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Session WASM exports
// ---------------------------------------------------------------------------

/// Create a new RDP session from a connected connector handle.
///
/// Takes the ConnectionResult from the connector (consuming it) and creates
/// a session with the specified screen dimensions.
/// Returns session handle (non-zero) on success, 0 on error.
#[no_mangle]
pub extern "C" fn session_new(connector_handle: u32, width: u32, height: u32) -> u32 {
    with_handles(|t| {
        // Take the connection result from the connector
        let connection_result = match t.get_mut(connector_handle) {
            Some(conn) => conn.take_connection_result(),
            None => return 0,
        };

        let connection_result = match connection_result {
            Some(cr) => cr,
            None => return 0, // Not connected or already consumed
        };

        match SessionHandle::new(connection_result, width as u16, height as u16) {
            Ok(session) => t.insert_session(session),
            Err(_) => 0,
        }
    })
}

/// Process incoming server data through the session.
///
/// Returns state code (STATE_SESSION_NEED_SEND, STATE_SESSION_NEED_RECV,
/// STATE_FRAME_AVAILABLE, STATE_SESSION_ERROR).
/// Response bytes to send back to the server are written to output_ptr_out/output_len_out.
#[no_mangle]
pub extern "C" fn session_step(
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

    let (state, output) = with_handles(|t| match t.get_session_mut(handle) {
        Some(sess) => sess.process_server_data(input),
        None => (session::STATE_SESSION_ERROR, Vec::new()),
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
                std::ptr::write(output_ptr_out as *mut u32, out_ptr);
                std::ptr::write(output_len_out as *mut u32, output.len() as u32);
            }
        }
    }

    state
}

/// Send a keyboard key event through the session.
///
/// scancode: USB HID scancode (u16 encoded as u32)
/// pressed: 1 for key down, 0 for key up
/// Returns state code. Response bytes written to output slots.
#[no_mangle]
pub extern "C" fn session_send_key(
    handle: u32,
    scancode: u32,
    pressed: u32,
    output_ptr_out: u32,
    output_len_out: u32,
) -> u32 {
    let (state, output) = with_handles(|t| match t.get_session_mut(handle) {
        Some(sess) => sess.send_key(scancode as u16, pressed != 0),
        None => (session::STATE_SESSION_ERROR, Vec::new()),
    });

    if !output.is_empty() {
        let out_ptr = wasm_alloc(output.len() as u32);
        if out_ptr != 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    output.as_ptr(),
                    out_ptr as *mut u8,
                    output.len(),
                );
                std::ptr::write(output_ptr_out as *mut u32, out_ptr);
                std::ptr::write(output_len_out as *mut u32, output.len() as u32);
            }
        }
    }

    state
}

/// Get the current session framebuffer as RGBA pixel data.
///
/// Writes the frame data pointer and length to output_ptr_out/output_len_out.
/// Returns packed (width << 16 | height) on success, 0 on error.
///
/// Note: The returned pointer points directly into the session's image buffer.
/// The caller must copy the data before the next session operation.
#[no_mangle]
pub extern "C" fn session_get_frame(
    handle: u32,
    output_ptr_out: u32,
    output_len_out: u32,
) -> u32 {
    with_handles(|t| match t.get_session_mut(handle) {
        Some(sess) => {
            let frame_data = sess.get_frame_rgba();
            if frame_data.is_empty() {
                return 0;
            }

            // Allocate WASM memory and copy the frame data
            let out_ptr = wasm_alloc(frame_data.len() as u32);
            if out_ptr == 0 {
                return 0;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    frame_data.as_ptr(),
                    out_ptr as *mut u8,
                    frame_data.len(),
                );
                std::ptr::write(output_ptr_out as *mut u32, out_ptr);
                std::ptr::write(output_len_out as *mut u32, frame_data.len() as u32);
            }

            // Return packed width|height
            let w = sess.width() as u32;
            let h = sess.height() as u32;
            (w << 16) | h
        }
        None => 0,
    })
}

/// Free a session handle.
#[no_mangle]
pub extern "C" fn session_free(handle: u32) {
    with_handles(|t| t.remove_session(handle));
}

// ---------------------------------------------------------------------------
// Utility WASM exports
// ---------------------------------------------------------------------------

/// Write version string to buffer. Returns bytes written.
#[no_mangle]
pub extern "C" fn version(ptr: u32, max_len: u32) -> u32 {
    let v = b"ironrdp-wasm-0.2.0";
    let len = v.len().min(max_len as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(v.as_ptr(), ptr as *mut u8, len);
    }
    len as u32
}
