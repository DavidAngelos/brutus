//! WASM memory allocator exports.
//! Go host uses these to allocate/free memory in WASM linear memory
//! for passing data across the boundary.

use std::alloc::{alloc, dealloc, Layout};

/// Allocate `size` bytes in WASM linear memory.
/// Returns pointer to allocated memory, or 0 on failure.
#[no_mangle]
pub extern "C" fn wasm_alloc(size: u32) -> u32 {
    if size == 0 {
        return 0;
    }
    let layout = match Layout::from_size_align(size as usize, 8) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        0
    } else {
        ptr as u32
    }
}

/// Free `size` bytes at `ptr` in WASM linear memory.
#[no_mangle]
pub extern "C" fn wasm_dealloc(ptr: u32, size: u32) {
    if ptr == 0 || size == 0 {
        return;
    }
    let layout = match Layout::from_size_align(size as usize, 8) {
        Ok(l) => l,
        Err(_) => return,
    };
    unsafe { dealloc(ptr as *mut u8, layout) }
}
