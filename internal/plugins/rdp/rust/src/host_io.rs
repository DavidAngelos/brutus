//! Host function declarations.
//! These are implemented by Go via wazero host module builder.
//! The Rust code calls these to perform I/O operations.
//!
//! Note: Most host functions are declared but not yet called from Rust code.
//! They are used by the Go host function bridge (wasm.go) for direct I/O.
//! The safe wrappers will be used in Phase 3 for full CredSSP implementation.

#![allow(dead_code)]

extern "C" {
    /// Read up to `buf_len` bytes from the network connection into WASM memory at `buf_ptr`.
    /// Returns bytes read on success, -1 on error.
    pub fn host_tcp_read(fd: u32, buf_ptr: u32, buf_len: u32) -> i32;

    /// Write `buf_len` bytes from WASM memory at `buf_ptr` to the network connection.
    /// Returns bytes written on success, -1 on error.
    pub fn host_tcp_write(fd: u32, buf_ptr: u32, buf_len: u32) -> i32;

    /// Upgrade the TCP connection to TLS.
    /// Returns 0 on success, -1 on error.
    pub fn host_tls_upgrade(fd: u32) -> i32;

    /// Get current time in milliseconds since epoch.
    pub fn host_clock_now_ms() -> u64;

    /// Fill buffer with cryptographically secure random bytes.
    /// Returns 0 on success, -1 on error.
    pub fn host_random_fill(buf_ptr: u32, buf_len: u32) -> i32;

    /// Log a message to the Go host.
    /// level: 0=debug, 1=info, 2=warn, 3=error
    pub fn host_log(level: u32, msg_ptr: u32, msg_len: u32);

    /// Get the TLS server's public key (SubjectPublicKeyInfo DER).
    /// Writes up to buf_len bytes to buf_ptr.
    /// Returns bytes written on success, -1 on error.
    pub fn host_get_tls_server_pubkey(buf_ptr: u32, buf_len: u32) -> i32;
}

/// Safe wrapper: read from network into a Vec<u8>.
pub fn tcp_read(fd: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
    let mut buf = vec![0u8; max_len];
    let n = unsafe { host_tcp_read(fd, buf.as_mut_ptr() as u32, max_len as u32) };
    if n < 0 {
        return Err("tcp read failed");
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Safe wrapper: write bytes to network.
pub fn tcp_write(fd: u32, data: &[u8]) -> Result<usize, &'static str> {
    let n = unsafe { host_tcp_write(fd, data.as_ptr() as u32, data.len() as u32) };
    if n < 0 {
        return Err("tcp write failed");
    }
    Ok(n as usize)
}

/// Safe wrapper: upgrade to TLS.
pub fn tls_upgrade(fd: u32) -> Result<(), &'static str> {
    let result = unsafe { host_tls_upgrade(fd) };
    if result < 0 {
        return Err("tls upgrade failed");
    }
    Ok(())
}

/// Safe wrapper: fill buffer with random bytes.
pub fn random_fill(buf: &mut [u8]) -> Result<(), &'static str> {
    let result = unsafe { host_random_fill(buf.as_mut_ptr() as u32, buf.len() as u32) };
    if result < 0 {
        return Err("random fill failed");
    }
    Ok(())
}

/// Safe wrapper: log message to host.
pub fn log_msg(level: u32, msg: &str) {
    unsafe { host_log(level, msg.as_ptr() as u32, msg.len() as u32) }
}

/// Safe wrapper: get TLS server public key (SubjectPublicKeyInfo DER).
pub fn get_tls_server_pubkey() -> Result<Vec<u8>, &'static str> {
    // Allocate a 4KB buffer for the public key (more than enough for RSA/EC keys)
    let mut buf = vec![0u8; 4096];
    let n = unsafe { host_get_tls_server_pubkey(buf.as_mut_ptr() as u32, buf.len() as u32) };
    if n < 0 {
        return Err("get tls server pubkey failed");
    }
    buf.truncate(n as usize);
    Ok(buf)
}
