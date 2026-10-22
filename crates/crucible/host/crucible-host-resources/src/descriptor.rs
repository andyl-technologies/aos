//! Ownership-consuming descriptor closure at the Linux syscall boundary.
//!
//! The close result is observable without transferring raw-descriptor authority
//! to callers. Resource owners remain responsible for their original accounting
//! and uncertain-close containment.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{IntoRawFd, OwnedFd};

/// Consumes a sole owned descriptor and reports the native close result.
///
/// The descriptor is invalid after this call even when closure reports an
/// error. Callers must not retry closure or reconstruct an owner; this function
/// supplies no resource reservation or authority to open another descriptor.
///
/// # Errors
/// Returns the actual Linux close error, including delayed I/O failures.
pub fn close_owned_descriptor(descriptor: OwnedFd) -> rustix::io::Result<()> {
    let raw = descriptor.into_raw_fd();
    // SAFETY: into_raw_fd transfers one valid owned descriptor exactly once.
    // Linux try_close invalidates it even on failure. This function neither
    // exposes the raw handle nor retries or reconstructs its ownership.
    unsafe { rustix::io::try_close(raw) }
}
