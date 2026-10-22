//! Installs the explicitly selected exec Main stack ceiling before loading code.
//!
//! This physical process control supplies no stack credit or semantic loan.
//! The actual process creator must retain the separately admitted backing,
//! loader/TLS inventory and cleanup owner through genuine child reap. The
//! optional scalar lives in the same prepaid attempt binding as other limits;
//! every duplicate observes one immutable selection before the first launch.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::atomic::Ordering;

use rustix::process::{Resource, Rlimit};

use super::{AttemptResourceBinding, QemuChildProcessContract};

impl QemuChildProcessContract {
    /// Selects the exact finite soft and hard exec Main stack limit once.
    ///
    /// Every duplicate shares this selection. Guarded QEMU and image-helper
    /// launches install it before exec and independently read back both limits.
    /// Without a selection, launch retains its existing inherited stack policy.
    ///
    /// This configures kernel containment only. It does not reserve backing,
    /// authenticate a stack grant, select an ABI profile or fund another thread.
    /// The containing issuer must retain those actual owners before launch.
    ///
    /// # Errors
    /// Refuses zero, infinity, a repeated selection, concurrent refinement, or
    /// any selection after the first attempted launch. A successful selection
    /// cannot be changed even when a later launch fails.
    pub fn configure_main_stack_limit(&self, bytes: u64) -> io::Result<()> {
        if bytes == 0 || bytes == libc::RLIM_INFINITY {
            return Err(refused(libc::EINVAL));
        }
        self.attempt_binding.configure_main_stack(bytes)
    }

    /// Returns the shared physical stack selection without issuing credit.
    #[must_use]
    pub fn main_stack_limit(&self) -> Option<u64> {
        selected_limit(&self.attempt_binding)
    }
}

/// Keeps refusal delivery inside the existing fixed control budget.
pub(super) fn refused(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

pub(super) fn selected_limit(binding: &AttemptResourceBinding) -> Option<u64> {
    match binding.main_stack_bytes.load(Ordering::Acquire) {
        0 => None,
        bytes => Some(bytes),
    }
}

/// Performs both scalar syscalls even when installation refuses.
///
/// Both wrappers use fixed syscall storage, without allocation or locks. They
/// are suitable for the existing child pre-exec cut. The readback corroborates
/// physical configuration; it cannot construct the containing resource owner.
pub(super) fn install_and_verify(bytes: u64) -> io::Result<()> {
    let expected = Rlimit {
        current: Some(bytes),
        maximum: Some(bytes),
    };
    let installed = rustix::process::setrlimit(Resource::Stack, expected);
    let actual = rustix::process::getrlimit(Resource::Stack);

    installed?;
    if actual != expected {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(())
}
