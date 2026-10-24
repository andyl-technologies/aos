//! Retains guest-memory write refusals without formatting on a live callback.
//!
//! Coordinate and native-write failures keep their original fields. Explicit
//! diagnostic requests may allocate; Display writes to the caller's formatter.
// SPDX-License-Identifier: GPL-2.0-only

use std::borrow::Cow;
use thiserror::Error;

/// A loud white-box guest-input write failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WhiteboxGuestInputWriteError {
    /// Retains the backend's original static or owned diagnostic.
    #[error("white-box guest input write failed: {message}")]
    Diagnostic {
        /// Original backend diagnostic without the common error prefix.
        message: Cow<'static, str>,
    },
    /// The input does not belong to the current doorbell callback.
    #[error(
        "white-box guest input write failed: delivery icount {delivery_icount} differs from callback icount {callback_icount}"
    )]
    CallbackIcountMismatch {
        /// Requested delivery retirement count.
        delivery_icount: u64,
        /// Actual callback retirement count.
        callback_icount: u64,
    },
    /// The deferred reply does not belong to the current resume boundary.
    #[error(
        "white-box guest input write failed: delivery icount {delivery_icount} differs from resume icount {resume_icount}"
    )]
    ResumeIcountMismatch {
        /// Requested delivery retirement count.
        delivery_icount: u64,
        /// Actual resumed retirement count.
        resume_icount: u64,
    },
    /// QEMU refused the exact per-vCPU virtual reply write.
    #[error(
        "white-box guest input write failed: qemu_plugin_crucible_write_memory_vaddr_for_vcpu failed for vCPU {vcpu_index} at guest virtual address {guest_address:#x} with {payload_len} bytes at resume icount {resume_icount}"
    )]
    VirtualReplyWriteRejected {
        /// vCPU passed to QEMU's guest-memory API.
        vcpu_index: u32,
        /// Guest virtual address passed to QEMU.
        guest_address: u64,
        /// Number of reply bytes passed to QEMU.
        payload_len: usize,
        /// Retirement count of the actual resume callback.
        resume_icount: u64,
    },
}

impl WhiteboxGuestInputWriteError {
    /// Builds a guest-input write error from an owned backend diagnostic.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::Diagnostic {
            message: Cow::Owned(message.into()),
        }
    }

    /// Retains a static backend diagnostic without allocating a string.
    #[must_use]
    pub const fn from_static(message: &'static str) -> Self {
        Self::Diagnostic {
            message: Cow::Borrowed(message),
        }
    }

    /// Returns the backend diagnostic without its common error prefix.
    ///
    /// Static and owned backend diagnostics borrow their original storage.
    /// Typed refusals are formatted only on this explicit reporting call;
    /// Display writes their fields directly to the caller's formatter.
    #[must_use]
    pub fn message(&self) -> Cow<'_, str> {
        match self {
            Self::Diagnostic { message } => Cow::Borrowed(message),
            Self::CallbackIcountMismatch {
                delivery_icount,
                callback_icount,
            } => Cow::Owned(format!(
                "delivery icount {delivery_icount} differs from callback icount {callback_icount}"
            )),
            Self::ResumeIcountMismatch {
                delivery_icount,
                resume_icount,
            } => Cow::Owned(format!(
                "delivery icount {delivery_icount} differs from resume icount {resume_icount}"
            )),
            Self::VirtualReplyWriteRejected {
                vcpu_index,
                guest_address,
                payload_len,
                resume_icount,
            } => Cow::Owned(format!(
                "qemu_plugin_crucible_write_memory_vaddr_for_vcpu failed for vCPU {vcpu_index} at guest virtual address {guest_address:#x} with {payload_len} bytes at resume icount {resume_icount}"
            )),
        }
    }
}
