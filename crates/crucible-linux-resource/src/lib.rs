//! Linux host-resource enforcement shared by Crucible daemon components.
//!
//! This crate owns the narrow raw-kernel boundary for ext4 project quotas.
//! [`LinuxProjectQuotaReservation`] installs and later releases an ephemeral
//! quota for one attempt directory. [`LinuxProjectQuotaBinder`] safely binds a
//! persistent CAS leaf to an operator-installed quota without granting quota
//! mutation authority to the store graph.
//!
//! The crate is Apache-licensed host code. It neither links QEMU nor crosses
//! the Crucible Unix-socket/shared-memory process protocol boundary.
//!
//! Unsafe boundary discipline:
//! - public callers use safe quota capability types;
//! - wrappers validate pinned filesystem and syscall invariants.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_project_quota;

#[cfg(feature = "cas")]
pub use linux_project_quota::LinuxProjectQuotaBinder;
pub use linux_project_quota::{
    LinuxProjectQuotaError, LinuxProjectQuotaInstallError, LinuxProjectQuotaLimits,
    LinuxProjectQuotaReleaseError, LinuxProjectQuotaReservation, validate_project_quota_root,
};
