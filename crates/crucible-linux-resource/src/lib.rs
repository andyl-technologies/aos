//! Linux host-resource enforcement shared by Crucible daemon components.
//!
//! Spec index: RFC-0020 files 04a, 06.
//!
//! This crate owns the narrow raw-kernel boundary for ext4 project quotas.
//! [`LinuxProjectQuotaReservation`] installs and later releases an ephemeral
//! quota for one attempt directory. [`LinuxProjectQuotaBinding`] safely pins
//! and verifies an operator-installed persistent quota without importing a
//! higher-layer storage interface.
//!
//! The crate is Apache-licensed host code. It neither links QEMU nor crosses
//! the Crucible Unix-socket/shared-memory process protocol boundary.
//!
//! Unsafe boundary discipline:
//! - public callers use safe quota capability types;
//! - wrappers validate pinned filesystem and syscall invariants.
//!
//! Module map: the private `linux_project_quota` module owns pinned ext4 project-quota
//! installation, usage verification, and fail-closed release authority.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_project_quota;

pub use linux_project_quota::{
    LinuxProjectQuotaBinding, LinuxProjectQuotaError, LinuxProjectQuotaInstallError,
    LinuxProjectQuotaLimits, LinuxProjectQuotaReleaseError, LinuxProjectQuotaReservation,
    validate_project_quota_root,
};
