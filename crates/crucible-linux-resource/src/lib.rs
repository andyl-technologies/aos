//! Linux host-resource enforcement shared by Crucible daemon components.
//!
//! Spec index: RFC-0020 files 04a, 06.
//!
//! This crate owns narrow raw-kernel boundaries for ext4 project quotas and
//! original descriptor read leases.
//! [`LinuxProjectQuotaReservation`] installs and later releases an ephemeral
//! quota for one attempt directory. [`LinuxProjectQuotaBinding`] safely pins
//! and verifies an operator-installed persistent quota without importing a
//! higher-layer storage interface.
//!
//! The crate is Apache-licensed host code. It neither links QEMU nor crosses
//! the Crucible Unix-socket/shared-memory process protocol boundary.
//!
//! Unsafe boundary discipline:
//! - public callers use safe resource capability types;
//! - wrappers validate pinned filesystem and syscall invariants.
//!
//! Module map: the private `linux_project_quota` module owns pinned ext4 project-quota
//! installation, usage verification, and fail-closed release authority. The private
//! `linux_read_lease` module owns one-time kernel read leases and their isolated
//! notification threads; callers retain complete measurements and namespace fences.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_project_quota;

pub use linux_project_quota::{
    LinuxProjectQuotaBinding, LinuxProjectQuotaError, LinuxProjectQuotaInstallError,
    LinuxProjectQuotaLimits, LinuxProjectQuotaReleaseError, LinuxProjectQuotaReservation,
    validate_project_quota_root,
};

mod linux_read_lease;

pub use linux_read_lease::{
    LinuxReadLease, LinuxReadLeaseError, LinuxReadLeaseFile, LinuxReadLeaseOwner,
};
