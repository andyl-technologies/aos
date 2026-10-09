//! Linux host-resource enforcement shared by Crucible daemon components.
//!
//! Implementation contract: Linux physical containment, host admission, and operational supervision.
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
//! [`host_services`] owns explicit task, descriptor, and resident-memory permits;
//! [`host_supervision`] owns clone-shared operational caps and progress budgets;
//! [`ram_policy`] owns pure host resource vectors and placement policy contracts.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_project_quota;

pub mod host_services;
pub mod host_supervision;
#[cfg(feature = "private-measurement-domain")]
#[doc(hidden)]
pub mod measurement_origin;
pub mod ram_policy;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use linux_project_quota::{
    LinuxProjectQuotaBinding, LinuxProjectQuotaController, LinuxProjectQuotaError,
    LinuxProjectQuotaInstallError, LinuxProjectQuotaLimits, LinuxProjectQuotaReleaseError,
    LinuxProjectQuotaReservation, validate_project_quota_root,
};

#[doc(hidden)]
#[cfg(feature = "private-measurement-domain")]
pub use linux_project_quota::{
    MeasurementStorageContract, MeasurementStorageError, MeasurementStoragePins,
};
