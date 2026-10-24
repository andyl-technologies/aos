//! Owns Crucible's host-resource admission, supervision, and placement policy.
//!
//! Implementation contract: Linux physical containment, host admission, and operational supervision.
//!
//! Module map:
//!
//! [`host_services`] retains actual task, descriptor, and memory permits;
//! [`host_supervision`] checks the same operational clocks and progress bounds;
//! [`ram_policy`] defines placement policy and physical resource vectors.
//! [`SupervisedProjectQuotaBinding`] adapts those bounds to the shared Linux
//! quota implementation without moving Crucible authority into that library.
//!
//! Private measurement ownership and its storage pins remain in this host
//! process. This Apache-licensed crate neither links QEMU nor participates in
//! its socket or shared-memory protocols as an implementation component.

//! Unsafe boundary discipline:
//! - public callers use safe host resource capabilities;
//! - wrappers retain original task, descriptor, and memory permits;
//! - `host_services::native_join` consumes one unique GNU/Linux pthread handle,
//!   checks its creation process, and records actual nonblocking join before
//!   independent operation posts; no blocking join or raw-ID constructor exists.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod descriptor;
pub mod host_services;
pub mod host_supervision;
#[cfg(feature = "private-measurement-domain")]
#[doc(hidden)]
pub mod measurement_origin;
#[cfg(feature = "private-measurement-domain")]
mod measurement_storage;
mod project_quota;
pub mod ram_policy;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use project_quota::{SupervisedProjectQuotaBinding, SupervisedProjectQuotaError};

#[doc(hidden)]
#[cfg(feature = "private-measurement-domain")]
pub use measurement_storage::{
    MeasurementStorageContract, MeasurementStorageError, MeasurementStoragePins,
    OwnedMeasurementStoragePins,
};
