//! GPL-side host paging primitives for stable QEMU guest mappings.
//!
//! Registration and preserved storage are operational resources. Their failures
//! never resolve a guest access with replacement bytes. Registration authority
//! must outlive the service worker, including during failure and fork handoff.
//! The kernel module deliberately does not enable user-mode-only faults or
//! assume experimental access-sampling features are available.

mod control;
pub(crate) mod controller;
mod engine;
mod fork;
mod kernel;
mod lifecycle;
mod performance;
mod source;
mod storage;
mod supervision;
pub(crate) use engine::PausedPagingOwner;
pub(crate) use lifecycle::install;
mod restore;

pub(crate) use kernel::{FaultEvent, Registration};
pub(crate) use storage::{PageRecord, PreservedPages};

/// The fixed logical and initially supported host page size.
pub(crate) const PAGE_BYTES: usize = 4096;
