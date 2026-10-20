//! Owns native host resources retained by Crucible processes.
//!
//! The private `linux_read_lease` module provides original read-only files and
//! isolated notification workers through safe capability types. Callers retain
//! responsibility for complete content measurements, namespace authentication
//! and the resource admission surrounding those operations.
//!
//! This crate contains Apache-licensed host code and does not link an emulator
//! or cross an emulator process protocol boundary.
//!
//! Spec index: RFC-0025 files 01, 02, 05, 08.
//!
//! Unsafe boundary discipline:
//! - public callers use safe resource capability types;
//! - wrappers validate descriptor/process/kernel invariants.
//! - the notification worker owns its signal mask and lease notifications.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_read_lease;

pub use linux_read_lease::{
    LinuxReadLease, LinuxReadLeaseError, LinuxReadLeaseFile, LinuxReadLeaseOwner,
};
