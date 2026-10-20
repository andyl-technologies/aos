//! Owns native host resources retained by Crucible processes.
//!
//! The private `linux_read_lease` module provides original read-only files and
//! isolated notification workers through safe capability types. Callers retain
//! responsibility for complete content measurements, namespace authentication
//! and the resource admission surrounding those operations. The private
//! `linux_directory_cleanup` module removes stopped private-directory contents
//! through an owned descriptor; it does not attest process reap or release the
//! surrounding quota, identifier or namespace authority. The private
//! `linux_pure_worker` module retains a same-PID child, independent disk input,
//! hard cgroup/rlimit controls and bounded disk output through actual waited reap and
//! resource cleanup. Its completion token proves physical custody only; callers
//! separately authenticate installation measurements and result semantics.
//! The private `linux_process_supervisor` module retains the actual coordinator's
//! irreversible shared CPU/address-space/descriptor ceilings, independently of
//! Source semantic rows and child-process operational controls.
//!
//! This crate contains Apache-licensed host code and does not link an emulator
//! or cross an emulator process protocol boundary.
//!
//! Spec index: RFC-0025 files 01, 02, 05, 06, 08.
//!
//! Unsafe boundary discipline:
//! - public callers use safe resource capability types;
//! - wrappers validate descriptor/process/kernel invariants.
//! - the notification worker owns its signal mask and lease notifications.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod linux_directory_cleanup;
mod linux_pure_worker;
mod linux_process_supervisor;
mod linux_read_lease;

pub use linux_directory_cleanup::{
    LinuxDirectoryCleanup, LinuxDirectoryCleanupBoundReason, LinuxDirectoryCleanupError,
    LinuxDirectoryCleanupOperation,
};
pub use linux_read_lease::{
    LinuxReadLease, LinuxReadLeaseError, LinuxReadLeaseFile, LinuxReadLeaseOwner,
};

pub use linux_pure_worker::{
    LinuxPureWorkerAttempt, LinuxPureWorkerAttemptIdentity, LinuxPureWorkerCompletion,
    LinuxPureWorkerConfiguration, LinuxPureWorkerDirectBuffers, LinuxPureWorkerError,
    LinuxPureWorkerFactory, LinuxPureWorkerFailure, LinuxPureWorkerLimits, LinuxPureWorkerOutcome,
    LinuxPureWorkerProgram, LinuxPureWorkerProgramIdentity,
};

pub use linux_process_supervisor::{
    LinuxProcessCeilingsData, LinuxProcessLimits, LinuxProcessSupervisor, LinuxProcessSupervisorError,
};
