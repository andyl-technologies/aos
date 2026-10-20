//! Explicit private Source tables for callback-order fixtures, never native exports.
//!
//! The model is explicitly attached to the same retained fixture owner before acquisition.
//! It models only signed API results; it grants no native account or operation.
// SPDX-License-Identifier: GPL-2.0-only

use super::{NativeSetupBorrow, NativeStartupApi, StartupSourceError};
use std::fs::File;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

pub(crate) struct InstallerStartupSourceModel {
    pub(super) api: NativeStartupApi,
    pub(super) setup: Option<ModelSetup>,
}

impl InstallerStartupSourceModel {
    pub(crate) const fn ready() -> Self {
        Self {
            api: NativeStartupApi {
                acquire: accept,
                check,
                query_slice: slice,
                registration_complete: complete,
            },
            setup: None,
        }
    }

    /// Attaches the same real fixture owners before selected acquisition.
    pub(crate) fn with_setup(mut self, setup: ModelSetup) -> Self {
        assert!(self.setup.is_none());
        self.setup = Some(setup);
        self
    }

    /// Reports explicit fixture selection without changing process environment.
    pub(crate) fn has_setup(&self) -> bool {
        self.setup.is_some()
    }

    pub(crate) fn refused_acquisition() -> Self {
        Self {
            api: NativeStartupApi {
                acquire: refuse,
                ..Self::ready().api
            },
            setup: None,
        }
    }
}

extern "C" fn accept(_plugin_id: u64, _plan_fd: i32) -> i32 {
    0
}

extern "C" fn refuse(_plugin_id: u64, _plan_fd: i32) -> i32 {
    -229
}

extern "C" fn check(_plugin_id: u64) -> i32 {
    0
}

extern "C" fn slice(_plugin_id: u64, bounded_ns: *mut u64) -> i32 {
    // SAFETY: the shared adapter lends an initialized u64 for this synchronous call.
    unsafe { *bounded_ns = 1_000_000 };
    0
}

extern "C" fn complete(_plugin_id: u64, status: i32) -> i32 {
    assert_eq!(status, 0);
    0
}

/// Owns the actual fixture aliases shared by the fixture and its Source keeper.
pub(crate) struct ModelSetupOwners {
    pub(crate) control: UnixStream,
    pub(crate) shmem: File,
    pub(crate) wake: File,
    pub(crate) plan: OwnedFd,
    pub(crate) source_publication: OwnedFd,
    pub(crate) source_cancellation: OwnedFd,
    pub(crate) _wake_peer: Option<File>,
}

/// Keeps borrowed fixture roles alive without claiming native acquisition proof.
#[derive(Clone)]
pub(crate) struct ModelSetup {
    owners: Arc<ModelSetupOwners>,
    frame: [u8; 61],
}

impl ModelSetup {
    /// Retains the fixture owners and its exact selected frame.
    pub(crate) fn new(owners: Arc<ModelSetupOwners>, frame: [u8; 61]) -> Self {
        Self { owners, frame }
    }

    /// Returns the still-owned fixture plan alias for modeled acquisition.
    pub(crate) fn plan_fd(&self) -> i32 {
        self.owners.plan.as_raw_fd()
    }

    /// Validates borrowed views while retaining every underlying fixture alias.
    ///
    /// # Errors
    /// Refuses a malformed fixed frame or overlapping descriptor roster.
    pub(crate) fn borrow(&self) -> Result<NativeSetupBorrow, StartupSourceError> {
        let roles = [
            self.owners.shmem.as_raw_fd(),
            self.owners.wake.as_raw_fd(),
            self.owners.plan.as_raw_fd(),
            self.owners.source_publication.as_raw_fd(),
            self.owners.source_cancellation.as_raw_fd(),
        ];
        NativeSetupBorrow::from_model(&self.frame, self.owners.control.as_raw_fd(), &roles)
    }

    /// Interrupts the real fixture owner so the actual borrowed reader can return.
    ///
    /// # Errors
    /// Returns the owning socket's actual shutdown error without retrying.
    pub(crate) fn shutdown_control(&self) -> std::io::Result<()> {
        self.owners.control.shutdown(Shutdown::Both)
    }
}

static CONTROL_MODEL_TOKEN: u8 = 1;
static RUNTIME_MODEL_TOKEN: u8 = 2;
static RUN_MODEL_TOKEN: u8 = 3;
static TEARDOWN_MODEL_TOKEN: u8 = 4;

pub(super) extern "C" fn reserve_control(
    _: u64,
    requests: *const super::control_purpose::Request,
    output: *mut *mut super::control_purpose::ControlPurpose,
) -> i32 {
    assert!(!requests.is_null() && !output.is_null());
    // SAFETY: the shared reservation adapter lends its actual fixed seven rows
    // and writable holder output throughout this synchronous private model call.
    let requests = unsafe { std::slice::from_raw_parts(requests, 7) };
    for request in requests {
        assert!(request.extent_bytes > 0);
        assert!(request.alignment_bytes.is_power_of_two());
        assert!(request.birth_count > 0);
    }
    // SAFETY: output is live; this opaque test identity is never dereferenced or
    // presented to production native code and grants no resource credit.
    unsafe { output.write(std::ptr::from_ref(&CONTROL_MODEL_TOKEN).cast_mut().cast()) };
    0
}

pub(super) extern "C" fn check_control(
    _: u64,
    purpose: *mut super::control_purpose::ControlPurpose,
) -> i32 {
    assert_eq!(
        purpose.cast::<u8>(),
        std::ptr::from_ref(&CONTROL_MODEL_TOKEN).cast_mut()
    );
    0
}

pub(super) extern "C" fn reserve_runtime(
    _: u64,
    requests: *const super::runtime_purpose::Request,
    count: usize,
    output: *mut *mut super::runtime_purpose::RuntimePurpose,
    claim: *mut *mut super::runtime_purpose::CommandClaim,
    child_claim: *mut *mut super::runtime_purpose::CallbackChildClaim,
    worker_claim: *mut *mut super::runtime_purpose::WorkerClaim,
    run_claim: *mut *mut crate::runtime::required_workers::abi::RunClaim,
    teardown_claim: *mut *mut crate::runtime::required_workers::abi::TeardownClaim,
) -> i32 {
    assert!(
        !requests.is_null()
            && !output.is_null()
            && !claim.is_null()
            && !child_claim.is_null()
            && !worker_claim.is_null()
            && !run_claim.is_null()
            && !teardown_claim.is_null()
    );
    assert!(count > 0 && count <= crate::runtime::prebirth::MAX_RUNTIME_ALLOCATIONS);
    // SAFETY: the same adapter supplies the full initialized configured span.
    // These layout facts and the model token confer no native resource credit.
    let requests = unsafe { std::slice::from_raw_parts(requests, count) };
    for request in requests {
        assert!(request.extent_bytes > 0);
        assert!(request.alignment_bytes.is_power_of_two());
        assert_eq!(request.birth_count, 1);
    }
    assert_eq!(
        requests.iter().filter(|request| request.role == 1).count(),
        1
    );
    assert_eq!(
        requests.iter().filter(|request| request.role == 2).count(),
        1
    );
    assert_eq!(
        requests.iter().filter(|request| request.role == 4).count(),
        1
    );
    assert_eq!(
        requests.iter().filter(|request| request.role == 5).count(),
        1
    );
    assert!(requests.iter().all(|request| request.reserved == 0));
    // SAFETY: outputs are live; these explicit model tokens never construct
    // Native containing authority or a production physical command allocation.
    unsafe {
        output.write(std::ptr::from_ref(&RUNTIME_MODEL_TOKEN).cast_mut().cast());
        claim.write(std::ptr::from_ref(&RUNTIME_MODEL_TOKEN).cast_mut().cast());
        child_claim.write(std::ptr::from_ref(&CONTROL_MODEL_TOKEN).cast_mut().cast());
        // These metadata-only fixture tokens never enter a native creator.
        run_claim.write(std::ptr::from_ref(&RUN_MODEL_TOKEN).cast_mut().cast());
        teardown_claim.write(std::ptr::from_ref(&TEARDOWN_MODEL_TOKEN).cast_mut().cast());
        if requests.iter().any(|request| request.role == 3) {
            worker_claim.write(std::ptr::from_ref(&CONTROL_MODEL_TOKEN).cast_mut().cast());
        }
    }
    0
}

pub(super) extern "C" fn check_runtime(
    _: u64,
    purpose: *mut super::runtime_purpose::RuntimePurpose,
) -> i32 {
    assert_eq!(
        purpose.cast::<u8>(),
        std::ptr::from_ref(&RUNTIME_MODEL_TOKEN).cast_mut()
    );
    0
}
