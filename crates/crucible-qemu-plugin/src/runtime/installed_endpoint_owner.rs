//! Actual local role allocations joined to the source's retained endpoint owner.
//!
//! Registration names the existing pinned runtime and the exact inbox, RUN and
//! teardown allocations. Worker registration occurs on each existing worker,
//! after immutable owner publication; installation never waits for those threads
//! under BQL. Local holding retains real transport and modeled admission, but
//! does not close kernel backlog or future producers and cannot issue RootSeal.

use std::ffi::{c_int, c_void};
use std::sync::Arc;
#[cfg(not(test))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(not(test))]
use crate::native_node_control::NativePreparationTransportState;
use crate::native_node_control::administrative_inbox::NativeAdministrativeInbox;

#[cfg(not(test))]
use super::OwnedCallbackRuntimeState;
#[cfg(not(test))]
use super::installed_endpoint_abi::NativeEndpointOwnerRegistration;
use super::installed_endpoint_abi::{
    NativeEndpointOwnerApi, NativeEndpointWorker, NativeEndpointWorkerKind,
    NativeInstalledEndpointOwner,
};
#[cfg(not(test))]
use super::installed_teardown::InstalledTeardownMailbox;
#[cfg(not(test))]
use super::native_run_control::NativeRunControlCustody;

/// Retains each actual role and any partial original transport holds for process life.
pub(crate) struct InstalledEndpointCustody {
    process_id: u32,
    #[cfg(not(test))]
    runtime_identity: usize,
    administration: Arc<NativeAdministrativeInbox>,
    #[cfg(not(test))]
    run: Arc<NativeRunControlCustody>,
    #[cfg(not(test))]
    teardown: Arc<InstalledTeardownMailbox>,
    api: NativeEndpointOwnerApi,
    native_owner: AtomicUsize,
    failed: AtomicBool,
    #[cfg(not(test))]
    transport: Mutex<Option<NativePreparationTransportState>>,
}

impl InstalledEndpointCustody {
    /// Registers only the explicit local ABI, retaining roles before source calls.
    ///
    /// # Errors
    /// Refuses missing ABI, another process, foreign role allocation, duplicate
    /// publication or source refusal. No worker is replaced or hold released.
    #[cfg(not(test))]
    pub(super) fn install(
        runtime: &OwnedCallbackRuntimeState,
        run: Arc<NativeRunControlCustody>,
        teardown: Arc<InstalledTeardownMailbox>,
    ) -> Result<Arc<Self>, c_int> {
        let control = crate::native_node_control::registered_owner().ok_or(-libc::ESTALE)?;
        let administration = control
            .original_administrative_actor()
            .ok_or(-libc::ESTALE)?;
        if !Arc::ptr_eq(administration.modeled_workers(), &runtime.workers)
            || !runtime.root_epoch.is_registered()
        {
            return Err(-libc::ESTALE);
        }
        let original = control
            .original_registered_root_policy()
            .ok_or(-libc::ESTALE)?;
        let owner = Arc::new(Self {
            process_id: std::process::id(),
            runtime_identity: std::ptr::from_ref(runtime) as usize,
            administration: Arc::clone(administration),
            run,
            teardown,
            api: NativeEndpointOwnerApi::resolve().ok_or(-libc::ENOTSUP)?,
            native_owner: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            transport: Mutex::new(None),
        });
        // V9 already retains the pinned runtime indefinitely. Store actual roles
        // there before the source may retain any callback or role reference.
        runtime
            .installed_endpoint
            .set(Arc::clone(&owner))
            .map_err(|_| -libc::EALREADY)?;
        let registration = NativeEndpointOwnerRegistration {
            version: 1,
            size: 64,
            original: &original,
            runtime: std::ptr::from_ref(runtime).cast_mut().cast(),
            administration: Arc::as_ptr(&owner.administration).cast_mut().cast(),
            run: Arc::as_ptr(&owner.run).cast_mut().cast(),
            teardown: Arc::as_ptr(&owner.teardown).cast_mut().cast(),
            try_hold: Some(retain_original),
            validate_held: Some(retain_original),
        };
        let mut native = std::ptr::null_mut();
        // SAFETY: Registration64 is the fixed GPL-local declaration. The exact
        // runtime and role allocations were retained before this synchronous call.
        let status = unsafe { (owner.api.register)(&registration, &mut native) };
        if status != 0 || native.is_null() {
            owner.failed.store(true, Ordering::Release);
            return Err(if status == 0 { -libc::ESTALE } else { status });
        }
        owner.native_owner.store(native as usize, Ordering::Release);
        control
            .publish_installed_endpoint(Arc::clone(&owner))
            .map_err(|_| -libc::EALREADY)?;
        Ok(owner)
    }

    pub(crate) fn native(&self) -> Result<*mut NativeInstalledEndpointOwner, c_int> {
        if self.process_id != std::process::id() {
            // Never touch inherited ownership locks in another process.
            return Err(-libc::ESTALE);
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(-libc::ENOTRECOVERABLE);
        }
        let native = self.native_owner.load(Ordering::Acquire) as *mut NativeInstalledEndpointOwner;
        if native.is_null() {
            return Err(-libc::EAGAIN);
        }
        Ok(native)
    }

    fn enroll(
        &self,
        kind: NativeEndpointWorkerKind,
        role: *mut c_void,
        descriptor: c_int,
    ) -> Result<bool, c_int> {
        let native = self.native()?;
        let mut worker: *mut NativeEndpointWorker = std::ptr::null_mut();
        // SAFETY: The source looks up its original owner before dereferencing it,
        // captures this actual thread's lifetime and validates the retained role.
        let status = unsafe {
            (self.api.register_current_worker)(native, kind, role, descriptor, &mut worker)
        };
        if status == -libc::EAGAIN {
            return Ok(false);
        }
        if status != 0 || worker.is_null() {
            self.failed.store(true, Ordering::Release);
            return Err(if status == 0 { -libc::ESTALE } else { status });
        }
        Ok(true)
    }

    /// Enrolls the sole original administrative reader without receiving a packet.
    ///
    /// # Errors
    /// Refuses source identity/lifetime contradictions and failed original custody.
    pub(crate) fn enroll_administration(&self) -> Result<bool, c_int> {
        let descriptor = self
            .administration
            .descriptor()
            .map_err(|_| -libc::ESTALE)?;
        self.enroll(
            NativeEndpointWorkerKind::Administration,
            Arc::as_ptr(&self.administration).cast_mut().cast(),
            descriptor,
        )
    }

    /// Enrolls the calling actual RUN worker before it receives socket bytes.
    ///
    /// # Errors
    /// Refuses source identity/lifetime contradictions or unavailable descriptor.
    #[cfg(not(test))]
    pub(super) fn enroll_run(&self) -> Result<bool, c_int> {
        let descriptor = self.run.descriptor().map_err(|_| -libc::EAGAIN)?;
        self.enroll(
            NativeEndpointWorkerKind::Run,
            Arc::as_ptr(&self.run).cast_mut().cast(),
            descriptor,
        )
    }

    /// Enrolls the calling actual teardown worker and its original receiver.
    ///
    /// # Errors
    /// Refuses source identity/lifetime contradictions or failed mailbox custody.
    #[cfg(not(test))]
    pub(super) fn enroll_teardown(&self) -> Result<bool, c_int> {
        if !self.teardown.lifetime_valid() {
            return Err(-libc::ESTALE);
        }
        self.enroll(
            NativeEndpointWorkerKind::Teardown,
            Arc::as_ptr(&self.teardown).cast_mut().cast(),
            -1,
        )
    }

    /// Observes actual source-local custody; success supplies no effect permit.
    ///
    /// # Errors
    /// Refuses foreign source lifetime or descriptor/retained-owner contradictions.
    pub(crate) fn observe_local_hold(&self) -> Result<bool, c_int> {
        let native = self.native()?;
        // SAFETY: The source looks up this exact installed native owner and
        // authenticates the fresh RR/BQL origin before invoking our callbacks.
        let status = unsafe { (self.api.try_hold_local)(native) };
        match status {
            0 => Ok(true),
            value if value == -libc::EAGAIN => Ok(false),
            value => {
                self.failed.store(true, Ordering::Release);
                Err(value)
            }
        }
    }

    #[cfg(not(test))]
    fn retain(&self, runtime: &OwnedCallbackRuntimeState) -> c_int {
        if self.native().is_err() || !self.teardown.lifetime_valid() {
            return -libc::ESTALE;
        }
        let mut transport = match self.transport.try_lock() {
            Ok(transport) => transport,
            Err(std::sync::TryLockError::WouldBlock) => return -libc::EAGAIN,
            Err(std::sync::TryLockError::Poisoned(_)) => return -libc::EOWNERDEAD,
        };
        if transport.is_none() {
            let Some(control) = crate::native_node_control::registered_owner() else {
                return -libc::ESTALE;
            };
            match control.prepare_runtime_epoch_transport(
                runtime.setup.mapped_region(),
                Arc::clone(&runtime.quiescence),
                Arc::clone(&runtime.workers),
            ) {
                Ok(Some(original)) => *transport = Some(original),
                Ok(None) => return -libc::EAGAIN,
                // Source invokes this callback under its native owner seam.
                // Return custody failure directly without taking stderr or
                // allocating a diagnostic while BQL may be held.
                Err(_) => return -libc::ENOTRECOVERABLE,
            }
        }
        let Some(original) = transport.as_mut() else {
            return -libc::ESTALE;
        };
        match original.try_retain(runtime.setup.mapped_region()) {
            Ok(true) => {
                // A historical retained image cannot prove current admission.
                // Observe the actual same held gates on every native validation.
                let callbacks = runtime.quiescence.snapshot();
                let workers = match runtime.workers.try_snapshot() {
                    Ok(Some(workers)) => workers,
                    Ok(None) => return -libc::EAGAIN,
                    Err(_) => return -libc::EOWNERDEAD,
                };
                if !callbacks.hot_fork_held
                    || callbacks.teardown_closed
                    || callbacks.in_flight != 0
                    || !workers.held
                    || workers.parked_mask != workers.worker_mask
                    || workers.pending_mask != 0
                    || workers.operations_in_flight != 0
                {
                    return -libc::EAGAIN;
                }
                0
            }
            Ok(false) => -libc::EAGAIN,
            // Keep the same native failure disposition and original holds;
            // callback failure must not acquire a process stderr lock under BQL.
            Err(_) => -libc::ENOTRECOVERABLE,
        }
    }
}

/// Retains or validates the same original runtime and endpoint role allocations.
///
/// # Safety
/// Runtime points to the original aligned pinned runtime retained for process
/// lifetime after source registration. Other role pointers identify the same
/// retained Arc allocations and are compared before use; none is adopted from
/// caller material. The native caller preserves these lifetimes for the call.
#[cfg(not(test))]
unsafe extern "C" fn retain_original(
    runtime: *mut c_void,
    administration: *mut c_void,
    run: *mut c_void,
    teardown: *mut c_void,
) -> c_int {
    if runtime.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The source invokes only its original retained registration; V9
    // pins this exact runtime allocation until process exit. Role pointers are
    // compared by identity below, never adopted or dereferenced from the caller.
    let runtime = unsafe { &*runtime.cast::<OwnedCallbackRuntimeState>() };
    let Some(owner) = runtime.installed_endpoint.get() else {
        return -libc::ESTALE;
    };
    if owner.runtime_identity != std::ptr::from_ref(runtime) as usize
        || administration != Arc::as_ptr(&owner.administration).cast_mut().cast()
        || run != Arc::as_ptr(&owner.run).cast_mut().cast()
        || teardown != Arc::as_ptr(&owner.teardown).cast_mut().cast()
    {
        return -libc::ESTALE;
    }
    owner.retain(runtime)
}
