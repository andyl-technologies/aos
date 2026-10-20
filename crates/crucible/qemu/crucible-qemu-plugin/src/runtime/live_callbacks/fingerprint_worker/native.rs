//! Runs the actual Source-created fingerprint worker and returns its owners.
//!
//! The matched module owns an ordinary Arc. Source retains its one raw owning
//! alias until physical join and matched destruction; canonical native worker
//! custody stays in the independently pinned Runtime throughout failure.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::fingerprint_native::{Api, MaterialRef, PipelineStatus, WorkRef, Worker, WorkerStatus};
use crate::runtime::native_worker::owner::OwnerField;
use crate::startup_source::runtime_purpose::{RuntimePurpose, WorkerClaim};
use std::ffi::c_void;

mod scope;
mod pipeline;

mod module;

/// Keeps Source's signed result beside the module's original typed failure.
#[derive(Debug)]
pub(super) struct NativeFailure {
    operation: &'static str,
    status: i32,
}

/// Keeps an actual entry malfunction apart from Main's canceled transaction.
#[derive(Debug)]
pub(super) struct EntryFailure {
    status: i32,
    pub(super) cause: FingerprintWorkerCause,
}

/// Retains independent effects and signed returns for one paid owning job.
#[derive(Debug, Default)]
pub(super) struct JobHistory {
    // This saved key is diagnostic-only after the owning projection is consumed.
    // It is never used to return custody or acquire another operation.
    identity: MaterialRef,
    material_serial: u64,
    work_serial: u64,
    submit_status: Option<i32>,
    take_status: Option<i32>,
    take_local_closed: Option<bool>,
    cooperative_close: bool,
    take_output: Option<WorkRef>,
    take_workspace: Option<(usize, usize)>,
    completion_result: Option<i32>,
    complete_status: Option<i32>,
    completion_attempted: bool,
    byte_loan_issued: bool,
    bytes_returned: bool,
    work_return_status: Option<i32>,
    work_return_output: Option<i32>,
    work_return_first_failure: Option<i32>,
    work_result: Option<i32>,
    material_return_failure: Option<FingerprintSamplerError>,
    material_return_last_status: Option<i32>,
    pipeline: Option<PipelineStatus>,
    observation_status: Option<i32>,
    observation_first_failure: Option<i32>,
}

/// Borrows the same actual native worker without adding an owning projection.
#[derive(Clone, Copy)]
pub(super) struct Handle {
    id: u64,
    worker: usize,
    api: Api,
}

/// Retains owned module inputs for the full born worker/control lifetime.
pub(super) struct Context {
    handle: Handle,
    slot: StableFingerprintSlotHandle,
    quiescence: Arc<LiveWorkerQuiescence>,
}

/// Owns the canonical native field inside the actual prepaid Runtime layout.
pub(in crate::runtime) struct SourceWorkerOwner {
    field: OwnerField<Worker>,
    id: u64,
    api: Option<Api>,
    attempted: bool,
    returned: bool,
    terminal_status: i32,
    installation_post_failure: Option<crate::StartupSourceError>,
    return_status: Option<i32>,
    return_observation_status: Option<i32>,
    registered: std::sync::atomic::AtomicBool,
    control_address: usize,
    creation_status: Option<i32>,
    transfer_status: Option<i32>,
    unattached: Option<LiveFingerprintDigestWorker>,
}

struct ConstructorInput {
    handle: Handle,
    projection: *const *mut Worker,
    slot: StableFingerprintSlotHandle,
    quiescence: Option<Arc<LiveWorkerQuiescence>>,
    control_address: *mut usize,
    first_status: i32,
}

impl SourceWorkerOwner {
    /// Creates the inert inline keeper before Source worker admission.
    pub(in crate::runtime) const fn new() -> Self {
        Self {
            field: OwnerField::new(),
            id: 0,
            api: None,
            attempted: false,
            returned: false,
            terminal_status: 0,
            installation_post_failure: None,
            return_status: None,
            return_observation_status: None,
            registered: std::sync::atomic::AtomicBool::new(false),
            control_address: 0,
            creation_status: None,
            transfer_status: None,
            unattached: None,
        }
    }

    /// Creates and transfers actual Source worker custody before exposing it.
    ///
    /// # Safety
    /// This field is inside the paid pinned Runtime; child/workspace are genuine
    /// same-Source projections and all synchronous inputs outlive this call.
    ///
    /// # Errors
    /// Retains every control, thread and canonical output before signed refusal.
    pub(in crate::runtime) unsafe fn create(
        &mut self,
        material: (u64, *mut RuntimePurpose, *mut WorkerClaim),
        child: *mut c_void,
        workspace: *mut c_void,
        slot: StableFingerprintSlotHandle,
        quiescence: Arc<LiveWorkerQuiescence>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.attempted {
            return Err(status_error(-libc::EALREADY));
        }
        let api = Api::resolve().map_err(status_error)?;
        let (id, runtime, claim) = material;
        self.id = id;
        self.api = Some(api);
        self.attempted = true;
        let handle = Handle { id, worker: 0, api };
        self.unattached = Some(LiveFingerprintDigestWorker {
            native: handle,
            native_retired: false,
            native_terminal_status: 0,
            native_close_failure: None,
            native_retire_scope_failure: None,
            owner_process: std::process::id(),
        });
        let worker = self
            .unattached
            .as_mut()
            .ok_or_else(|| status_error(-libc::EPROTO))?;
        let mut input = ConstructorInput {
            handle,
            projection: self.field.creation_projection_address(),
            slot,
            quiescence: Some(quiescence),
            control_address: &mut self.control_address,
            first_status: 0,
        };
        let status = (api.create)(
            id,
            runtime,
            claim,
            child,
            workspace,
            std::ptr::from_mut(&mut input).cast(),
            self.field.creation_address(),
        );
        self.creation_status = Some(status);
        let born = self.field.record_birth();
        worker.native.worker = born as usize;
        if input.first_status != 0 {
            return Err(status_error(input.first_status));
        }
        native_status(status)?;
        if self.field.projection().is_null() || self.control_address == 0 {
            return Err(status_error(-libc::EPROTO));
        }
        let status = self
            .field
            .transfer(|creation, canonical| (api.transfer)(id, creation, canonical));
        self.transfer_status = Some(status);
        native_status(status)?;
        if !self.field.creation_consumed() {
            return Err(status_error(-libc::EPROTO));
        }
        Ok(())
    }

    /// Records the independent installing post even when actual birth failed.
    pub(in crate::runtime) fn record_installation_post(
        &mut self,
        result: Result<(), crate::StartupSourceError>,
    ) {
        if let Err(source) = result {
            self.installation_post_failure.get_or_insert(source);
        }
    }

    /// Moves only a successfully born worker into its actual typed child.
    ///
    /// # Errors
    /// Refuses negative creation/transfer or repeated movement of the same view.
    pub(in crate::runtime) fn take_worker(
        &mut self,
    ) -> Result<LiveFingerprintDigestWorker, LiveVcpuTimeCallbackError> {
        if self.creation_status != Some(0) || self.transfer_status != Some(0) {
            return Err(status_error(-libc::ESTALE));
        }
        self.unattached
            .take()
            .ok_or_else(|| status_error(-libc::EALREADY))
    }

    /// Reports actual canonical identity consumption independently of health.
    ///
    /// This becomes true only after the native physical-return journal, native
    /// identity-return operation and consumed canonical field all corroborate the
    /// same worker. It grants no readiness or successful terminal disposition.
    pub(in crate::runtime) fn identity_is_returned(&self) -> bool {
        self.returned
    }

    /// Returns canonical identity only after actual worker physical retirement.
    ///
    /// # Errors
    /// Retains busy, failed or uncertain worker/material/control/stack owners.
    pub(in crate::runtime) fn identity_return(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if !self.attempted {
            return Ok(());
        }
        if self.returned {
            return native_status(self.terminal_status);
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ENOSYS))?;
        if self.unattached.is_none() && !self.field.projection().is_null() {
            let mut journal = WorkerStatus::default();
            native_status((api.observe)(
                self.id,
                self.field.projection(),
                &mut journal,
            ))?;
            validate_status(&journal)?;
            self.unattached = Some(LiveFingerprintDigestWorker {
                native: Handle {
                    id: self.id,
                    worker: self.field.projection() as usize,
                    api,
                },
                native_retired: journal.physical_returned == 1,
                native_terminal_status: self.terminal_status,
                native_close_failure: None,
                native_retire_scope_failure: None,
                owner_process: std::process::id(),
            });
        }
        // A worker can be physically retired while retaining negative health.
        // Preserve that owned result and independently consume exact identity.
        let retirement_error = self.unattached.as_mut().and_then(|worker| {
            let result = worker.retire();
            if worker.native_terminal_status != 0 {
                self.terminal_status = worker.native_terminal_status;
            }
            result.err()
        });
        if self.field.projection().is_null() {
            // No output means no native birth; preserve the first refusal and
            // do not manufacture a successful return of an attempted purpose.
            return Err(status_error(-libc::ESTALE));
        }
        let mut journal = WorkerStatus::default();
        let observation = (api.observe)(self.id, self.field.projection(), &mut journal);
        if observation != 0 {
            self.return_observation_status.get_or_insert(observation);
        }
        if observation != 0 {
            return Err(retirement_error.unwrap_or_else(|| status_error(observation)));
        }
        if let Err(source) = validate_status(&journal) {
            return Err(retirement_error.unwrap_or(source));
        }
        if journal.physical_returned != 1 || journal.control_lifetime_uncertain != 0 {
            return Err(retirement_error.unwrap_or_else(|| status_error(-libc::EBUSY)));
        }
        let field = self.field.return_address();
        let status = (api.identity_return)(self.id, field);
        if status != 0 {
            self.return_status.get_or_insert(status);
        }
        if status != 0 {
            return Err(retirement_error.unwrap_or_else(|| status_error(status)));
        }
        // SAFETY: field is this pinned owner's live canonical slot or its live
        // creation slot, lent synchronously to the exact native return operation.
        // Successful status alone does not prove that canonical custody ended.
        if !unsafe { (*field).is_null() } {
            return Err(retirement_error.unwrap_or_else(|| status_error(-libc::EPROTO)));
        }
        self.returned = true;
        self.field.returned();
        if let Some(source) = retirement_error {
            return Err(source);
        }
        native_status(self.terminal_status)
    }

    /// Waits for real registration under the original installing Source slice.
    ///
    /// # Errors
    /// Preserves actual worker, membership, Source or deadline failure.
    pub(in crate::runtime) fn wait_registered(
        &self,
        wait_slice: impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let worker = self
            .unattached
            .as_ref()
            .ok_or_else(|| status_error(-libc::ESTALE))?;
        worker.wait_registered(wait_slice)?;
        self.registered.store(true, Ordering::Release);
        Ok(())
    }

    /// Rechecks actual native health after the real registration acknowledgement.
    ///
    /// # Errors
    /// Refuses an ended native worker, current module failure or lost membership.
    pub(in crate::runtime) fn check_registered(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        if !self.attempted {
            return Ok(());
        }
        if !self.registered.load(Ordering::Acquire) {
            return Err(status_error(-libc::ECHILD));
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ENOSYS))?;
        let status = Handle {
            id: self.id,
            worker: self.field.projection() as usize,
            api,
        }
        .observe()?;
        let first = [
            status.first_status,
            status.post_status,
            status.create_status,
            status.mask_restore_status,
            status.attr_destroy_status,
            status.control_lifetime_status,
        ]
        .into_iter()
        .find(|status| *status != 0);
        if let Some(status) = first {
            return Err(status_error(status));
        }
        if status.born != 1
            || status.initialized != 1
            || status.closing != 0
            || status.entry_returned != 0
            || status.control_lifetime_uncertain != 0
        {
            return Err(status_error(-libc::ECHILD));
        }
        let handle = Handle {
            id: self.id,
            worker: self.field.projection() as usize,
            api,
        };
        handle.with_control(false, |control| {
            let state = control.lock();
            if !state.registered || state.closed || state.failure.is_some() {
                drop(state);
                return Err(LiveFingerprintDigestWorker::failed(control));
            }
            drop(state);
            check_worker_identity(control)
        })
    }
}

impl Handle {
    fn pointer(self) -> *mut Worker {
        self.worker as *mut Worker
    }

    fn observe(self) -> Result<WorkerStatus, LiveVcpuTimeCallbackError> {
        let mut status = WorkerStatus::default();
        native_status((self.api.observe)(self.id, self.pointer(), &mut status))?;
        validate_status(&status)?;
        Ok(status)
    }

    /// Corroborates current physical birth and the actual Rust actor membership.
    ///
    /// # Errors
    /// Retains the first native, registration or worker-lifetime refusal.
    pub(super) fn check_readiness(
        self,
        control: &Arc<FingerprintWorkerControl>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let status = self.observe()?;
        let first = [
            status.first_status,
            status.post_status,
            status.create_status,
            status.mask_restore_status,
            status.attr_destroy_status,
            status.control_lifetime_status,
        ]
        .into_iter()
        .find(|status| *status != 0);
        if let Some(status) = first {
            control.refuse_native("readiness", status);
            return Err(LiveFingerprintDigestWorker::failed(control));
        }
        if status.born != 1
            || status.initialized != 1
            || status.closing != 0
            || status.entry_returned != 0
            || status.control_lifetime_uncertain != 0
        {
            control.refuse_native("readiness", -libc::ECHILD);
            return Err(LiveFingerprintDigestWorker::failed(control));
        }
        Ok(())
    }

    /// Observes whether the actual native workspace retains any work/byte loan.
    ///
    /// # Errors
    /// Refuses stale observation or genuinely outstanding material/byte custody.
    pub(super) fn workspace_quiet(self) -> Result<(), i32> {
        self.observe()
            .map_err(|_| -libc::ESTALE)
            .and_then(|status| {
                if status.material_held == 0
                    && status.bytes_held == 0
                    && status.control_lifetime_uncertain == 0
                {
                    Ok(())
                } else {
                    Err(-libc::EBUSY)
                }
            })
    }
}

impl FingerprintWorkerControl {
    fn record_native_failure(&self, operation: &'static str, status: i32) {
        let mut state = self.lock();
        if state.native_failure.is_none() {
            state.native_failure = Some(NativeFailure { operation, status });
        }
    }

    fn refuse_native(&self, operation: &'static str, status: i32) {
        self.record_native_failure(operation, status);
        let mut state = self.lock();
        if state.failure.is_none() {
            state.failure = Some(FingerprintWorkerCause::Native { operation, status });
        }
        drop(state);
        self.available.notify_all();
        self.capacity.notify_all();
    }
}

impl LiveFingerprintDigestWorker {
    /// Corroborates the actual Source workspace is free of live byte/material loans.
    ///
    /// # Safety
    /// The caller retains complete callback/ring/worker and native producer exclusion.
    ///
    /// # Errors
    /// Refuses another process or actual outstanding workspace custody.
    pub(in crate::runtime::live_callbacks) unsafe fn hold_workspace_for_parent_park(
        &self,
    ) -> Result<(), i32> {
        if !self.creator_process_is_current() {
            return Err(-libc::EPERM);
        }
        self.native.workspace_quiet()
    }

    /// Rechecks the same Source workspace before the caller releases exclusion.
    ///
    /// # Safety
    /// The caller retains the same complete parent exclusion through disposition.
    ///
    /// # Errors
    /// Refuses another process or actual outstanding workspace custody.
    pub(in crate::runtime::live_callbacks) unsafe fn restore_workspace_for_parent_park(
        &self,
    ) -> Result<(), i32> {
        if !self.creator_process_is_current() {
            return Err(-libc::EPERM);
        }
        self.native.workspace_quiet()
    }

    /// Checks native workspace debt while the caller owns the complete fork barrier.
    ///
    /// # Safety
    /// The caller retains the complete native callback/ring/worker fork barrier.
    ///
    /// # Errors
    /// Refuses another process or actual outstanding workspace custody.
    pub(in crate::runtime::live_callbacks) unsafe fn hold_workspace_for_fork(
        &self,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        if !self.creator_process_is_current() {
            return Err(DeviceDigestWorkspaceError::Admission {
                status: -libc::EPERM,
            });
        }
        self.native
            .workspace_quiet()
            .map_err(|status| DeviceDigestWorkspaceError::Admission { status })
    }

    /// Checks the unchanged Source owner before parent fork-barrier release.
    ///
    /// # Safety
    /// The caller retains the same complete parent fork barrier through return.
    ///
    /// # Errors
    /// Refuses another process or actual outstanding workspace custody.
    pub(in crate::runtime::live_callbacks) unsafe fn restore_workspace_after_fork(
        &self,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        if !self.creator_process_is_current() {
            return Err(DeviceDigestWorkspaceError::Admission {
                status: -libc::EPERM,
            });
        }
        self.native
            .workspace_quiet()
            .map_err(|status| DeviceDigestWorkspaceError::Admission { status })
    }

    /// Makes only this inherited non-owning view inert before reconstruction.
    ///
    /// # Errors
    /// Refuses disarming in the original creator process.
    pub(in crate::runtime::live_callbacks) fn disarm_child_workspace(
        &mut self,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        if self.creator_process_is_current() {
            return Err(DeviceDigestWorkspaceError::Admission {
                status: -libc::EPERM,
            });
        }
        // The actual mapping/descriptor remain with Runtime's Source owner.
        // Do not touch copied Source locks, return its owner or close any FD.
        self.native_retired = true;
        Ok(())
    }

    /// Borrows the capture journal solely inside a genuine Source control scope.
    ///
    /// # Errors
    /// Refuses Source lifetime admission, contention, poison or the action itself.
    pub(in crate::runtime::live_callbacks) fn with_capture(
        &self,
        action: impl for<'a> FnOnce(
            &'a mut crate::fingerprint_sampler::CaptureAttempt,
        ) -> Result<(), FingerprintCaptureActionError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.native.with_control(false, |control| {
            let mut attempt = control
                .capture_attempt
                .try_lock()
                .map_err(|_| status_error(-libc::EBUSY))?;
            match action(&mut attempt) {
                Ok(()) => Ok(()),
                Err(FingerprintCaptureActionError::Worker(source)) => Err(source),
                Err(FingerprintCaptureActionError::Sampler { boundary, source }) => {
                    let mut state = control.lock();
                    state
                        .sampler_action_failure
                        .get_or_insert((boundary, source));
                    if state.failure.is_none() {
                        state.failure = Some(FingerprintWorkerCause::ModuleAction);
                    }
                    drop(state);
                    Err(Self::failed(control))
                }
            }
        })
    }

    /// Keeps the actual capture loan throughout a parent transfer observation.
    ///
    /// # Errors
    /// Refuses retained capture debt or Source/control lifetime admission.
    pub(in crate::runtime::live_callbacks) fn with_capture_transfer<R: Copy + 'static>(
        &self,
        action: impl FnOnce() -> Result<R, i32>,
    ) -> Result<R, i32> {
        self.native
            .with_control(false, |control| {
                let attempt = control
                    .capture_attempt
                    .try_lock()
                    .map_err(|_| status_error(-libc::EBUSY))?;
                if attempt.has_material_debt() {
                    return Ok(Err(-libc::EBUSY));
                }
                Ok(action())
            })
            .map_err(|_| -libc::ESTALE)?
    }

    /// Waits for real registration using the caller's retained installing Source.
    ///
    /// # Errors
    /// Preserves actual Source, native birth, module and worker-membership refusal.
    pub(in crate::runtime::live_callbacks) fn wait_registered(
        &self,
        mut wait_slice: impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        loop {
            let waiting = self.native.with_control(false, |control| {
                let slice = control.check_original(&mut wait_slice)?;
                self.native.check_readiness(control)?;
                let state = control.lock();
                if state.failure.is_some() {
                    drop(state);
                    return Err(Self::failed(control));
                }
                let registered = state.registered;
                drop(state);
                if registered {
                    check_worker_identity(control)?;
                    control.check_original(&mut wait_slice)?;
                    Ok(None)
                } else {
                    Ok(Some(slice))
                }
            })?;
            let Some(slice) = waiting else {
                return Ok(());
            };
            std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
    }

    /// Observes the genuine native physical-return journal without body access.
    ///
    /// # Errors
    /// Refuses a stale or invalid native owner observation.
    pub(in crate::runtime::live_callbacks) fn physically_returned(&self) -> Result<bool, i32> {
        self.native
            .observe()
            .map(|status| status.physical_returned == 1)
            .map_err(|_| -libc::ESTALE)
    }

    /// Performs one nonblocking physical return; refusal retains native custody.
    ///
    /// # Errors
    /// Preserves live material, aliases, failed cleanup, busy join or uncertain drop.
    pub(in crate::runtime) fn retire(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.native_retired {
            return native_status(self.native_terminal_status);
        }
        if !self.creator_process_is_current() {
            return Err(status_error(-libc::EPERM));
        }
        let handle = self.native;
        let before = handle.observe()?;
        if before.physical_returned == 1 {
            self.native_retired = true;
            return native_status(self.native_terminal_status);
        }
        // Close, cleanup and join have independent physical effects. An earlier
        // semantic refusal cannot skip a later actual nonblocking join attempt.
        let close_status = (handle.api.close)(handle.id, handle.pointer());
        if close_status != 0 {
            self.native_close_failure.get_or_insert(close_status);
        }
        let mut first_error = (close_status != 0).then(|| status_error(close_status));
        if before.initialized == 1 && before.destroyed == 0 {
            let cleanup = handle.with_control(true, |control| {
                control.close();
                if close_status != 0 {
                    control.refuse_native("close", close_status);
                }
                let mut error = None;
                match control.capture_attempt.try_lock() {
                    Ok(mut attempt) => {
                        if let Err(source) = attempt.retire_native_material(handle.id, handle.api) {
                            control
                                .lock()
                                .native_cleanup_failure
                                .get_or_insert(source.clone());
                            control.refuse(FingerprintWorkerCause::Digest(source));
                            error = Some(Self::failed(control));
                        }
                    }
                    Err(_) => error = Some(status_error(-libc::EBUSY)),
                }
                if let Err(source) = self.drain_control(control, true) {
                    if error.is_none() {
                        error = Some(source);
                    }
                }
                let mut state = control.lock();
                let failed = state.failure.is_some() || error.is_some();
                if failed && !state.terminal_failure_issued {
                    state.terminal_failure_issued = true;
                    drop(state);
                    return Err(error.unwrap_or_else(|| Self::failed(control)));
                }
                // The first owned failure keeps its full transcript alive. On
                // later cleanup attempts do not mint another Arc that would
                // prevent final uniqueness after its real external aliases end.
                Ok(failed)
            });
            match cleanup {
                Ok(true) => self.native_terminal_status = -libc::EIO,
                Ok(false) => {}
                Err(source) => {
                    let owned_failure = matches!(
                        source,
                        LiveVcpuTimeCallbackError::FingerprintWorkerFailed { .. }
                            | LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { .. }
                    );
                    if owned_failure {
                        self.native_terminal_status = -libc::EIO;
                    }
                    if let LiveVcpuTimeCallbackError::CallbackChildStorage {
                        source: crate::StartupSourceError::NativeStatus { status },
                    } = &source
                    {
                        self.native_retire_scope_failure.get_or_insert(*status);
                    }
                    if owned_failure || first_error.is_none() {
                        // Owning typed output must survive a later native error;
                        // its independent close refusal is already journaled.
                        first_error = Some(source);
                    }
                }
            }
        }
        let join_status = (handle.api.tryjoin)(handle.id, handle.pointer());
        let observed = handle.observe();
        if let Ok(journal) = &observed {
            if journal.first_status != 0 {
                self.native_terminal_status = journal.first_status;
            }
            if journal.physical_returned == 1 {
                self.native_retired = true;
            }
        }
        if let Some(source) = first_error {
            return Err(source);
        }
        let journal = observed?;
        native_status(join_status)?;
        if journal.physical_returned != 1 || (journal.initialized == 1 && journal.destroyed != 1) {
            return Err(status_error(-libc::EBUSY));
        }
        native_status(self.native_terminal_status)
    }
}

impl LiveFingerprintDigestWork {
    fn publish_native(
        &mut self,
        slot: &FingerprintSampleSlot,
        sample: &crucible_qemu_shmem::FingerprintSample,
        handle: Handle,
        work: &WorkRef,
    ) -> Result<(), FingerprintWorkerCause> {
        if self.publication != MaterialPublication::NotStarted {
            return Err(FingerprintWorkerCause::UnsettledWork);
        }
        let current = || {
            let mut bounded_ns = 0;
            let status =
                (handle.api.worker_material_current)(handle.pointer(), work, &mut bounded_ns);
            if status != 0 || bounded_ns == 0 {
                Err(FingerprintWorkerCause::Native {
                    operation: "publication Original",
                    status: if status != 0 {
                        status
                    } else {
                        -libc::ETIMEDOUT
                    },
                })
            } else {
                Ok(())
            }
        };
        current()?;
        self.publication = MaterialPublication::Attempted;
        slot.publish(sample)
            .map_err(FingerprintWorkerCause::Publication)?;
        self.publication = MaterialPublication::Published;
        current()?;
        self.publication = MaterialPublication::AcknowledgementAttempted;
        if !slot.acknowledge_capture_v1(self.capture_request) {
            return Err(FingerprintWorkerCause::CaptureChanged {
                request: self.capture_request,
            });
        }
        self.publication = MaterialPublication::Acknowledged;
        // Terminal Original failure after ACK is retained as failed health.
        current()
    }
}

// SAFETY: projections never dereference Native objects in Rust. Each fixed slot
// mutex serializes its worker and Main uses; actual native return authenticates
// process/thread/incarnation. Saved diagnostic keys grant no owning operation.
unsafe impl Send for LiveFingerprintDigestWork {}

fn check_worker_identity(
    control: &Arc<FingerprintWorkerControl>,
) -> Result<(), LiveVcpuTimeCallbackError> {
    let context = control
        .native
        .as_ref()
        .ok_or_else(|| status_error(-libc::ESTALE))?;
    let snapshot = context.quiescence.identity_snapshot().map_err(|source| {
        control.refuse(FingerprintWorkerCause::Registration(source));
        LiveFingerprintDigestWorker::failed(control)
    })?;
    let index = WORKER_FINGERPRINT.trailing_zeros() as usize;
    if snapshot.process_id != u64::from(std::process::id())
        || snapshot.membership_generation == 0
        || snapshot.worker_mask & WORKER_FINGERPRINT == 0
        || snapshot.thread_ids[index] == 0
    {
        control.refuse_native("worker membership", -libc::ECHILD);
        return Err(LiveFingerprintDigestWorker::failed(control));
    }
    Ok(())
}

fn validate_status(status: &WorkerStatus) -> Result<(), LiveVcpuTimeCallbackError> {
    if status.schema_version != 2 || status.struct_size as usize != size_of::<WorkerStatus>() {
        Err(status_error(-libc::EPROTO))
    } else {
        Ok(())
    }
}

fn native_status(status: i32) -> Result<(), LiveVcpuTimeCallbackError> {
    if status == 0 {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

fn status_error(status: i32) -> LiveVcpuTimeCallbackError {
    LiveVcpuTimeCallbackError::CallbackChildStorage {
        source: crate::StartupSourceError::NativeStatus { status },
    }
}
