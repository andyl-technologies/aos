//! Borrows one genuine Launch for the existing finite systemd worker calls.
//!
//! Every native receiver is parked on the original before its first await.
//! Native/storage reuse requires the lower same-original physical proofs. A
//! returned status, shutdown, completed SDK future or caller boolean cannot
//! release this receiving window. Ordinary workers do not construct this type.

mod schedule;
mod native_schedule;
mod phase;
mod compensation;
pub(crate) use compensation::{HostLaunchCompensationLoanV1, HostLaunchVerificationAffinityV1};
use compensation::CompensationCallV1;
use phase::WorkerPhaseEntryV4;
mod submission;
mod stop;
mod acquisition_disposal;
pub(crate) use acquisition_disposal::HostLaunchAcquisitionDisposedV4;
pub(super) use submission::PayloadSubmissionV3;

use std::sync::{Arc, Weak};

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_systemd_client::{
    GuardianUnitPropertyOriginalV2, HostSystemdCallV2, HostSystemdConnectionOriginalV2,
    HostSystemdNativeDisposedV2, HostSystemdStorageCompactedV2, PayloadUnitPropertyOriginalV2,
};
use tokio::sync::Mutex;

use crate::plan::HostExecutionReceivingLoanV2;
mod cleanup_funding;
use cleanup_funding::WorkerReceivingOriginalV5;
use crate::{HostError, Result};

use self::schedule::{HostLaunchWorkerScheduleV2, MAXIMUM_CALLS};
use self::native_schedule::HostLaunchNativeScheduleV2;

pub(crate) use schedule::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V3;
const LIVE_NATIVE_CALLS: usize = 3;
type RequestIdentity = ([u8; 16], [u8; 32], [u8; 32]);

/// Describes one closed worker phase on its actual consumed Launch.
///
/// Only this module's source roster and real predecessor disposal checks may
/// construct a phase. The upper loan compares its liability on the same
/// original; this DATA object supplies neither a new grant nor a capacity.
#[derive(Clone, Copy)]
pub(crate) struct HostLaunchWorkerPhaseV4 {
    request: RequestIdentity,
    current_native_files: usize,
    compensation_prearm: bool,
}

impl HostLaunchWorkerPhaseV4 {
    pub(crate) fn request_identity_v4(&self) -> RequestIdentity {
        self.request
    }

    /// Identifies the private healthy-phase quote; this DATA grants no entry.
    pub(crate) fn compensation_prearm_v1(&self) -> bool {
        self.compensation_prearm
    }

    pub(crate) fn current_native_files_v4(&self) -> usize {
        self.current_native_files
    }
}

#[derive(Clone, Copy)]
enum WorkerFailureV2 {
    Call(usize),
    Kernel,
    Inspection(usize),
    Supervisor(usize),
    Snapshot(usize),
    Shifted(usize),
    Phase,
}

/// Holds one consumed Launch's complete finite native SDK roster.
pub(crate) struct HostLaunchWorkerOriginalV2 {
    request: RequestIdentity,
    schedule: HostLaunchWorkerScheduleV2,
    calls: Vec<Arc<Mutex<SystemdCallOriginalV2>>>,
    used: [usize; 6],
    first: Option<WorkerFailureV2>,
    known_job_failure: Option<usize>,
    native_schedule: Option<HostLaunchNativeScheduleV2>,
    inspections: Vec<Arc<Mutex<super::systemd::PayloadInspectionQuiescenceOriginalV2>>>,
    supervisors: Vec<Arc<Mutex<super::systemd::SupervisorProofOriginalV2>>>,
    snapshots: Vec<Arc<Mutex<super::systemd::RuntimeProofOriginalV2>>>,
    shifted: Vec<Arc<Mutex<super::shifted_payload_inspection::ShiftedPayloadOriginalV2>>>,
    kernel_rechecks: super::kernel_recheck::PayloadKernelRechecksV2,
    completed_limit_points: Vec<super::limit_original::BoundLimitNativeDisposedV4>,
    active_limit_point: bool,
    guardian_path_bytes: usize,
    phase_error: Option<HostError>,
    compensation_scope: Option<(super::HostRuntimeIdentity, [u8; 32])>,
    compensation_prearm: Option<HostLaunchWorkerPhaseV4>,
    compensation_entered: bool,
    compensation_result: Option<Result<()>>,
}

impl HostLaunchWorkerOriginalV2 {
    /// Admits the concrete SDK/property roster before constructing its owner.
    ///
    /// # Errors
    /// Rejects another request/purpose, overflow, reentry into a closed original
    /// or a complete roster exceeding the same consumed Launch capacity.
    pub(crate) fn reserve_sdk_before_catalog_v2(
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
        complete: &mut aos_sandbox_model::ResourceVector,
        request: &AuthenticatedBrokerMethodRequestV1,
        guardian: &crate::plan::GuardianConfig,
    ) -> Result<Arc<Mutex<Self>>> {
        Self::reserve_program_before_native_v4(&mut WorkerReceivingOriginalV5::Launch(receiving), complete, request, guardian, false)
    }

    pub(crate) fn reserve_resident_stop_before_native_v4(
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
        complete: &mut aos_sandbox_model::ResourceVector,
        request: &AuthenticatedBrokerMethodRequestV1,
        guardian: &crate::plan::GuardianConfig,
    ) -> Result<Arc<Mutex<Self>>> {
        Self::reserve_program_before_native_v4(&mut WorkerReceivingOriginalV5::Launch(receiving), complete, request, guardian, true)
    }

    /// Reserves the same Stop-only roster on the genuine fresh cleanup loan.
    ///
    /// # Errors
    /// Refuses another authenticated request, closed loan or insufficient
    /// original capacity before allocating or entering the native program.
    pub(crate) fn reserve_cleanup_stop_before_native_v1(
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        complete: &mut aos_sandbox_model::ResourceVector,
        request: &AuthenticatedBrokerMethodRequestV1,
        guardian: &crate::plan::GuardianConfig,
    ) -> Result<Arc<Mutex<Self>>> {
        WorkerReceivingOriginalV5::require_stop_method_v1(request)?;
        Self::reserve_program_before_native_v4(&mut WorkerReceivingOriginalV5::Cleanup(receiving), complete, request, guardian, true)
    }

    fn reserve_program_before_native_v4(
        receiving: &mut WorkerReceivingOriginalV5<'_, '_>,
        complete: &mut aos_sandbox_model::ResourceVector,
        request: &AuthenticatedBrokerMethodRequestV1,
        guardian: &crate::plan::GuardianConfig,
        resident_stop: bool,
    ) -> Result<Arc<Mutex<Self>>> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        receiving.require_launch_request_v2(request)?;
        let path_bytes = guardian.worker_property_path_bytes_v2();
        let guardian = GuardianUnitPropertyOriginalV2::receiving_obligations_for_path_v2(path_bytes)
            .ok_or(HostError::ResourceExhausted)?;
        let payload = PayloadUnitPropertyOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let kernel = super::kernel_recheck::PayloadKernelRechecksV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let bytes = guardian.0.checked_add(payload.0)
            .and_then(|bytes| bytes.checked_add(kernel.0))
            .and_then(|bytes| bytes.checked_add(
                2 * std::mem::size_of::<HostLaunchWorkerReceivingV2<'static, 'static>>()
                    + 4 * std::mem::size_of::<ReadOnlyPostV2>()
                    + 2 * std::mem::size_of::<HostLaunchCompensationLoanV1<'static, 'static, 'static>>()
                    + 4 * std::mem::size_of::<CompensationCallV1>()
                    + 2 * std::mem::size_of::<super::systemd::launch_payload::LaunchPayloadWorkerV3<'static, 'static, 'static, 'static>>(),
            ))
            .and_then(|bytes| bytes.checked_add(
                2 * std::mem::size_of::<Mutex<Self>>() + 4 * std::mem::size_of::<usize>()
                    + 4 * std::mem::size_of::<super::limit_original::BoundLimitNativeDisposedV4>(),
            )).ok_or(HostError::ResourceExhausted)?;
        let names = guardian.2.checked_add(payload.2)
            .and_then(|names| names.checked_add(kernel.2))
            .ok_or(HostError::ResourceExhausted)?;
        // The real window rejects a second FD-bearing submission until the
        // first properties AND SDK socket/message leaves physically retire.
        // Their memory and namespace suppliers remain conservatively summed.
        let properties = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::OpenFiles, u64::try_from(guardian.1.max(payload.1).checked_add(kernel.1)
                .ok_or(HostError::ResourceExhausted)?).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| HostError::ResourceExhausted)?);
        let stop_native = super::systemd::StopQuiescenceOriginalV3::receiving_demand_v3()
            .ok_or(HostError::ResourceExhausted)?;
        let mut complete_stop_native = ResourceVector::ZERO;
        for dimension in D::ALL {
            // A Stop collector belongs to its actual SDK row. Window reuse
            // requires physical disposal of BOTH SDK and Stop temporary FDs.
            // Failed jobs/ambiguous native prefixes occupy that same row.
            let simultaneous = if dimension == D::OpenFiles {
                LIVE_NATIVE_CALLS
            } else {
                // Keep every row's memory/namespace/traffic source liability;
                // native FD disposal alone grants no other reduction.
                HostLaunchWorkerScheduleV2::call_limit(HostSystemdCallV2::ExactStop)
            };
            complete_stop_native = complete_stop_native.with(dimension,
                stop_native.get(dimension).checked_mul(simultaneous as u64)
                    .ok_or(HostError::ResourceExhausted)?);
        }
        let properties = properties.checked_add(complete_stop_native)
            .map_err(|_| HostError::ResourceExhausted)?;
        *complete = complete.checked_add(properties.with(D::OpenFiles, 0)).map_err(|_| HostError::ResourceExhausted)?;
        receiving.require_complete_v2(*complete)?;
        let remaining = receiving.remaining_launch_capacity_v2(*complete)?;
        let native_schedule = if resident_stop { None } else { Some(match HostLaunchNativeScheduleV2::derive(remaining, path_bytes) {
            Ok(schedule) => schedule,
            Err(error) => {
                let minimum = HostLaunchNativeScheduleV2::minimum_demand()?
                    .checked_add(HostLaunchWorkerScheduleV2::minimum_demand(path_bytes)?)
                    .map_err(|_| HostError::ResourceExhausted)?;
                *complete = complete.checked_add(minimum.with(D::OpenFiles, 0)).map_err(|_| HostError::ResourceExhausted)?;
                receiving.require_complete_v2(*complete)?;
                return Err(error);
            }
        }) };
        let native_demand = native_schedule.map_or(ResourceVector::ZERO, |schedule| schedule.demand());
        *complete = complete.checked_add(native_demand.with(D::OpenFiles, 0))
            .map_err(|_| HostError::ResourceExhausted)?;
        receiving.require_complete_v2(*complete)?;
        let remaining = receiving.remaining_launch_capacity_v2(*complete)?;
        let planned = if resident_stop {
            HostLaunchWorkerScheduleV2::derive_resident_stop_v4(remaining)
        } else {
            HostLaunchWorkerScheduleV2::derive(remaining, path_bytes)
        };
        let schedule = match planned {
            Ok(schedule) => schedule,
            Err(error) => {
                // A finite but unaffordable minimum reaches the SAME real
                // comparison before any allocation/SDK entry, retaining its
                // genuine financial failure on the intrinsic original.
                let minimum = if resident_stop {
                    HostLaunchWorkerScheduleV2::minimum_resident_stop_demand_v4()
                } else {
                    HostLaunchWorkerScheduleV2::minimum_demand(path_bytes)
                };
                if let Ok(minimum) = minimum {
                    *complete = complete.checked_add(minimum.with(D::OpenFiles, 0)).map_err(|_| HostError::ResourceExhausted)?;
                    receiving.require_complete_v2(*complete)?;
                }
                return Err(error);
            }
        };
        *complete = complete.checked_add(schedule.demand().with(D::OpenFiles, 0)).map_err(|_| HostError::ResourceExhausted)?;
        receiving.require_complete_v2(*complete)?;
        Ok(Arc::new(Mutex::new(Self::new(request, schedule, native_schedule, path_bytes))))
    }

    // The enclosing real Launch admits the full schedule and concrete owner
    // construction before calling this inert allocation. No public adopter,
    // account, descriptor or replacement deadline is supplied here.
    fn new(
        request: &AuthenticatedBrokerMethodRequestV1,
        schedule: HostLaunchWorkerScheduleV2,
        native_schedule: Option<HostLaunchNativeScheduleV2>,
        guardian_path_bytes: usize,
    ) -> Self {
        Self {
            request: identity(request),
            schedule,
            calls: Vec::with_capacity(MAXIMUM_CALLS),
            used: [0; 6],
            first: None,
            known_job_failure: None,
            native_schedule,
            inspections: Vec::with_capacity(2),
            supervisors: Vec::with_capacity(2),
            snapshots: Vec::with_capacity(2),
            shifted: Vec::with_capacity(2),
            kernel_rechecks: super::kernel_recheck::PayloadKernelRechecksV2::new(),
            completed_limit_points: Vec::with_capacity(2),
            active_limit_point: false,
            guardian_path_bytes,
            phase_error: None,
            compensation_scope: None,
            compensation_prearm: None,
            compensation_entered: false,
            compensation_result: None,
        }
    }
}

enum StopNativeCompletionV1<'proof> {
    Resident(&'proof crate::broker::HostResidentStopNativeCompletedV4),
    Cleanup(&'proof crate::broker::HostStopCleanupNativeCompletedV1),
}

impl StopNativeCompletionV1<'_> {
    fn request(&self) -> ([u8;16],[u8;32],[u8;32]) {
        match self { Self::Resident(proof)=>proof.request_identity_v4(),
            Self::Cleanup(proof)=>proof.request_identity_v1() }
    }

    fn matches_worker(&self, worker: &Arc<Mutex<HostLaunchWorkerOriginalV2>>,
        request: ([u8;16],[u8;32],[u8;32]),
    ) -> bool {
        match self { Self::Resident(proof)=>proof.matches_worker_v4(worker,request),
            Self::Cleanup(proof)=>proof.matches_worker_v1(worker,request) }
    }
}

impl HostLaunchWorkerOriginalV2 {
    pub(crate) fn require_resident_stop_parent_disposal_v4(
        &self,
        completed: &crate::broker::HostResidentStopNativeCompletedV4,
    ) -> Result<()> {
        self.require_stop_parent_disposal_engine_v1(StopNativeCompletionV1::Resident(completed))
    }

    pub(crate) fn require_cleanup_stop_parent_disposal_v1(&self,
        completed: &crate::broker::HostStopCleanupNativeCompletedV1,
    ) -> Result<()> {
        self.require_stop_parent_disposal_engine_v1(StopNativeCompletionV1::Cleanup(completed))
    }

    fn require_stop_parent_disposal_engine_v1(&self, completed: StopNativeCompletionV1<'_>) -> Result<()> {
        if !self.schedule.is_resident_stop_v4() || self.first.is_some()
            || completed.request() != self.request
        {
            return Err(closed("Stop parent disposal lacks its actual completed program"));
        }
        for row in &self.calls {
            if Arc::strong_count(row) != 1 {
                return Err(closed("Stop native row still has another owner"));
            }
            let row = row.try_lock().map_err(|_| closed("Stop native row is still borrowed"))?;
            if row.storage_is_physically_compacted() { continue; }
            if row.call != HostSystemdCallV2::ExactStop
                || !matches!(row.first, None | Some(CallFailureV2::JobResult))
                || !matches!(row.disposition, Some(Ok(())))
                || !row.disposal.as_ref().is_some_and(|result|
                    result.as_ref().is_ok_and(|proof| proof.belongs_to_v2(&row.native)))
                || row.operation.is_some() || row.readback.is_some() || row.guard.is_some()
            {
                return Err(closed("Stop native row lacks whole raw physical termination"));
            }
        }
        Ok(())
    }

    pub(crate) async fn finish_resident_stop_sdk_v4(
        original: &Arc<Mutex<Self>>,
        completed: &crate::broker::HostResidentStopNativeCompletedV4,
    ) -> Result<()> {
        Self::finish_stop_sdk_engine_v1(original, StopNativeCompletionV1::Resident(completed)).await
    }

    pub(crate) async fn finish_cleanup_stop_sdk_v1(
        original: &Arc<Mutex<Self>>,
        completed: &crate::broker::HostStopCleanupNativeCompletedV1,
    ) -> Result<()> {
        Self::finish_stop_sdk_engine_v1(original, StopNativeCompletionV1::Cleanup(completed)).await
    }

    pub(crate) fn format_cleanup_sdk_failure_v1(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        let slot = self.known_job_failure.or(match self.first {
            Some(WorkerFailureV2::Call(slot)) => Some(slot),
            _ => None,
        })?;
        let Some(row) = self.calls.get(slot) else {
            return Some(Err(std::fmt::Error));
        };
        let Ok(row) = row.try_lock() else {
            return Some(Err(std::fmt::Error));
        };
        // The ordinary retained row formatter resolves the original raw native
        // cause, including the separately retained cleanup-post destinations.
        Some(std::fmt::Display::fmt(&CallFailureViewV2(&row), formatter))
    }

    pub(crate) fn cleanup_sdk_posts_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        let each = super::systemd::StopQuiescenceOriginalV3::cleanup_post_receiving_demand_v1()?;
        let mut complete = aos_sandbox_model::ResourceVector::ZERO;
        for _ in 0..schedule::RESIDENT_STOP_EFFECTS_V4 {
            complete = complete.checked_add(each).ok()?;
        }
        Some(complete)
    }

    pub(crate) async fn observe_cleanup_sdk_posts_once_v1(
        original: &Arc<Mutex<Self>>,
        worker: &super::RetainedPayloadWorkerV1<'_>,
    ) -> Result<()> {
        let count = {
            let held = original.lock().await;
            if !held.schedule.is_resident_stop_v4() {
                return Err(closed("cleanup SDK posts lack their closed Stop roster"));
            }
            held.calls.len()
        };
        let mut first = None;
        for index in 0..count {
            let receiver = {
                let held = original.lock().await;
                held.calls
                    .get(index)
                    .cloned()
                    .ok_or_else(|| closed("cleanup SDK row disappeared"))?
            };
            let mut row = receiver.lock().await;
            if row.storage_is_physically_compacted() || row.call != HostSystemdCallV2::ExactStop {
                continue;
            }
            let result = match row.stop_native.as_ref() {
                // A refused entry before native preparation has no held
                // PIDFD/monitor. It cannot satisfy positive disposal below.
                None => continue,
                Some(native) => match native.lock() {
                    Ok(mut native) => {
                        native.confirm_prepared_cleanup_absence_once_v1(&worker.worker.cgroup_root)
                    }
                    Err(_) => Err(closed("cleanup SDK native owner is poisoned")),
                },
            };
            if let Err(cause) = result {
                row.readback.get_or_insert(cause);
                row.first.get_or_insert(CallFailureV2::NativeReadback);
                first.get_or_insert(index);
            }
            // Earlier body/row failures cannot suppress independently prepaid
            // observations of another actual held PIDFD and population OFD.
        }
        if let Some(index) = first {
            original
                .lock()
                .await
                .first
                .get_or_insert(WorkerFailureV2::Call(index));
            return Err(closed(
                "cleanup SDK native post refused; original rows remain retained",
            ));
        }
        Ok(())
    }

    async fn finish_stop_sdk_engine_v1(
        original: &Arc<Mutex<Self>>,
        completed: StopNativeCompletionV1<'_>,
    ) -> Result<()> {
        let count = {
            let held = original.lock().await;
            if !held.schedule.is_resident_stop_v4()
                || held.first.is_some()
                || !completed.matches_worker(original, held.request)
            {
                return Err(closed(
                    "Stop SDK termination lacks its actual whole native proof",
                ));
            }
            held.calls.len()
        };
        for index in 0..count {
            let receiver = {
                let held = original.lock().await;
                held.calls
                    .get(index)
                    .cloned()
                    .ok_or_else(|| closed("Stop SDK row disappeared"))?
            };
            let mut row = receiver.lock().await;
            if row.storage_is_physically_compacted() {
                continue;
            }
            if matches!(completed, StopNativeCompletionV1::Cleanup(_)) {
                let native = row
                    .stop_native
                    .as_ref()
                    .ok_or_else(|| closed("cleanup SDK native post owner is absent"))?;
                native
                    .lock()
                    .map_err(|_| closed("cleanup SDK native post owner is poisoned"))?
                    .require_cleanup_native_posts_v1()?;
            }
            // A known semantic failed job remains a failed job. Whole native
            // Stop absence/death/hangup can now close its finished raw channel;
            // no earlier Native error or partial prefix may use this frontier.
            let known_terminal_scope = match (&row.first, &row.stop_result) {
                (
                    Some(CallFailureV2::JobResult),
                    Some(aos_systemd_client::ExactStopOutcome::JobFailed(_)),
                ) => true,
                (
                    None,
                    Some(
                        aos_systemd_client::ExactStopOutcome::Residual(_)
                        | aos_systemd_client::ExactStopOutcome::AwaitingAbsence(_)
                        | aos_systemd_client::ExactStopOutcome::MissingManagerObject,
                    ),
                ) => {
                    matches!(row.primary, Some(Ok(())))
                }
                _ => false,
            };
            if row.call != HostSystemdCallV2::ExactStop
                || !known_terminal_scope
                || !matches!(row.disposition, Some(Ok(())))
                || row.disposal.is_some()
                || row.operation.is_some()
                || row.readback.is_some()
                || row.guard.is_some()
            {
                return Err(closed(
                    "Stop row has unresolved native custody at whole termination",
                ));
            }
            if let Err(cause) = row.dispose_sdk_files_v4().await {
                drop(row);
                original
                    .lock()
                    .await
                    .first
                    .get_or_insert(WorkerFailureV2::Call(index));
                return Err(cause);
            }
        }
        Ok(())
    }
}

/// Borrows only the same authenticated request and already-consumed flight.
pub(crate) struct HostLaunchWorkerReceivingV2<'call, 'original> {
    receiving: WorkerReceivingOriginalV5<'call, 'original>,
    request: &'call AuthenticatedBrokerMethodRequestV1,
    original: Arc<Mutex<HostLaunchWorkerOriginalV2>>,
    deadline: tokio::time::Instant,
    write_clock: crate::broker::HostLaunchWriteClockV2,
    payload_entry: Option<super::GuardianObservation>,
}

impl<'call, 'original> HostLaunchWorkerReceivingV2<'call, 'original> {
    /// Borrows the actual resident roster without opening another account.
    ///
    /// # Errors
    /// Rejects a different request or an inactive/closed Launch interval.
    pub(crate) async fn new(
        receiving: &'call mut HostExecutionReceivingLoanV2<'original>,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        original: Arc<Mutex<HostLaunchWorkerOriginalV2>>,
        deadline: tokio::time::Instant,
        write_clock: crate::broker::HostLaunchWriteClockV2,
    ) -> Result<Self> {
        receiving.require_launch_request_v2(request)?;
        if original.lock().await.request != identity(request) {
            return Err(closed("worker original differs from its genuine Launch"));
        }
        Ok(Self {
            receiving: WorkerReceivingOriginalV5::Launch(receiving),
            request,
            original,
            deadline,
            write_clock,
            payload_entry: None,
        })
    }

    /// Borrows the same concrete worker/clock using fresh Stop cleanup funding.
    ///
    /// # Errors
    /// Refuses another request, closed cleanup or a Launch-capable roster.
    pub(crate) async fn new_cleanup_stop_v1(
        receiving: &'call mut crate::plan::HostControlPreparationReceivingV5<'original>,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        original: Arc<Mutex<HostLaunchWorkerOriginalV2>>,
        deadline: tokio::time::Instant,
        write_clock: crate::broker::HostLaunchWriteClockV2,
    ) -> Result<Self> {
        WorkerReceivingOriginalV5::require_stop_method_v1(request)?;
        receiving.require_cleanup_request_v1(request)?;
        {
            let held = original.lock().await;
            if held.request != identity(request) || !held.schedule.is_resident_stop_v4() {
                return Err(closed("cleanup worker differs from its exact Stop-only roster"));
            }
        }
        Ok(Self { receiving: WorkerReceivingOriginalV5::Cleanup(receiving), request,
            original, deadline, write_clock, payload_entry: None })
    }

    pub(crate) fn require_final_retention_v3(&mut self, request: &[u8; 16]) -> Result<()> {
        if self.request.request_id() != *request {
            return Err(closed("final runtime retention names a different request"));
        }
        self.require_current()?;
        self.admit_final_promotion_v4()
    }

    pub(crate) fn component_report_original_failure_entered_v2(&self) -> bool {
        self.receiving.component_report_original_failure_entered_v2()
    }

    pub(crate) fn require_component_startup_report_v2(
        &self, scope: &crate::broker::component_startup::ComponentStartupReportScopeV2,
    ) -> Result<()> {
        self.require_current()?;
        if scope.request_v2() != identity(self.request) {
            return Err(closed("component report is foreign to the actual paid worker"));
        }
        scope.require_deadline_v2()
    }

    fn require_current(&self) -> Result<()> {
        if self.original.try_lock().map_err(|_| closed("worker original is borrowed"))?
            .compensation_entered
        {
            return Err(closed("retained negative worker cannot enter a healthy port"));
        }
        self.receiving.require_launch_request_v2(self.request)
    }

    // Only the genuine borrowed Launch may enter this finite, prepaid native
    // roster. It leaves the real input pins resident for later worker/posts.
    pub(super) async fn recheck_payload_v2(
        &mut self,
        payload: &super::PinnedPayloadLeader,
        supervisor: &super::PinnedLeader,
    ) -> Result<()> {
        self.require_current()?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Kernel).await?;
        let mut original = self.original.lock().await;
        if original.request != identity(self.request) || original.first.is_some() {
            return Err(closed("payload recheck differs from its healthy Launch"));
        }
        let result = original.kernel_rechecks.observe_once(payload, supervisor);
        if result.is_err() {
            original.first.get_or_insert(WorkerFailureV2::Kernel);
        }
        result
    }

    // The receiver is parked before root duplication, freezer writes or scan
    // growth. Its returned payload remains on that same actual owner, including
    // after a failed independently owed thaw, until upper disposition.
    pub(super) async fn inspect_payload_v2(
        &mut self,
        input: &aos_sandbox_linux::path::BeneathRoot,
        supervisor_pid: u32,
        expected_root: (u64, u64),
        expected_network: (u64, u64),
    ) -> Result<Arc<Mutex<super::systemd::PayloadInspectionQuiescenceOriginalV2>>> {
        self.require_current()?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Inspection).await?;
        let (slot, receiver, limits) = {
            let mut original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some()
                || original.inspections.len() == 2
            {
                return Err(closed("payload inspection differs from its healthy finite Launch"));
            }
            if let Some(previous) = original.inspections.last() {
                if !previous.lock().await.native_is_disposed_v4() {
                    return Err(closed("earlier inspection native prefix remains occupied"));
                }
            }
            if original.completed_limit_points.len() != original.inspections.len() {
                return Err(closed("earlier actual limit point remains occupied"));
            }
            let slot = original.inspections.len();
            let receiver = Arc::new(Mutex::new(
                super::systemd::PayloadInspectionQuiescenceOriginalV2::new(
                    self.deadline, self.write_clock.clone(),
                ),
            ));
            original.inspections.push(Arc::clone(&receiver));
            (slot, receiver, original.native_schedule.ok_or_else(|| closed("control program has no inspection schedule"))?.limits())
        };
        let outcome = receiver.lock().await.discover_once(
            input, supervisor_pid, expected_root, expected_network, limits,
        );
        if outcome.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Inspection(slot));
            return Err(self.retained_failure().await);
        }
        Ok(receiver)
    }

    // This actual native receiver is resident before its first observation.
    // The shared supervisor recipe keeps the lower inspection output on its
    // original, so a later liveness/kernel failure cannot drop payload pins.
    pub(super) async fn verify_supervisor_v2(
        &mut self,
        worker: &super::SystemdOneShotWorker,
        pins: &crate::plan::LaunchPins,
        leader: &super::PinnedLeader,
        policy: aos_systemd_client::PayloadRootContinuityPolicyV1,
    ) -> Result<Arc<Mutex<super::systemd::SupervisorProofOriginalV2>>> {
        self.require_current()?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Supervisor).await?;
        let (slot, receiver) = {
            let mut original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some()
                || original.supervisors.len() == 2
            {
                return Err(closed("supervisor proof differs from its healthy finite Launch"));
            }
            if let Some(previous) = original.supervisors.last() {
                if !previous.lock().await.native_is_disposed_v4() {
                    return Err(closed("earlier supervisor native prefix remains occupied"));
                }
            }
            let slot = original.supervisors.len();
            let receiver = Arc::new(Mutex::new(
                super::systemd::SupervisorProofOriginalV2::new(self.deadline),
            ));
            original.supervisors.push(Arc::clone(&receiver));
            (slot, receiver)
        };
        let outcome = receiver.lock().await.verify_once(
            &worker.cgroup_root, pins, leader, policy, self,
        ).await;
        if outcome.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Supervisor(slot));
            return Err(self.retained_failure().await);
        }
        Ok(receiver)
    }

    pub(super) async fn runtime_snapshot_v2(
        &mut self,
        pins: &crate::plan::LaunchPins,
        supervisor: &super::PinnedLeader,
        payload: &super::PinnedPayloadLeader,
    ) -> Result<crate::state::transition::RuntimeProofSnapshot> {
        self.require_current()?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Snapshot).await?;
        let (slot, receiver) = {
            let mut original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some()
                || original.snapshots.len() == 2
            {
                return Err(closed("runtime snapshot differs from its healthy finite Launch"));
            }
            if let Some(previous) = original.snapshots.last() {
                if !previous.lock().await.native_is_disposed_v4() {
                    return Err(closed("earlier snapshot native prefix remains occupied"));
                }
            }
            let slot = original.snapshots.len();
            let receiver = Arc::new(Mutex::new(
                super::systemd::RuntimeProofOriginalV2::new(self.deadline),
            ));
            original.snapshots.push(Arc::clone(&receiver));
            (slot, receiver)
        };
        let outcome = receiver.lock().await.capture_once(pins, supervisor, payload);
        match outcome {
            Ok(snapshot) => Ok(snapshot),
            Err(_) => {
                self.original.lock().await.first.get_or_insert(WorkerFailureV2::Snapshot(slot));
                Err(self.retained_failure().await)
            }
        }
    }

    pub(super) async fn inspect_shifted_v2(
        &mut self,
        identity: &super::HostRuntimeIdentity,
        spec: &aos_systemd_client::SandboxUnitSpec,
        invocation_id: [u8; 16],
        supervisor: &super::PinnedLeader,
        payload: &super::PinnedPayloadLeader,
        proof: &crate::state::transition::RuntimeProofSnapshot,
    ) -> Result<super::shifted_payload_inspection::VerifiedShiftedPayloadInspectionV1> {
        self.require_current()?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Shifted).await?;
        let (slot, receiver) = {
            let mut original = self.original.lock().await;
            if original.request != self::identity(self.request) || original.first.is_some()
                || original.shifted.len() == 2
            {
                return Err(closed("shifted inspection differs from its healthy finite Launch"));
            }
            if let Some(previous) = original.shifted.last() {
                let previous = previous.lock().await;
                let disposed = previous.disposal_proof()
                    .ok_or_else(|| closed("earlier shifted temporary native window remains occupied"))?;
                if !disposed.belongs_to_v2(&previous, original.shifted.len() - 1) {
                    return Err(closed("shifted native disposal belongs to another original"));
                }
            }
            let slot = original.shifted.len();
            let receiver = Arc::new(Mutex::new(
                super::shifted_payload_inspection::ShiftedPayloadOriginalV2::new(slot),
            ));
            original.shifted.push(Arc::clone(&receiver));
            (slot, receiver)
        };
        let outcome = receiver.lock().await.inspect_once(
            identity, spec, invocation_id, supervisor, payload, proof, self,
        ).await;
        if outcome.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Shifted(slot));
            return Err(self.retained_failure().await);
        }
        let completed = receiver.lock().await.take_completed_once()
            .ok_or_else(|| closed("completed actual shifted record is absent"))?;
        self.dispose_inspection_prefixes_before_limits_v4(slot).await?;
        self.admit_native_phase_v4(WorkerPhaseEntryV4::Limits).await?;
        self.original.lock().await.active_limit_point = true;
        Ok(completed)
    }

    async fn dispose_inspection_prefixes_before_limits_v4(&mut self, slot: usize) -> Result<()> {
        let (inspection, supervisor, snapshot) = {
            let original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some()
                || original.inspections.len() != slot + 1
                || original.supervisors.len() != slot + 1
                || original.snapshots.len() != slot + 1
            {
                return Err(closed("inspection prefix differs from its actual proof point"));
            }
            (Arc::clone(&original.inspections[slot]),
                Arc::clone(&original.supervisors[slot]),
                Arc::clone(&original.snapshots[slot]))
        };
        if !supervisor.lock().await.inspection()
            .is_some_and(|actual| Arc::ptr_eq(actual, &inspection))
        {
            return Err(closed("inspection prefix has another supervisor association"));
        }

        // The actual shifted record has completed both kernel bookends and
        // liveness after Q's independently owed thaw and supervisor/snapshot
        // checks. Its payload/supervisor pins are already on the readback.
        // Complete these local native intervals before limit capture begins.
        let result = inspection.lock().await.dispose_completed_native_once_v4();
        if result.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Inspection(slot));
            return Err(self.retained_failure().await);
        }
        let result = supervisor.lock().await.dispose_completed_native_once_v4();
        if result.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Supervisor(slot));
            return Err(self.retained_failure().await);
        }
        let result = snapshot.lock().await.dispose_completed_native_once_v4();
        if result.is_err() {
            self.original.lock().await.first.get_or_insert(WorkerFailureV2::Snapshot(slot));
            return Err(self.retained_failure().await);
        }
        Ok(())
    }

    pub(in crate::worker) async fn complete_ready_limit_point_v4(
        &mut self,
        state: &mut super::BoundPayloadReadbackV1,
    ) -> Result<()> {
        let snapshot = state.verified()?.proof;
        {
            let original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some()
                || original.completed_limit_points.len() == 2
                || original.completed_limit_points.len() + 1 != original.inspections.len()
            {
                return Err(closed("Ready limit point differs from its actual Launch"));
            }
            let source = original.snapshots.last()
                .ok_or_else(|| closed("Ready limit snapshot is absent"))?;
            let source = source.lock().await;
            if !source.native_is_disposed_v4() || !source.matches_snapshot_v4(snapshot) {
                return Err(closed("Ready limit witness differs from its actual point"));
            }
        }
        state.retire_ready_limit_files_once_v4()?;
        let proof = state.limit_native.as_ref()
            .and_then(|native| native.worker_disposal_v4())
            .ok_or_else(|| closed("Ready limit disposal proof is absent"))?;
        let mut original = self.original.lock().await;
        original.completed_limit_points.push(proof);
        original.active_limit_point = false;
        Ok(())
    }

    async fn prepare_call(
        &mut self,
        call: HostSystemdCallV2,
        obligation: CallObligationV2,
    ) -> Result<Arc<Mutex<SystemdCallOriginalV2>>> {
        let admitted_phase = if matches!(&obligation, CallObligationV2::Primary) {
            Some(self.admit_native_phase_v4(WorkerPhaseEntryV4::Sdk(call)).await?)
        } else {
            None
        };
        match &obligation {
            CallObligationV2::Owed(_) => {
                self.receiving.require_launch_readonly_post_request_v2(self.request)?;
            }
            CallObligationV2::Primary => {
                self.require_current()?;
            }
            CallObligationV2::Compensation(permit) => permit.require_v1(self, call).await?,
        }
        let mut original = self.original.lock().await;
        if original.request != identity(self.request) || original.calls.len() == MAXIMUM_CALLS {
            return Err(closed("worker call roster is exhausted or replaced"));
        }
        if (original.first.is_some() || original.kernel_rechecks.failure().is_some())
            && matches!(&obligation, CallObligationV2::Primary)
        {
            return Err(closed("worker original retains an earlier failure"));
        }
        if carries_descriptors(call) && !original.inspections.is_empty() {
            return Err(closed("a descriptor submission cannot follow payload proof entry"));
        }
        if original.known_job_failure.is_some()
            && matches!(call, HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart)
        {
            return Err(closed("a known failed job cannot admit another start"));
        }
        let index = call_index(call);
        if original.used[index] == original.schedule.call_limit_for_program_v4(call) {
            return Err(closed("worker closed call class is exhausted"));
        }

        let mut live = 0;
        let mut descriptor_submission = false;
        for previous in &original.calls {
            let previous = previous.lock().await;
            if !previous.storage_is_physically_compacted() {
                live += 1;
                descriptor_submission |= carries_descriptors(previous.call);
            }
        }
        if live >= LIVE_NATIVE_CALLS || descriptor_submission && carries_descriptors(call) {
            return Err(closed("worker native receiving window remains occupied"));
        }

        let slot = original.calls.len();
        let parent_post = match obligation {
            CallObligationV2::Primary | CallObligationV2::Compensation(_) => None,
            CallObligationV2::Owed(post) => {
                if !matches!(call, HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve)
                    || call != post.call
                    || !Arc::ptr_eq(&post.original, &self.original)
                    || !original.calls.get(post.parent_slot)
                        .is_some_and(|parent| Arc::ptr_eq(parent, &post.parent))
                {
                    return Err(closed("read-only worker post differs from its prearmed parent"));
                }
                {
                    let mut parent = post.parent.lock().await;
                    if !parent.prearmed_phase.as_ref().is_some_and(|phase| {
                        phase.request_identity_v4() == identity(self.request)
                            && matches!(parent.call, HostSystemdCallV2::GuardianStart
                                | HostSystemdCallV2::PayloadStart)
                            && parent.posts.len() <= 2
                    }) {
                        return Err(closed("read-only child lacks its actual healthy parent phase prearm"));
                    }
                    let destination = parent.posts.get_mut(post.index)
                        .ok_or_else(|| closed("worker post destination is absent"))?;
                    if destination.call != call || destination.child.is_some() {
                        return Err(closed("worker post was replaced or entered already"));
                    }
                    destination.child = Some(slot);
                }
                Some(ParentPostV2 {
                    parent: post.parent,
                    index: post.index,
                })
            }
        };
        let native = original.schedule.call(call)?;
        let effect_gate = matches!(call, HostSystemdCallV2::GuardianStart
            | HostSystemdCallV2::PayloadStart | HostSystemdCallV2::ExactStop)
            .then(|| self.write_clock.sdk_gate_v3());
        // The parent stores the entire receiver before constructing its future.
        // Cancellation cannot discard it or make the slot available again.
        let receiver = Arc::new_cyclic(|this| {
            Mutex::new(SystemdCallOriginalV2::new(
                slot, call, native, parent_post, this.clone(), effect_gate, admitted_phase,
            ))
        });
        original.calls.push(Arc::clone(&receiver));
        original.used[index] += 1;
        Ok(receiver)
    }

    /// Observes one exact role with its paid SDK and native absence original.
    ///
    /// # Errors
    /// Retains every reached native prefix and the chronological actual cause.
    pub(crate) async fn observe_role_v2(
        &mut self,
        worker: &super::RetainedPayloadWorkerV1<'_>,
        identity: &super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
    ) -> Result<super::GuardianObservation> {
        self.observe_exact(worker.worker, identity, role, None).await
    }

    // This actual Sandbox SDK row keeps its completed DTO and all following
    // cgroup/freezer/leader prefixes until local SDK posts/disposal succeed.
    pub(super) async fn observe_sandbox_v2(
        &mut self,
        worker: &super::SystemdOneShotWorker,
        identity: &super::HostRuntimeIdentity,
    ) -> Result<super::WorkerObservation> {
        let receiver = self.prepare_call(HostSystemdCallV2::SandboxObserve, CallObligationV2::Primary).await?;
        let mut absent = None;
        {
            let mut row = receiver.lock().await;
            let primary = async {
                row.connect(self.deadline).await?;
                let name = aos_systemd_client::SandboxUnitName::from_incarnation(*identity.incarnation_id());
                let observed = {
                    let client = row.native.client_v2()
                        .ok_or_else(|| closed("sandbox observation lost its same connected client"))?;
                    client.observe_sandbox_unit(&name).await
                };
                let observed = match observed {
                    Ok(observed) => observed,
                    Err(error) => {
                        row.operation = Some(error);
                        row.first.get_or_insert(CallFailureV2::Operation);
                        return Err(closed("sandbox SDK observation failed; cause retained"));
                    }
                };
                match observed {
                    Some(observed) => {
                        row.sandbox = Some(super::systemd::SandboxNativeOriginalV2::new());
                        row.sandbox.as_mut().ok_or_else(|| closed("sandbox native destination is absent"))?
                            .capture_once(worker, identity, observed)?;
                    }
                    None => {
                        row.absence = Some(ExactCgroupAbsenceOriginalV2::new());
                        worker.verify_absent_exact_cgroup_engine_v2(name.cgroup_path(), row.absence.as_mut())?;
                        absent = Some(super::WorkerObservation {
                            state: super::ObservedRuntimeState::Absent,
                            invocation_id: None,
                            leader: None,
                            payload: None,
                        });
                    }
                }
                Ok(())
            }.await;
            if let Err(error) = primary {
                row.readback = Some(error);
                row.first.get_or_insert(CallFailureV2::NativeReadback);
                row.primary = Some(Err(closed("sandbox native primary failed; cause retained")));
            } else {
                row.primary = Some(Ok(()));
            }
            row.finish().await;
            if row.first.is_none() {
                match self.receiving.require_launch_readonly_post_request_v2(self.request) {
                    Ok(()) => { let _ = row.dispose_positive().await; }
                    Err(error) => {
                        row.guard = Some(error);
                        row.first.get_or_insert(CallFailureV2::Guard);
                    }
                }
            }
        }
        self.record_failure(&receiver).await;
        let mut row = receiver.lock().await;
        if row.first.is_none() {
            // No fallible native/post operation follows this exclusive move.
            // The immediately surrounding shared verification recipe parks it
            // on its actual upper readback before the next check.
            return match row.sandbox.as_mut() {
                Some(native) => native.take_completed_once()
                    .ok_or_else(|| closed("completed sandbox native output is absent")),
                None => absent.ok_or_else(|| closed("completed sandbox absence is absent")),
            };
        }
        drop(row);
        Err(self.retained_failure().await)
    }

    /// Reads the fixed supervisor policy on this consumed Launch's native row.
    ///
    /// The caller retains the returned DATA before applying the sole policy
    /// validator. The same row owns constructor, RPC, close and disposal causes;
    /// a failed observation never releases its physical native window.
    ///
    /// # Errors
    /// Refuses another request, an exhausted roster, a failed native prefix or
    /// any independent readonly post or disposition failure.
    pub(crate) async fn observe_supervisor_policy_v2(
        &mut self,
        spec: &aos_systemd_client::SandboxUnitSpec,
        supervisor_pid: u32,
    ) -> Result<Vec<aos_systemd_client::OwnedValue>> {
        let receiver = self.prepare_call(
            HostSystemdCallV2::SupervisorPolicy,
            CallObligationV2::Primary,
        ).await?;
        {
            let mut row = receiver.lock().await;
            let primary = async {
                row.connect(self.deadline).await?;
                row.supervisor_read = Some(aos_systemd_client::ServicePropertiesReadOriginalV2::new());
                let SystemdCallOriginalV2 { native, supervisor_read, .. } = &mut *row;
                let client = native.client_v2()
                    .ok_or_else(|| closed("supervisor policy lost its same native client"))?;
                let archive = supervisor_read.as_mut()
                    .ok_or_else(|| closed("supervisor policy archive is absent"))?;
                let observed = archive.observe_deadline_once_v2(
                    client, spec.name().as_str(), supervisor_pid,
                    crate::plan::supervisor_policy_properties_v2(), &[], self.deadline,
                ).await;
                if observed.is_err() {
                    row.operation = Some(aos_systemd_client::Error::HostLaunchRetained(
                        "supervisor policy refused; original archive retained",
                    ));
                    row.first.get_or_insert(CallFailureV2::Operation);
                    return Err(closed("supervisor policy RPC failed; actual cause retained"));
                }
                let Some((values, units)) = archive.take_completed_v2() else {
                    return Err(closed("completed supervisor policy archive is absent"));
                };
                let retired = archive.retire_completed_native_aliases_v2();
                row.supervisor_policy = Some(values);
                row.supervisor_unit_values = Some(units);
                if !retired || row.supervisor_unit_values.as_ref().is_none_or(|units| !units.is_empty()) {
                    return Err(closed("supervisor policy aliases lack whole positive retirement"));
                }
                Ok(())
            }.await;
            match primary {
                Ok(()) => row.primary = Some(Ok(())),
                Err(cause) => {
                    row.readback = Some(cause);
                    row.first.get_or_insert(CallFailureV2::NativeReadback);
                    row.primary = Some(Err(closed("supervisor policy primary failed; original retained")));
                }
            }
            row.finish().await;
            if row.first.is_none() {
                match self.receiving.require_launch_readonly_post_request_v2(self.request) {
                    Ok(()) => { let _ = row.dispose_positive().await; }
                    Err(cause) => {
                        row.guard = Some(cause);
                        row.first.get_or_insert(CallFailureV2::Guard);
                    }
                }
            }
        }
        self.record_failure(&receiver).await;
        let mut row = receiver.lock().await;
        if row.first.is_none() {
            return row.supervisor_policy.take()
                .ok_or_else(|| closed("completed supervisor policy DATA is absent"));
        }
        drop(row);
        Err(self.retained_failure().await)
    }

    /// Submits one Guardian and always runs its prearmed exact identity post.
    ///
    /// # Errors
    /// Retains property/guard/submission/native failures and owed-post debt.
    pub(crate) async fn start_guardian_v2(
        &mut self,
        worker: &super::RetainedPayloadWorkerV1<'_>,
        spec: &aos_systemd_client::GuardianUnitSpec,
        identity: &super::HostRuntimeIdentity,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<super::GuardianStartObservation> {
        self.start_guardian(worker.worker, spec, identity, before_effect).await
    }

    async fn observe_exact(
        &mut self,
        worker: &super::SystemdOneShotWorker,
        identity: &super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        post: Option<ReadOnlyPostV2>,
    ) -> Result<super::GuardianObservation> {
        self.observe_exact_kind_v3(worker, identity, role, post, false, None).await
    }

    async fn observe_exact_kind_v3(
        &mut self,
        worker: &super::SystemdOneShotWorker,
        identity: &super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        post: Option<ReadOnlyPostV2>,
        post_unref: bool,
        compensation: Option<CompensationCallV1>,
    ) -> Result<super::GuardianObservation> {
        let obligation = match (post, compensation) {
            (None, Some(permit)) => CallObligationV2::Compensation(permit),
            (Some(_), Some(_)) => return Err(closed("negative call cannot adopt an owed parent")),
            (Some(post), None) => CallObligationV2::Owed(post),
            (None, None) => CallObligationV2::Primary,
        };
        let call = if post_unref { HostSystemdCallV2::PostUnrefObserve } else { HostSystemdCallV2::ExactObserve };
        let receiver = self.prepare_call(call, obligation).await?;
        let mut completed = None;
        {
            let mut row = receiver.lock().await;
            let primary = async {
                row.connect(self.deadline).await?;
                let client = match row.native.take_exact_client_once_v2() {
                    Ok(client) => client,
                    Err(error) => {
                        row.operation = Some(error);
                        row.first.get_or_insert(CallFailureV2::Operation);
                        return Err(closed("exact worker transfer failed; cause retained"));
                    }
                };
                let name = aos_systemd_client::SandboxUnitName::from_incarnation(*identity.incarnation_id());
                let returned = if post_unref {
                    client.observe_after_unref(&name, role).await.map(|observation| match observation {
                        aos_systemd_client::PostUnrefUnitObservation::Absent => None,
                        aos_systemd_client::PostUnrefUnitObservation::Present(observation) => Some(observation),
                    })
                } else {
                    client.observe_exact_unit(&name, role).await
                };
                let observation = match returned {
                    Ok(observation) => observation,
                    Err(error) => {
                        row.operation = Some(error);
                        row.first.get_or_insert(CallFailureV2::Operation);
                        return Err(closed("exact worker observation failed; cause retained"));
                    }
                };
                let observation = match observation {
                    Some(observation) => super::systemd::project_exact_observation(observation),
                    None => {
                        let path = match role {
                            aos_systemd_client::ExactUnitRole::Guardian => name.guardian_cgroup_path(),
                            aos_systemd_client::ExactUnitRole::Payload => name.cgroup_path(),
                        };
                        row.absence = Some(ExactCgroupAbsenceOriginalV2::new());
                        worker.verify_absent_exact_cgroup_engine_v2(path, row.absence.as_mut())?;
                        super::GuardianObservation {
                            binding: None,
                            invocation_id: None,
                            state: super::GuardianObservedState::Absent,
                        }
                    }
                };
                completed = Some(observation);
                Ok(())
            }.await;
            if let Err(error) = primary {
                row.readback = Some(error);
                row.first.get_or_insert(CallFailureV2::NativeReadback);
                row.primary = Some(Err(closed("exact worker primary failed; cause retained")));
            } else {
                row.primary = Some(Ok(()));
            }
            // This prearmed native finish is independent of the actual
            // constructor/RPC/native-absence result. It always parks its result.
            row.finish().await;
        }
        self.record_failure(&receiver).await;
        {
            let mut row = receiver.lock().await;
            if row.first.is_none() {
                // This exact read-only recipe has completed its native absence
                // bookend or full SDK sandwich, actual Unref and task/transport
                // disposition. The Launch-wide post remains independently owed.
                match self.receiving.require_launch_readonly_post_request_v2(self.request) {
                    Ok(()) => {
                        if row.dispose_positive().await.is_err() {
                            completed = None;
                        }
                    }
                    Err(error) => {
                        row.guard = Some(error);
                        row.first.get_or_insert(CallFailureV2::Guard);
                        completed = None;
                    }
                }
            } else {
                completed = None;
            }
        }
        self.record_failure(&receiver).await;
        match completed {
            Some(observation) => Ok(observation),
            None => Err(self.retained_failure().await),
        }
    }

    async fn retained_failure(&self) -> HostError {
        let original = self.original.lock().await;
        if let Some(slot) = original.known_job_failure {
            let receiver = original.calls.get(slot).cloned();
            drop(original);
            return match receiver {
                Some(receiver) => {
                    let receiver = receiver.lock().await;
                    HostError::Worker(format!("original Launch job failed: {}", CallFailureViewV2(&receiver)))
                }
                None => closed("known failed job original is unavailable"),
            };
        }
        match original.first {
            Some(WorkerFailureV2::Call(slot)) => {
                let receiver = original.calls.get(slot).cloned();
                drop(original);
                if let Some(receiver) = receiver {
                    let receiver = receiver.lock().await;
                    HostError::Worker(format!("original Launch worker failed: {}", CallFailureViewV2(&receiver)))
                } else {
                    closed("worker failed; original call destination is unavailable")
                }
            }
            Some(WorkerFailureV2::Phase) => match original.phase_error.as_ref() {
                Some(cause) => HostError::Worker(format!("actual worker phase refused: {cause}")),
                None => closed("actual worker phase refusal remains resident"),
            },
            Some(WorkerFailureV2::Kernel) => match original.kernel_rechecks.failure() {
                Some(cause) => HostError::Worker(format!("original payload recheck failed: {cause}")),
                None => closed("payload recheck failed; original remains resident"),
            },
            Some(WorkerFailureV2::Inspection(slot)) => {
                let receiver = original.inspections.get(slot).cloned();
                drop(original);
                if let Some(receiver) = receiver {
                    let receiver = receiver.lock().await;
                    match receiver.failure() {
                        Some(cause) => HostError::Worker(format!("original payload inspection failed: {cause}")),
                        None => closed("payload inspection failed; original remains resident"),
                    }
                } else {
                    closed("payload inspection failed; original destination is unavailable")
                }
            }
            Some(WorkerFailureV2::Supervisor(slot)) => {
                let receiver = original.supervisors.get(slot).cloned();
                drop(original);
                if let Some(receiver) = receiver {
                    let receiver = receiver.lock().await;
                    match receiver.failure() {
                        Some(cause) => HostError::Worker(format!("original supervisor proof failed: {cause}")),
                        None => closed("supervisor proof failed; original remains resident"),
                    }
                } else {
                    closed("supervisor proof failed; original destination is unavailable")
                }
            }
            Some(WorkerFailureV2::Snapshot(slot)) => {
                let receiver = original.snapshots.get(slot).cloned();
                drop(original);
                if let Some(receiver) = receiver {
                    let receiver = receiver.lock().await;
                    match receiver.failure() {
                        Some(cause) => HostError::Worker(format!("original runtime snapshot failed: {cause}")),
                        None => closed("runtime snapshot failed; original remains resident"),
                    }
                } else {
                    closed("runtime snapshot failed; original destination is unavailable")
                }
            }
            Some(WorkerFailureV2::Shifted(slot)) => {
                let receiver = original.shifted.get(slot).cloned();
                drop(original);
                if let Some(receiver) = receiver {
                    let receiver = receiver.lock().await;
                    match receiver.failure() {
                        Some(cause) => HostError::Worker(format!("original shifted inspection failed: {cause}")),
                        None => closed("shifted inspection failed; original remains resident"),
                    }
                } else {
                    closed("shifted inspection failed; original destination is unavailable")
                }
            }
            None => closed("worker interval failed; originals remain resident"),
        }
    }

    async fn prearm_readonly_post(
        &self,
        parent: &Arc<Mutex<SystemdCallOriginalV2>>,
        call: HostSystemdCallV2,
    ) -> Result<ReadOnlyPostV2> {
        self.require_current()?;
        if !matches!(call, HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve) {
            return Err(closed("worker owed destination is not read-only"));
        }
        let original = self.original.lock().await;
        let mut receiver = parent.lock().await;
        if receiver.entered || receiver.posts.len() == 2
            || !original.calls.get(receiver.slot).is_some_and(|actual| Arc::ptr_eq(actual, parent))
        {
            return Err(closed("worker post must arm on its actual parent before entry"));
        }
        let index = receiver.posts.len();
        receiver.posts.push(ReadOnlyPostDestinationV2 {
            call,
            child: None,
            completed: None,
        });
        Ok(ReadOnlyPostV2 {
            original: Arc::clone(&self.original),
            parent: Arc::clone(parent),
            parent_slot: receiver.slot,
            index,
            call,
        })
    }

    async fn record_failure(&self, receiver: &Arc<Mutex<SystemdCallOriginalV2>>) {
        // Release the row before taking its parent. Admission takes parent
        // then row locks, so retaining both here would invert that order.
        let failure = {
            let receiver = receiver.lock().await;
            receiver.first.map(|cause| (receiver.slot, cause,
                receiver.readback.is_some() || matches!(receiver.disposition, Some(Err(_)))))
        };
        if let Some((slot, cause, later_failure)) = failure {
            let mut original = self.original.lock().await;
            if matches!(cause, CallFailureV2::JobResult) {
                // A terminal failed job is known semantic DATA, as in the old
                // reducer. Keep its native row occupied and permit only later
                // read/Stop calls selected by that same reducer, never a start.
                original.known_job_failure.get_or_insert(slot);
                if later_failure {
                    // Keep the earlier known job as diagnostic primary, while
                    // an ambiguous later post/close still fences new IO.
                    original.first.get_or_insert(WorkerFailureV2::Call(slot));
                }
            } else {
                original.first.get_or_insert(WorkerFailureV2::Call(slot));
            }
        }
    }
}

// A post token can be produced only while its actual parent remains in this
// original and before that parent's constructor enters. The parent owns the
// destination independently; dropping the token leaves unresolved debt.
struct ReadOnlyPostV2 {
    original: Arc<Mutex<HostLaunchWorkerOriginalV2>>,
    parent: Arc<Mutex<SystemdCallOriginalV2>>,
    parent_slot: usize,
    index: usize,
    call: HostSystemdCallV2,
}

struct ReadOnlyPostDestinationV2 {
    call: HostSystemdCallV2,
    child: Option<usize>,
    completed: Option<Weak<Mutex<SystemdCallOriginalV2>>>,
}

struct ParentPostV2 {
    parent: Arc<Mutex<SystemdCallOriginalV2>>,
    index: usize,
}

enum CallObligationV2 {
    Primary,
    Owed(ReadOnlyPostV2),
    Compensation(CompensationCallV1),
}

#[derive(Clone, Copy)]
enum CallFailureV2 {
    JobResult,
    GuardianProperties,
    PayloadProperties,
    Constructor,
    Operation,
    Guard,
    NativeReadback,
    Disposition,
    PhysicalDisposal,
    StorageCompaction,
}

struct SystemdCallOriginalV2 {
    slot: usize,
    call: HostSystemdCallV2,
    self_reference: Weak<Mutex<Self>>,
    native: HostSystemdConnectionOriginalV2,
    effect_gate: Option<Arc<dyn aos_systemd_client::HostLaunchEffectWriteGateV3>>,
    prearmed_phase: Option<HostLaunchWorkerPhaseV4>,
    gate_arm: Option<std::result::Result<(), aos_systemd_client::Error>>,
    entered: bool,
    posts: Vec<ReadOnlyPostDestinationV2>,
    parent_post: Option<ParentPostV2>,
    absence: Option<ExactCgroupAbsenceOriginalV2>,
    guardian: Option<GuardianUnitPropertyOriginalV2>,
    payload: Option<PayloadUnitPropertyOriginalV2>,
    sandbox: Option<super::systemd::SandboxNativeOriginalV2>,
    supervisor_policy: Option<Vec<aos_systemd_client::OwnedValue>>,
    supervisor_unit_values: Option<Vec<aos_systemd_client::OwnedValue>>,
    supervisor_read: Option<aos_systemd_client::ServicePropertiesReadOriginalV2>,
    job_result: Option<aos_systemd_client::JobResult>,
    stop_native: Option<Arc<std::sync::Mutex<super::systemd::StopQuiescenceOriginalV3>>>,
    stop_disposed: Option<super::systemd::StopQuiescenceDisposedV4>,
    stop_result: Option<aos_systemd_client::ExactStopOutcome>,
    constructor: Option<std::result::Result<(), aos_systemd_client::Error>>,
    operation: Option<aos_systemd_client::Error>,
    guard: Option<HostError>,
    readback: Option<HostError>,
    primary: Option<Result<()>>,
    disposition: Option<std::result::Result<(), aos_systemd_client::Error>>,
    disposal: Option<std::result::Result<HostSystemdNativeDisposedV2, aos_systemd_client::Error>>,
    compaction: Option<std::result::Result<HostSystemdStorageCompactedV2, aos_systemd_client::Error>>,
    first: Option<CallFailureV2>,
}

impl SystemdCallOriginalV2 {
    fn new(
        slot: usize,
        call: HostSystemdCallV2,
        schedule: aos_systemd_client::HostLaunchReceiveScheduleV2,
        parent_post: Option<ParentPostV2>,
        self_reference: Weak<Mutex<Self>>,
        effect_gate: Option<Arc<dyn aos_systemd_client::HostLaunchEffectWriteGateV3>>,
        prearmed_phase: Option<HostLaunchWorkerPhaseV4>,
    ) -> Self {
        Self {
            slot,
            call,
            self_reference,
            native: HostSystemdConnectionOriginalV2::new(schedule),
            effect_gate,
            prearmed_phase,
            gate_arm: None,
            entered: false,
            posts: Vec::with_capacity(2),
            parent_post,
            absence: None,
            guardian: None,
            payload: None,
            sandbox: None,
            supervisor_policy: None,
            supervisor_unit_values: None,
            supervisor_read: None,
            job_result: None,
            stop_native: None,
            stop_disposed: None,
            stop_result: None,
            constructor: None,
            operation: None,
            guard: None,
            readback: None,
            primary: None,
            disposition: None,
            disposal: None,
            compaction: None,
            first: None,
        }
    }

    async fn connect(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        if self.entered {
            return Err(closed("worker constructor was already entered"));
        }
        self.entered = true;
        if let Some(gate) = self.effect_gate.as_ref() {
            self.gate_arm = Some(self.native.arm_effect_write_gate_v3(
                Arc::clone(gate), schedule::EFFECT_WRITE_ATTEMPTS_PER_CALL_V3,
            ));
            if !matches!(self.gate_arm, Some(Ok(()))) {
                self.first.get_or_insert(CallFailureV2::Constructor);
                return Err(closed("worker native effect clock gate refused before connect"));
            }
        }
        self.constructor = Some(self.native.connect_once_v2(deadline).await);
        if !matches!(self.constructor, Some(Ok(()))) {
            self.first.get_or_insert(CallFailureV2::Constructor);
            return Err(closed("worker connection failed; original remains resident"));
        }
        Ok(())
    }

    // Always called after an entered native constructor, including a refused
    // primary. The real lower owner prearms cleanup outcomes independently.
    async fn finish(&mut self) {
        self.disposition = Some(self.native.finish_connection_once_v2().await);
        if !matches!(self.disposition, Some(Ok(()))) {
            self.first.get_or_insert(CallFailureV2::Disposition);
        }
    }

    // Only actual callers of the complete existing worker recipe set primary
    // positive after all its local native/semantic/bookend checks. Launch-wide
    // after, CAS and Sent stay separately owed on the enclosing Launch original.
    async fn dispose_positive(&mut self) -> Result<()> {
        let result = self.dispose_positive_inner().await;
        if let Err(error) = result {
            self.guard.get_or_insert(error);
            self.first.get_or_insert(CallFailureV2::Guard);
            return Err(closed("worker positive disposal refused; actual frontier retained"));
        }
        Ok(())
    }

    async fn dispose_positive_inner(&mut self) -> Result<()> {
        if self.first.is_some() || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.disposition, Some(Ok(())))
        {
            return Err(closed("worker local interval has no positive disposition"));
        }
        for post in &self.posts {
            let child = post.completed.as_ref().and_then(Weak::upgrade)
                .ok_or_else(|| closed("worker read-only post remains owed"))?;
            let child = child.lock().await;
            if post.child != Some(child.slot) || !child.storage_is_physically_compacted() {
                return Err(closed("worker post lacks its actual same-original compacted proof"));
            }
        }
        if let Some(post) = self.parent_post.as_ref() {
            let parent = post.parent.lock().await;
            if !parent.posts.get(post.index)
                .is_some_and(|destination| destination.child == Some(self.slot)
                    && destination.completed.is_none())
            {
                return Err(closed("worker post differs from its prearmed parent destination"));
            }
        }
        let stop_completion = match self.stop_native.as_ref() {
            Some(original) => {
                let outcome = self.stop_result.as_ref()
                    .ok_or_else(|| closed("Stop native collector has no actual typed outcome"))?;
                match super::systemd::StopQuiescenceOriginalV3::prepare_temporary_disposal_v4(
                    original, self.slot, outcome,
                )? {
                    Some(completed) => Some(completed),
                    // Preserve the old typed residual/foreign projection while
                    // keeping this actual native window occupied. A later call
                    // cannot turn SDK-only compaction into Stop FD credit.
                    None => return Ok(()),
                }
            }
            None => None,
        };
        self.dispose_sdk_files_v4().await?;

        if let Some(completed) = stop_completion {
            // The actual same SDK native proof above follows all local unit,
            // Unref/RemoveMatch and join posts. No later global check borrows
            // these Stop-only duplicates; real runtime input pins stay held.
            self.stop_disposed = Some(completed.dispose_from_row_v4(&mut self.stop_native)?);
        }

        // These exact transferred property aliases are no longer needed by any
        // later local or global check. Input specification pins remain on the
        // launch. Failed property/native prefixes never enter this branch.
        drop(self.absence.take());
        drop(self.guardian.take());
        drop(self.payload.take());
        let Some(Ok(disposed)) = self.disposal.take() else {
            std::process::abort();
        };
        self.compaction = Some(self.native.compact_positive_storage_once_v2(disposed));
        if !self.storage_is_physically_compacted() {
            self.first.get_or_insert(CallFailureV2::StorageCompaction);
            return Err(closed("worker storage compaction failed; original remains resident"));
        }
        if let Some(post) = self.parent_post.take() {
            let mut parent = post.parent.lock().await;
            // The private destination was checked before physical disposal;
            // it cannot be replaced by another call. Keep a weak reference to
            // the actual child whose opaque compacted proof remains resident.
            let Some(destination) = parent.posts.get_mut(post.index) else {
                std::process::abort();
            };
            destination.completed = Some(self.self_reference.clone());
        }
        Ok(())
    }

    async fn dispose_sdk_files_v4(&mut self) -> Result<()> {
        self.disposal = Some(match self.native.prepare_positive_native_disposal_v2() {
            Ok(disposal) => disposal.dispose_once_v2().await,
            Err(error) => Err(error),
        });
        let positive = self.disposal.as_ref().is_some_and(|result| {
            result.as_ref().is_ok_and(|proof| proof.belongs_to_v2(&self.native))
        });
        if !positive {
            self.first.get_or_insert(CallFailureV2::PhysicalDisposal);
            return Err(closed("worker native disposal failed; original remains resident"));
        }

        Ok(())
    }

    fn storage_is_physically_compacted(&self) -> bool {
        self.absence.is_none() && self.guardian.is_none() && self.payload.is_none()
            && self.stop_native.is_none()
            && (self.call != HostSystemdCallV2::ExactStop || self.stop_disposed.as_ref()
                .is_some_and(|proof| proof.belongs_to_row_v4(self.slot)))
            && self.compaction.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to_v2(&self.native))
            })
    }
}

// Keeps the expected negative path observation alongside its independent
// successful root bookend. Expected NOENT is not a failed local interval; every
// other actual errno stays on the same lower destination and closes the row.
pub(super) struct ExactCgroupAbsenceOriginalV2 {
    pub(super) duplicate: Option<std::io::Result<std::os::fd::OwnedFd>>,
    pub(super) root: aos_sandbox_linux::cgroup::CgroupRootOriginalV2,
    pub(super) completed_root: Option<aos_sandbox_linux::cgroup::CgroupV2Root>,
    pub(super) resolution: aos_sandbox_linux::cgroup::CgroupChildOriginalV2,
    pub(super) resolution_was_absent: bool,
    pub(super) after: aos_sandbox_linux::cgroup::CgroupChildOriginalV2,
}

impl ExactCgroupAbsenceOriginalV2 {
    pub(in crate::worker) fn new() -> Self {
        Self {
            duplicate: None,
            root: aos_sandbox_linux::cgroup::CgroupRootOriginalV2::new(),
            completed_root: None,
            resolution: aos_sandbox_linux::cgroup::CgroupChildOriginalV2::new(),
            resolution_was_absent: false,
            after: aos_sandbox_linux::cgroup::CgroupChildOriginalV2::new(),
        }
    }

    pub(in crate::worker) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_linux::cgroup::{CgroupChildOriginalV2, CgroupRootOriginalV2};

        let name = aos_systemd_client::SandboxUnitName::from_incarnation([0; 16]);
        let path_bytes = name.guardian_cgroup_path().as_str().trim_start_matches('/').len()
            .max(name.cgroup_path().as_str().trim_start_matches('/').len());
        let mut result = ResourceVector::ZERO;
        for (bytes, files, names) in [
            CgroupRootOriginalV2::receiving_obligations_v2()?,
            CgroupChildOriginalV2::receiving_obligations_v2(path_bytes)?,
            CgroupChildOriginalV2::receiving_obligations_v2(1)?,
        ] {
            result = result.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::MetadataEntries, u64::try_from(names).ok()?)).ok()?;
        }
        Some(result)
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.duplicate.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.root.failure().map(|error| error as _))
            .or_else(|| (!self.resolution_was_absent)
                .then(|| self.resolution.failure()).flatten().map(|error| error as _))
            .or_else(|| self.after.failure().map(|error| error as _))
    }
}

struct CallFailureViewV2<'owner>(&'owner SystemdCallOriginalV2);

impl std::fmt::Display for CallFailureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let row = self.0;
        match row.first {
            Some(CallFailureV2::JobResult) => {
                if let Some(result) = row.job_result.as_ref() {
                    return write!(formatter, "unit start job completed as {result:?}");
                }
            }
            Some(CallFailureV2::GuardianProperties) => {
                if let Some(error) = row.guardian.as_ref().and_then(|owner| owner.failure()) {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::PayloadProperties) => {
                if let Some(error) = row.payload.as_ref().and_then(|owner| owner.failure()) {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::Constructor | CallFailureV2::Operation) => {
                let returned = if matches!(row.first, Some(CallFailureV2::Constructor)) {
                    row.native.constructor_failure_v2()
                } else {
                    row.supervisor_read.as_ref().and_then(|archive| archive.failure())
                        .or(row.operation.as_ref())
                };
                if let Some(error) = returned {
                    // Only the exact returned native marker may resolve to
                    // the original raw cause. Later cleanup cannot replace an
                    // earlier pure SDK/property/semantic error.
                    if let Ok(Some(native)) = row.native.native_failure_for_returned_v2(error) {
                        match native.cause() {
                            aos_systemd_client::HostSystemdNativeFailureRefV2::Native(cause) => {
                                return std::fmt::Display::fmt(cause, formatter);
                            }
                            aos_systemd_client::HostSystemdNativeFailureRefV2::Protocol(cause) => {
                                return std::fmt::Display::fmt(cause, formatter);
                            }
                            aos_systemd_client::HostSystemdNativeFailureRefV2::Ended => {}
                        }
                    }
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::Guard) => {
                if let Some(error) = row.guard.as_ref() {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::NativeReadback) => {
                if let Some(native) = row.stop_native.as_ref() {
                    if let Ok(native) = native.lock() {
                        if let Some(cause) = native.failure() {
                            return std::fmt::Display::fmt(cause, formatter);
                        }
                    }
                }
                if let Some(error) = row.absence.as_ref().and_then(ExactCgroupAbsenceOriginalV2::failure) {
                    return std::fmt::Display::fmt(error, formatter);
                }
                if let Some(error) = row.sandbox.as_ref().and_then(|native| native.failure()) {
                    return std::fmt::Display::fmt(error, formatter);
                }
                if let Some(error) = row.readback.as_ref() {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::Disposition) => {
                if let Some(Err(error)) = row.disposition.as_ref() {
                    if row.native.native_disposition_failure_is_selected_v2() {
                        if let Ok(Some(native)) = row.native.native_failure_v2() {
                            match native.cause() {
                                aos_systemd_client::HostSystemdNativeFailureRefV2::Native(cause) => {
                                    return std::fmt::Display::fmt(cause, formatter);
                                }
                                aos_systemd_client::HostSystemdNativeFailureRefV2::Protocol(cause) => {
                                    return std::fmt::Display::fmt(cause, formatter);
                                }
                                aos_systemd_client::HostSystemdNativeFailureRefV2::Ended => {}
                            }
                        }
                    }
                    if let Ok(disposition) = row.native.disposition_failure_v2() {
                        if let Some(cause) = disposition.cause_for_returned_v2(error) {
                            return std::fmt::Display::fmt(cause, formatter);
                        }
                    }
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::PhysicalDisposal) => {
                if let Some(error) = row.native.native_disposal_failure_v2() {
                    return std::fmt::Display::fmt(error, formatter);
                }
                if let Some(Err(error)) = row.disposal.as_ref() {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            Some(CallFailureV2::StorageCompaction) => {
                if let Some(error) = row.native.storage_compaction_failure_v2() {
                    return std::fmt::Display::fmt(error, formatter);
                }
                if let Some(Err(error)) = row.compaction.as_ref() {
                    return std::fmt::Display::fmt(error, formatter);
                }
            }
            None => {}
        }
        formatter.write_str("worker receiver remains closed")
    }
}

fn call_index(call: HostSystemdCallV2) -> usize {
    match call {
        HostSystemdCallV2::GuardianStart => 0,
        HostSystemdCallV2::PayloadStart => 1,
        HostSystemdCallV2::SandboxObserve => 2,
        HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve => 3,
        HostSystemdCallV2::ExactStop => 4,
        HostSystemdCallV2::SupervisorPolicy => 5,
    }
}

fn carries_descriptors(call: HostSystemdCallV2) -> bool {
    matches!(call, HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart)
}

fn identity(request: &AuthenticatedBrokerMethodRequestV1) -> RequestIdentity {
    (request.request_id(), request.session_binding(), request.signed_request_digest())
}

fn closed(message: &'static str) -> HostError {
    HostError::Fence(message)
}


#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn absence_root_refusal_keeps_the_actual_native_error_before_any_child_probe() {
        let temporary = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(
            temporary.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let root = aos_sandbox_linux::path::BeneathRoot::from_owned(descriptor).unwrap();
        let identity = rustix::fs::fstat(root.as_fd()).unwrap();
        let worker = super::super::SystemdOneShotWorker::new(root);
        let path = aos_systemd_client::SandboxUnitName::from_incarnation([1; 16]).guardian_cgroup_path();
        let mut original = ExactCgroupAbsenceOriginalV2::new();

        let returned = worker.verify_absent_exact_cgroup_engine_v2(path, Some(&mut original));

        assert!(returned.is_err());
        assert!(original.completed_root.is_none());
        assert!(original.resolution.failure().is_none());
        assert!(original.after.failure().is_none());
        assert!(!original.resolution_was_absent);
        let actual = original.root.failure().unwrap();
        let selected = original.failure().unwrap();
        assert_eq!(actual as *const _ as *const (), selected as *const _ as *const ());
        assert_eq!(rustix::fs::fstat(worker.cgroup_root.as_fd()).unwrap().st_ino, identity.st_ino);
        assert!(original.root.take_completed_once().is_none());
    }
}
