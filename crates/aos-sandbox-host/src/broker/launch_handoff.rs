//! Connects one authenticated launch to its same paid native Agent capsule.
//!
//! The genuine phase remains borrowed through Guardian and both original
//! observations. Only real protected response Sent may dispose positive launch
//! opening scratch; the consumed launch resident operation remains occupied.

pub(super) mod write_clock;
pub(super) mod runtime_retention;
mod resident_native;
mod live_cleanup;
pub(crate) use live_cleanup::{HostLiveCleanupOwnerV1, HostLiveCleanupParentV1};
pub(crate) use resident_native::HostLaunchResidentNativeV4;
pub(in crate::broker) mod capture_resident;
pub(super) mod capture_stop;
pub(super) mod terminal_stage;
pub(in crate::broker) mod execution_monitor;
pub(in crate::broker) mod capture_terminal;
pub(in crate::broker) mod execution_query;
pub(in crate::broker) mod next_execution;
pub(in crate::broker) mod stop_admission;

use std::sync::{Arc, Mutex};
use aos_sandbox::runtime_execution::{DormantRuntimeExecutionOpeningV2, DormantRuntimeExecutionOwnerV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use crate::live_agent::launch_original::HostAgentLaunchOriginalV2;
use crate::plan::{HostCatalog, HostExecutionReceivingLoanV2};
use crate::state::{HostState, HostStateStore, HostStateWriteAttemptV2};
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::guardian_transaction::SelectedVerificationFailureBorrowV1;
use super::{HostBroker, ValidatedRuntimeApplyResponse};
use super::argument_handoff::ArgumentClockV2;

// One initial admission, three advancing start phases, PayloadVerified,
// cleanup selection and stop result, each eight-step cleanup selection/stop
// result, and final completion. These are existing finite reducer frontiers.
const LAUNCH_WRITES: usize = 1 + 3 + 1 + 2 + 2 * 8 + 1;

enum OpeningReceivingV1<'call, 'original> {
    Execution(&'call mut HostExecutionReceivingLoanV2<'original>),
    Cleanup(&'call mut crate::plan::HostControlPreparationReceivingV5<'original>),
}

impl OpeningReceivingV1<'_, '_> {
    fn require_complete(&mut self, complete: ResourceVector) -> Result<()> {
        match self {
            Self::Execution(receiving) => receiving.require_complete_v2(complete),
            Self::Cleanup(receiving) => receiving.raise_complete_v1(complete),
        }
    }
}

pub(super) struct LaunchStateWritesV2 {
    slots: [HostStateWriteAttemptV2; LAUNCH_WRITES],
    used: usize,
}

impl LaunchStateWritesV2 {
    fn new() -> Self {
        Self { slots: std::array::from_fn(|_| HostStateWriteAttemptV2::new()), used: 0 }
    }

    pub(super) fn commit_once(&mut self, store: &impl HostStateStore, state: &HostState) -> Result<()> {
        let slot = self.slots.get_mut(self.used)
            .ok_or(HostError::Fence("Host launch State transition schedule is exhausted"))?;
        self.used += 1;
        store.commit_retaining_v2(state, slot)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.slots.iter().take(self.used).find_map(HostStateWriteAttemptV2::failure)
    }
}

#[derive(Clone, Copy)]
pub(super) enum LaunchFirstV2 { Before, Opening, Primary, Names, After, NativeFinish }

pub(super) struct HostLaunchOriginalV2 {
    pub(super) opening: Option<DormantRuntimeExecutionOpeningV2>,
    pub(super) owner: Option<DormantRuntimeExecutionOwnerV1>,
    // Failed Capture Stop borrows its existing four journals; no lock/OFD is reopened.
    borrowed_stop_owner: Option<Arc<Mutex<super::argument_handoff::ArgumentStageOriginalV2>>>,
    pub(super) owner_error: Option<aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1>,
    pub(super) claim_demand: Option<std::result::Result<ResourceVector, aos_sandbox::journal::JournalAppendReceivingDemandErrorV1>>,
    pub(super) names: [[aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1; 4]; 2],
    pub(super) name_results: [[Option<std::result::Result<(), aos_sandbox::JournalError>>; 4]; 2],
    pub(super) setup: Option<HostAgentLaunchOriginalV2>,
    pub(super) catalog: Option<crate::plan::HostLaunchCatalogOriginalV2>,
    pub(super) compilation: Option<crate::plan::HostLaunchCompilationOriginalV2>,
    compilation_disposed: Option<crate::plan::HostLaunchCompilationDisposedV2>,
    pub(super) prepared_payload: Option<crate::plan::PreparedLaunch>,
    pub(super) guardian_spec: Option<aos_systemd::GuardianUnitSpec>,
    pub(super) guardian: Option<super::guardian_preparation::GuardianPreparationOriginalV2>,
    pub(super) clock: Option<ArgumentClockV2>,
    pub(super) worker: Option<Arc<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>>,
    pub(super) worker_deadline: Option<tokio::time::Instant>,
    pub(super) acquisition_disposed: Option<crate::worker::launch::HostLaunchAcquisitionDisposedV4>,
    capture: Option<capture_resident::HostCaptureResidentV3>,
    next_execution: Option<Box<next_execution::HostExecutionTransitionOriginalV5>>,
    stop_admission: Option<Box<stop_admission::HostCaptureStopAdmissionOriginalV4>>,
    stop_admission_request: Option<crate::plan::HostExecutionRequestBindingV2>,
    stop_admission_funding: Option<Result<()>>,
    next_execution_funding: Option<Result<()>>,
    next_execution_funding_selected: bool,
    pub(super) writes: Option<Arc<Mutex<LaunchStateWritesV2>>>,
    pub(super) before: Option<Result<()>>,
    pub(super) opening_result: Option<Result<()>>,
    pub(super) primary: Option<Result<ValidatedRuntimeApplyResponse>>,
    pub(super) after: Option<Result<()>>,
    pub(super) native_finish: Option<Result<()>>,
    pub(super) first: Option<LaunchFirstV2>,
    pub(super) complete: ResourceVector,
    pub(super) request: ([u8; 16], [u8; 32], [u8; 32]),
    pub(super) deadline: u64,
    pub(super) namespace_scope_v4: Option<([u8; 16], aos_sandbox_protocol::ValidatedAssignmentFence, [u8; 32])>,
    pub(super) authenticated_sent: bool,
    resident_native: Option<HostLaunchResidentNativeV4>,
    pub(in crate::broker) resident_stop: Option<Arc<Mutex<super::resident_stop::HostResidentStopOriginalV4>>>,
    pub(super) lease: Option<aos_sandbox_core::VerifiedOwnershipLease>,
    pub(super) intersection: Option<aos_sandbox_core::BrokerAdmissionIntersection>,
    authorization: Option<aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts>,
    request_bytes: Vec<u8>,
    pub(super) agent_authentication: Option<Result<()>>,
    pub(super) replacement: Option<std::result::Result<(), crate::live_agent::HostAgentLiveErrorV1>>,
    pub(super) agent_binding: Option<aos_sandbox_agent::AgentSessionBindingV1>,
    pub(super) component_report: Option<Arc<tokio::sync::Mutex<crate::worker::HostComponentStartupReportOriginalV2>>>,
    component_report_funding: Option<Result<()>>,
    pub(super) backend_policy: Option<Vec<aos_systemd::OwnedValue>>,
    pub(super) backend_policy_result: Option<Result<crate::plan::VerifiedLiveSupervisorPolicyV1>>,
    pub(super) backend_readiness: crate::plan::HostComponentBackendCompletionV2,
}

impl HostLaunchOriginalV2 {
    pub(super) fn reserve_component_report_before_catalog_v2(
        &mut self,
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
    ) -> Result<()> {
        if self.component_report_funding.is_some() || self.component_report.is_some() {
            return Err(HostError::Fence("component report source is already entered"));
        }
        self.component_report_funding = Some((|| {
            let report = crate::worker::HostComponentStartupReportOriginalV2::receiving_demand_v2()
                .ok_or(HostError::ResourceExhausted)?;
            let clock = ArgumentClockV2::sdk_write_demand_v3().ok_or(HostError::ResourceExhausted)?;
            self.complete = self.complete.checked_add(report).and_then(|demand| demand.checked_add(clock))
                .map_err(|_| HostError::ResourceExhausted)?;
            receiving.require_complete_v2(self.complete)
        })());
        if !matches!(self.component_report_funding, Some(Ok(()))) {
            return Err(HostError::Fence("component report source exceeds its same Launch; cause retained"));
        }
        self.clock.as_mut().ok_or(HostError::AgentLaunchQuarantined)?
            .prepare_component_report_writes_v2()?;
        self.component_report = Some(Arc::new(tokio::sync::Mutex::new(
            crate::worker::HostComponentStartupReportOriginalV2::new(),
        )));
        Ok(())
    }

    fn fixed_representation_bytes_v4(request: &AuthenticatedBrokerMethodRequestV1) -> Option<usize> {
        let artifacts = request.authorization()?;
        let input = [request.exact_body(), artifacts.broker_plan(), artifacts.broker_plan_signature(),
            artifacts.ownership_lease(), artifacts.ownership_lease_signature()]
            .into_iter().try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()))?;
        // The bounded shared codecs and current/proposed pure Host models use
        // dominant byte peaks; allocator/decoder overhead stays cgroup-backed.
        let bytes = (3 * std::mem::size_of::<Self>())
            .checked_add(2 * std::mem::size_of::<LaunchStateWritesV2>())?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::size_of::<crate::plan::HostLaunchCatalogOriginalV2>())?
            .checked_add(input.checked_mul(8)?)?;
        Some(bytes)
    }

    pub(super) fn fixed_demand(request: &AuthenticatedBrokerMethodRequestV1, runtime: &super::ValidatedRuntimeRequest) -> Option<ResourceVector> {
        let artifacts = request.authorization()?;
        let bytes = Self::fixed_representation_bytes_v4(request)?;
        let mut demand = DormantRuntimeExecutionOpeningV2::fixed_preparation_demand_v2()?
            .checked_add(super::guardian_transaction::RetainedHostLimitAttemptV1::guardian_handoff_demand_v2()?).ok()?
            .checked_add(HostAgentLaunchOriginalV2::receiving_demand_v2()?).ok()?
            .checked_add(crate::plan::HostLaunchCompilationOriginalV2::receiving_demand_v2()?).ok()?
            .checked_add(crate::plan::HostComponentBackendCompletionV2::receiving_demand_v2()?).ok()?
            .checked_add(ArgumentClockV2::receiving_demand_v2()?).ok()?
            .checked_add(ArgumentClockV2::launch_write_demand_v2()?).ok()?
            .checked_add(ArgumentClockV2::sdk_write_demand_v3()?).ok()?
            .checked_add(ArgumentClockV2::handshake_write_demand_v3()?).ok()?
            .checked_add(runtime_retention::HostLaunchRuntimeRetentionV3::receiving_demand_v3()?
                .with(D::OpenFiles, 0)).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::ConcurrentOperations, 1)).ok()?;
        for _ in 0..2 {
            demand = demand.checked_add(DormantRuntimeExecutionOwnerV1::execution_currentness_demand_v2()?).ok()?;
        }
        demand = demand.checked_add(HostStateWriteAttemptV2::sequence_demand_v2(LAUNCH_WRITES)?).ok()?;
        // Reserve both fixed proof points' full semantic liabilities before
        // catalog derives its residual. Native descriptors occupy one actual
        // limit interval: its positive disposal gates the next proofpoint.
        let limit = crate::worker::limit_original::HostLimitNativeOriginalV2::receiving_demand_v2()?;
        for _ in 0..2 {
            // The next proofpoint requires physical disposal of the previous
            // complete limit original. Keep both full byte/name liabilities.
            for dimension in aos_sandbox_core::ResourceDimension::ALL {
                if dimension != D::OpenFiles {
                    let next = demand.get(dimension).checked_add(limit.get(dimension))?;
                    demand = demand.with(dimension, next);
                }
            }
        }
        // No native limit descriptor exists at this constructor boundary. The
        // actual worker phase admits its whole source-derived interval before
        // first capture, including every still-held prior point/native prefix.
        // All semantic byte and real namespace liabilities remain reserved.
        // Reserve the complete reached Guardian credential construction before
        // catalog/export can derive bounds from the remaining Launch capacity.
        demand = demand.checked_add(super::guardian_preparation::GuardianPreparationOriginalV2::receiving_demand_v2(
            &super::GuardianOriginalInputV1::Runtime(runtime), artifacts,
        ).ok()?).ok()?;
        Some(demand)
    }

    pub(in crate::broker) fn fixed_stop_demand_v4(
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Option<ResourceVector> {
        let bytes = Self::fixed_representation_bytes_v4(request)?;
        let mut demand = DormantRuntimeExecutionOpeningV2::fixed_preparation_demand_v2()?
            .checked_add(ArgumentClockV2::receiving_demand_v2()?).ok()?
            .checked_add(ArgumentClockV2::launch_write_demand_v2()?).ok()?
            .checked_add(ArgumentClockV2::sdk_write_demand_v3()?).ok()?
            .checked_add(HostStateWriteAttemptV2::sequence_demand_v2(LAUNCH_WRITES)?).ok()?
            .checked_add(super::resident_stop::HostResidentStopOriginalV4::receiving_demand_v4()?).ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)).ok()?;
        for _ in 0..2 {
            demand = demand.checked_add(DormantRuntimeExecutionOwnerV1::execution_currentness_demand_v2()?).ok()?;
        }
        // This is a new interval of the SAME already consumed Launch. Its
        // existing concurrent-operation slot stays occupied; no second slot is
        // created merely because the authenticated Stop has a fresh request.
        Some(demand)
    }

    pub(in crate::broker) fn require_failed_capture_stop_parent_v4(&self) -> Result<()> {
        if !self.authenticated_sent || self.first.is_some() || self.resident_stop.is_some()
            || self.capture.as_ref().is_none_or(|resident| !resident.monitor_failed_data_v5())
            || !self.resident_native.as_ref().is_some_and(|proof| proof.request_identity_v4() == self.request)
            || self.lease.is_none() || self.intersection.is_none()
        {
            return Err(HostError::Fence("fresh Capture Stop lacks its actual retained Launch"));
        }
        Ok(())
    }

    pub(in crate::broker) fn require_resident_stop_parent_v4(&self) -> Result<()> {
        if !self.authenticated_sent || self.first.is_some() || self.capture.is_some()
            || self.resident_stop.is_some()
            || !self.resident_native.as_ref().is_some_and(|proof|
                proof.request_identity_v4() == self.request)
            || self.lease.is_none() || self.intersection.is_none()
        {
            return Err(HostError::Fence("Stop lacks the actual disposed-acquisition resident Launch"));
        }
        Ok(())
    }

    pub(super) fn new(request: &AuthenticatedBrokerMethodRequestV1, complete: ResourceVector,
        boot: [u8; 16], deadline: u64, runtime: Option<&super::ValidatedRuntimeRequest>) -> Self
    {
        Self {
            opening: Some(DormantRuntimeExecutionOpeningV2::new()), owner: None, borrowed_stop_owner: None, owner_error: None, claim_demand: None,
            names: std::array::from_fn(|_| std::array::from_fn(|_| aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new())),
            name_results: std::array::from_fn(|_| std::array::from_fn(|_| None)), setup: None,
            catalog: Some(crate::plan::HostLaunchCatalogOriginalV2::new()),
            compilation: Some(crate::plan::HostLaunchCompilationOriginalV2::new()),
            compilation_disposed: None,
            prepared_payload: None,
            guardian_spec: None,
            guardian: Some(super::guardian_preparation::GuardianPreparationOriginalV2::new()),
            clock: None,
            worker: None,
            worker_deadline: None, acquisition_disposed: None, capture: None, next_execution: None, stop_admission: None, stop_admission_request: None, stop_admission_funding: None, next_execution_funding: None, next_execution_funding_selected: false,
            writes: Some(Arc::new(Mutex::new(LaunchStateWritesV2::new()))),
            before: None, opening_result: None, primary: None, after: None,
            native_finish: None, first: None, complete,
            request: (request.request_id(), request.session_binding(), request.signed_request_digest()),
            namespace_scope_v4: runtime.and_then(|request| request.launch_plan().map(|plan|
                (boot, *request.fence(), *plan.attachment_anchor_handle()))),
            deadline, authenticated_sent: false, resident_native: None, resident_stop: None, lease: None, intersection: None,
            authorization: request.authorization().cloned(), request_bytes: request.exact_body().to_vec(),
            agent_authentication: None, replacement: None, agent_binding: None,
            component_report: None,
            component_report_funding: None,
            backend_policy: None, backend_policy_result: None,
            backend_readiness: crate::plan::HostComponentBackendCompletionV2::new(),
        }
    }

    /// Retires successful local collectors after the payload reaches this owner.
    ///
    /// # Errors
    /// Refuses reentry, incomplete native posts, or mismatched accounting.
    pub(super) fn dispose_compilation_once_v2(
        &mut self,
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_same_request(request)?;
        receiving.require_launch_request_v2(request)?;
        if self.compilation_disposed.is_some() {
            return Err(HostError::Fence("Host compiler disposal was already recorded"));
        }
        let prepared = self.prepared_payload.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        self.compilation_disposed = Some(crate::plan::HostLaunchCompilationOriginalV2::dispose_completed_v2(
            &mut self.catalog, &mut self.compilation, prepared, self.request, self.complete,
        )?);
        let disposed = self.compilation_disposed.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        receiving.retain_compilation_disposal_v2(disposed)?;
        self.complete = disposed.current_demand_v2();
        Ok(())
    }

    pub(super) fn prepare_opening(&mut self, receiving: &mut HostExecutionReceivingLoanV2<'_>) -> Result<()> {
        self.prepare_opening_for_program_v4(OpeningReceivingV1::Execution(receiving), true)
    }

    pub(in crate::broker) fn prepare_borrowed_stop_owner_v4(
        &mut self,
        stage: Arc<Mutex<super::argument_handoff::ArgumentStageOriginalV2>>,
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
    ) -> Result<()> {
        if self.borrowed_stop_owner.is_some() || self.owner.is_some() || self.opening_result.is_some() {
            return Err(HostError::Fence("Stop journal borrower is already occupied"));
        }
        // Park the exact Stage before claim geometry, validation or any native
        // sample. A refusal never returns its journals or clears earlier debt.
        self.borrowed_stop_owner = Some(stage);
        self.opening_result = Some((|| {
            self.retain_worker_deadline_v2()?;
            let stage = self.borrowed_stop_owner.as_ref()
                .ok_or(HostError::Fence("Stop held journal Stage is absent"))?;
            let mut held = stage.lock().map_err(|_| HostError::Fence("Stop held journal Stage is poisoned"))?;
            let owner = held.owner.as_mut().ok_or(HostError::Fence("Stop held journals are absent"))?;
            self.claim_demand = Some(owner.initial_claim_receiving_demand_v2());
            let demand = self.claim_demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(HostError::Fence("Stop held claim geometry failed; original cause retained"))?;
            self.complete = self.complete.checked_add(demand).map_err(|_| HostError::ResourceExhausted)?;
            receiving.require_complete_v2(self.complete)?;
            match owner.claim() {
                Ok(claim) => drop(claim),
                Err(cause) => {
                    self.owner_error = Some(cause);
                    return Err(HostError::Fence("Stop held claim failed; original cause retained"));
                }
            }
            drop(held);
            self.observe_names_once_v2(0)
        })());
        if !matches!(self.opening_result, Some(Ok(()))) {
            self.first.get_or_insert(LaunchFirstV2::Opening);
            return Err(HostError::Fence("Stop held journal preparation failed; original retained"));
        }
        Ok(())
    }

    pub(in crate::broker) fn has_stop_journal_owner_v4(&self) -> bool {
        self.owner.is_some() || self.borrowed_stop_owner.is_some()
    }

    pub(in crate::broker) fn failed_capture_stop_stage_v4(&self) -> Result<Option<(
        Arc<Mutex<super::argument_handoff::ArgumentStageOriginalV2>>,
        capture_stop::HostCaptureFailedStageV4,
    )>> {
        self.capture.as_ref().filter(|resident| resident.monitor_failed_data_v5())
            .map(capture_resident::HostCaptureResidentV3::failed_stop_stage_v4).transpose()
    }

    pub(in crate::broker) fn prepare_stop_opening_v4(
        &mut self,
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
    ) -> Result<()> {
        self.prepare_opening_for_program_v4(OpeningReceivingV1::Execution(receiving), false)?;
        self.claim_stop_opening_v1()
    }

    pub(in crate::broker) fn prepare_cleanup_stop_opening_v1(&mut self,
        receiving: &mut crate::plan::HostControlPreparationReceivingV5<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        self.require_same_request(request)?;
        receiving.require_cleanup_request_v1(request)?;
        self.prepare_opening_for_program_v4(OpeningReceivingV1::Cleanup(receiving), false)?;
        self.claim_stop_opening_v1()
    }

    fn claim_stop_opening_v1(&mut self) -> Result<()> {
        let result = self.owner.as_mut().ok_or(HostError::AgentLaunchQuarantined)?.claim();
        match result {
            Ok(claim) => drop(claim),
            Err(cause) => {
                self.owner_error = Some(cause);
                self.first.get_or_insert(LaunchFirstV2::Opening);
                return Err(HostError::Fence("Stop native claim failed; original retained"));
            }
        }
        self.observe_names_once_v2(0)
    }

    fn prepare_opening_for_program_v4(
        &mut self,
        mut receiving: OpeningReceivingV1<'_, '_>,
        agent_setup: bool,
    ) -> Result<()> {
        let result = (|| {
            for index in 0..4 {
                self.retain_worker_deadline_v2()?;
                let opening = self.opening.as_mut().ok_or(HostError::Fence("Host launch opening is absent"))?;
                if opening.prepare_next_once_v2().map_err(|error| HostError::State(error.to_string()))? != index {
                    return Err(HostError::Fence("Host launch fixed opening order changed"));
                }
                let extent = opening.captured_extent_v2(index)
                    .ok_or(HostError::Fence("Host launch captured prefix is absent"))?;
                // This SAME captured replay still executes the full common
                // semantic hooks. The private claim bound below gives no credit
                // for their earlier prospective maps and decoded native rows.
                let native = extent.dominant_native_receiving_demand_v1()
                    .map_err(|error| HostError::State(error.to_string()))?;
                let semantic = extent.dominant_semantic_receiving_demand_v1()
                    .map_err(|error| HostError::State(error.to_string()))?;
                let additional = native.checked_add(semantic)
                    .map_err(|_| HostError::ResourceExhausted)?;
                self.complete = self.complete.checked_add(additional).map_err(|_| HostError::ResourceExhausted)?;
                receiving.require_complete(self.complete)?;
                self.retain_worker_deadline_v2()?;
                self.opening.as_mut().ok_or(HostError::Fence("Host launch opening is absent"))?
                    .replay_prepared_once_v2(index).map_err(|error| HostError::State(error.to_string()))?;
            }
            self.owner = Some(self.opening.as_mut().ok_or(HostError::Fence("Host launch opening is absent"))?
                .take_owner_once_v2().map_err(|error| HostError::State(error.to_string()))?);
            // The actual owner exists, but claim has not decoded or initialized
            // any store. Price its SAME reached private models and optional
            // native genesis appends before the first claim can run.
            self.claim_demand = Some(self.owner.as_ref()
                .ok_or(HostError::Fence("Host launch native owner is absent"))?
                .initial_claim_receiving_demand_v2());
            let additional = match self.claim_demand.as_ref() {
                Some(Ok(demand)) => *demand,
                Some(Err(_)) => return Err(HostError::Fence("Host launch claim geometry failed; actual cause retained")),
                None => return Err(HostError::Fence("Host launch claim geometry is absent")),
            };
            self.complete = self.complete.checked_add(additional)
                .map_err(|_| HostError::ResourceExhausted)?;
            receiving.require_complete(self.complete)?;
            if agent_setup {
                let OpeningReceivingV1::Execution(receiving) = &mut receiving else {
                    return Err(HostError::Fence("cleanup opening cannot acquire a Launch Agent"));
                };
                self.setup = Some(HostAgentLaunchOriginalV2::new(receiving)
                    .map_err(|error| HostError::Worker(error.to_string()))?);
            }
            Ok(())
        })();
        if result.is_err() { self.first.get_or_insert(LaunchFirstV2::Opening); }
        self.opening_result = Some(result);
        if !matches!(self.opening_result, Some(Ok(()))) {
            return Err(HostError::Fence("Host launch native opening failed; originals retained"));
        }
        Ok(())
    }

    fn retain_worker_deadline_v2(&mut self) -> Result<()> {
        // Save the minimum of the existing eight opening observations. This
        // adds no clock sample and never renews the original signed cutoff.
        let observed = self.clock.as_mut().ok_or(HostError::Fence("Host launch clock is absent"))?
            .deadline(self.deadline)?;
        let observed = tokio::time::Instant::from_std(observed);
        self.worker_deadline = Some(self.worker_deadline.map_or(observed, |previous| previous.min(observed)));
        Ok(())
    }

    pub(super) fn reserve_worker_before_catalog_v2(
        &mut self,
        receiving: &mut HostExecutionReceivingLoanV2<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        guardian: &crate::plan::GuardianConfig,
    ) -> Result<()> {
        self.require_same_request(request)?;
        if self.worker.is_some() || self.worker_deadline.is_none() {
            return Err(HostError::Fence("Host launch worker reservation is repeated or has no original deadline"));
        }
        self.worker = Some(crate::worker::launch::HostLaunchWorkerOriginalV2::reserve_sdk_before_catalog_v2(
            receiving, &mut self.complete, request, guardian,
        )?);
        Ok(())
    }

    pub(super) fn observe_names_once_v2(&mut self, index: usize) -> Result<()> {
        let borrowed = self.borrowed_stop_owner.as_ref().map(|stage| stage.lock())
            .transpose().map_err(|_| HostError::Fence("Stop held journal Stage is poisoned"))?;
        let owner = match borrowed.as_ref() {
            Some(stage) => stage.owner.as_ref(),
            None => self.owner.as_ref(),
        }.ok_or(HostError::Fence("Host launch native owner is absent"))?;
        let result = if index == 0 {
            owner.observe_execution_names_v2(&mut self.names[index], &mut self.name_results[index])
        } else {
            owner.observe_execution_names_post_v2(&mut self.names[index], &mut self.name_results[index])
        };
        if result.is_err() { self.first.get_or_insert(LaunchFirstV2::Names); }
        result.map_err(|_| HostError::Fence("Host launch native names changed; originals retained"))
    }

    pub(super) fn require_same_request(&self, request: &AuthenticatedBrokerMethodRequestV1) -> Result<()> {
        if self.request != (request.request_id(), request.session_binding(), request.signed_request_digest()) {
            return Err(HostError::Fence("Host launch resident request association differs"));
        }
        Ok(())
    }

    pub(in crate::broker) fn transport_body_digest_v1(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};

        Sha256::digest(&self.request_bytes).into()
    }

    pub(in crate::broker) fn require_unsent_stop_launch_v1(
        &self,
        launch: ([u8; 16], [u8; 32], [u8; 32]),
    ) -> Result<()> {
        if !self.authenticated_sent || self.first.is_some() || self.request != launch
            || self.next_execution.is_some() || self.stop_admission.is_some()
        {
            return Err(HostError::Fence("unsent Stop lacks its exact positive resident Launch"));
        }
        Ok(())
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn launch_is_entered_v2(&self, request: &[u8; 16]) -> bool {
        self.launch_original.as_ref().is_some_and(|original| original.lock()
            .is_ok_and(|original| &original.request.0 == request && !original.authenticated_sent))
    }

    pub(super) fn commit_launch_state_v2(&self, state: &HostState) -> Result<()> {
        let writes = self.active_launch_writes.as_ref()
            .ok_or(HostError::Fence("Host launch State writer is absent"))?;
        writes.lock().map_err(|_| HostError::Fence("Host launch State writer is poisoned"))?
            .commit_once(&self.store, state)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn retain_authenticated_launch_response_v2(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if self.retire_authenticated_cleanup_response_v1(request)? { return Ok(()); }
        if self.retain_authenticated_stop_response_v4(request)? { return Ok(()); }
        use aos_sandbox_broker::BrokerEffectStatusV1;
        use sha2::{Digest as _, Sha256};
        let transport_digest: [u8; 32] = Sha256::digest(request.exact_body()).into();
        let effect = self.state.effect(&request.request_id())
            .ok_or(HostError::Fence("Host Runtime response has no durable effect"))?;
        let effect = self.authority.open_effect(&request.request_id(), effect)?;
        if effect.status() != BrokerEffectStatusV1::Complete
            || effect.transport_request_digest().as_bytes() != &transport_digest
        { return Err(HostError::Fence("Host Runtime response differs from its durable effect")); }
        let Some(stage) = self.launch_original.as_ref() else {
            // An ordinary effect or authenticated historical replay creates no
            // Agent, financial completion or new launch-resident permission.
            return Ok(());
        };
        let original = self.component_control.as_ref().cloned()
            .ok_or(HostError::Fence("Host launch intrinsic original is absent"))?;
        let mut original = original.lock().map_err(|_| HostError::Fence("Host launch original is poisoned"))?;
        let mut stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        if stage.request.0 != request.request_id() { return Ok(()); }
        stage.require_same_request(request)?;
        if stage.authenticated_sent || stage.first.is_some()
            || !matches!(stage.before, Some(Ok(()))) || !matches!(stage.after, Some(Ok(())))
            || !matches!(stage.native_finish, Some(Ok(()))) || stage.primary.is_some()
            || stage.prepared_payload.is_some() || stage.guardian_spec.is_some()
            || self.live_agent.is_none()
        { return Err(HostError::Fence("Host launch response cannot dispose incomplete native custody")); }
        // All fallible native/currentness/association work occurs while every
        // actual opening, key, descriptor and handshake original is resident.
        let limit_attempt = self.live_limit_attempts.get(&request.request_id())
            .ok_or(HostError::Fence("Launch limit acquisition is absent"))?;
        limit_attempt.require_acquisition_disposal_v4()?;
        if self.runtime_pins.len() != 1 || self.observed_leaders.len() != 1 {
            return Err(HostError::Fence("first Launch does not retain its exact two live pin owners"));
        }
        if let Some(report) = stage.component_report.as_ref() {
            if Arc::strong_count(report) != 1 {
                return Err(HostError::Fence("component report acquisition still has another owner"));
            }
            report.try_lock().map_err(|_| HostError::Fence("component report acquisition is still borrowed"))?
                .require_completed_for_disposal_v2()?;
        }
        let resident_native = resident_native::ResidentNativePendingV4::prepare(
            &stage, &self.runtime_pins, &self.observed_leaders,
            self.live_agent.as_ref().ok_or(HostError::AgentLaunchQuarantined)?,
        )?;
        let HostLaunchOriginalV2 { worker, acquisition_disposed, opening, owner, setup,
            clock, writes, catalog, compilation, guardian, component_report, names, .. } = &mut *stage;
        let worker_disposal = crate::worker::launch::HostLaunchWorkerOriginalV2
            ::prepare_acquisition_disposal_v4(worker, (
                request.request_id(), request.session_binding(), request.signed_request_digest(),
            ))?;
        let completion = original.prepare_authenticated_launch_disposal_v2(request)?;

        // All fallible association/native/alias checks ran while the entire
        // acquisition remained held. The actual live Runtime pins and Agent
        // stay separate; only their completed acquisition collectors retire.
        drop(self.live_limit_attempts.remove(&request.request_id()));
        *acquisition_disposed = worker_disposal.dispose_after_parent_disposal_v4();
        let scratch = (opening.take(), owner.take(), setup.take(), clock.take(),
            writes.take(), catalog.take(), compilation.take(), guardian.take(), component_report.take());
        drop(scratch);
        for interval in names {
            for names in interval { names.settle_positive_once_v1(); }
        }
        stage.resident_native = Some(resident_native.after_disposal(&stage));
        stage.authenticated_sent = true;
        completion.complete_after_disposal_v2(stage.resident_native.as_ref()
            .unwrap_or_else(|| std::process::abort()));
        Ok(())
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn validate_launch_replacement_v2(
        &self, retained: Option<&crate::live_agent::HostAgentLiveSessionV1>,
    ) -> Result<()> {
        let stage = self.launch_original.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        let mut stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        let HostLaunchOriginalV2 { owner, owner_error, replacement, agent_binding, .. } = &mut *stage;
        let claim = match owner.as_mut().ok_or(HostError::AgentLaunchQuarantined)?.claim() {
            Ok(claim) => claim,
            Err(error) => { *owner_error = Some(error); return Err(HostError::AgentLaunchQuarantined); }
        };
        let incoming = self.live_agent.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        *replacement = Some((|| {
            incoming.validate_claim(&claim)?;
            if let Some(retained) = retained {
                match retained.validate_claim(&claim) {
                    Ok(()) => return Err(crate::live_agent::HostAgentLiveErrorV1::RecoveryRequired),
                    Err(crate::live_agent::HostAgentLiveErrorV1::Binding) => (),
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })());
        if !matches!(replacement, Some(Ok(()))) {
            return Err(HostError::Fence("current guest agent session already retained or cannot be validated"));
        }
        *agent_binding = Some(incoming.session_binding());
        Ok(())
    }

    pub(crate) fn take_paid_authenticated_agent_launch_v2(
        &mut self,
    ) -> Result<Option<crate::live_agent::HostAgentLiveSessionV1>> {
        let Some(stage) = self.launch_original.as_ref() else { return Ok(None); };
        let stage = stage.lock().map_err(|_| HostError::Fence("Host launch capsule is poisoned"))?;
        let Some(incoming) = self.live_agent.as_ref() else { return Ok(None); };
        if !stage.authenticated_sent || stage.first.is_some()
            || !matches!(stage.replacement, Some(Ok(())))
            || stage.agent_binding != Some(incoming.session_binding())
            || stage.lease.is_none() || stage.intersection.is_none()
        { return Err(HostError::Fence("Host launch is not a completed paid Agent handoff")); }
        // The same incoming Agent stayed parent-owned through all actual
        // validation, outcome CAS/Sent and native disposal. This is only a move.
        Ok(self.live_agent.take())
    }
}

/// Borrows the same launch owners while formatting the first retained cause.
///
/// Both locks follow the production original-before-capsule order. This view
/// neither clones an error nor observes, extracts or completes a native owner.
pub struct HostLaunchFailureViewV2<'broker> {
    original: std::sync::MutexGuard<'broker, crate::plan::HostComponentControlStartupV2>,
    stage: HostFailureStageV4<'broker>,
}

enum HostFailureStageV4<'broker> {
    Cleanup(std::sync::MutexGuard<'broker,super::stop_cleanup::HostStopCleanupOriginalV1>),
    Launch(std::sync::MutexGuard<'broker, HostLaunchOriginalV2>,
        Option<SelectedVerificationFailureBorrowV1<'broker>>),
    TerminalInventory(&'broker super::terminal_inventory::HostTerminalInventoryOriginalV4),
    NativeInventory(&'broker super::native_inventory::HostNativeInventoryOriginalV5),
    NativeInventoryAdmission(&'broker HostError, bool),
}

fn financial_projection(error: &HostError) -> bool {
    matches!(error, HostError::Fence(
        "Host execution native representation exceeds its phase"
    ))
}

struct HostStageFailureBorrowV4<'owner> {
    original: &'owner crate::plan::HostComponentControlStartupV2,
    stage: &'owner HostLaunchOriginalV2,
    selected_verification: Option<SelectedVerificationFailureBorrowV1<'owner>>,
}

pub(super) fn format_cleanup_stage_failure_v1(original:&crate::plan::HostComponentControlStartupV2,
    stage:&HostLaunchOriginalV2,formatter:&mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    std::fmt::Display::fmt(&HostStageFailureBorrowV4 { original,stage, selected_verification: None },formatter)
}

impl HostStageFailureBorrowV4<'_> {
    fn format_cause_v2(
        &self,
        cause: &(dyn std::error::Error + 'static),
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        // Resolve only the exact financial projection from this SAME original.
        // A later owed post never displaces a concrete earlier body cause.
        if cause.downcast_ref::<HostError>().is_some_and(financial_projection) {
            std::fmt::Display::fmt(self.original.failure(), formatter)
        } else {
            std::fmt::Display::fmt(cause, formatter)
        }
    }
}

impl std::fmt::Display for HostStageFailureBorrowV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stage = &*self.stage;
        if stage.first.is_none() {
            if let Some(result) = stage.format_stop_admission_failure_v4(self.original, formatter) {
                return result;
            }
            if let Some(Err(cause)) = stage.next_execution_funding.as_ref() {
                if stage.next_execution_funding_selected {
                    return std::fmt::Display::fmt(self.original.failure(), formatter);
                }
                return std::fmt::Display::fmt(cause, formatter);
            }
            if let Some(transition) = stage.next_execution.as_ref().filter(|transition| transition.failed_v5()) {
                return transition.format_failure_v5(&self.original, formatter);
            }
            if let Some(resident) = stage.capture.as_ref().filter(|resident| resident.monitor_failed_data_v5()) {
                {
                    let held = resident.stage_for_terminal_disposal_v3().lock().map_err(|_| std::fmt::Error)?;
                    if let Some(accepted) = held.accepted.as_ref() {
                        if let Some(formatted) = accepted.format_capture_stop_entry_failure_v4(self.original, formatter) {
                            return formatted;
                        }
                    }
                }
                return resident.format_monitor_failure_v5(&self.original, formatter);
            }
        }
        if matches!(stage.first, Some(LaunchFirstV2::Primary)) {
            if let Some(Err(cause)) = stage.component_report_funding.as_ref() {
                return self.format_cause_v2(cause, formatter);
            }
            if let Some(report) = stage.component_report.as_ref() {
                if let Ok(report) = report.try_lock() {
                    if let Some(cause) = report.failure_v2() {
                        if report.selected_original_failure_v2() {
                            return std::fmt::Display::fmt(self.original.failure(), formatter);
                        }
                        if report.challenge_clock_failed_v2() {
                            if let Some(clock) = stage.clock.as_ref().and_then(ArgumentClockV2::failure) {
                                return self.format_cause_v2(clock, formatter);
                            }
                        }
                        return self.format_cause_v2(cause, formatter);
                    }
                }
            }
            if let Some(cause) = stage.backend_policy_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| stage.backend_readiness.failure())
            {
                return self.format_cause_v2(cause, formatter);
            }
        }
        let primary = stage.primary.as_ref().and_then(|result| result.as_ref().err());
        let returned = match stage.first {
            Some(LaunchFirstV2::Before | LaunchFirstV2::After | LaunchFirstV2::NativeFinish) => {
                return std::fmt::Display::fmt(self.original.failure(), formatter);
            }
            Some(LaunchFirstV2::Opening) => {
                let returned = stage.opening_result.as_ref().and_then(|result| result.as_ref().err());
                if returned.is_some_and(financial_projection) {
                    return std::fmt::Display::fmt(self.original.failure(), formatter);
                }
                let actual = stage.opening.as_ref().and_then(DormantRuntimeExecutionOpeningV2::failure)
                    .or_else(|| stage.claim_demand.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| stage.owner_error.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
                    .or_else(|| stage.clock.as_ref().and_then(ArgumentClockV2::failure));
                if let Some(actual) = actual {
                    return self.format_cause_v2(actual, formatter);
                }
                returned
            }
            Some(LaunchFirstV2::Primary) => {
                // A failed Agent setup may be followed by Guardian containment.
                // Its retained primary therefore precedes later cleanup clocks
                // and writes. Successful setup contributes no failure here.
                let actual = stage.catalog.as_ref().and_then(crate::plan::HostLaunchCatalogOriginalV2::failure)
                    .or_else(|| stage.compilation.as_ref().and_then(crate::plan::HostLaunchCompilationOriginalV2::failure))
                    // A native-write clock refusal precedes the handshake's
                    // propagated RecoveryRequired marker on this same Stage.
                    .or_else(|| stage.clock.as_ref().and_then(ArgumentClockV2::handshake_write_failure_v3))
                    .or_else(|| stage.setup.as_ref().and_then(HostAgentLaunchOriginalV2::failure))
                    .or_else(|| stage.guardian.as_ref().and_then(super::guardian_preparation::GuardianPreparationOriginalV2::failure))
                    .or_else(|| stage.owner_error.as_ref()
                        .map(|cause| cause as &(dyn std::error::Error + 'static)));
                if let Some(actual) = actual {
                    return self.format_cause_v2(actual, formatter);
                }
                // Only the real failed-verification association selects here.
                // Later cleanup clock/snapshot failures stay retained below.
                if let Some(selected) = self.selected_verification.as_ref() {
                    if let Some(actual) = selected.cause_v1(self.original.failure(),
                        stage.clock.as_ref().and_then(ArgumentClockV2::failure))
                    {
                        return std::fmt::Display::fmt(actual, formatter);
                    }
                }
                if let Some(actual) = stage.clock.as_ref().and_then(ArgumentClockV2::failure)
                    .or_else(|| stage.agent_authentication.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
                {
                    return self.format_cause_v2(actual, formatter);
                }
                if let Some(writes) = stage.writes.as_ref() {
                    let writes = writes.lock().map_err(|_| std::fmt::Error)?;
                    if let Some(actual) = writes.failure() {
                        return self.format_cause_v2(actual, formatter);
                    }
                }
                if let Some(actual) = stage.owner.as_ref()
                    .and_then(DormantRuntimeExecutionOwnerV1::accepted_execution_native_failure_v2)
                {
                    return self.format_cause_v2(actual, formatter);
                }
                if let Some(actual) = stage.replacement.as_ref().and_then(|result| result.as_ref().err()) {
                    return self.format_cause_v2(actual, formatter);
                }
                primary
            }
            Some(LaunchFirstV2::Names) => {
                for (owners, results) in stage.names.iter().zip(&stage.name_results) {
                    for (owner, result) in owners.iter().zip(results) {
                        if let Some(returned) = result.as_ref().and_then(|result| result.as_ref().err()) {
                            return match owner.failure() {
                                Some(actual) => self.format_cause_v2(actual, formatter),
                                None => std::fmt::Display::fmt(returned, formatter),
                            };
                        }
                    }
                }
                primary
            }
            None if self.original.require_admitted_original().is_err() => {
                return std::fmt::Display::fmt(self.original.failure(), formatter);
            }
            None => None,
        };
        match returned {
            Some(error) => self.format_cause_v2(error, formatter),
            None => formatter.write_str("Host launch has no retained failure"),
        }
    }
}

impl std::fmt::Display for HostLaunchFailureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (stage, selected_verification) = match &self.stage {
            HostFailureStageV4::Cleanup(original)=>return original.format_failure_v1(&self.original,formatter),
            HostFailureStageV4::Launch(stage, selected) => (&**stage, *selected),
            HostFailureStageV4::NativeInventory(read) => {
                if read.original_failure_selected_v5() {
                    return std::fmt::Display::fmt(self.original.failure(), formatter);
                }
                return read.format_failure_v5(formatter);
            }
            HostFailureStageV4::NativeInventoryAdmission(cause, original_selected) => {
                return if *original_selected {
                    std::fmt::Display::fmt(self.original.failure(), formatter)
                } else { std::fmt::Display::fmt(cause, formatter) };
            }
            HostFailureStageV4::TerminalInventory(read) => {
                // Preserve the selected frontier even if a later owed native
                // post also failed. Guarded diagnostics do not reenter health.
                if matches!(read.first, Some(0 | 1 | 4 | 7)) {
                    return std::fmt::Display::fmt(self.original.failure(), formatter);
                }
                return match read.pure_failure_v4() {
                    Some(cause) => std::fmt::Display::fmt(cause, formatter),
                    None => formatter.write_str("Host terminal Inventory retains a refusal"),
                };
            }
        };
        // The original acquisition is already positive when a fresh Stop is
        // entered. Borrow its nested owner under the same lock order; never
        // replace an earlier acquisition cause with a later control failure.
        if stage.first.is_none() {
            if let Some(stop) = stage.resident_stop.as_ref() {
                let stop = stop.lock().map_err(|_| std::fmt::Error)?;
                let stage = stop.stage.lock().map_err(|_| std::fmt::Error)?;
                if let Some(formatted) = stop.format_unsent_disposal_failure_v1(&self.original, formatter) {
                    return formatted;
                }
                if let Some(formatted) = stop.format_capture_failure_v4(&stage, &self.original, formatter) {
                    return formatted;
                }
                if matches!(stage.first, Some(LaunchFirstV2::Primary)) {
                    if let Some(cause) = stop.failure() {
                        return std::fmt::Display::fmt(cause, formatter);
                    }
                    if let Some(Err(cause)) = stop.sdk_terminal.as_ref() {
                        return std::fmt::Display::fmt(cause, formatter);
                    }
                }
                if let Some(cause) = stop.disposal_error.as_ref() {
                    return std::fmt::Display::fmt(cause, formatter);
                }
                return std::fmt::Display::fmt(&HostStageFailureBorrowV4 {
                    original: &self.original,
                    stage: &stage,
                    selected_verification: None,
                }, formatter);
            }
        }
        std::fmt::Display::fmt(&HostStageFailureBorrowV4 {
            original: &self.original,
            stage,
            selected_verification,
        }, formatter)
    }
}

impl std::fmt::Debug for HostLaunchFailureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    /// Borrows the exact paid launch's chronological diagnostics.
    ///
    /// # Errors
    /// Rejects absent intrinsic custody or poisoned owner locks. The result
    /// supplies no retry, resource admission or native completion permission.
    pub fn launch_failure_view_v2(&self) -> Result<Option<HostLaunchFailureViewV2<'_>>> {
        if let Some(cleanup)=self.stop_cleanup_original.as_ref() {
            let original=self.component_control.as_ref().ok_or(HostError::Fence("cleanup diagnostic Control is absent"))?
                .lock().map_err(|_|HostError::Fence("cleanup diagnostic Control is poisoned"))?;
            let cleanup=cleanup.lock().map_err(|_|HostError::Fence("cleanup diagnostic native original is poisoned"))?;
            return Ok(Some(HostLaunchFailureViewV2 { original,stage:HostFailureStageV4::Cleanup(cleanup) }));
        }
        if let Some(read) = self.native_inventory_v5.as_ref().filter(|read| read.failed_v5()) {
            let original = self.component_control.as_ref()
                .ok_or(HostError::Fence("Host native inventory diagnostic original is absent"))?
                .lock().map_err(|_| HostError::Fence("Host native inventory diagnostic original is poisoned"))?;
            return Ok(Some(HostLaunchFailureViewV2 { original, stage: HostFailureStageV4::NativeInventory(read) }));
        }
        let admission = self.native_inventory_funding_v5.as_ref().and_then(|r| r.as_ref().err())
            .or_else(|| self.native_inventory_entry_v5.as_ref()?.as_ref().err())
            .or_else(|| self.native_inventory_shape_v5.as_ref()?.as_ref().err());
        if let Some(cause) = admission {
            let original = self.component_control.as_ref()
                .ok_or(HostError::Fence("Host native inventory diagnostic original is absent"))?
                .lock().map_err(|_| HostError::Fence("Host native inventory diagnostic original is poisoned"))?;
            return Ok(Some(HostLaunchFailureViewV2 { original,
                stage: HostFailureStageV4::NativeInventoryAdmission(cause, self.native_inventory_original_selected_v5) }));
        }
        if let Some(read) = self.terminal_inventory_v4.as_ref().filter(|read| read.first.is_some()) {
            let original = self.component_control.as_ref()
                .ok_or(HostError::Fence("Host terminal Inventory diagnostic original is absent"))?
                .lock().map_err(|_| HostError::Fence("Host terminal Inventory diagnostic original is poisoned"))?;
            return Ok(Some(HostLaunchFailureViewV2 { original,
                stage: HostFailureStageV4::TerminalInventory(read) }));
        }
        let Some(stage) = self.launch_original.as_ref() else { return Ok(None); };
        let original = self.component_control.as_ref()
            .ok_or(HostError::Fence("Host launch diagnostic original is absent"))?
            .lock().map_err(|_| HostError::Fence("Host launch diagnostic original is poisoned"))?;
        let stage = stage.lock().map_err(|_| HostError::Fence("Host launch diagnostic capsule is poisoned"))?;
        if stage.first.is_none() {
            let stop_failed = match stage.resident_stop.as_ref() {
                Some(stop) => {
                    let stop = stop.lock().map_err(|_| HostError::Fence("Stop diagnostic original is poisoned"))?;
                    let nested = stop.stage.lock().map_err(|_| HostError::Fence("Stop diagnostic stage is poisoned"))?;
                    nested.first.is_some() || stop.disposal_error.is_some()
                        || stop.unsent_disposal_failure_v1().is_some()
                }
                None => false,
            };
            if !stop_failed && original.require_admitted_original().is_ok()
                && stage.capture.as_ref().is_none_or(|resident| !resident.monitor_failed_data_v5())
            {
                return Ok(None);
            }
        }
        let selected_verification = if matches!(stage.first, Some(LaunchFirstV2::Primary)) {
            self.live_limit_attempts.get(&stage.request.0)
                .and_then(|attempt| attempt.selected_verification_failure_v1(&stage))
        } else { None };
        Ok(Some(HostLaunchFailureViewV2 { original,
            stage: HostFailureStageV4::Launch(stage, selected_verification) }))
    }
}
