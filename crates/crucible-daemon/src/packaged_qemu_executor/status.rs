//! Snapshot-coherent operational status for the packaged QEMU executor.
//!
//! This module couples short executor-actor snapshots to durable assignment,
//! materializer, and live QEMU lifecycle generations. Observations fail closed
//! whenever ownership or any sampled generation changes during projection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// crucible-lint: allow host-nondeterminism-state -- immutable scheduler inputs are forwarded through lifecycle ownership while status remains operational-only.
use crucible::{Configuration, ScenarioDef};
use crucible::{ScenarioDefForm, SchedulerError, SchedulerEventLogEntry};
// crucible-lint: allow host-nondeterminism-state -- These engine types are forwarded only through scheduler-owned lifecycle traits; operational observations never influence engine state.
use crucible::{QuantumOutcome, QuantumRequest, QuantumTerminalVerdict};
// crucible-lint: allow host-nondeterminism-state -- The wrapper preserves the validated production lifecycle boundary and observes only ownership phases.
use crucible_api::{
    ProductionFaultEvidenceSnapshot, ProductionVmLifecycleResumeState,
    ProductionVmNodeReplayLaunchProfile,
};
use crucible_campaign::{
    CampaignHash, CampaignName, CampaignOperationalEvidence, CampaignOperationalStatus,
    CampaignOperationalStatusProvider, CampaignRepository, CampaignSnapshotId, CampaignWorldStatus,
    DaemonEpoch, ExecutionId,
};
use crucible_protocol::SelectionReply;
use crucible_qemu::QemuNodeSelectablePendingRequest;

use super::PackagedAttemptAdmission;
use super::exact_pin_materializer::{PackagedExactPinStatus, PackagedExactPinStatusHandle};
use crate::assignment_ledger::{
    AttemptRuntimeState, directory_assignment_retention_generation,
    visit_directory_attempt_states_bounded,
};
use crate::executor_pool::LocalExecutorOperationalSnapshot;
use crate::executor_supervisor::LocalExecutionActivity;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptWorkResult, AttemptWorkerFailure, CapturedAttemptCheckpoint, DirectoryAssignmentLedger,
    ExactCheckpointStore, LocalAttemptWorker, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, QemuHotForkWorldLifecycleFactory,
    QemuHotForkWorldLifecycleStart, QemuProductionExactResumeLifecycleFactory,
    QemuProductionExactResumeLifecycleOwner, QueuedAttempt,
};

const MAX_PACKAGED_STATUS_ATTEMPT_RECORDS: usize = 65_536;

pub(super) struct PackagedQemuOperationalStatusProvider {
    pub(super) repository: Arc<CampaignRepository>,
    pub(super) campaigns: BTreeSet<CampaignName>,
    pub(super) ledger_root: PathBuf,
    pub(super) pool:
        crate::LocalExecutorPoolService<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(super) lifecycles: PackagedWorldLifecycleTracker,
    pub(super) materializer: PackagedExactPinStatusHandle,
}

#[derive(Clone)]
pub(super) struct PackagedWorldLifecycleTracker {
    state: Arc<Mutex<PackagedWorldLifecycleState>>,
}

struct PackagedWorldLifecycleState {
    revision: u64,
    valid: bool,
    phases: BTreeMap<ExecutionId, PackagedWorldLifecyclePhase>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackagedWorldLifecycleSnapshot {
    pub(super) revision: u64,
    pub(super) phases: BTreeMap<ExecutionId, PackagedWorldLifecyclePhase>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PackagedWorldLifecyclePhase {
    Preparing,
    Running,
    TearingDown,
    PostProcessing,
}

pub(super) struct PackagedAttemptLifecycleLease {
    tracker: PackagedWorldLifecycleTracker,
    execution: ExecutionId,
    finished: bool,
}

pub(super) struct PackagedStatusAttemptWorker<W> {
    pub(super) inner: W,
    pub(super) lifecycles: PackagedWorldLifecycleTracker,
}

pub(super) struct PackagedStatusLifecycleFactory<F> {
    pub(super) inner: F,
    pub(super) lifecycles: PackagedWorldLifecycleTracker,
}

pub(super) struct PackagedStatusHotForkFactory<F> {
    pub(super) inner: F,
    pub(super) lifecycles: PackagedWorldLifecycleTracker,
}

pub(super) struct PackagedStatusLifecycle<L> {
    inner: L,
    lifecycles: PackagedWorldLifecycleTracker,
    execution: Option<ExecutionId>,
    shutdown_finished: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OperationalPhase {
    Preparing,
    Running,
    Checkpointing,
    Publishing,
    Canceling,
    Paused,
}

impl PackagedWorldLifecycleTracker {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(PackagedWorldLifecycleState {
                revision: 0,
                valid: true,
                phases: BTreeMap::new(),
            })),
        }
    }

    pub(super) fn begin(&self, execution: ExecutionId) -> PackagedAttemptLifecycleLease {
        self.mutate(|state| {
            if state.phases.contains_key(&execution)
                || state.phases.len() >= crate::MAX_LOCAL_EXECUTOR_WORKERS
            {
                state.valid = false;
                return;
            }
            state
                .phases
                .insert(execution, PackagedWorldLifecyclePhase::Preparing);
        });
        PackagedAttemptLifecycleLease {
            tracker: self.clone(),
            execution,
            finished: false,
        }
    }

    pub(super) fn running(&self, execution: ExecutionId) {
        self.mutate(|state| match state.phases.get_mut(&execution) {
            Some(phase @ PackagedWorldLifecyclePhase::Preparing) => {
                *phase = PackagedWorldLifecyclePhase::Running;
            }
            Some(_) | None => state.valid = false,
        });
    }

    fn tearing_down(&self, execution: ExecutionId) {
        self.mutate(|state| match state.phases.get_mut(&execution) {
            Some(phase @ PackagedWorldLifecyclePhase::Running) => {
                *phase = PackagedWorldLifecyclePhase::TearingDown;
            }
            Some(_) | None => state.valid = false,
        });
    }

    fn post_processing(&self, execution: ExecutionId) {
        self.mutate(|state| match state.phases.get_mut(&execution) {
            Some(phase @ PackagedWorldLifecyclePhase::TearingDown) => {
                *phase = PackagedWorldLifecyclePhase::PostProcessing;
            }
            Some(_) | None => state.valid = false,
        });
    }

    fn finish(&self, execution: ExecutionId) {
        self.mutate(|state| match state.phases.get(&execution) {
            Some(
                PackagedWorldLifecyclePhase::Preparing
                | PackagedWorldLifecyclePhase::PostProcessing,
            ) => {
                state.phases.remove(&execution);
            }
            Some(_) | None => state.valid = false,
        });
    }

    fn invalidate(&self) {
        match self.state.lock() {
            Ok(mut state) => state.valid = false,
            Err(poisoned) => poisoned.into_inner().valid = false,
        }
    }

    pub(super) fn snapshot(&self) -> Option<PackagedWorldLifecycleSnapshot> {
        let state = self.state.lock().ok()?;
        if !state.valid || state.revision == u64::MAX {
            return None;
        }
        Some(PackagedWorldLifecycleSnapshot {
            revision: state.revision,
            phases: state.phases.clone(),
        })
    }

    fn mutate(&self, update: impl FnOnce(&mut PackagedWorldLifecycleState)) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                poisoned.into_inner().valid = false;
                return;
            }
        };
        if !state.valid {
            return;
        }
        let Some(revision) = state.revision.checked_add(1) else {
            state.valid = false;
            return;
        };
        update(&mut state);
        state.revision = revision;
    }
}

impl PackagedAttemptLifecycleLease {
    pub(super) fn finish(mut self) {
        self.tracker.finish(self.execution);
        self.finished = true;
    }
}

impl Drop for PackagedAttemptLifecycleLease {
    fn drop(&mut self) {
        if !self.finished {
            self.tracker.invalidate();
        }
    }
}

impl<W> LocalAttemptWorker for PackagedStatusAttemptWorker<W>
where
    W: LocalAttemptWorker,
{
    type Error = W::Error;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        let lease = self.lifecycles.begin(queued.execution());
        let result = self.inner.execute(queued);
        lease.finish();
        result
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.inner.reconcile_execution(disposition)
    }
}

impl<F> QemuFreshAttemptLifecycleFactory for PackagedStatusLifecycleFactory<F>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    type Lifecycle = PackagedStatusLifecycle<F::Lifecycle>;
    type Error = F::Error;

    fn start_fresh_lifecycle(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- The wrapper forwards the canonical scenario unchanged and records only an operational phase.
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        // crucible-lint: allow host-nondeterminism-state -- The wrapper forwards the canonical start configuration unchanged.
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let lifecycle = self.inner.start_fresh_lifecycle(
            scenario,
            source,
            start,
            signal_fault_replay,
            context,
        )?;
        match context.runtime_basis() {
            Some(basis) => self.lifecycles.running(basis.execution()),
            None => self.lifecycles.invalidate(),
        }
        Ok(PackagedStatusLifecycle {
            inner: lifecycle,
            lifecycles: self.lifecycles.clone(),
            execution: context.runtime_basis().map(|basis| basis.execution()),
            shutdown_finished: false,
        })
    }
}

impl<F> QemuProductionExactResumeLifecycleFactory for PackagedStatusLifecycleFactory<F>
where
    F: QemuProductionExactResumeLifecycleFactory,
{
    type Lifecycle = PackagedStatusLifecycle<F::Lifecycle>;
    type Error = F::Error;

    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: crucible_campaign::ExactCheckpointId,
        // crucible-lint: allow host-nondeterminism-state -- The wrapper forwards the canonical scenario unchanged and records only an operational phase.
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        // crucible-lint: allow host-nondeterminism-state -- The wrapper forwards the canonical resume configurations unchanged.
        initial: &Configuration,
        // crucible-lint: allow host-nondeterminism-state -- The wrapper forwards the optional post-selection configuration unchanged.
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let lifecycle = self.inner.start_resume_lifecycle(
            checkpoints,
            checkpoint,
            scenario,
            source,
            initial,
            post_selection,
            context,
        )?;
        match context.runtime_basis() {
            Some(basis) => self.lifecycles.running(basis.execution()),
            None => self.lifecycles.invalidate(),
        }
        Ok(PackagedStatusLifecycle {
            inner: lifecycle,
            lifecycles: self.lifecycles.clone(),
            execution: context.runtime_basis().map(|basis| basis.execution()),
            shutdown_finished: false,
        })
    }
}

impl<F> QemuHotForkWorldLifecycleFactory for PackagedStatusHotForkFactory<F>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    type Lifecycle = F::Lifecycle;
    type Error = F::Error;

    fn try_start(
        &mut self,
        input: &crate::CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        let started = self.inner.try_start(input, context)?;
        if matches!(started, QemuHotForkWorldLifecycleStart::Started(_)) {
            match context.runtime_basis() {
                Some(basis) => self.lifecycles.running(basis.execution()),
                None => self.lifecycles.invalidate(),
            }
        }
        Ok(started)
    }

    fn recover(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.inner.recover(lifecycle)
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        self.inner.quarantine(lifecycle);
    }
}

impl<L> QemuFreshAttemptLifecycleOwner for PackagedStatusLifecycle<L>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.inner.enable_signal_fault_campaign_promotion();
    }

    // crucible-lint: allow host-nondeterminism-state -- Quantum ownership remains with the wrapped lifecycle; this method forwards the request and outcome unchanged.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- The wrapped lifecycle remains the sole quantum driver.
        self.inner.drive_quantum(request)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.inner.terminal_verdict_for_stop()
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.inner.exact_checkpoint_ready()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.inner.drain_pending_selectable_requests()
    }

    fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError> {
        self.inner.enqueue_selectable_reply(pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.inner.capture_attempt_checkpoint(context)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        self.inner.replay_launch_profiles()
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.inner.fault_evidence_snapshot()
    }

    fn pending_network_output_count(&self) -> usize {
        self.inner.pending_network_output_count()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.shutdown_finished {
            self.lifecycles.invalidate();
            return self.inner.shutdown();
        }
        if let Some(execution) = self.execution {
            self.lifecycles.tearing_down(execution);
        } else {
            self.lifecycles.invalidate();
        }

        let result = self.inner.shutdown();
        self.shutdown_finished = true;
        match (&result, self.execution) {
            (Ok(_), Some(execution)) => self.lifecycles.post_processing(execution),
            (Ok(_), None) | (Err(_), _) => self.lifecycles.invalidate(),
        }
        result
    }
}

impl<L> QemuProductionExactResumeLifecycleOwner for PackagedStatusLifecycle<L>
where
    L: QemuProductionExactResumeLifecycleOwner,
{
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError> {
        self.inner.resume_state()
    }
}

impl<L> Drop for PackagedStatusLifecycle<L> {
    fn drop(&mut self) {
        if !self.shutdown_finished {
            self.lifecycles.invalidate();
        }
    }
}

impl CampaignOperationalStatusProvider for PackagedQemuOperationalStatusProvider {
    fn operational_status(
        &self,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> CampaignOperationalStatus {
        self.observe(campaign, snapshot).map_or(
            CampaignOperationalStatus::Unavailable,
            CampaignOperationalStatus::Observed,
        )
    }
}

impl PackagedQemuOperationalStatusProvider {
    /// Observes disk-backed generations outside the short executor actor lock.
    ///
    /// The first and final actor snapshots are the lock-order boundary. No
    /// repository, ledger-directory, or materializer I/O occurs while the
    /// actor is held. A monotone actor revision plus ledger and materializer
    /// generations reject every intervening ownership or durable-state change.
    fn observe(
        &self,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> Option<CampaignOperationalEvidence> {
        if !self.campaigns.contains(campaign) {
            return None;
        }
        if self.repository.head(campaign.as_str()).ok()?.snapshot_id() != snapshot {
            return None;
        }

        let ledger_before = directory_assignment_retention_generation(&self.ledger_root).ok()?;
        let actor_before = self.pool.operational_snapshot().ok()?;
        let lifecycles_before = self.lifecycles.snapshot()?;
        let materializer_before = self.materializer.status(campaign, snapshot).ok()?;

        let mut runtime_states = Vec::new();
        let complete = visit_directory_attempt_states_bounded(
            &self.ledger_root,
            MAX_PACKAGED_STATUS_ATTEMPT_RECORDS,
            &mut |key, state| runtime_states.push((key, state)),
        )
        .ok()?;
        if !complete {
            return None;
        }

        let materializer_after = self.materializer.status(campaign, snapshot).ok()?;
        let lifecycles_after = self.lifecycles.snapshot()?;
        let actor_after = self.pool.operational_snapshot().ok()?;
        let ledger_after = directory_assignment_retention_generation(&self.ledger_root).ok()?;
        if ledger_before != ledger_after
            || materializer_before != materializer_after
            || lifecycles_before != lifecycles_after
            || !successive_actor_snapshots(&actor_before, &actor_after)
            || self.repository.head(campaign.as_str()).ok()?.snapshot_id() != snapshot
        {
            return None;
        }

        let candidates = runtime_states
            .iter()
            .map(|(key, _state)| (key.lineage(), key.attempt()))
            .collect::<Vec<_>>();
        let membership = self
            .repository
            .attempt_membership_at(snapshot, &candidates)
            .ok()?;
        if membership.len() != runtime_states.len() {
            return None;
        }

        let activities = actor_before
            .activities
            .iter()
            .map(|activity| (activity.execution, *activity))
            .collect::<BTreeMap<_, _>>();
        if lifecycles_before.phases.keys().any(|execution| {
            !activities
                .get(execution)
                .is_some_and(|activity| activity.worker_in_flight)
        }) {
            return None;
        }
        let mut worlds = [0_u64; 6];
        let mut retained = materializer_before.selected_roots.clone();
        let mut materialized = materializer_before.selected_roots.clone();
        for ((_key, state), member) in runtime_states.iter().zip(membership) {
            if !member {
                continue;
            }
            for checkpoint in state.retained_checkpoint_roots().into_iter().flatten() {
                retained.insert(checkpoint);
            }
            for checkpoint in state.materialized_checkpoint_roots().into_iter().flatten() {
                materialized.insert(checkpoint);
            }
            let phase = operational_phase(
                *state,
                actor_before.daemon_epoch,
                &activities,
                &lifecycles_before.phases,
            )
            .ok()?;
            if let Some(phase) = phase {
                let slot = match phase {
                    OperationalPhase::Preparing => 0,
                    OperationalPhase::Running => 1,
                    OperationalPhase::Checkpointing => 2,
                    OperationalPhase::Publishing => 3,
                    OperationalPhase::Canceling => 4,
                    OperationalPhase::Paused => 5,
                };
                worlds[slot] = worlds[slot].checked_add(1)?;
            }
        }

        let inventory_generation = packaged_status_generation(
            campaign,
            snapshot,
            ledger_before.as_bytes(),
            &actor_before,
            &lifecycles_before,
            &materializer_before,
        );
        Some(CampaignOperationalEvidence::new(
            actor_before.daemon_epoch,
            inventory_generation,
            CampaignWorldStatus::new(
                worlds[0], worlds[1], worlds[2], worlds[3], worlds[4], worlds[5],
            ),
            u64::try_from(retained.len()).ok()?,
            u64::try_from(materialized.len()).ok()?,
        ))
    }
}

pub(super) fn successive_actor_snapshots(
    before: &LocalExecutorOperationalSnapshot,
    after: &LocalExecutorOperationalSnapshot,
) -> bool {
    before.revision == after.revision
        && before.daemon_epoch == after.daemon_epoch
        && before.activities == after.activities
}

pub(super) fn operational_phase(
    state: AttemptRuntimeState,
    daemon_epoch: DaemonEpoch,
    activities: &BTreeMap<ExecutionId, LocalExecutionActivity>,
    lifecycles: &BTreeMap<ExecutionId, PackagedWorldLifecyclePhase>,
) -> Result<Option<OperationalPhase>, ()> {
    let activity = activities.get(&state.execution());
    match state {
        AttemptRuntimeState::Paused { .. } => Ok(Some(OperationalPhase::Paused)),
        AttemptRuntimeState::CheckpointPromoting { .. } => {
            Ok(Some(OperationalPhase::Checkpointing))
        }
        AttemptRuntimeState::Completed { .. } => Ok(None),
        AttemptRuntimeState::Canceled {
            daemon_epoch: epoch,
            ..
        } => Ok(activity
            .filter(|_| epoch == daemon_epoch)
            .map(|_| OperationalPhase::Canceling)),
        AttemptRuntimeState::CheckpointRequested {
            daemon_epoch: epoch,
            ..
        }
        | AttemptRuntimeState::CheckpointPublishing {
            daemon_epoch: epoch,
            ..
        } => {
            if epoch != daemon_epoch {
                return Ok(None);
            }
            let Some(activity) = activity else {
                return Err(());
            };
            if activity.cancellation_requested {
                Ok(Some(OperationalPhase::Canceling))
            } else {
                Ok(Some(OperationalPhase::Checkpointing))
            }
        }
        AttemptRuntimeState::Publishing {
            daemon_epoch: epoch,
            ..
        } => {
            if epoch != daemon_epoch {
                return Ok(None);
            }
            activity
                .map(|_| Some(OperationalPhase::Publishing))
                .ok_or(())
        }
        AttemptRuntimeState::Running {
            daemon_epoch: epoch,
            ..
        } => {
            if epoch != daemon_epoch {
                return Ok(None);
            }
            let Some(activity) = activity else {
                return Err(());
            };
            if activity.cancellation_requested || activity.cancellation_pending {
                Ok(Some(OperationalPhase::Canceling))
            } else if activity.completion_pending {
                Ok(Some(OperationalPhase::Publishing))
            } else if !activity.worker_in_flight {
                Ok(Some(OperationalPhase::Preparing))
            } else {
                match lifecycles.get(&state.execution()) {
                    Some(PackagedWorldLifecyclePhase::Preparing) => {
                        Ok(Some(OperationalPhase::Preparing))
                    }
                    Some(PackagedWorldLifecyclePhase::Running) => {
                        Ok(Some(OperationalPhase::Running))
                    }
                    Some(PackagedWorldLifecyclePhase::TearingDown) => Err(()),
                    Some(PackagedWorldLifecyclePhase::PostProcessing) => {
                        Ok(Some(OperationalPhase::Publishing))
                    }
                    None => Err(()),
                }
            }
        }
    }
}

fn packaged_status_generation(
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    ledger_generation: [u8; 32],
    actor: &LocalExecutorOperationalSnapshot,
    lifecycles: &PackagedWorldLifecycleSnapshot,
    materializer: &PackagedExactPinStatus,
) -> CampaignHash {
    let mut material = Vec::with_capacity(256);
    material.extend_from_slice(&(campaign.as_str().len() as u64).to_be_bytes());
    material.extend_from_slice(campaign.as_str().as_bytes());
    material.extend_from_slice(snapshot.to_string().as_bytes());
    material.extend_from_slice(&ledger_generation);
    material.extend_from_slice(&actor.daemon_epoch.as_bytes());
    material.extend_from_slice(&actor.revision.to_be_bytes());
    material.extend_from_slice(&lifecycles.revision.to_be_bytes());
    for (execution, phase) in &lifecycles.phases {
        material.extend_from_slice(&execution.as_bytes());
        material.push(match phase {
            PackagedWorldLifecyclePhase::Preparing => 0,
            PackagedWorldLifecyclePhase::Running => 1,
            PackagedWorldLifecyclePhase::TearingDown => 2,
            PackagedWorldLifecyclePhase::PostProcessing => 3,
        });
    }
    material.extend_from_slice(&materializer.generation.as_bytes());
    CampaignHash::derive("crucible.executor.packaged-campaign-status.v1", &material)
}
