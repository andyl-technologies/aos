//! Attempt-guarded construction of the production QEMU lifecycle.
//!
//! This module is the daemon-side join between an admitted campaign execution
//! context and the production lifecycle scheduler. It installs one exact
//! process/resource guard before lifecycle construction, validates the guard's
//! resource and cancellation incarnation, and transfers that authority into
//! `QemuAttemptProductionVmNodeLauncher`. `QemuFreshExecutionRunner` keeps
//! final drain and teardown outside the modeled driver and seals a result only
//! after those final events are available. Exact roots normally retain their
//! physical resume path; newly selected continuation control cold executes
//! because a checkpoint captured before selection cannot contain that input.

use crucible::{
    CheckpointTerminalCause, Configuration, ContentHash, Decision, FingerprintSample, NodeId,
    QuantumLoop, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, ScenarioDef,
    ScenarioDefForm, Schedule, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SchedulerQuiescence, Seed, SelectionDecision, VirtualTime,
};
use crucible_api::vm_lifecycle::RetentionDrain;
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmExactHotForkSourceBoundary,
    ProductionVmLifecycleConfig, ProductionVmLifecycleLoop, ProductionVmNodeReplayLaunchProfile,
    build_production_vm_exact_resume_lifecycle, build_production_vm_lifecycle_loop_with_launcher,
};
use crucible_campaign::{
    AttemptContinuationInput, AttemptStartMode, CampaignHash, ChoiceDiscovery, ChoiceOpportunityId,
    ChoiceSource, ConfigurationArtifact, ConfigurationId, ExactCheckpointId,
    MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES, SelectionOrigin, StopCondition,
};
use crucible_cas::content_store::StoreError;
use crucible_protocol::SelectionReply;
use crucible_qemu::{
    QemuNodeSelectablePendingRequest, QemuParkedCampaignMarker, QemuVmRealizationError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use thiserror::Error;

use crate::crucible_execution::CrucibleAttemptOrigin;
use crate::guest_selectable::{
    GuestSelectableBoundaryDiagnosticStage, GuestSelectableError, GuestSelectableReplayAttemptRole,
    GuestSelectableReplayCorrelation, GuestSelectableReplayMismatch,
    GuestSelectableReplayOpportunityContext, GuestSelectableReplayPhase,
    record_guest_selectable_boundary_diagnostic, resolve_guest_selectable, selected_guest_reply,
};
use crate::qemu_campaign_driver::{DEFAULT_MAXIMUM_EVENT_LOG_BYTES, RetainedAttemptLog};
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionProduct,
    AttemptWorkerFailure, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, CrucibleResolvedAttemptStart, ExactCheckpointStore,
    ExactCheckpointStoreError, MAX_QEMU_ATTEMPT_GENERATION_NODES,
    ProductionAttemptCheckpointRestoreError, QemuAttemptGenerationResourceOwner,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmNodeLauncher, QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory,
    QemuAttemptStartReplayProof, QemuAttemptStartVerifier, QemuExactResumeBasis,
    QemuSavepointReplayProof, QemuSelectedOriginVerifier,
    authenticate_attempt_production_resume_boundary, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact, install_attempt_production_resume_checkpoint,
};

mod app_random_branch_replay;
use app_random_branch_replay::{AppRandomLaunchWindow, app_random_branch_replay};

mod interactive_session;
pub use interactive_session::{
    InteractiveQemuSessionError, build_guarded_interactive_qemu_session,
};

mod failure_classification;
mod guest_selectable;
pub(crate) use failure_classification::{
    classify_production_lifecycle_failure, production_lifecycle_failure_class,
};
use guest_selectable::{apply_replayed_guest_selectables, publish_replayed_host_outcomes};

mod remote_observation_resume;
pub use remote_observation_resume::RemoteObservationResumeFactory;

mod resume_admission;
use resume_admission::validate_exact_resume_request;

mod attempt_config;
pub(crate) use attempt_config::config_for_assignment_host_watchdog;
use attempt_config::config_for_attempt_trace_storage;

mod network_fault_replay;
use network_fault_replay::{
    cross_replayed_network_fault_boundary, every_vm_parked_for,
    park_replayed_network_fault_markers, recorded_branch_at,
};

mod start_replay_log;
use start_replay_log::{
    StartReplayProgress, append_start_replay_events, observe_replayed_choice_free_boot,
    with_replay_progress,
};

/// Failure to bind an admitted attempt to a fresh production VM lifecycle.
#[derive(Debug, Error)]
pub enum QemuAttemptProductionVmLifecycleError {
    /// The fresh lifecycle path was asked to resume an exact checkpoint.
    #[error("fresh production VM lifecycle cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(ExactCheckpointId),
    /// The serialized scenario form did not reconstruct the supplied identity.
    #[error("production VM lifecycle scenario form does not match the supplied scenario")]
    ScenarioIdentityMismatch,
    /// The scenario's QEMU-node count is outside the attempt-owner bound.
    #[error(
        "production VM lifecycle node count {0} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
    )]
    InvalidNodeCount(usize),
    /// No physical execution quantum remains before process installation.
    #[error("refuse production VM resources: {0}")]
    ResourceRefusal(#[source] crate::executor_worker::ExecutionQuantumBudgetError),
    /// The assignment's policy-keyed host safety deadline expired before launch.
    #[error("production VM assignment host watchdog expired before lifecycle construction")]
    HostWatchdogExpired,
    /// The authenticated checkpoint did not expose a complete dense replay boundary.
    #[error("production VM checkpoint has no complete replay boundary")]
    InvalidResumeBoundary,
    /// Installing the attempt resource guard failed.
    #[error("install production VM attempt resources: {0}")]
    ResourceInstallation(#[source] QemuVmRealizationError),
    /// The installed guard did not echo the exact admitted attempt contract.
    #[error(
        "production VM resource guard did not install the exact admitted limits and cancellation signal"
    )]
    ResourceContractMismatch,
    /// Releasing a mismatched resource guard failed.
    #[error("release mismatched production VM attempt resources: {0}")]
    ResourceContractCleanup(#[source] QemuVmRealizationError),
    /// The production lifecycle rejected construction under the installed guard.
    #[error("build guarded production VM lifecycle: {0}")]
    Lifecycle(#[source] LifecycleApiError),
    /// The durable version-nine root failed exact attempt resume admission.
    #[error("install production VM attempt checkpoint: {0}")]
    CheckpointRestore(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The resolved start configuration does not form an executable branch plan.
    #[error("derive exact app-random branch replay: {0}")]
    InvalidAppRandomBranchReplay(String),
    /// The authenticated live-network branch selection could not be decoded.
    #[error("derive exact live-network branch replay: {0}")]
    InvalidNetworkBranchReplay(String),
    /// The authenticated promoted signal-fault plan names a different start.
    #[error("derive exact signal-fault branch replay: {0}")]
    InvalidSignalFaultBranchReplay(String),
    /// The modeled continuation control is malformed for the authenticated scenario.
    #[error("derive modeled continuation control")]
    InvalidContinuationInput,
    /// The attempt's resolved-effect trace directory could not be created.
    #[error("create production VM resolved-effect trace storage: {0}")]
    TraceStorage(#[source] std::io::Error),
}

mod resource_admission;
pub use resource_admission::{
    QemuFreshScenarioResourceError, validate_fresh_qemu_scenario_resources,
};

/// Factory that binds one admitted attempt to the guarded production lifecycle.
pub(crate) struct QemuAttemptProductionVmLifecycleFactory<R> {
    config: ProductionVmLifecycleConfig,
    resources: R,
    terminal_checkpoints: Option<Arc<ExactCheckpointStore>>,
    continuations: Vec<OwnedQemuAttemptContinuation>,
    authenticated_network_selections: Vec<SelectionDecision>,
}

/// Owned continuation state retained between admission and lifecycle startup.
#[derive(Clone, Debug)]
pub(super) struct OwnedQemuAttemptContinuation {
    input: AttemptContinuationInput,
    source: Configuration,
}

/// Runner-owned fresh lifecycle operations hidden from modeled drivers.
///
/// The owner includes shutdown because the campaign runner, rather than the
/// modeled driver, must perform the final event drain and resource teardown.
/// Drivers receive only [`QemuFreshAttemptLifecycle`], which deliberately does
/// not expose this terminal capability.
pub trait QemuFreshAttemptLifecycleOwner {
    /// Enables exact live signal-fault promotion from the current boundary.
    ///
    /// The fresh runner calls this only after the admitted start configuration
    /// has been materialized. Previously retained signal-fault frontiers remain
    /// replay-only evidence and cannot become discoveries retroactively.
    fn enable_signal_fault_campaign_promotion(&mut self);

    /// Installs an exact nonterminal scheduler frontier for this attempt.
    ///
    /// Passing `None` clears the prior attempt's frontier.
    ///
    /// Deterministic fixture lifecycles whose outcomes are already bounded may
    /// accept the frontier without additional work.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the lifecycle cannot install the
    /// frontier without crossing its current scheduler boundary.
    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError>;

    /// Enables a one-RUN preselection pause for live-network choice attempts.
    fn set_live_network_choice_pause(&mut self, _enabled: bool) {}

    /// Enables concurrent execution until the audited choice-free boot marker.
    fn set_choice_free_parallel_boot(&mut self, _enabled: bool) {}

    /// Returns the exact unresolved network choice at this boundary.
    fn live_network_preselection(&self) -> Option<crucible::LiveNetworkPreselection> {
        None
    }

    /// Commits an exact live-network branch selection while retaining its
    /// physical output suffix for the following replay quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if no matching choice is reserved.
    fn select_live_network_preselection(
        &mut self,
        _selection: SelectionDecision,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("lifecycle has no selectable live-network reservation"),
        })
    }

    /// Resolves a reserved network choice through its default.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when no reservation is available.
    fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("lifecycle has no live-network preselection"),
        })
    }

    /// Hands an exact network choice to the observation owner.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when no matching reservation is available.
    fn handoff_live_network_preselection(
        &mut self,
        _expected: &crucible::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("lifecycle has no live-network preselection"),
        })
    }

    /// Advances one scheduler quantum under the attempt resource guard.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler or guarded backend cannot
    /// complete the exact quantum.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;

    /// Returns the absolute scheduler-quantum coordinate at the current boundary.
    #[must_use]
    fn completed_quanta(&self) -> u64;

    /// Returns the segmented event-log offset retained by the live scheduler.
    ///
    /// Every owner answers explicitly. A refusing default once hid two
    /// wrappers that dropped the offset, silently disabling anchor roots,
    /// whose replay proof binds it.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this lifecycle cannot expose an exact
    /// replay boundary.
    fn event_log_offset(&self) -> Result<crucible::EventLogOffset, SchedulerError>;

    /// Observes the terminal verdict without consuming checkpoint ownership.
    #[must_use]
    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict>;

    /// Retains the semantic terminal cause in the exact checkpoint continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when `cause` conflicts with terminal evidence
    /// already retained by the lifecycle.
    fn prepare_terminal_checkpoint(
        &mut self,
        cause: CheckpointTerminalCause,
    ) -> Result<(), SchedulerError>;

    /// Returns whether every live node can enter an exact checkpoint now.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when live-node or host-I/O state cannot be
    /// inspected consistently.
    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError>;

    /// Reads an exact physical park for a declared campaign phase marker.
    ///
    /// # Errors
    ///
    /// Returns an error when the live VM's physical stop cannot be verified.
    fn parked_campaign_marker(
        &mut self,
        _node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign marker proof is unavailable"),
        })
    }

    /// Releases a parked VM after the atomic environment choice is applied.
    ///
    /// # Errors
    ///
    /// Returns an error when no matching physical marker park exists.
    fn release_parked_campaign_marker(
        &mut self,
        _node: &NodeId,
        _marker: &str,
        _selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign marker release is unavailable"),
        })
    }

    /// Parks held campaign markers named in `markers` and publishes their peers.
    ///
    /// Owners without held campaign markers return zero. Published peer
    /// outcomes merge into `outcome`, which then names the post-park boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when a held marker lacks its physical park or peer
    /// publication fails.
    fn park_held_campaign_markers(
        &mut self,
        _markers: &[&str],
        _outcome: &mut QuantumOutcome,
    ) -> Result<usize, SchedulerError> {
        Ok(0)
    }

    /// Joins every scheduler park to one frontier at a validated all-VM boundary.
    ///
    /// Returns the joined frontier, or `None` when no VM was parked.
    ///
    /// # Errors
    ///
    /// Returns an error when the scheduler rejects the join.
    fn join_campaign_parks_to_frontier(&mut self) -> Result<Option<VirtualTime>, SchedulerError> {
        Ok(None)
    }

    /// Commits one network fault campaign branch at the joined all-VM boundary.
    ///
    /// Returns the selected configuration and its recorded event-log entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner has no scheduler or refuses the boundary.
    fn append_network_fault_campaign_branch(
        &mut self,
        _branch: &crucible::NetworkFaultCampaignBranch,
    ) -> Result<(Configuration, Vec<SchedulerEventLogEntry>), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("network fault campaign branch append is unavailable"),
        })
    }

    /// Authenticates a previously released physical marker on this selected branch.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner cannot inspect its exact release ledger.
    fn campaign_marker_release_committed(
        &self,
        _node: &NodeId,
        _marker: &str,
        _selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign marker release proof is unavailable"),
        })
    }

    /// Reports whether adapter-owned network queues are empty at activation.
    ///
    /// # Errors
    ///
    /// Returns an error when network queue state cannot be authenticated.
    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign network queue proof is unavailable"),
        })
    }

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a live node's request stream is malformed
    /// or violates its single-pending-request contract.
    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError>;

    /// Projects a retained guest pause into the shared scheduler clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the pause overflows or its admitted mapping is absent.
    fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        let ticks = pending
            .pending()
            .trap_tick_ps()
            .checked_add(
                crucible_protocol::selectable_catalog_plan::SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
            )
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("guest selectable pause boundary overflowed"),
            })?;
        Ok(VirtualTime { ticks })
    }

    /// Authenticates an already committed held source independently of peer time.
    ///
    /// The default grants no early visibility. Implementations must validate
    /// original ownership and the exact retained request without effects.
    ///
    /// # Errors
    ///
    /// Returns an error when original held ownership cannot be authenticated.
    fn pending_selectable_request_is_committed_source(
        &self,
        _pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    /// Publishes an already committed held suffix without another guest RUN.
    ///
    /// Owners without retained host outcomes return `None`. Implementations
    /// authenticate the released configuration and preserve failed publication
    /// for ordered retirement; this hook grants no new execution authority.
    ///
    /// # Errors
    ///
    /// Returns an error when original ownership or publication guards refuse.
    fn publish_released_host_outcomes(
        &mut self,
        _configuration: &Configuration,
    ) -> Result<Option<QuantumOutcome>, SchedulerError> {
        Ok(None)
    }

    /// Applies one exact semantic reply at the authoritative scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the request is stale, names another node
    /// generation, or the reply violates the retained reservation.
    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>;

    /// Captures the exact current attempt continuation without CAS publication.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the current boundary is unsafe or the
    /// complete production continuation cannot be durably captured and reopened.
    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError>;

    /// Copies immutable node launch profiles for independent background replay.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when replay launch profiles are unavailable
    /// or inconsistent with the live lifecycle.
    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError>;

    /// Captures read-only production fault evidence at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a fault adapter or retained trace cannot
    /// be inspected consistently.
    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError>;

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    fn pending_network_output_count(&self) -> usize;

    /// Samples one node's concrete execution fingerprint at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the node is absent or its live state cannot
    /// be read consistently.
    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError>;

    /// Prepares exact terminal fingerprints before lifecycle teardown.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when any authenticated scenario node cannot
    /// be sampled at the terminal boundary.
    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError>;

    /// Exports the exact resolved-effect trace retained by the live fault runtime.
    ///
    /// The result is a segmented trace handle; its segments stay in the
    /// lifecycle's segment store.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when retained effect evidence cannot be exported.
    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible::model::ResolvedEffectTrace>, SchedulerError>;

    /// Settles the final boundary without teardown so the world may be retained.
    ///
    /// [`QemuFinalBoundaryDrain::Retainable`] means the boundary settled with
    /// no new entries; a later [`Self::shutdown`] then publishes none either.
    /// [`QemuFinalBoundaryDrain::Drained`] entries were appended and precede
    /// whatever shutdown returns. [`QemuFinalBoundaryDrain::Ineligible`]
    /// changes nothing and names the refusing check. Owners that cannot
    /// retain their world use the default.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the boundary cannot be settled. The
    /// caller must then shut the lifecycle down.
    fn drain_final_events_for_retention(
        &mut self,
    ) -> Result<QemuFinalBoundaryDrain, SchedulerError> {
        Ok(QemuFinalBoundaryDrain::Ineligible(
            source_retention::RETENTION_UNSUPPORTED_OWNER,
        ))
    }

    /// Performs final drain, process reap, lease release, and aggregate release.
    ///
    /// Returned entries are the only scheduler observations produced during
    /// teardown and must be supplied to modeled result sealing.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when final drain or resource cleanup cannot
    /// be attested. The implementation must retain unfinished authority in
    /// quarantine on failure.
    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>;
}

impl QemuFreshAttemptLifecycleOwner for ProductionVmLifecycleLoop {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        ProductionVmLifecycleLoop::enable_signal_fault_campaign_promotion(self);
    }

    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        ProductionVmLifecycleLoop::set_attempt_stop_frontier(self, frontier)
    }

    fn set_live_network_choice_pause(&mut self, enabled: bool) {
        ProductionVmLifecycleLoop::set_live_network_choice_pause(self, enabled);
    }

    fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        ProductionVmLifecycleLoop::set_choice_free_parallel_boot(self, enabled);
    }

    fn live_network_preselection(&self) -> Option<crucible::LiveNetworkPreselection> {
        ProductionVmLifecycleLoop::live_network_preselection(self)
    }

    fn select_live_network_preselection(
        &mut self,
        selection: SelectionDecision,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        ProductionVmLifecycleLoop::select_live_network_preselection(self, selection)
    }

    fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        ProductionVmLifecycleLoop::settle_live_network_preselection(self)
    }

    fn handoff_live_network_preselection(
        &mut self,
        expected: &crucible::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        ProductionVmLifecycleLoop::handoff_live_network_preselection(self, expected)
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QuantumLoop::drive_quantum(self, request)
    }

    fn completed_quanta(&self) -> u64 {
        ProductionVmLifecycleLoop::completed_quanta(self)
    }

    fn event_log_offset(&self) -> Result<crucible::EventLogOffset, SchedulerError> {
        Ok(ProductionVmLifecycleLoop::event_log_offset(self))
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QuantumLoop::terminal_verdict_for_stop(self)
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        QuantumLoop::prepare_terminal_checkpoint(self, cause)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        ProductionVmLifecycleLoop::exact_checkpoint_ready(self)
    }

    fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        ProductionVmLifecycleLoop::parked_campaign_marker(self, node)
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        ProductionVmLifecycleLoop::release_parked_campaign_marker(self, node, marker, selected)
    }

    fn park_held_campaign_markers(
        &mut self,
        markers: &[&str],
        outcome: &mut QuantumOutcome,
    ) -> Result<usize, SchedulerError> {
        ProductionVmLifecycleLoop::park_held_campaign_markers(self, markers, outcome)
    }

    fn join_campaign_parks_to_frontier(&mut self) -> Result<Option<VirtualTime>, SchedulerError> {
        ProductionVmLifecycleLoop::join_campaign_parks_to_frontier(self)
    }

    fn append_network_fault_campaign_branch(
        &mut self,
        branch: &crucible::NetworkFaultCampaignBranch,
    ) -> Result<(Configuration, Vec<SchedulerEventLogEntry>), SchedulerError> {
        ProductionVmLifecycleLoop::append_network_fault_campaign_branch(self, branch)
    }

    fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        Ok(
            ProductionVmLifecycleLoop::campaign_marker_release_committed(
                self, node, marker, selected,
            ),
        )
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        ProductionVmLifecycleLoop::campaign_network_queues_empty(self)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        ProductionVmLifecycleLoop::drain_pending_selectable_requests(self)
    }

    fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        ProductionVmLifecycleLoop::pending_selectable_request_time(self, pending)
    }

    fn pending_selectable_request_is_committed_source(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<bool, SchedulerError> {
        ProductionVmLifecycleLoop::pending_selectable_request_is_committed_source(self, pending)
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        ProductionVmLifecycleLoop::apply_selectable_reply(
            self, parent, decision, selected, pending, reply,
        )
    }

    fn publish_released_host_outcomes(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<QuantumOutcome>, SchedulerError> {
        ProductionVmLifecycleLoop::publish_released_host_outcomes(self, configuration)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.capture_portable_exact_checkpoint_with_boundary(&mut || {
            if context.cancellation().is_canceled() {
                return Err(SchedulerError::OperationalBoundary {
                    class: SchedulerOperationalFailureClass::Canceled,
                    message: String::from("checkpoint capture canceled"),
                });
            }
            Ok(())
        })
        .map(CapturedAttemptCheckpoint::from_production_closure)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        ProductionVmLifecycleLoop::replay_launch_profiles(self).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("derive production replay launch profiles: {error}"),
            }
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        ProductionVmLifecycleLoop::fault_evidence_snapshot(self)
    }

    fn pending_network_output_count(&self) -> usize {
        ProductionVmLifecycleLoop::pending_network_output_count(self)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- this delegates a read-only fingerprint sample to the scheduler-owned lifecycle.
        QuantumLoop::sample_fingerprint(self, node)
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        ProductionVmLifecycleLoop::prepare_terminal_fingerprints(self)
    }

    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible::model::ResolvedEffectTrace>, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- this copies scheduler-retained replay evidence without feeding it into execution.
        QuantumLoop::resolved_effect_trace(self)
    }

    fn drain_final_events_for_retention(
        &mut self,
    ) -> Result<QemuFinalBoundaryDrain, SchedulerError> {
        Ok(
            match ProductionVmLifecycleLoop::drain_final_boundary_for_retention(self)? {
                RetentionDrain::Declined(refusal) => {
                    QemuFinalBoundaryDrain::Ineligible(refusal.token())
                }
                RetentionDrain::Settled(entries) if entries.is_empty() => {
                    QemuFinalBoundaryDrain::Retainable
                }
                RetentionDrain::Settled(entries) => QemuFinalBoundaryDrain::Drained(entries),
            },
        )
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- scheduler shutdown returns authoritative final evidence and does not synthesize modeled state.
        QuantumLoop::shutdown(self)
    }
}

mod source_retention;
pub use source_retention::QemuFinalBoundaryDrain;

mod anchor_root;
pub(crate) use anchor_root::{QemuAnchorRootMaterializer, QemuAnchorRootOutcome};
pub(crate) use source_retention::{
    QemuPublishedRootAdmission, QemuPublishedRootRetirementError, QemuPublishedRootSink,
    QemuPublishedRootState, QemuRetainedSourcePreparation,
};

mod evidence;
#[cfg(test)]
pub(crate) use evidence::QemuTerminalEvidenceExecutionRunnerError;
pub use evidence::{
    QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot,
    QemuObservedFreshAttemptLifecycleFactory, QemuObservedFreshAttemptLifecycleFactoryError,
};
pub(crate) use evidence::{
    QemuObservedFreshAttemptLifecycle, QemuTerminalEvidenceExecutionRunner,
    map_observed_evidence_failure, map_observed_inner_failure,
};

mod campaign_run;
#[cfg(any(test, feature = "test-support"))]
pub use campaign_run::GuardedCampaignRunRecorder;
#[cfg(any(test, feature = "test-support"))]
pub use campaign_run::test_support::{
    GuardedDefaultCampaignTestTrace, run_guarded_default_campaign_test_fixture,
    run_guarded_default_campaign_test_fixture_into_sink,
    run_guarded_default_campaign_test_fixture_with_choice_offer,
    run_guarded_default_campaign_test_fixture_with_trace,
    run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer,
};
pub use campaign_run::{
    DEFAULT_GUARDED_CAMPAIGN_MAX_CHOICES, DiscardGuardedCampaignProgress,
    GuardedCampaignBranchAcceptance, GuardedCampaignExploration,
    GuardedCampaignExplorationCompletion, GuardedCampaignExplorationStrategy,
    GuardedCampaignFindingExport, GuardedCampaignFindingExportFrame,
    GuardedCampaignFindingExportFrames, GuardedCampaignFindingExportReadError,
    GuardedCampaignFindingObjectProof, GuardedCampaignFindingOccurrenceObjectProof,
    GuardedCampaignFindingOccurrenceQueryProof, GuardedCampaignFindingOracle,
    GuardedCampaignFindingOracleError, GuardedCampaignFindingOracleEvaluation,
    GuardedCampaignFindingOracleSource, GuardedCampaignFindingOracleSourceLoadError,
    GuardedCampaignFindingQueryProof, GuardedCampaignFindingTriageReplaySegmentProof,
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError, GuardedCampaignRunSink,
    GuardedCampaignRunSinkError, GuardedCampaignSupplementalFinding,
    GuardedCampaignTimeoutEvidence, GuardedDefaultCampaignInvariantError,
    GuardedDefaultCampaignObservation, GuardedDefaultCampaignObservationSource,
    GuardedDefaultCampaignProductionRunnerError, GuardedDefaultCampaignResumeProof,
    GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError, GuardedDefaultCampaignRunRequest,
    GuardedDefaultCampaignSavepoint, GuardedDefaultCampaignSupervisorError,
    GuardedDefaultCampaignWatchFrame, run_guarded_default_campaign,
    run_guarded_default_campaign_with_sink, validate_remote_resume_replay_closure,
};
pub(crate) use campaign_run::{
    GuardedCampaignReplayChoices, GuardedCampaignReplaySelection, MAX_REPLAY_CLOSURE_FRAME_BYTES,
    MAX_REPLAY_CLOSURE_FRAMES, MAX_REPLAY_CLOSURE_ROOT_BYTES, REPLAY_CLOSURE_OBJECT_KIND,
    REPLAY_CLOSURE_OBJECT_SCHEMA_VERSION, closure_object_id,
};

/// Narrow modeled-execution view of one guarded fresh QEMU lifecycle.
///
/// This facade exposes bounded scheduler progress and read-only evidence but no
/// shutdown or raw node-launch authority. The runner therefore remains the
/// unique owner of final drain and resource release.
pub struct QemuFreshAttemptLifecycle<'a> {
    owner: &'a mut dyn QemuFreshAttemptLifecycleOwner,
}

impl QemuFreshAttemptLifecycle<'_> {
    pub(crate) fn new(
        owner: &mut dyn QemuFreshAttemptLifecycleOwner,
    ) -> QemuFreshAttemptLifecycle<'_> {
        QemuFreshAttemptLifecycle { owner }
    }

    /// Advances exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the guarded lifecycle rejects or cannot
    /// complete the quantum.
    pub fn drive_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.owner.drive_quantum(request)
    }

    /// Installs the exact nonterminal frontier for the current attempt.
    ///
    /// Passing `None` clears the prior attempt's frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the lifecycle cannot install the
    /// frontier without crossing its current scheduler boundary.
    pub fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.owner.set_attempt_stop_frontier(frontier)
    }

    /// Enables exact preselection pauses for the current choice-search attempt.
    pub fn set_live_network_choice_pause(&mut self, enabled: bool) {
        self.owner.set_live_network_choice_pause(enabled);
    }

    /// Enables concurrent execution through an audited choice-free boot epoch.
    pub fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        self.owner.set_choice_free_parallel_boot(enabled);
    }

    /// Returns the exact unresolved live-network choice, if present.
    #[must_use]
    pub fn live_network_preselection(&self) -> Option<crucible::LiveNetworkPreselection> {
        self.owner.live_network_preselection()
    }

    /// Commits a replayed live-network selection at its reserved boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the reservation or selection differs.
    pub fn select_live_network_preselection(
        &mut self,
        selection: SelectionDecision,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner.select_live_network_preselection(selection)
    }

    /// Resolves a reservation through its ordinary default decision.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the reservation cannot be settled.
    pub fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        self.owner.settle_live_network_preselection()
    }

    /// Hands the exact reservation to a NextChoice observation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the reservation does not match.
    pub fn handoff_live_network_preselection(
        &mut self,
        expected: &crucible::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        self.owner.handoff_live_network_preselection(expected)
    }

    /// Returns the absolute scheduler-quantum coordinate at the current boundary.
    #[must_use]
    pub fn completed_quanta(&self) -> u64 {
        self.owner.completed_quanta()
    }

    /// Observes the terminal verdict without consuming checkpoint ownership.
    #[must_use]
    pub fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.owner.terminal_verdict_for_stop()
    }

    /// Returns whether every live node can enter an exact checkpoint now.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live checkpoint boundary cannot be
    /// inspected consistently.
    pub fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.owner.exact_checkpoint_ready()
    }

    /// Reads the parked physical marker proof for one VM.
    ///
    /// # Errors
    ///
    /// Returns an error when the live proof cannot be authenticated.
    pub fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        self.owner.parked_campaign_marker(node)
    }

    /// Releases one parked VM after its network fault selection commits.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained park is absent or stale.
    pub fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        self.owner
            .release_parked_campaign_marker(node, marker, selected)
    }

    /// Parks held campaign markers named in `markers` and publishes their peers.
    ///
    /// # Errors
    ///
    /// Returns an error when a held marker lacks its physical park or peer
    /// publication fails.
    pub fn park_held_campaign_markers(
        &mut self,
        markers: &[&str],
        outcome: &mut QuantumOutcome,
    ) -> Result<usize, SchedulerError> {
        self.owner.park_held_campaign_markers(markers, outcome)
    }

    /// Joins every scheduler park to one frontier at a validated all-VM boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the scheduler rejects the join.
    pub fn join_campaign_parks_to_frontier(
        &mut self,
    ) -> Result<Option<VirtualTime>, SchedulerError> {
        self.owner.join_campaign_parks_to_frontier()
    }

    /// Authenticates a prior release of one selected physical marker park.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner cannot inspect its exact release ledger.
    pub fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        self.owner
            .campaign_marker_release_committed(node, marker, selected)
    }

    /// Reports whether network effect queues are empty at activation.
    ///
    /// # Errors
    ///
    /// Returns an error when queue state cannot be authenticated.
    pub fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        self.owner.campaign_network_queues_empty()
    }

    /// Captures read-only production fault evidence at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when retained production evidence cannot be
    /// inspected consistently.
    pub fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.owner.fault_evidence_snapshot()
    }

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    pub fn pending_network_output_count(&self) -> usize {
        self.owner.pending_network_output_count()
    }

    /// Samples one node's concrete execution fingerprint at the current boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the node is absent or its stopped state
    /// cannot be read consistently.
    pub fn sample_fingerprint(
        &mut self,
        node: NodeId,
    ) -> Result<FingerprintSample, SchedulerError> {
        self.owner.sample_fingerprint(node)
    }
}

/// Validated modeled control for one selected continuation boundary.
#[derive(Clone, Copy, Debug)]
pub struct QemuAttemptContinuation<'a> {
    input: &'a AttemptContinuationInput,
    source: &'a Configuration,
}

impl<'a> QemuAttemptContinuation<'a> {
    /// Returns the modeled control applied after the source boundary.
    #[must_use]
    pub const fn input(self) -> &'a AttemptContinuationInput {
        self.input
    }

    /// Returns the authenticated configuration at the source boundary.
    #[must_use]
    pub const fn source(self) -> &'a Configuration {
        self.source
    }
}

/// Factory for one guarded scenario-genesis lifecycle used by the campaign runner.
pub(crate) trait QemuFreshAttemptLifecycleFactory {
    /// Exact lifecycle owner created for one attempt.
    type Lifecycle: QemuFreshAttemptLifecycleOwner;
    /// Factory-specific admission or construction failure.
    type Error;

    /// Selects modeled continuation control for the next semantic attempt.
    ///
    /// The default rejects a present input. Supporting factories must retain
    /// the exact value and consume it before allocating guest resources.
    fn configure_attempt_continuation(
        &mut self,
        continuation: Option<QemuAttemptContinuation<'_>>,
    ) -> bool {
        continuation.is_none()
    }

    /// Selects every controlled continuation needed by one cold replay.
    ///
    /// The sequence is ordered from the oldest source boundary through the
    /// current attempt. Factories supporting only one generation retain their
    /// existing behavior through the default implementation.
    fn configure_attempt_continuations(
        &mut self,
        continuations: &[QemuAttemptContinuation<'_>],
    ) -> bool {
        match continuations {
            [] => self.configure_attempt_continuation(None),
            [continuation] => self.configure_attempt_continuation(Some(*continuation)),
            _ => false,
        }
    }

    /// Supplies the repository-authenticated producer for this fresh start.
    fn configure_authenticated_start(&mut self, _start: &CrucibleResolvedAttemptStart) {}

    /// Starts one scenario-genesis lifecycle under the admitted attempt context.
    ///
    /// # Errors
    ///
    /// Returns a classified failure for invalid semantic input, canceled or
    /// unavailable resource installation, or lifecycle construction failure.
    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>>;

    /// Prepares a drained lifecycle as a retained source at `boundary`.
    ///
    /// The lifecycle has settled its final boundary with no new entries, and
    /// `boundary` is the configuration it stopped at. Factories rebind the
    /// world to the configuration an exact resume at that boundary would use
    /// before preparation. Factories that cannot retain worlds return the
    /// lifecycle unchanged through the default.
    fn prepare_retained_source(
        &mut self,
        lifecycle: Self::Lifecycle,
        _source: &ScenarioDefForm,
        _boundary: &Configuration,
    ) -> QemuRetainedSourcePreparation<Self::Lifecycle> {
        QemuRetainedSourcePreparation::Recovered(lifecycle)
    }
}

/// Two-phase modeled driver for one guarded fresh production lifecycle.
///
/// [`Self::drive`] may advance and inspect the lifecycle but cannot shut it
/// down. [`Self::seal`] runs only after runner-owned shutdown, or a
/// non-destructive final drain proven empty at a paused boundary, has supplied
/// every final event-log entry, preventing a candidate from being accepted at
/// a pre-teardown observable boundary.
pub trait QemuFreshAttemptDriver {
    /// Driver state retained between modeled stop and final shutdown drain.
    type Pending;
    /// Driver-specific modeled or result-construction failure.
    type Error: std::fmt::Display;

    /// Borrows the modeled stop's exact choice closure and terminal event count.
    ///
    /// Drivers without a durable terminal boundary leave auxiliary finding
    /// capture unavailable; the semantic observation still seals normally.
    fn terminal_checkpoint_choices(
        &self,
        _pending: &Self::Pending,
    ) -> Option<(QemuCheckpointChoiceProvenance, u64)> {
        None
    }

    /// Returns the configuration and replay proof of a retainable modeled stop.
    ///
    /// A retainable stop pauses a continuing run at a published next-choice
    /// boundary with discovered choices, no live-network preselection, and no
    /// terminal verdict, so the runner may keep its stopped world as a
    /// reusable source. Drivers without that projection use the default.
    ///
    /// # Errors
    ///
    /// Returns the stable kebab-case token of the first refused condition
    /// when the stop is not retainable.
    fn retention_boundary(
        &self,
        _pending: &Self::Pending,
    ) -> Result<(Configuration, QemuSavepointReplayProof), &'static str> {
        Err("driver-has-no-retention-projection")
    }

    /// Checks whether the pending modeled stop has a declared property failure.
    ///
    /// Drivers without an authenticated offline property projection leave
    /// property-derived terminal capture unavailable.
    ///
    /// # Errors
    ///
    /// Returns a driver error when the retained event prefix cannot be checked.
    fn has_terminal_assertion_failure(
        &self,
        _pending: &Self::Pending,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Drives the lifecycle to a modeled stop without returning an accepted product.
    ///
    /// `materialization` contains the bounded event history, terminal state,
    /// and quiescence reconstructed while the runner reached `input`'s exact
    /// start. The driver must preserve that history when evaluating or sealing
    /// cumulative modeled evidence. Event-relative stops begin at the admitted
    /// start; absolute virtual-time and scheduler-quantum coordinates may
    /// already be satisfied by the authenticated replay prefix.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal modeled failure.
    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>>;

    /// Seals one product after final lifecycle drain and resource cleanup.
    ///
    /// `final_events` is the complete dense suffix produced during shutdown.
    /// A conforming observation builder must incorporate it into the canonical
    /// evidence or reject the result.
    ///
    /// # Errors
    ///
    /// Returns a classified failure when the drained events cannot be projected
    /// into the exact modeled result.
    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>;

    /// Seals a product with the exact runtime effect trace when the driver owns it.
    ///
    /// Drivers without fault evidence retain their existing seal behavior.
    ///
    /// # Errors
    ///
    /// Returns the same classified failure as [`Self::seal`] when final drain
    /// cannot be incorporated into the modeled result.
    fn seal_with_trace(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
        _resolved_effect_trace: Option<crucible::model::ResolvedEffectTrace>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.seal(pending, final_events)
    }
}

/// Runner-owned disposition after modeled fresh-attempt driving.
#[derive(Debug)]
pub enum QemuFreshDriveOutcome<P> {
    /// A modeled stop was reached and awaits final-drain sealing.
    Observation(P),
    /// The sticky checkpoint request reached an exact capture-ready boundary.
    CheckpointRequested(QemuCheckpointChoiceProvenance),
}

mod checkpoint_provenance;
pub use checkpoint_provenance::QemuCheckpointChoiceProvenance;

/// Fresh-QEMU campaign runner with exact prefix replay and runner-owned teardown.
///
/// The runner reconstructs an admitted selection-free or standardized
/// model-sampled schedule from scenario genesis before lending the lifecycle to
/// its modeled driver. Producer-owned overrides remain rejected before resource
/// installation until their versioned live injection protocol is available.
pub(crate) struct QemuFreshExecutionRunner<F, D> {
    lifecycles: F,
    driver: D,
    finding_replay_capture:
        Option<crate::automatic_finding_runner::QemuFindingReplayCaptureProducer>,
    terminal_exact_retention:
        Option<Arc<dyn crate::automatic_finding_runner::FindingExactRetentionSource>>,
    published_root_retention: Option<Arc<dyn QemuPublishedRootSink>>,
    pending_retention: Option<source_retention::QemuPendingPublishedRoot>,
}

/// Stable reasons an exact finding candidate cannot be reconstructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuFindingCandidateIncompatibility {
    PrefixDiverged,
    PrefixTerminated,
    SelectionMismatch,
}

/// Result of one private exact finding-candidate replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QemuFindingCandidateReplayOutcome {
    Observed(Box<crate::qemu_campaign_driver::QemuFindingCandidateBoundaryEvidence>),
    DeterministicallyIncompatible(QemuFindingCandidateIncompatibility),
}

type QemuFindingCandidateReplayFailure<LifecycleError> = Box<
    AttemptWorkerFailure<
        QemuFreshExecutionRunnerError<LifecycleError, crate::QemuFreshModeledDriverError>,
    >,
>;

impl<F, D> QemuFreshExecutionRunner<F, D> {
    /// Creates a genesis-start runner from its guarded lifecycle factory and modeled driver.
    #[must_use]
    pub const fn new(lifecycles: F, driver: D) -> Self {
        Self {
            lifecycles,
            driver,
            finding_replay_capture: None,
            terminal_exact_retention: None,
            published_root_retention: None,
            pending_retention: None,
        }
    }

    pub(crate) fn with_finding_replay_capture(
        mut self,
        producer: crate::automatic_finding_runner::QemuFindingReplayCaptureProducer,
    ) -> Self {
        self.finding_replay_capture = Some(producer);
        self
    }

    pub(crate) fn with_terminal_exact_retention_source(
        mut self,
        source: Arc<dyn crate::automatic_finding_runner::FindingExactRetentionSource>,
    ) -> Self {
        self.terminal_exact_retention = Some(source);
        self
    }

    pub(crate) fn finding_replay_capture_mut(
        &mut self,
    ) -> Option<&mut crate::automatic_finding_runner::QemuFindingReplayCaptureProducer> {
        self.finding_replay_capture.as_mut()
    }

    /// Reconstructs and evaluates one exact candidate without publishing an observation.
    pub(crate) fn replay_finding_candidate_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        expected_replay: Option<&crate::qemu_campaign_driver::QemuFindingCandidateBoundaryEvidence>,
        context: &AttemptExecutionContext,
    ) -> Result<QemuFindingCandidateReplayOutcome, QemuFindingCandidateReplayFailure<F::Error>>
    where
        F: QemuFreshAttemptLifecycleFactory,
        D: crate::qemu_campaign_driver::QemuFindingReplayDriver,
    {
        let validated_continuations = validated_attempt_continuations(input).map_err(|()| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
        })?;
        let continuations = validated_continuations.controls();
        if !self
            .lifecycles
            .configure_attempt_continuations(&continuations)
        {
            return Err(Box::new(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ContinuationInputUnsupported,
            )));
        }
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(Box::new(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(checkpoint),
            )));
        }

        let scenario = input.scenario().scenario_def();
        let CrucibleResolvedAttemptStart::Discover {
            configuration: target,
        } = input.start()
        else {
            return Err(Box::new(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::FindingCandidateStartUnsupported,
            )));
        };
        let signal_fault_replay = input.signal_fault_replay();
        let scenario_artifact = encode_crucible_scenario_artifact(input.scenario())
            .map_err(|error| crate::QemuFreshModeledDriverError::Artifact(Box::new(error)))
            .map_err(AttemptWorkerFailure::Terminal)
            .map_err(map_fresh_driver_failure)?;
        let encoded_candidate =
            encode_crucible_configuration_artifact(&scenario_artifact, &target.schedule)
                .map_err(|error| crate::QemuFreshModeledDriverError::Artifact(Box::new(error)))
                .map_err(AttemptWorkerFailure::Terminal)
                .map_err(map_fresh_driver_failure)?;
        if encoded_candidate != *candidate {
            return Err(Box::new(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::Driver(
                    crate::QemuFreshModeledDriverError::Artifact(Box::new(
                        crate::CrucibleArtifactError::SemanticIdentityMismatch {
                            artifact: "finding replay candidate configuration",
                        },
                    )),
                ),
            )));
        }
        if let Some(decision) = unsupported_fresh_replay_decision(target, signal_fault_replay) {
            return Err(Box::new(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                    configuration: target.id(),
                    decision,
                },
            )));
        }

        self.lifecycles.configure_authenticated_start(input.start());
        let mut lifecycle = self
            .lifecycles
            .start_fresh_lifecycle(
                &scenario,
                input.scenario(),
                target,
                signal_fault_replay,
                context,
            )
            .map_err(map_fresh_lifecycle_failure)?;
        let materialization = materialize_fresh_start(&mut lifecycle, input, target, context, true)
            .map_err(Box::new)
            .and_then(|materialization| {
                replay_selected_origins(&mut lifecycle, input, context, materialization)
                    .map_err(Box::new)
            });

        // Matching the candidate schedule reconstructs the attempt start;
        // the failure may occur later, at the original declared stop.
        let pending = materialization.and_then(|materialization| {
            let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
            let outcome = crate::qemu_campaign_driver::drive_modeled_attempt(
                &mut facade,
                input,
                context,
                materialization,
            )
            .map_err(map_fresh_driver_failure)
            .map_err(Box::new)?;
            match outcome {
                QemuFreshDriveOutcome::Observation(pending) => Ok(pending),
                QemuFreshDriveOutcome::CheckpointRequested(_) => {
                    Err(Box::new(AttemptWorkerFailure::Terminal(
                        QemuFreshExecutionRunnerError::UnsolicitedCheckpoint,
                    )))
                }
            }
        });
        let pending = pending.and_then(|pending| {
            lifecycle
                .prepare_terminal_fingerprints()
                .map(|()| pending)
                .map_err(map_terminal_fingerprint_capture_failure)
                .map_err(Box::new)
        });
        let cleanup = lifecycle.shutdown();

        let (pending, final_events) = match (pending, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_)) => {
                if let Some(reason) = finding_candidate_incompatibility(&failure) {
                    return Ok(
                        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(reason),
                    );
                }
                return Err(failure);
            }
            (Ok(_), Err(cleanup)) => {
                return Err(Box::new(AttemptWorkerFailure::Terminal(
                    QemuFreshExecutionRunnerError::Cleanup(cleanup),
                )));
            }
            (Err(failure), Err(cleanup)) => {
                return Err(Box::new(AttemptWorkerFailure::Terminal(
                    cleanup_after_fresh_runner_failure(*failure, cleanup),
                )));
            }
        };
        let evidence = match self.driver.build_finding_candidate_boundary_evidence(
            pending,
            candidate,
            final_events,
        ) {
            Ok(evidence) => evidence,
            Err(crate::QemuFreshModeledDriverError::FindingCandidateSelectionContinued) => {
                return Ok(
                    QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
                        QemuFindingCandidateIncompatibility::SelectionMismatch,
                    ),
                );
            }
            Err(error) => {
                return Err(Box::new(map_fresh_driver_failure(
                    AttemptWorkerFailure::Terminal(error),
                )));
            }
        };
        let evidence = match expected_replay {
            Some(expected) => {
                evidence
                    .compare_against_expected_replay(expected)
                    .map_err(|error| {
                        Box::new(map_fresh_driver_failure(AttemptWorkerFailure::Terminal(
                            error,
                        )))
                    })?
            }
            None => evidence,
        };
        Ok(QemuFindingCandidateReplayOutcome::Observed(Box::new(
            evidence,
        )))
    }
}

fn finding_candidate_incompatibility<F, D>(
    failure: &AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
) -> Option<QemuFindingCandidateIncompatibility> {
    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(error)) = failure
    else {
        return None;
    };
    match error {
        QemuFreshStartReplayError::Diverged | QemuFreshStartReplayError::DivergedAt { .. } => {
            Some(QemuFindingCandidateIncompatibility::PrefixDiverged)
        }
        QemuFreshStartReplayError::Terminated => {
            Some(QemuFindingCandidateIncompatibility::PrefixTerminated)
        }
        QemuFreshStartReplayError::GuestSelectable(GuestSelectableError::ReplayMismatch(_)) => {
            Some(QemuFindingCandidateIncompatibility::SelectionMismatch)
        }
        _ => None,
    }
}

/// Failure from one phase of the private `QemuFreshExecutionRunner`.
#[derive(Debug, Error)]
pub enum QemuFreshExecutionRunnerError<F, D> {
    /// The modeled continuation input does not name its authenticated time boundary.
    #[error("fresh production QEMU runner received invalid modeled continuation input")]
    InvalidContinuationInput,
    /// The lifecycle factory cannot consume this attempt's modeled continuation input.
    #[error("fresh production QEMU runner does not support modeled continuation input")]
    ContinuationInputUnsupported,
    /// The fresh runner was asked to execute a durable resume incarnation.
    #[error("fresh production QEMU runner cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(ExactCheckpointId),
    /// Private finding replay received a branch edge or selected continuation input.
    #[error("finding candidate replay requires a resolved discovery start")]
    FindingCandidateStartUnsupported,
    /// The target contains a producer-owned override with no live injection path.
    #[error(
        "fresh production QEMU runner cannot inject decision {decision} of configuration `{configuration:?}`"
    )]
    StartDecisionUnsupported {
        /// Exact target configuration.
        configuration: crucible::ContentHash,
        /// Zero-based unsupported schedule position.
        decision: usize,
    },
    /// Exact replay from scenario genesis failed.
    #[error("fresh production QEMU start replay failed: {0}")]
    StartReplay(#[source] QemuFreshStartReplayError),
    /// Guarded lifecycle admission or construction failed.
    #[error("fresh production QEMU lifecycle construction failed")]
    Lifecycle(#[source] F),
    /// Modeled driving or post-shutdown result sealing failed.
    #[error("fresh production QEMU attempt driver failed")]
    Driver(#[source] D),
    /// Final drain, process reap, or resource release failed.
    #[error("fresh production QEMU lifecycle cleanup failed: {0}")]
    Cleanup(#[source] SchedulerError),
    /// Complete production checkpoint capture failed at a safe boundary.
    #[error("fresh production QEMU checkpoint capture failed: {0}")]
    CheckpointCapture(#[source] SchedulerError),
    /// Exact terminal execution fingerprint capture failed before teardown.
    #[error("fresh production QEMU terminal fingerprint capture failed: {0}")]
    TerminalFingerprintCapture(#[source] SchedulerError),
    /// The live runtime could not provide its canonical resolved-effect trace.
    #[error("fresh production QEMU resolved-effect trace capture failed: {0}")]
    ResolvedEffectTraceCapture(#[source] SchedulerError),
    /// Producer-side replay content failed authentication or bounded capture.
    #[error("capture private finding production replay: {0}")]
    FindingReplayCapture(#[source] crate::FindingProductionReplayCaptureError),
    /// Completed process-local replay evidence could not be read.
    #[error("read private finding production replay evidence: {0}")]
    FindingReplayEvidence(#[source] SchedulerError),
    /// The prepared exact root could not be handed to the durable supervisor phase.
    #[error("fresh production QEMU checkpoint handoff failed: {0}")]
    CheckpointHandoff(#[source] CheckpointHandoffFailure),
    /// A modeled driver requested capture without the supervisor's sticky signal.
    #[error("fresh production QEMU driver returned an unsolicited checkpoint request")]
    UnsolicitedCheckpoint,
    /// Capture mode reached the runner without its supervisor-prelatched request.
    #[error("materialized-start capture did not carry a prelatched checkpoint request")]
    CaptureCheckpointNotRequested,
    /// The exact materialized start was not safe for checkpoint capture.
    #[error("materialized-start capture was not checkpoint ready")]
    CaptureStartNotCheckpointReady,
    /// A retained thin-attempt world awaits its prior durable disposition.
    #[error("fresh production QEMU runner still retains a prior attempt's world")]
    PriorRetentionPending,
    /// A retained thin-attempt world could not be released completely.
    #[error("release retained published-root source: {0}")]
    PublishedRootRetention(String),
    /// Cleanup failed after the driver had already returned a failure.
    #[error(
        "fresh production QEMU driver failed: {}; cleanup also failed: {cleanup}",
        driver_diagnostic
    )]
    CleanupAfterDriver {
        /// Original driver failure retained for diagnosis.
        driver: D,
        /// Bounded text from the original failure, captured before cleanup reporting.
        driver_diagnostic: String,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
    /// Cleanup failed after start replay or another runner-owned phase failed.
    // The retained error is recursive, so Debug exposes it without a cyclic Display bound.
    #[error(
        "fresh production QEMU lifecycle cleanup failed after a prior runner failure: {cleanup}; original runner failure: {failure:?}"
    )]
    CleanupAfterRunner {
        /// Original runner failure retained for diagnosis.
        failure: Box<QemuFreshExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
}

// Keep the first cause visible without copying unbounded guest-origin text into logs.
fn bounded_driver_failure(driver: &impl std::fmt::Display) -> String {
    use std::fmt::Write;

    const MAX_BYTES: usize = 512;

    struct BoundedMessage {
        text: String,
        truncated: bool,
    }

    impl std::fmt::Write for BoundedMessage {
        fn write_str(&mut self, part: &str) -> std::fmt::Result {
            let remaining = MAX_BYTES.saturating_sub(self.text.len());
            if part.len() <= remaining {
                self.text.push_str(part);
                return Ok(());
            }

            let mut end = remaining;
            while !part.is_char_boundary(end) {
                end -= 1;
            }
            self.text.push_str(&part[..end]);
            self.truncated = true;
            Err(std::fmt::Error)
        }
    }

    let mut message = BoundedMessage {
        text: String::new(),
        truncated: false,
    };
    let _ = write!(&mut message, "{driver}");
    if message.truncated {
        message.text.push_str("[truncated]");
    }
    message.text
}

/// Bounded history reconstructed before one fresh attempt begins.
#[derive(Debug)]
pub struct QemuFreshStartMaterialization {
    restored_configuration: Option<Configuration>,
    event_log: RetainedAttemptLog,
    completed_quanta: u64,
    frontier: crucible::VirtualTime,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    attempt_event_count: usize,
    replayed_discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    replayed_discovery_bytes: usize,
    retain_replayed_discoveries: bool,
    /// Recorded network fault branch parent at which replay stops early.
    ///
    /// Replay that reaches this configuration with every VM parked and joined
    /// returns before appending the branch, leaving the boundary for anchor
    /// retention. It is cleared once reached.
    anchor_stop: Option<crucible::ContentHash>,
    /// Whether this replay stopped at its anchor instead of its target.
    anchor_reached: bool,
}

impl QemuFreshStartMaterialization {
    #[cfg(test)]
    pub(crate) fn genesis() -> Self {
        Self::at_quanta(0)
    }

    pub(crate) fn at_quanta(completed_quanta: u64) -> Self {
        Self {
            restored_configuration: None,
            event_log: RetainedAttemptLog::new(DEFAULT_MAXIMUM_EVENT_LOG_BYTES),
            completed_quanta,
            frontier: crucible::VirtualTime::default(),
            terminal_quiescence: None,
            terminal_verdict: None,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
            anchor_stop: None,
            anchor_reached: false,
        }
    }

    pub(crate) const fn attempt_event_count(&self) -> usize {
        self.attempt_event_count
    }

    pub(crate) const fn with_attempt_event_count(mut self, event_count: usize) -> Self {
        self.attempt_event_count = event_count;
        self
    }

    /// Stops replay at `parent`, the parent of a recorded network fault branch.
    ///
    /// When replay reaches `parent` with every VM parked and the parks joined
    /// to the recorded frontier, it returns before appending the branch or
    /// releasing any VM. The scheduler then holds exactly the boundary every
    /// descendant's thin replay crosses, which anchor retention may keep.
    #[must_use]
    pub(crate) const fn with_anchor_stop(mut self, parent: crucible::ContentHash) -> Self {
        self.anchor_stop = Some(parent);
        self.anchor_reached = false;
        self
    }

    /// Returns whether replay stopped at its anchor instead of its target.
    ///
    /// The restored configuration then names the anchor, and the frontier is
    /// the joined park frontier.
    #[must_use]
    pub(crate) const fn anchor_reached(&self) -> bool {
        self.anchor_reached
    }

    /// Records that replay stopped at its anchor with parks joined at `frontier`.
    fn stop_at_anchor(&mut self, frontier: crucible::VirtualTime) {
        self.anchor_stop = None;
        self.anchor_reached = true;
        self.frontier = frontier;
    }

    /// Returns whether `current` is the anchor this replay must stop at.
    fn stops_at_anchor(&self, current: &Configuration) -> bool {
        self.anchor_stop == Some(current.id())
    }

    fn retain_replayed_discovery(
        &mut self,
        discovery: ChoiceDiscovery,
    ) -> Result<(), GuestSelectableError> {
        if !self.retain_replayed_discoveries {
            return Ok(());
        }
        let opportunity = discovery.opportunity().id()?;
        if let Some(existing) = self.replayed_discoveries.get(&opportunity) {
            if existing.opportunity() == discovery.opportunity() {
                return Ok(());
            }
            return Err(GuestSelectableError::Campaign(
                crucible_campaign::CampaignCodecError::InvalidValue {
                    reason: "replayed guest selectable changed an existing opportunity",
                },
            ));
        }
        let bytes = discovery
            .declaration()
            .canonical_bytes()
            .len()
            .checked_add(discovery.domain().canonical_bytes().len())
            .and_then(|bytes| bytes.checked_add(discovery.opportunity().canonical_bytes().len()))
            .and_then(|bytes| self.replayed_discovery_bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES)
            .ok_or(GuestSelectableError::Campaign(
                crucible_campaign::CampaignCodecError::LimitExceeded {
                    limit: "finding-replay-choice-discovery-bytes",
                },
            ))?;
        self.replayed_discovery_bytes = bytes;
        self.replayed_discoveries.insert(opportunity, discovery);
        Ok(())
    }

    /// Consumes the materialization into cumulative replay evidence and state.
    ///
    /// `frontier`, `terminal_quiescence`, and `terminal_verdict` describe the
    /// exact admitted start after replay, not a later attempt quantum.
    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        RetainedAttemptLog,
        u64,
        crucible::VirtualTime,
        Option<SchedulerQuiescence>,
        Option<QuantumTerminalVerdict>,
    ) {
        (
            self.event_log,
            self.completed_quanta,
            self.frontier,
            self.terminal_quiescence,
            self.terminal_verdict,
        )
    }

    /// Moves bounded prefix discoveries into the modeled attempt driver.
    pub(crate) fn take_replayed_discoveries(
        &mut self,
    ) -> BTreeMap<ChoiceOpportunityId, ChoiceDiscovery> {
        std::mem::take(&mut self.replayed_discoveries)
    }

    pub(crate) fn from_resume_parts(
        restored_configuration: Configuration,
        event_log: RetainedAttemptLog,
        completed_quanta: u64,
        frontier: crucible::VirtualTime,
        terminal_quiescence: SchedulerQuiescence,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            restored_configuration: Some(restored_configuration),
            event_log,
            completed_quanta,
            frontier,
            terminal_quiescence: Some(terminal_quiescence),
            terminal_verdict,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
            anchor_stop: None,
            anchor_reached: false,
        }
    }

    /// Carries one verified origin stop into the next continuation segment.
    pub(crate) fn from_origin_parts(
        event_log: RetainedAttemptLog,
        completed_quanta: u64,
        frontier: crucible::VirtualTime,
        terminal_quiescence: Option<SchedulerQuiescence>,
    ) -> Self {
        Self {
            restored_configuration: None,
            event_log,
            completed_quanta,
            frontier,
            terminal_quiescence,
            terminal_verdict: None,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
            anchor_stop: None,
            anchor_reached: false,
        }
    }

    fn selected_origin_proof(
        &self,
        configuration: &Configuration,
    ) -> Result<QemuSavepointReplayProof, crate::QemuFreshModeledDriverError> {
        QemuSavepointReplayProof::from_retained_boundary(
            configuration,
            self.completed_quanta,
            self.frontier,
            &self.event_log,
        )
        .and_then(|proof| proof.with_attempt_event_count(self.attempt_event_count))
    }

    fn attempt_start_proof(
        &self,
        configuration: &Configuration,
    ) -> Result<QemuAttemptStartReplayProof, crate::QemuFreshModeledDriverError> {
        QemuAttemptStartReplayProof::from_retained_boundary(configuration, &self.event_log)
    }

    /// Returns the scheduler configuration after restoration and authenticated start replay.
    #[must_use]
    pub(crate) const fn restored_configuration(&self) -> Option<&Configuration> {
        self.restored_configuration.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        event_log: RetainedAttemptLog,
        frontier: crucible::VirtualTime,
        terminal_quiescence: Option<SchedulerQuiescence>,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            restored_configuration: None,
            event_log,
            completed_quanta: 0,
            frontier,
            terminal_quiescence,
            terminal_verdict,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
            anchor_stop: None,
            anchor_reached: false,
        }
    }
}

/// A stable hot-fork refusal token and, when a check failed to run, its error.
///
/// Diagnostic rows render it as `reason=<token>` followed by
/// ` detail="<error>"` only when the error exists, so rows for ordinary
/// refusals and admissions keep their exact shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HotForkRefusal {
    reason: &'static str,
    detail: Option<String>,
}

impl HotForkRefusal {
    /// Longest error text one diagnostic row carries.
    const DETAIL_CHARS: usize = 1024;

    /// Pairs a refusal token with the error that produced it.
    pub(crate) fn with_detail(reason: &'static str, detail: impl std::fmt::Display) -> Self {
        Self {
            reason,
            detail: Some(
                detail
                    .to_string()
                    .chars()
                    .take(Self::DETAIL_CHARS)
                    .collect(),
            ),
        }
    }

    /// Returns the stable refusal token.
    pub(crate) const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Returns the error text of a check that failed to run, if any.
    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl From<&'static str> for HotForkRefusal {
    fn from(reason: &'static str) -> Self {
        Self {
            reason,
            detail: None,
        }
    }
}

impl std::fmt::Display for HotForkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reason={}", self.reason)?;
        if let Some(detail) = &self.detail {
            write!(f, " detail={detail:?}")?;
        }
        Ok(())
    }
}

/// Refuses an exact event-log offset, for test lifecycles without a scheduler.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn refuse_event_log_offset() -> Result<crucible::EventLogOffset, SchedulerError> {
    Err(SchedulerError::BoundaryViolation {
        message: String::from("lifecycle has no exact event-log offset"),
    })
}

/// Failure while reconstructing one exact fresh-QEMU start configuration.
#[derive(Debug, Error)]
pub enum QemuFreshStartReplayError {
    /// The attempt was canceled before its start configuration was reached.
    #[error("fresh start replay was canceled")]
    Canceled,
    /// The lifecycle scheduler rejected one replay quantum.
    #[error("fresh start replay scheduler failed: {0}")]
    Scheduler(#[source] SchedulerError),
    /// A paused guest selectable did not match the exact replay decision.
    #[error("fresh start replay guest selectable failed: {0}")]
    GuestSelectable(#[source] GuestSelectableError),
    /// Replay produced a schedule outside the exact requested prefix.
    #[error("fresh start replay diverged from the requested schedule")]
    Diverged,
    /// Replay names the first decision or progress condition that differed.
    #[error(
        "fresh start replay diverged at decision {index} ({reason}): expected {expected}; observed {observed}"
    )]
    DivergedAt {
        /// Stable classification of the failed replay condition.
        reason: &'static str,
        /// Zero-based decision position where replay stopped matching.
        index: usize,
        /// Bounded description of the requested decision or progress.
        expected: String,
        /// Bounded description of the live decision or progress.
        observed: String,
    },
    /// The scenario stopped before reaching the requested configuration.
    #[error("fresh start replay reached a terminal verdict before the requested configuration")]
    Terminated,
    /// The lifecycle does not stand at the configuration replay starts from.
    #[error("fresh start replay starts at {expected}, but the lifecycle stands at {observed}")]
    SourceMismatch {
        /// The configuration replay was asked to start from.
        expected: String,
        /// The configuration the lifecycle's materialization stands at.
        observed: String,
    },
    /// One selected origin attempt failed modeled replay validation.
    #[error("selected continuation origin replay failed")]
    Origin(#[source] Box<crate::QemuFreshModeledDriverError>),
    /// The independently replayed attempt-start evidence could not be represented.
    #[error("ordinary attempt-start replay proof construction failed")]
    AttemptStartProof(#[source] Box<crate::QemuFreshModeledDriverError>),
    /// Origin verification was requested for an ordinary discovery or branch start.
    #[error("selected continuation origin verification received no origin chain")]
    OriginMissing,
    /// Attempt-start verification was requested for a selected continuation.
    #[error("ordinary attempt-start verification received a selected continuation")]
    OrdinaryStartMissing,
    /// Origin replay attempted an operational checkpoint before the continuation boundary.
    #[error("selected continuation origin replay requested an operational checkpoint")]
    OriginUnexpectedCheckpoint,
    /// Origin replay stopped at a configuration different from the claimed boundary.
    #[error("selected continuation origin replay reached a different configuration")]
    OriginReachedMismatch,
    /// An earlier origin could not be rebuilt from the decoded terminal origin.
    #[error("selected continuation origin materialization failed: {0}")]
    OriginMaterialization(#[source] crate::crucible_execution::CrucibleOriginMaterializationError),
    /// Replay exhausted the attempt's admitted execution-quanta ceiling.
    #[error("fresh start replay exhausted the admitted execution-quanta ceiling")]
    QuantumLimit,
    /// Physical replay work exhausted the execution-wide quantum reservation.
    #[error("fresh start replay resource refusal: {0}")]
    ResourceRefusal(#[source] crate::executor_worker::ExecutionQuantumBudgetError),
    /// The scheduler's authoritative absolute quantum coordinate moved backward.
    #[error("fresh start replay scheduler quantum coordinate regressed from {before} to {after}")]
    QuantumCounterRegressed {
        /// Coordinate before the replay operation.
        before: u64,
        /// Coordinate after the replay operation.
        after: u64,
    },
    /// The retained materialization and live scheduler name different quantum coordinates.
    #[error(
        "fresh start materialization quantum coordinate {materialized} differs from live scheduler coordinate {authoritative}"
    )]
    QuantumCoordinateMismatch {
        /// Coordinate carried by the retained start materialization.
        materialized: u64,
        /// Coordinate reported by the live scheduler lifecycle.
        authoritative: u64,
    },
    /// The replayed start log refused an entry or could not read a segment.
    #[error("fresh start replay event log failed: {0}")]
    EventLog(#[source] Box<crate::QemuFreshModeledDriverError>),
    /// Replayed event history exceeded the observation projection bound.
    #[error("fresh start replay exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
    },
    /// A replay quantum's event history exceeded the observation projection bound.
    ///
    /// The progress fields distinguish a prefix that genuinely outgrows the
    /// bound from a replay that stopped advancing its schedule toward the
    /// requested configuration while quanta kept running.
    #[error(
        "fresh start replay exceeded `{limit}` at quanta {completed_quanta} with {retained_entries} retained entries ({retained_bytes} bytes) and schedule {schedule_len} of {target_schedule_len}"
    )]
    EventLogLimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
        /// Entries retained when the bound was reached.
        retained_entries: usize,
        /// Encoded log bytes retained when the bound was reached.
        retained_bytes: u64,
        /// Absolute quantum coordinate of the rejected quantum.
        completed_quanta: u64,
        /// Decisions replayed through the rejected quantum.
        schedule_len: usize,
        /// Decisions in the requested start configuration.
        target_schedule_len: usize,
    },
}

fn replay_decision_detail(decision: Option<&Decision>) -> String {
    const MAX_CHARS: usize = 512;

    let detail = match decision {
        Some(decision) => format!("{decision:?}"),
        None => String::from("<none>"),
    };
    let mut chars = detail.chars();
    let bounded: String = chars.by_ref().take(MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else {
        bounded
    }
}

/// Summarizes the decisions within eight entries of `index`, one per entry.
///
/// Each entry is `position:kind` with the fields that order it: a delivery
/// order's time and its consumer/producer/sequence keys, or a draw's stream
/// name. Values are omitted; a reordering shows as the same entries at
/// different positions.
fn replay_decision_window(
    history: &crucible::History<Decision>,
    index: usize,
    length: usize,
) -> String {
    const RADIUS: usize = 8;

    let start = index.saturating_sub(RADIUS);
    let end = index.saturating_add(RADIUS).min(length);
    (start..end)
        .filter_map(|position| history.get(position).map(|decision| (position, decision)))
        .map(|(position, decision)| {
            let summary = match decision {
                Decision::DeliveryOrder(order) => {
                    let keys = order
                        .order
                        .iter()
                        .map(|key| {
                            format!(
                                "{}<-{}#{}",
                                key.consumer.node.name,
                                key.producer.node.name.chars().take(14).collect::<String>(),
                                key.sequence
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("+");
                    format!("order@{}:{keys}", order.at.ticks)
                }
                Decision::RngDraw(draw) => {
                    format!("rng:{}", draw.stream.name.replace('\n', ";"))
                }
                Decision::Override(_) => String::from("override"),
                Decision::Preemption(_) => String::from("preemption"),
                Decision::Selection(_) => String::from("selection"),
            };
            format!("{position}:{summary}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Copy)]
struct GuestSelectableReplayContext<'a> {
    phase: GuestSelectableReplayPhase,
    attempt_role: GuestSelectableReplayAttemptRole,
    attempt: &'a crucible_campaign::Attempt,
    start: &'a CrucibleResolvedAttemptStart,
    scenario: crucible_campaign::ScenarioDefId,
    source: &'a ScenarioDefForm,
    target: &'a Configuration,
}

mod genesis_checkpoint;
pub(crate) use genesis_checkpoint::capture_fresh_genesis_checkpoint_candidate;
pub use genesis_checkpoint::{
    QemuFreshGenesisCheckpointCandidate, QemuFreshGenesisCheckpointCaptureFailure,
    QemuFreshGenesisCheckpointError,
};

enum QemuFreshRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R> {
    /// Creates a factory from trusted lifecycle configuration and host resources.
    #[must_use]
    pub const fn new(config: ProductionVmLifecycleConfig, resources: R) -> Self {
        Self {
            config,
            resources,
            terminal_checkpoints: None,
            continuations: Vec::new(),
            authenticated_network_selections: Vec::new(),
        }
    }

    /// Selects the campaign store for recoverable terminal checkpoint imports.
    #[must_use]
    pub(crate) fn with_terminal_checkpoints(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        self.terminal_checkpoints = Some(checkpoints);
        self
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn begin_fresh(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        self.begin_fresh_with_config(scenario, source, context, self.config.clone())
    }

    /// Builds one resumed lifecycle from an exact promoted version-nine root.
    ///
    /// The campaign root is installed and completely authenticated before the
    /// attempt process guard exists. Only a closure whose every live snapshot
    /// carries source-bound matching replay evidence reaches the guarded
    /// multi-node launcher. Missing or invalid roots never fall back to fresh
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAttemptProductionVmLifecycleError`] when the context/root
    /// basis, scenario, branch prefix, replay evidence, resource contract, or
    /// guarded lifecycle construction is invalid or unavailable.
    pub fn begin_resume(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        validate_exact_resume_request(checkpoint, basis, context)?;
        let QemuExactResumeBasis {
            scenario,
            source,
            initial,
            post_selection,
        } = basis;

        let maximum_nodes = source.world().vm_nodes().len();
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                maximum_nodes,
            ));
        }

        let installed = install_attempt_production_resume_checkpoint(
            checkpoints,
            checkpoint,
            source,
            initial,
            post_selection,
            context.cancellation(),
        )
        .map_err(|error| {
            QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(error))
        })?;
        let config = production_lifecycle_config_for_start(
            &self.config,
            source,
            installed.configuration(),
            AppRandomLaunchWindow::RestoredTarget,
            None,
            &[],
        )?;
        let config = config_for_assignment_host_watchdog(config, context)?;
        let config = config_for_attempt_trace_storage(config, context)?;
        let decoded = installed.into_decoded();
        self.with_attempt_launcher(context, source, maximum_nodes, |launcher| {
            build_production_vm_exact_resume_lifecycle(scenario, source, &config, decoded, launcher)
        })
    }

    /// Authenticates one resume boundary without launching a guest process.
    ///
    /// # Errors
    ///
    /// Returns the same source and semantic validation errors as [`Self::begin_resume`],
    /// or [`QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary`] when
    /// the portable scheduler retains only an event suffix.
    pub fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<
        (
            crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
            ProductionVmExactHotForkSourceBoundary,
        ),
        QemuAttemptProductionVmLifecycleError,
    > {
        validate_exact_resume_request(checkpoint, basis, context)?;
        let QemuExactResumeBasis {
            source,
            initial,
            post_selection,
            ..
        } = basis;

        let boundary = authenticate_attempt_production_resume_boundary(
            checkpoints,
            checkpoint,
            source,
            initial,
            post_selection,
            context.cancellation(),
        )
        .map_err(|error| {
            QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(error))
        })?;
        let proof = QemuSavepointReplayProof::from_checkpoint(
            boundary.configuration(),
            boundary.scheduler(),
            boundary.event_log_segments(),
        )
        .map_err(|_| QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary)?;
        let selected = crate::qemu_campaign_driver::QemuSelectedResumeBoundary::new(
            boundary.configuration().clone(),
            proof,
        );
        Ok((selected, boundary.into_hot_fork_source()))
    }

    fn begin_fresh_with_config(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
        config: ProductionVmLifecycleConfig,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(
                QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint),
            );
        }
        if source.scenario_def() != *scenario {
            return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
        }
        let maximum_nodes = source.world().vm_nodes().len();
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                maximum_nodes,
            ));
        }

        let config = config_for_assignment_host_watchdog(config, context)?;
        let config = config_for_attempt_trace_storage(config, context)?;
        self.with_attempt_launcher(context, source, maximum_nodes, |launcher| {
            build_production_vm_lifecycle_loop_with_launcher(scenario, source, &config, launcher)
        })
    }

    fn with_attempt_launcher<T>(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        maximum_nodes: usize,
        build: impl FnOnce(
            QemuAttemptProductionVmNodeLauncher<R::Guard>,
        ) -> Result<T, LifecycleApiError>,
    ) -> Result<T, QemuAttemptProductionVmLifecycleError> {
        let process_resources = context
            .process_resources()
            .map_err(QemuAttemptProductionVmLifecycleError::ResourceRefusal)?;
        let selected_checkpoint = context.take_selected_checkpoint();
        let guard = self.resources.begin(
            process_resources,
            context.cancellation().clone(),
            selected_checkpoint,
        );
        let mut guard = match guard {
            Ok(guard) => guard,
            Err(failure) => {
                let (error, selected_checkpoint) = failure.into_parts();
                if let Some(selected_checkpoint) = selected_checkpoint {
                    context.restore_selected_checkpoint(selected_checkpoint);
                }
                return Err(QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    error,
                ));
            }
        };
        if guard.resource_limits() != process_resources
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard
                .finish()
                .map_err(QemuAttemptProductionVmLifecycleError::ResourceContractCleanup)?;
            return Err(QemuAttemptProductionVmLifecycleError::ResourceContractMismatch);
        }

        let owner = QemuAttemptGenerationResourceOwner::new(guard, maximum_nodes)
            .map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)?;
        let mut launcher = QemuAttemptProductionVmNodeLauncher::new(owner);
        if let Some(checkpoints) = &self.terminal_checkpoints {
            launcher = launcher.with_terminal_checkpoint_import(
                Arc::clone(checkpoints),
                source.clone(),
                context.cancellation().clone(),
            );
        }
        build(launcher).map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)
    }
}

impl<R> QemuFreshAttemptLifecycleFactory for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = QemuAttemptProductionVmLifecycleError;

    fn configure_authenticated_start(&mut self, start: &CrucibleResolvedAttemptStart) {
        self.authenticated_network_selections = authenticated_live_network_start_selection(start)
            .into_iter()
            .collect();
    }

    fn configure_attempt_continuations(
        &mut self,
        continuations: &[QemuAttemptContinuation<'_>],
    ) -> bool {
        self.continuations.clear();
        self.continuations
            .extend(
                continuations
                    .iter()
                    .map(|continuation| OwnedQemuAttemptContinuation {
                        input: continuation.input().clone(),
                        source: continuation.source().clone(),
                    }),
            );
        true
    }

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let config = production_lifecycle_config_for_start(
            &self.config,
            source,
            start,
            AppRandomLaunchWindow::Genesis,
            Some(signal_fault_replay),
            &std::mem::take(&mut self.authenticated_network_selections),
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        let config = production_lifecycle_config_for_continuations(config, &self.continuations)
            .map_err(AttemptWorkerFailure::Terminal)?;
        self.begin_fresh_with_config(scenario, source, context, config)
            .map_err(classify_production_lifecycle_failure)
    }

    fn prepare_retained_source(
        &mut self,
        lifecycle: Self::Lifecycle,
        source: &ScenarioDefForm,
        boundary: &Configuration,
    ) -> QemuRetainedSourcePreparation<Self::Lifecycle> {
        source_retention::prepare_production_retained_source(
            &self.config,
            lifecycle,
            source,
            boundary,
        )
    }
}

mod attempt_input;
use attempt_input::{unsupported_fresh_replay_decision, validated_attempt_continuations};

#[path = "qemu_campaign_lifecycle/continuation.rs"]
mod continuation;
use continuation::*;

mod start_replay;
use start_replay::*;
pub(crate) use start_replay::{
    StartReplayCursor, materialize_start_from, materialize_start_from_tracked,
    replay_pauses_before_live_network_choice,
};

fn map_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. }
        | SchedulerError::UndeclaredConsoleMatcher(_) => None,
    };
    let error = QemuFreshExecutionRunnerError::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. }
        | SchedulerError::UndeclaredConsoleMatcher(_) => None,
    };
    let error = QemuFreshExecutionRunnerError::TerminalFingerprintCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
    }
}

fn map_fresh_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
    }
}

fn map_fresh_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error))
        }
    }
}

fn cleanup_after_fresh_runner_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
    cleanup: SchedulerError,
) -> QemuFreshExecutionRunnerError<F, D>
where
    D: std::fmt::Display,
{
    let driver = match failure {
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error)) => error,
        AttemptWorkerFailure::Retryable(error)
        | AttemptWorkerFailure::Canceled(error)
        | AttemptWorkerFailure::Terminal(error) => {
            return QemuFreshExecutionRunnerError::CleanupAfterRunner {
                failure: Box::new(error),
                cleanup,
            };
        }
    };
    let driver_diagnostic = bounded_driver_failure(&driver);
    QemuFreshExecutionRunnerError::CleanupAfterDriver {
        driver,
        driver_diagnostic,
        cleanup,
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
