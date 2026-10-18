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

use crate::{
    ProductionFaultEvidenceSnapshot, ProductionVmExactHotForkSourceBoundary,
    ProductionVmLifecycleConfig, ProductionVmLifecycleLoop, ProductionVmNodeReplayLaunchProfile,
};
use crucible::{
    CheckpointTerminalCause, Configuration, ContentHash, Decision, FingerprintSample, NodeId,
    QuantumLoop, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, ScenarioDef,
    ScenarioDefForm, Schedule, SchedulerError, SchedulerEventLogEntry,
    SchedulerOperationalFailureClass, SchedulerQuiescence, Seed, SelectionDecision, VirtualTime,
};
use crucible_api::LifecycleApiError;
use crucible_campaign::{
    AttemptContinuationInput, AttemptStartMode, CampaignHash, ChoiceDiscovery, ChoiceOpportunityId,
    ChoiceSource, ConfigurationArtifact, ConfigurationId, ExactCheckpointId,
    MAX_OBSERVATION_CHOICE_DISCOVERIES, MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES, SelectionOrigin,
    StopCondition,
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
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionProduct,
    AttemptWorkerFailure, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, CrucibleResolvedAttemptStart, ExactCheckpointStore,
    ExactCheckpointStoreError, MAX_QEMU_ATTEMPT_GENERATION_NODES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES, MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
    ProductionAttemptCheckpointRestoreError, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmNodeLauncher,
    QemuAttemptResourceGuardFactory, QemuAttemptStartReplayProof, QemuAttemptStartVerifier,
    QemuExactResumeBasis, QemuSavepointReplayProof, QemuSelectedOriginVerifier,
    authenticate_attempt_production_resume_boundary, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact, install_attempt_production_resume_checkpoint,
};

mod app_random_branch_replay;
use app_random_branch_replay::app_random_branch_replay;

mod interactive_session;
pub use interactive_session::InteractiveQemuSessionError;

mod failure_classification;
pub(crate) use failure_classification::{
    classify_production_lifecycle_failure, production_lifecycle_failure_class,
};

mod remote_observation_resume;
pub use remote_observation_resume::RemoteObservationResumeFactory;

mod source_construction;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
pub(crate) use source_construction::{NativeObservationOwner, NativeObservationRetirementError};
pub(crate) use source_construction::{
    capture_exact_prepared_source, capture_fresh_prepared_source, resume_prepared_source,
};

pub use source_construction::{
    ImportedSourcePreparationFailure, SourceGenerationStorageRefusal, SourceMainPreparationRefusal,
    SourcePostInstallationRefusal,
};

mod resume_admission;
pub(crate) use resume_admission::validate_exact_resume_request;

/// Keeps checked configuration separate from later native custody delivery.
pub(crate) struct PreparedNativeWorld<'a> {
    pub(crate) registration: &'a Arc<dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory>,
    pub(crate) process_resources: crucible_campaign::AttemptResourceLimits,
    pub(crate) consumer_control_bytes: u64,
}

/// Keeps actual first causes after the same Source has physically returned.
///
/// These values are moved from the original empty publication shell and its
/// completed receipt. Full terminal history keeps the same role occupied until
/// its original token and raw leaves are destroyed. It permits no new work.
#[derive(Debug)]
pub struct SourceCleanupHistory {
    first: Option<SourceInstallationFirst>,
    cleanup: Option<SourceCleanupCause>,
    cleanup_post: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    terminal_receipt: Option<SourceCleanupHandoff>,
}

/// Keeps the original receipt allocation through its actual terminal history.
///
/// The Box is the original Main-preborn token, not a replacement error box.
/// The inline mutex permits shared error reporting over its Send-only body;
/// callbacks borrow raw leaves only within that history lock.
struct SourceCleanupHandoff {
    receipt: std::sync::Mutex<Option<SourceCleanupReceipt>>,
}

type SourceCleanupReceipt = Box<
    dyn crucible_api::ProductionVmCleanupHandoff<
            Failure = crate::ProductionVmConstructionCleanupError,
            PostBody = crate::ProductionVmConstructionPostBody,
        >,
>;

impl SourceCleanupHandoff {
    fn new(receipt: SourceCleanupReceipt) -> Self {
        Self {
            receipt: std::sync::Mutex::new(Some(receipt)),
        }
    }

    fn receipt_mut(&mut self) -> Option<&mut SourceCleanupReceipt> {
        match self.receipt.get_mut() {
            Ok(receipt) => receipt,
            Err(poisoned) => poisoned.into_inner(),
        }
        .as_mut()
    }

    fn with_receipt<R>(
        &self,
        apply: impl FnOnce(
            &dyn crucible_api::ProductionVmCleanupHandoff<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = crate::ProductionVmConstructionPostBody,
            >,
        ) -> R,
    ) -> Option<R> {
        let receipt = match self.receipt.lock() {
            Ok(receipt) => receipt,
            Err(poisoned) => poisoned.into_inner(),
        };
        receipt.as_ref().map(|receipt| apply(receipt.as_ref()))
    }

    fn has_failure(&self) -> bool {
        self.with_receipt(|receipt| {
            receipt.first_failure().is_some()
                || receipt
                    .retained_post_body()
                    .is_some_and(|body| body.first_failure().is_some())
        })
        .is_some_and(|failed| failed)
    }

    fn with_terminal_history<R>(
        &self,
        apply: impl FnOnce(&crate::ProductionVmConstructionPostBody) -> R,
    ) -> Option<R> {
        self.with_receipt(|receipt| receipt.retained_post_body().map(apply))
            .flatten()
    }

    fn visit_history(
        &self,
        apply: &mut impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
    ) {
        let _observed = self.with_receipt(|receipt| {
            if let Some(first) = receipt.first_failure() {
                apply("Source receipt cleanup", first);
            }
            if let Some(body) = receipt.retained_post_body() {
                body.visit_history(apply);
            }
        });
    }
}

impl std::fmt::Debug for SourceCleanupHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.with_receipt(|receipt| {
            formatter
                .debug_struct("SourceCleanupHandoff")
                .field("first_failure", &receipt.first_failure())
                .field("terminal_history", &receipt.retained_post_body())
                .finish_non_exhaustive()
        })
        .unwrap_or_else(|| formatter.write_str("Source cleanup receipt consumed"))
    }
}

impl std::fmt::Display for SourceCleanupHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.with_receipt(|receipt| {
            if let Some(first) = receipt.first_failure() {
                return std::fmt::Display::fmt(first, formatter);
            }
            match receipt.retained_post_body() {
                Some(body) => std::fmt::Display::fmt(body, formatter),
                None => formatter.write_str("Source terminal history is unavailable"),
            }
        })
        .unwrap_or_else(|| formatter.write_str("Source cleanup receipt consumed"))
    }
}

impl std::error::Error for SourceCleanupHandoff {}

impl Drop for SourceCleanupHandoff {
    fn drop(&mut self) {
        let receipt = match self.receipt.get_mut() {
            Ok(receipt) => receipt,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(receipt) = receipt.take() {
            receipt.dispose();
        }
    }
}

/// Retains the concrete cleanup refusal without replacing the constructor cause.
#[derive(Debug)]
pub(crate) enum SourceCleanupCause {
    Cleanup(crate::ProductionVmConstructionCleanupError),
    Native(QemuVmRealizationError),
    Body(crucible_linux_resource::host_services::process_birth::ServiceBirthError),
}

impl SourceCleanupCause {
    pub(crate) fn as_error(&self) -> &(dyn std::error::Error + 'static) {
        match self {
            Self::Cleanup(first) => first,
            Self::Native(first) => first,
            Self::Body(first) => first,
        }
    }
}

#[derive(Debug)]
enum SourceInstallationFirst {
    Api(LifecycleApiError),
    Native(QemuVmRealizationError),
}

impl SourceCleanupHistory {
    /// Borrows the actual cleanup error independently of the constructor error.
    ///
    /// The primary error source remains the original constructor refusal when
    /// present. This accessor also exposes a later physical cleanup refusal.
    pub fn cleanup_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cleanup
            .as_ref()
            .map(SourceCleanupCause::as_error)
            .or_else(|| {
                self.terminal_receipt
                    .as_ref()
                    .filter(|held| held.has_failure())
                    .map(|held| held as &dyn std::error::Error)
            })
    }

    /// Borrows the independent post-check of the same retained World Cleanup.
    pub fn cleanup_post_error(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.cleanup_post.as_ref()
    }

    /// Borrows full terminal history within its original receipt's history lock.
    ///
    /// The containing role remains occupied until this history and its original
    /// token are disposed. The callback must not reenter this history. This
    /// supplies no new operation, native authority or unlocked raw-body borrow.
    pub fn with_terminal_history<R>(
        &self,
        apply: impl FnOnce(&crate::ProductionVmConstructionPostBody) -> R,
    ) -> Option<R> {
        self.terminal_receipt.as_ref()?.with_terminal_history(apply)
    }

    /// Visits every retained raw cause without extracting or formatting it.
    pub fn visit_history(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
    ) {
        match &self.first {
            Some(SourceInstallationFirst::Api(first)) => apply("Source constructor", first),
            Some(SourceInstallationFirst::Native(first)) => apply("Source constructor", first),
            None => {}
        }
        if let Some(first) = &self.cleanup {
            apply("Source cleanup", first.as_error());
        }
        if let Some(first) = &self.cleanup_post {
            apply("Source cleanup postcheck", first);
        }
        if let Some(receipt) = &self.terminal_receipt {
            receipt.visit_history(&mut apply);
        }
    }

    fn is_empty(&self) -> bool {
        self.first.is_none() && self.cleanup_error().is_none() && self.cleanup_post.is_none()
    }

    pub(crate) fn from_native(first: QemuVmRealizationError) -> Self {
        Self {
            first: Some(SourceInstallationFirst::Native(first)),
            cleanup: None,
            cleanup_post: None,
            terminal_receipt: None,
        }
    }
}

impl std::fmt::Display for SourceCleanupHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Source physically returned; first: {:?}; cleanup: {:?}; cleanup post: {:?}; terminal: {:?}",
            self.first, self.cleanup, self.cleanup_post, self.terminal_receipt
        )
    }
}

impl std::error::Error for SourceCleanupHistory {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.first {
            Some(SourceInstallationFirst::Api(first)) => Some(first),
            Some(SourceInstallationFirst::Native(first)) => Some(first),
            None => self.cleanup_error().or_else(|| {
                self.cleanup_post_error()
                    .map(|first| first as &dyn std::error::Error)
            }),
        }
    }
}

/// Failure to bind an admitted attempt to a fresh production VM lifecycle.
#[derive(Debug, Error)]
pub enum QemuAttemptProductionVmLifecycleError {
    /// The original Main role retains the actual prepared Source and first cause.
    #[error(transparent)]
    PreparedSource(#[from] crate::lifecycle_cleanup::PreparedSourceFailure),
    /// Genuine Main refused before the fixed Source bodies were constructed.
    #[error(transparent)]
    SourceMainPreparation(#[from] SourceMainPreparationRefusal),
    /// Actual Source return completed, with its original typed historical causes.
    #[error(transparent)]
    SourceCleanupHistory(#[from] SourceCleanupHistory),
    /// The actual Source factory retains installation custody for later cleanup.
    #[error("Source installation remains retained: {diagnostic}")]
    SourceInstallRetained {
        /// Diagnostic rendered only after the exact owning body was parked.
        diagnostic: String,
    },
    /// Original artifact metadata authority refused a model or configuration copy.
    #[error("copy admitted production lifecycle metadata: {0}")]
    ModelCopy(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The complete operational RAM partition could not be retained before launch.
    #[error("admit operational host RAM: {0}")]
    HostRamAdmission(#[source] crucible_api::host_operational::HostRamAdmissionError),
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
    /// Resource begin retained its first refusal and independent rollback cause.
    #[error("install production VM attempt resources: {0}")]
    ResourceBeginInstallation(
        #[source] crate::crucible_qemu_session::QemuAttemptResourceGuardBeginReport,
    ),
    /// Generation metadata refused before native effects, with boundary status.
    #[error(transparent)]
    SourceGenerationStorage(#[from] SourceGenerationStorageRefusal),
    /// The installed guard did not echo the exact admitted attempt contract.
    #[error(
        "production VM resource guard did not install the exact admitted limits and cancellation signal"
    )]
    ResourceContractMismatch,
    /// Releasing a mismatched resource guard failed.
    #[error("release mismatched production VM attempt resources: {0}")]
    ResourceContractCleanup(#[source] crate::QemuAttemptResourceGuardCleanupFailure),
    /// The production lifecycle rejected construction under the installed guard.
    #[error("build guarded production VM lifecycle: {0}")]
    Lifecycle(#[source] LifecycleApiError),
    /// The durable paged checkpoint root failed exact attempt resume admission.
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
}

mod ram_registration;
#[cfg(test)]
pub(crate) use ram_registration::create_native_qualification_ram_registration_factory;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(crate) use ram_registration::{ConfiguredStageOperation, StagePrepareError};
mod resource_admission;
pub(crate) use ram_registration::{
    ConfiguredParkDrainRegistration, create_host_ram_registration_factory,
    create_host_ram_registration_with_park_owner, host_ram_launch_requirements,
};
pub use resource_admission::{
    QemuFreshScenarioResourceError, validate_fresh_qemu_scenario_resources,
};

/// Factory that binds one admitted attempt to the guarded production lifecycle.
pub(crate) struct QemuAttemptProductionVmLifecycleFactory<R: QemuAttemptResourceGuardFactory> {
    config: Arc<ProductionVmLifecycleConfig>,
    resources: R,
    terminal_checkpoints: Option<Arc<ExactCheckpointStore>>,
    continuations: Vec<OwnedQemuAttemptContinuation>,
    authenticated_network_selections: Vec<SelectionDecision>,
    retained_install: Option<source_construction::RetainedSourceInstall>,
    lifecycle_outstanding: bool,
    prepared_source: Option<crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>>,
    // Retained model copies close before their original metadata credits.
    _decode_custody: Option<crucible::owned_decode::DecodeCustody>,
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
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when this lifecycle cannot expose an exact
    /// replay boundary.
    fn event_log_offset(&self) -> Result<crucible::EventLogOffset, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("lifecycle has no exact event-log offset"),
        })
    }

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

    /// Copies the exact resolved-effect trace retained by the live fault runtime.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when retained effect evidence cannot be encoded.
    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError>;

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
        Ok(())
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- this copies scheduler-retained replay evidence without feeding it into execution.
        QuantumLoop::resolved_effect_trace(self)
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        // crucible-lint: allow host-nondeterminism-state -- scheduler shutdown returns authoritative final evidence and does not synthesize modeled state.
        QuantumLoop::shutdown(self)
    }
}

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
#[cfg(test)]
pub(crate) use campaign_run::native_throughput::{
    NativeCampaignProbe, run as run_native_throughput_campaign,
};
pub(crate) use campaign_run::run_admitted_finding_branch;
mod start_replay;
#[cfg(test)]
mod tests;
pub(crate) use campaign_run::GuardedCampaignReplaySelection;
#[cfg(any(test, feature = "test-support"))]
pub use campaign_run::test_support::{
    GuardedDefaultCampaignTestTrace, run_guarded_default_campaign_test_fixture,
    run_guarded_default_campaign_test_fixture_with_choice_offer,
    run_guarded_default_campaign_test_fixture_with_trace,
    run_guarded_default_campaign_test_fixture_with_trace_and_choice_offer,
};
#[cfg(feature = "private-measurement-domain")]
pub(crate) use campaign_run::{
    ConfiguredCampaignPlannerError, LocalCampaignPlannerKind, LocalCampaignPlannerService,
    LocalCampaignPlannerServiceError, configured_campaign_planner,
};
pub use campaign_run::{
    GuardedCampaignBranchAcceptance, GuardedCampaignExploration,
    GuardedCampaignExplorationCompletion, GuardedCampaignExplorationStrategy,
    GuardedCampaignFindingExport, GuardedCampaignFindingObjectProof,
    GuardedCampaignFindingOccurrenceObjectProof, GuardedCampaignFindingOccurrenceProof,
    GuardedCampaignFindingOracle, GuardedCampaignFindingOracleError,
    GuardedCampaignFindingOracleEvaluation, GuardedCampaignFindingOracleSource,
    GuardedCampaignFindingOracleSourceLoadError, GuardedCampaignFindingProof,
    GuardedCampaignFindingQueryProof, GuardedCampaignFindingTriageReplayProof,
    GuardedCampaignFindingTriageReplaySegmentProof, GuardedCampaignFindingTriageReplaySet,
    GuardedCampaignOwner, GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    GuardedCampaignSupplementalFinding, GuardedCampaignTimeoutEvidence,
    GuardedDefaultCampaignInvariantError, GuardedDefaultCampaignObservation,
    GuardedDefaultCampaignObservationSource, GuardedDefaultCampaignProductionRunnerError,
    GuardedDefaultCampaignResumeProof, GuardedDefaultCampaignRun,
    GuardedDefaultCampaignRunConfigurationError, GuardedDefaultCampaignRunError,
    GuardedDefaultCampaignRunRequest, GuardedDefaultCampaignSavepoint,
    GuardedDefaultCampaignSupervisorError, GuardedDefaultCampaignWatchFrame,
    GuardedFindingBranchError, GuardedFindingMidpointError, GuardedImportedFindingMidpoint,
    run_guarded_default_campaign, validate_remote_resume_replay_closure,
};
pub(crate) use start_replay::materialize_start_from;
use start_replay::*;

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

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// The result remains untrusted guest input until the modeled driver binds
    /// it to the scenario declaration and selects a legal value.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request stream is malformed.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.owner.drain_pending_selectable_requests()
    }

    /// Projects a retained guest pause into the shared scheduler clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the pause overflows or its admitted mapping is absent.
    pub fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        self.owner.pending_selectable_request_time(pending)
    }

    /// Applies one exact semantic reply at the authoritative scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request/reply binding fails.
    pub fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner
            .apply_selectable_reply(parent, decision, selected, pending, reply)
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

    /// Returns the actual lifecycle to its same retained cleanup owner.
    ///
    /// # Errors
    /// Operational factories retain the whole lifecycle on a refused handoff.
    /// This default is only for resource-free lifecycle implementations.
    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        drop(lifecycle);
        Ok(())
    }

    /// Retries retained installation custody before the actual worker returns.
    ///
    /// # Errors
    /// Refuses while the same factory still owns an unreturned installation.
    /// Resource-free factories use the default; operational factories override it.
    fn try_retire_original(
        &mut self,
        _original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

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
}

/// Two-phase modeled driver for one guarded fresh production lifecycle.
///
/// [`Self::drive`] may advance and inspect the lifecycle but cannot shut it
/// down. [`Self::seal`] runs only after runner-owned shutdown has supplied every
/// final event-log entry, preventing a candidate from being accepted at a
/// pre-teardown observable boundary.
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
        _resolved_effect_trace: Option<Vec<u8>>,
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

/// In-attempt choices retained until the raw exact root owns their records.
#[derive(Debug)]
pub struct QemuCheckpointChoiceProvenance {
    configuration: Configuration,
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
}

impl QemuCheckpointChoiceProvenance {
    pub(crate) fn new(
        configuration: Configuration,
        discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Self {
        Self {
            configuration,
            discoveries,
        }
    }

    pub(crate) fn configuration_id(&self) -> ConfigurationId {
        ConfigurationId::from_hash(CampaignHash::from_bytes(self.configuration.id().bytes))
    }

    pub(crate) fn bind_capture(
        self,
        source: &ScenarioDefForm,
        capture: CapturedAttemptCheckpoint,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        if capture.scenario() != source.id()
            || capture.configuration() != self.configuration.id()
            || self.configuration.def != source.scenario_def()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "checkpoint choice records differ from the captured boundary",
                ),
            });
        }
        let closure = GuardedCampaignReplayClosure::from_owned_discoveries(
            source,
            &self.configuration.schedule,
            &self.discoveries,
        )
        .and_then(|closure| closure.to_canonical_bytes())
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("authenticate checkpoint choice records: {error}"),
        })?;
        Ok(capture.with_choice_closure(closure))
    }
}

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

impl<F: crate::completed_reproduction::PrepareCompletedReproduction, D>
    crate::completed_reproduction::PrepareCompletedReproduction for QemuFreshExecutionRunner<F, D>
{
    fn prepare_completed_reproduction(
        &mut self,
    ) -> Result<
        crate::lifecycle_cleanup::ServiceMainHandle,
        crate::QemuAttemptProductionVmLifecycleError,
    > {
        crate::completed_reproduction::PrepareCompletedReproduction::prepare_completed_reproduction(
            &mut self.lifecycles,
        )
    }
}

impl<F, D> QemuFreshExecutionRunner<F, D> {
    /// Creates a genesis-start runner from its guarded lifecycle factory and modeled driver.
    #[must_use]
    pub const fn new(lifecycles: F, driver: D) -> Self {
        Self {
            lifecycles,
            driver,
            finding_replay_capture: None,
            terminal_exact_retention: None,
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
        let _decode_scope = input.enter_decode_scope();
        let continuations = validated_attempt_continuations(input).map_err(|()| {
            fresh_metadata_failure(QemuFreshExecutionRunnerError::InvalidContinuationInput)
        })?;
        if !self
            .lifecycles
            .configure_attempt_continuations(&continuations)
        {
            return Err(Box::new(fresh_metadata_failure(
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
                    .map_err(|source| {
                        Box::new(map_fresh_driver_failure(AttemptWorkerFailure::Terminal(
                            crate::QemuFreshModeledDriverError::Configuration(source),
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
    /// Original metadata authority refused a launch or replay model allocation.
    #[error("admit fresh runner artifact metadata: {0}")]
    ArtifactAdmission(#[source] crucible::owned_decode::DecodeAdmissionError),
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
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    completed_quanta: u64,
    frontier: crucible::VirtualTime,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    attempt_event_count: usize,
    replayed_discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    replayed_discovery_bytes: usize,
    retain_replayed_discoveries: bool,
}

impl QemuFreshStartMaterialization {
    #[cfg(test)]
    pub(crate) fn genesis() -> Self {
        Self::at_quanta(0)
    }

    pub(crate) fn at_quanta(completed_quanta: u64) -> Self {
        Self {
            restored_configuration: None,
            event_log: Vec::new(),
            event_log_bytes: 0,
            completed_quanta,
            frontier: crucible::VirtualTime::default(),
            terminal_quiescence: None,
            terminal_verdict: None,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
        }
    }

    pub(crate) const fn attempt_event_count(&self) -> usize {
        self.attempt_event_count
    }

    pub(crate) const fn with_attempt_event_count(mut self, event_count: usize) -> Self {
        self.attempt_event_count = event_count;
        self
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
        if self.replayed_discoveries.len() == MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(GuestSelectableError::Campaign(
                crucible_campaign::CampaignCodecError::LimitExceeded {
                    limit: "finding-replay-choice-discovery-count",
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
    /// The byte count is the checked aggregate canonical material length of
    /// `event_log`. `frontier`, `terminal_quiescence`, and `terminal_verdict`
    /// describe the exact admitted start after replay, not a later attempt
    /// quantum.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<SchedulerEventLogEntry>,
        usize,
        u64,
        crucible::VirtualTime,
        Option<SchedulerQuiescence>,
        Option<QuantumTerminalVerdict>,
    ) {
        (
            self.event_log,
            self.event_log_bytes,
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
        event_log: Vec<SchedulerEventLogEntry>,
        event_log_bytes: usize,
        completed_quanta: u64,
        frontier: crucible::VirtualTime,
        terminal_quiescence: SchedulerQuiescence,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            restored_configuration: Some(restored_configuration),
            event_log,
            event_log_bytes,
            completed_quanta,
            frontier,
            terminal_quiescence: Some(terminal_quiescence),
            terminal_verdict,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
        }
    }

    /// Carries one verified origin stop into the next continuation segment.
    pub(crate) fn from_origin_parts(
        event_log: Vec<SchedulerEventLogEntry>,
        event_log_bytes: usize,
        completed_quanta: u64,
        frontier: crucible::VirtualTime,
        terminal_quiescence: Option<SchedulerQuiescence>,
    ) -> Self {
        Self {
            restored_configuration: None,
            event_log,
            event_log_bytes,
            completed_quanta,
            frontier,
            terminal_quiescence,
            terminal_verdict: None,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
        }
    }

    fn selected_origin_proof(
        &self,
        configuration: &Configuration,
    ) -> Result<QemuSavepointReplayProof, crate::QemuFreshModeledDriverError> {
        QemuSavepointReplayProof::from_reached_boundary(
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
        QemuAttemptStartReplayProof::from_reached_boundary(configuration, &self.event_log)
    }

    /// Returns the scheduler configuration after restoration and authenticated start replay.
    #[must_use]
    pub(crate) const fn restored_configuration(&self) -> Option<&Configuration> {
        self.restored_configuration.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        event_log: Vec<SchedulerEventLogEntry>,
        frontier: crucible::VirtualTime,
        terminal_quiescence: Option<SchedulerQuiescence>,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        let event_log_bytes = event_log
            .iter()
            .map(|entry| {
                entry
                    .canonical_material_len()
                    .unwrap_or_else(|source| panic!("fixture event material admission: {source}"))
            })
            .sum();
        Self {
            restored_configuration: None,
            event_log,
            event_log_bytes,
            completed_quanta: 0,
            frontier,
            terminal_quiescence,
            terminal_verdict,
            attempt_event_count: 0,
            replayed_discoveries: BTreeMap::new(),
            replayed_discovery_bytes: 0,
            retain_replayed_discoveries: false,
        }
    }
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
    /// Replayed event history exceeded the observation projection bound.
    #[error("fresh start replay exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
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

/// Failure before a fresh genesis checkpoint candidate reached teardown.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointCaptureFailure {
    /// The freshly launched lifecycle was not at an exact checkpoint boundary.
    #[error("fresh genesis lifecycle is not checkpoint ready")]
    NotCheckpointReady,
    /// Exact checkpoint capture failed at the authenticated genesis boundary.
    #[error("capture fresh genesis checkpoint: {0}")]
    Capture(#[source] SchedulerError),
    /// Immutable replay launch profiles could not be copied from the lifecycle.
    #[error("capture fresh genesis replay launch profiles: {0}")]
    LaunchProfiles(#[source] SchedulerError),
    /// The capture named a scenario or configuration other than exact genesis.
    #[error("fresh genesis checkpoint capture returned a foreign semantic basis")]
    BasisMismatch,
}

/// Exact native capture and immutable launch basis produced at fresh genesis.
#[derive(Debug)]
pub struct QemuFreshGenesisCheckpointCandidate {
    capture: CapturedAttemptCheckpoint,
    launch_profiles: Vec<ProductionVmNodeReplayLaunchProfile>,
}

impl QemuFreshGenesisCheckpointCandidate {
    /// Returns the exact captured scenario identity.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        self.capture.scenario()
    }

    /// Returns the exact captured genesis configuration identity.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        self.capture.configuration()
    }

    /// Returns immutable replay profiles in World node order.
    #[must_use]
    pub fn launch_profiles(&self) -> &[ProductionVmNodeReplayLaunchProfile] {
        &self.launch_profiles
    }

    /// Consumes the candidate into its native capture and immutable profiles.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CapturedAttemptCheckpoint,
        Vec<ProductionVmNodeReplayLaunchProfile>,
    ) {
        (self.capture, self.launch_profiles)
    }
}

/// Failure while producing one independently captured genesis checkpoint candidate.
#[derive(Debug, Error)]
pub enum QemuFreshGenesisCheckpointError<E> {
    /// Fresh lifecycle construction failed with its original retry class.
    #[error("start fresh genesis checkpoint lifecycle: {0}")]
    Start(#[source] AttemptWorkerFailure<E>),
    /// Capture failed after lifecycle construction and teardown succeeded.
    #[error(transparent)]
    Capture(#[from] QemuFreshGenesisCheckpointCaptureFailure),
    /// Returning the actual lifecycle to its original owner refused.
    ///
    /// The factory retains that same lifecycle. Independent capture and
    /// semantic-shutdown failures remain inline rather than recursively boxed.
    #[error("return fresh genesis checkpoint lifecycle: {retirement}")]
    Retirement {
        /// Earlier capture failure, independent of shutdown and return.
        capture: Option<QemuFreshGenesisCheckpointCaptureFailure>,
        /// Earlier semantic shutdown failure, independent of physical return.
        cleanup: Option<SchedulerError>,
        /// Actual original-owner return refusal.
        #[source]
        retirement: E,
    },
    /// Teardown failed and therefore retains precedence over an earlier result.
    #[error("tear down fresh genesis checkpoint lifecycle: {cleanup}")]
    Cleanup {
        /// Earlier capture failure, when teardown followed another failure.
        prior: Option<Box<QemuFreshGenesisCheckpointCaptureFailure>>,
        /// Mandatory lifecycle teardown failure.
        #[source]
        cleanup: SchedulerError,
    },
}

/// Captures a fresh exact checkpoint at the scenario's genesis ready boundary.
///
/// This is the QEMU-backed bootstrap primitive for a future authenticated baked-
/// genesis catalog. It starts the ordinary production lifecycle at exact
/// genesis, performs no modeled quantum, captures through the same portable
/// checkpoint path used by attempts, and always tears the lifecycle down before
/// returning. The returned value remains only a candidate: a catalog owner must
/// require the current paged production closure and authenticate its
/// complete semantic snapshot catalog before replay validation.
///
/// # Errors
///
/// Returns [`QemuFreshGenesisCheckpointError`] when guarded lifecycle startup
/// fails, genesis is not checkpoint ready, capture returns a foreign basis, or
/// mandatory teardown or return to the original lifecycle owner refuses.
/// Original-owner return refusal preserves independent capture and teardown
/// causes. After an accepted return, teardown keeps its existing precedence.
pub(crate) fn capture_fresh_genesis_checkpoint_candidate<F>(
    factory: &mut F,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<QemuFreshGenesisCheckpointCandidate, QemuFreshGenesisCheckpointError<F::Error>>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    let scenario = source.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let signal_fault_replay = crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone());
    let mut lifecycle = factory
        .start_fresh_lifecycle(&scenario, source, &genesis, &signal_fault_replay, context)
        .map_err(QemuFreshGenesisCheckpointError::Start)?;

    let captured = match lifecycle.exact_checkpoint_ready() {
        Ok(true) => lifecycle
            .capture_attempt_checkpoint(context)
            .map_err(QemuFreshGenesisCheckpointCaptureFailure::Capture)
            .and_then(|capture| {
                if capture.scenario() != scenario.id() || capture.configuration() != genesis.id() {
                    return Err(QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch);
                }
                let launch_profiles = lifecycle
                    .replay_launch_profiles()
                    .map_err(QemuFreshGenesisCheckpointCaptureFailure::LaunchProfiles)?;
                Ok(QemuFreshGenesisCheckpointCandidate {
                    capture,
                    launch_profiles,
                })
            }),
        Ok(false) => Err(QemuFreshGenesisCheckpointCaptureFailure::NotCheckpointReady),
        Err(error) => Err(QemuFreshGenesisCheckpointCaptureFailure::Capture(error)),
    };
    let cleanup = lifecycle.shutdown();
    // Semantic shutdown does not destroy the paid Loop or return its original
    // carrier. Every post-start cut must hand that SAME owner back explicitly,
    // including a negative shutdown that already made physical progress.
    let returned = factory.retire_lifecycle(lifecycle);
    if let Err(retirement) = returned {
        return Err(QemuFreshGenesisCheckpointError::Retirement {
            capture: captured.err(),
            cleanup: cleanup.err(),
            retirement,
        });
    }

    match (captured, cleanup) {
        (Ok(capture), Ok(_final_events)) => Ok(capture),
        (Err(error), Ok(_final_events)) => Err(error.into()),
        (Ok(_capture), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: None,
            cleanup,
        }),
        (Err(prior), Err(cleanup)) => Err(QemuFreshGenesisCheckpointError::Cleanup {
            prior: Some(Box::new(prior)),
            cleanup,
        }),
    }
}

enum QemuFreshRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

/// Attaches the live original-start execution supervisor to a QEMU lifecycle.
pub(crate) fn config_for_assignment_host_watchdog(
    config: ProductionVmLifecycleConfig,
    context: &AttemptExecutionContext,
) -> Result<
    (ProductionVmLifecycleConfig, ConfiguredParkDrainRegistration),
    QemuAttemptProductionVmLifecycleError,
> {
    if context
        .remaining_host_watchdog()
        .is_some_and(|remaining| remaining.is_zero())
    {
        return Err(QemuAttemptProductionVmLifecycleError::HostWatchdogExpired);
    }
    let supervisor = context
        .host_operation_supervisor()
        .ok_or(QemuAttemptProductionVmLifecycleError::HostWatchdogExpired)?;
    let (registration, park_drain_registration) =
        create_host_ram_registration_with_park_owner(context)
            .map_err(QemuAttemptProductionVmLifecycleError::HostRamAdmission)?;
    Ok((
        config
            .with_host_operation_supervisor(supervisor.clone())
            .with_host_ram_registration_factory(registration),
        park_drain_registration,
    ))
}

impl<R: QemuAttemptResourceGuardFactory> QemuAttemptProductionVmLifecycleFactory<R> {
    /// Creates a factory from trusted lifecycle configuration and host resources.
    #[must_use]
    pub fn new(config: impl Into<Arc<ProductionVmLifecycleConfig>>, resources: R) -> Self {
        Self {
            config: config.into(),
            resources,
            terminal_checkpoints: None,
            continuations: Vec::new(),
            authenticated_network_selections: Vec::new(),
            retained_install: None,
            lifecycle_outstanding: false,
            prepared_source: None,
            _decode_custody: None,
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
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn begin_fresh(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        source_construction::validate_fresh_source_request(scenario, source, context)?;
        let prepared = self.selected_prepared_source()?;
        let lifecycle = source_construction::fresh_prepared_source(
            &prepared,
            &self.config,
            None,
            self.terminal_checkpoints.clone(),
            scenario,
            source,
            context,
        )?;
        self.lifecycle_outstanding = true;
        Ok(lifecycle)
    }

    /// Builds one resumed lifecycle from an exact promoted paged checkpoint root.
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
        self.begin_resume_with_exposure(
            checkpoints,
            checkpoint,
            basis,
            context,
            crate::vm_lifecycle::RetainedConstructionExposure::Released,
        )
    }

    /// Restores the exact World without releasing any live native node.
    pub(crate) fn begin_stopped_transfer(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<crate::ProductionVmStoppedLifecycle, QemuAttemptProductionVmLifecycleError> {
        self.begin_resume_with_exposure(
            checkpoints,
            checkpoint,
            basis,
            context,
            crate::vm_lifecycle::RetainedConstructionExposure::AwaitingOwnershipCommit,
        )
        .map(crate::ProductionVmStoppedLifecycle::from_retained_loop)
    }

    fn begin_resume_with_exposure(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
        exposure: crate::vm_lifecycle::RetainedConstructionExposure,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        let prepared = self.selected_prepared_source()?;
        let lifecycle = resume_prepared_source(
            &prepared,
            &self.config,
            self.terminal_checkpoints.clone(),
            checkpoints,
            checkpoint,
            basis,
            context,
            exposure,
        )?;
        self.lifecycle_outstanding = true;
        Ok(lifecycle)
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
        source_construction::authenticate_resume_contents(checkpoints, checkpoint, basis, context)
    }

    fn begin_fresh_with_config(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
        config: ProductionVmLifecycleConfig,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        source_construction::validate_fresh_source_request(scenario, source, context)?;
        let prepared = self.selected_prepared_source()?;
        let lifecycle = source_construction::fresh_prepared_source(
            &prepared,
            &self.config,
            Some(config),
            self.terminal_checkpoints.clone(),
            scenario,
            source,
            context,
        )?;
        self.lifecycle_outstanding = true;
        Ok(lifecycle)
    }

    /// Prepares the configured native World request before admission.
    ///
    /// This validates the topology and resource projection shared by ordinary
    /// and diagnostic launchers. It returns no World guard or native authority.
    ///
    /// # Errors
    /// Refuses missing operational authority, inconsistent resource partitions,
    /// native controller failure, or failed qualification before process launch.
    /// Configures the genuine common World request with its actual consumer extent.
    pub(crate) fn prepare_native_world_with_geometry<'a>(
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        config: &'a ProductionVmLifecycleConfig,
        consumer_geometry: impl FnOnce() -> Result<u64, LifecycleApiError>,
    ) -> Result<PreparedNativeWorld<'a>, QemuAttemptProductionVmLifecycleError> {
        let original_remaining = context
            .process_resources()
            .map_err(QemuAttemptProductionVmLifecycleError::ResourceRefusal)?;
        let registration = config.host_ram_registration_factory().ok_or_else(|| {
            QemuAttemptProductionVmLifecycleError::HostRamAdmission(
                crucible_api::host_operational::HostRamAdmissionError::contract(
                    "native process limits require retained host RAM ownership",
                ),
            )
        })?;
        let shapes = source
            .world()
            .vm_nodes()
            .iter()
            .map(
                |node| crucible_api::host_operational::ProductionHostRamLaunchShape {
                    node: node.id.name.clone(),
                    declared_ram_bytes: u64::from(node.memory_mib) * 1024 * 1024,
                    vcpus: u32::from(node.smp_vcpus),
                },
            )
            .collect::<Vec<_>>();
        registration
            .configure_world(&shapes)
            .map_err(QemuAttemptProductionVmLifecycleError::HostRamAdmission)?;
        let native = registration
            .native_world_limits()
            .map_err(QemuAttemptProductionVmLifecycleError::HostRamAdmission)?;
        // The request retains its semantic resource basis. Kernel containment
        // receives only the native subset of its independently admitted host
        // allocation; CAS and host services retain the complementary subset.
        let process_resources = crucible_campaign::AttemptResourceLimits::new(
            native.cpu_slots,
            native.resident_bytes,
            native.writable_bytes,
            original_remaining.maximum_execution_quanta(),
        )
        .map_err(|error| {
            QemuAttemptProductionVmLifecycleError::HostRamAdmission(
                crucible_api::host_operational::HostRamAdmissionError::contract(error.to_string()),
            )
        })?;
        let consumer_control_bytes =
            consumer_geometry().map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)?;
        Ok(PreparedNativeWorld {
            registration,
            process_resources,
            consumer_control_bytes,
        })
    }

    /// Completes publication only after the actual launcher retains the guard.
    ///
    /// # Errors
    /// Preserves the initiating controller, contract, or qualification refusal.
    /// The caller retains and cleans the same launcher on every error.
    pub(crate) fn complete_native_world_guard_installation(
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        config: &ProductionVmLifecycleConfig,
        guard: &mut R::Guard,
        process_resources: crucible_campaign::AttemptResourceLimits,
    ) -> Result<(), SourcePostInstallationRefusal> {
        let registration = config.host_ram_registration_factory().ok_or_else(|| {
            SourcePostInstallationRefusal::HostRam(
                crucible_api::host_operational::HostRamAdmissionError::contract(
                    "native process limits require retained host RAM ownership",
                ),
            )
        })?;
        if guard.resource_limits() != process_resources
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            return Err(SourcePostInstallationRefusal::ContractMismatch);
        }

        if let Some(registry) = context.host_operational_registry() {
            guard
                .retain_original_native_registry(registry.clone())
                .map_err(SourcePostInstallationRefusal::Native)?;
        }

        for node in source.world().vm_nodes() {
            let _controller_resources = registration
                .reserve_native_controller_resources(&node.id.name)
                .map_err(SourcePostInstallationRefusal::HostRam)?;
            let controller = guard
                .native_resource_controller_for_node(&node.id)
                .map_err(SourcePostInstallationRefusal::Native)?;
            if let Err(error) =
                registration.bind_native_resource_controller(&node.id.name, controller)
            {
                return Err(SourcePostInstallationRefusal::HostRam(error));
            }
        }

        let qualification = (|| {
            if option_env!("CRUCIBLE_PAGING_QUALIFICATION_JSON").is_none() {
                return Ok(());
            }
            let mut operation = None;
            let mut boundary = || -> std::io::Result<()> {
                if operation.is_none() {
                    operation = Some(
                        context
                            .host_operation_supervisor()
                            .ok_or_else(|| std::io::Error::other("qualification lacks original supervision"))?
                            .begin(crucible_linux_resource::host_supervision::HostOperationClass::Setup)
                            .map_err(std::io::Error::other)?,
                    );
                }
                operation
                    .as_ref()
                    .ok_or_else(|| {
                        std::io::Error::other("qualification supervision is unavailable")
                    })?
                    .wait_slice()
                    .map_err(std::io::Error::other)?;
                Ok(())
            };
            for node in source.world().vm_nodes() {
                let credentials = guard
                    .child_process_contract_for_node(&node.id)
                    .map_err(SourcePostInstallationRefusal::Native)?
                    .effective_credentials();
                let registrar = crate::paging_qualification::scoped_registrar(
                    context
                        .host_operational_registry()
                        .cloned()
                        .ok_or_else(|| {
                            SourcePostInstallationRefusal::HostRam(
                                crucible_api::host_operational::HostRamAdmissionError::contract(
                                    "qualification lacks admitted registry",
                                ),
                            )
                        })?,
                    config,
                    node,
                    credentials,
                    &mut boundary,
                )
                .map_err(|error| {
                    SourcePostInstallationRefusal::HostRam(
                        crucible_api::host_operational::HostRamAdmissionError::contract(
                            error.to_string(),
                        ),
                    )
                })?;
                if let Some(registrar) = registrar {
                    registration
                        .bind_node_registrar(&node.id.name, registrar)
                        .map_err(SourcePostInstallationRefusal::HostRam)?;
                }
            }
            if let Some(operation) = operation {
                operation.complete().map_err(|error| {
                    SourcePostInstallationRefusal::HostRam(
                        crucible_api::host_operational::HostRamAdmissionError::contract(
                            error.to_string(),
                        ),
                    )
                })?;
            }
            Ok::<_, SourcePostInstallationRefusal>(())
        })();
        if let Err(error) = qualification {
            return Err(error);
        }

        Ok(())
    }
}

impl<R> QemuFreshAttemptLifecycleFactory for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = QemuAttemptProductionVmLifecycleError;

    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        self.retain_returned_lifecycle(lifecycle)
    }

    fn try_retire_original(
        &mut self,
        _original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        // Cleanup authority stays with the exact saved installation owner.
        self.retry_retained_source_installation()
    }

    fn configure_authenticated_start(&mut self, start: &CrucibleResolvedAttemptStart) {
        self.authenticated_network_selections = Vec::new();
        if let Some(selection) = authenticated_live_network_start_selection(start)
            && crucible::owned_decode::reserve_vec(&mut self.authenticated_network_selections, 1)
                .is_ok()
        {
            self.authenticated_network_selections.push(selection);
        }
        self._decode_custody = crucible::owned_decode::current_custody();
    }

    fn configure_attempt_continuations(
        &mut self,
        continuations: &[QemuAttemptContinuation<'_>],
    ) -> bool {
        // Close both previous buffers before replacing their shared credit.
        self.continuations = Vec::new();
        self.authenticated_network_selections = Vec::new();
        self._decode_custody = crucible::owned_decode::current_custody();
        for continuation in continuations {
            let input = match continuation.input().clone_admitted() {
                Ok(input) => input,
                Err(_) => return false,
            };
            let source = match continuation.source().try_clone_admitted() {
                Ok(source) => source,
                Err(_) => return false,
            };
            if crucible::owned_decode::reserve_vec(&mut self.continuations, 1).is_err() {
                return false;
            }
            self.continuations
                .push(OwnedQemuAttemptContinuation { input, source });
        }
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
        if let Some(account) = crucible::owned_decode::current_budget() {
            account.check().map_err(|source| {
                AttemptWorkerFailure::Retryable(QemuAttemptProductionVmLifecycleError::ModelCopy(
                    Box::new(source),
                ))
            })?;
        }
        let config = production_lifecycle_config_for_start(
            &self.config,
            source,
            start,
            Some(signal_fault_replay),
            &std::mem::take(&mut self.authenticated_network_selections),
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        let config = production_lifecycle_config_for_continuations(config, &self.continuations)
            .map_err(AttemptWorkerFailure::Terminal)?;
        self.begin_fresh_with_config(scenario, source, context, config)
            .map_err(classify_production_lifecycle_failure)
    }
}

#[path = "qemu_campaign_lifecycle/continuation.rs"]
mod continuation;
use continuation::*;
