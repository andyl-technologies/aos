//! Concrete modeled driving and observation projection for campaign QEMU attempts.
//!
//! The shared semantic core advances only through [`QemuModeledAttemptLifecycle`],
//! stops on the attempt's exact semantic boundary or a modeled terminal verdict,
//! and retains a bounded dense event log. Fresh and exact execution seal after
//! runner-owned shutdown contributes its final observational suffix. Both paths
//! reconstruct the exact child artifact, evaluate scenario properties offline,
//! derive grow-only coverage identities, and produce one self-contained
//! campaign observation candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crucible::model::MeasurementTerminalState;
use crucible::{
    AssertionPhase, Configuration, ContentHash, Decision, EngineError, EventLogCoverageObservation,
    FailureClusterReportDivergence, FailureClusterReportFailure, FailurePropertyViolationRecord,
    FailureTimeoutBudgetKind, FailureTimeoutRecord, FingerprintSample, HostAssertionOutcomeKind,
    NodeId, ObservableEventPayload, OfflineAssertionCheckError, OfflineAssertionChecker,
    QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerOperationalFailureClass, SchedulerQuiescence,
    SelectionDecision, VirtualTime, compare_event_log_determinism,
    coverage_fingerprint_from_event_log, try_step,
};
use crucible_campaign::{
    AssertionViolationWitness, AttemptStartMode, BoundedStopProof, CampaignCodecError,
    CampaignHash, ChoiceDiscovery, ChoiceDomainId, ChoiceOpportunityId, ConfigurationArtifact,
    ConfigurationId, CoverageProjection, MAX_OBSERVATION_CHOICE_DISCOVERIES,
    MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES, Observation, ObservationCandidate,
    ObservationCondition, ObservationEventLogProof, ObservationQuantumBoundary,
    ObservationStopProof, ObservationStopSatisfaction, PolicyTimeoutKind, PropertyEvidence,
    PropertyVerdict, PropertyVerdictSet, SelectableId, Selection, SelectionOrigin, StopCondition,
    StopOutcome,
};
use crucible_cas::content_store::ContentId;
use crucible_protocol::SelectionReply;
use crucible_qemu::QemuNodeSelectablePendingRequest;
use thiserror::Error;

use crate::CrucibleResolvedAttemptStart;
use crate::guest_selectable::{
    GuestSelectableBoundaryDiagnosticStage, GuestSelectableError,
    record_guest_selectable_boundary_diagnostic, resolve_guest_selectable, selected_guest_reply,
};
use crate::qemu_campaign_lifecycle::{
    GuardedCampaignFindingOracle, GuardedCampaignFindingOracleError,
    GuardedCampaignFindingOracleEvaluation, QemuCheckpointChoiceProvenance,
};
use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleFindingReplayEvidence, CrucibleMeasurementError,
    CrucibleMeasurementReplayEvidence, CrucibleObservationBoundaryEvidence,
    PreparedSemanticAttemptResult, PreparedSemanticResultCodecError, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycle, QemuFreshDriveOutcome, QemuFreshStartMaterialization,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
    evaluate_crucible_measurement_publication,
    evaluate_crucible_observation_measurement_publication,
};

mod selection_projection;

use selection_projection::produced_selections_after_start;

/// Maximum scheduler entries retained by one in-memory fresh-attempt projection.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES: usize = 1_000_000;

/// Maximum aggregate canonical event material retained by one fresh attempt.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES: usize = 64 * 1024 * 1024;

/// Maximum property-by-event evaluations admitted by one fresh-attempt seal.
pub const MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS: usize = 1_000_000;

/// Failure while driving or projecting one fresh modeled campaign attempt.
#[derive(Debug, Error)]
pub enum QemuFreshModeledDriverError {
    /// A campaign decision violated the scenario's configuration limits.
    #[error("fresh campaign configuration step failed: {0}")]
    Configuration(#[source] EngineError),
    /// The attempt was canceled at a modeled boundary.
    #[error("fresh campaign attempt was canceled")]
    Canceled,
    /// Scheduler progress or final event validation failed.
    #[error("fresh campaign scheduler failed: {0}")]
    Scheduler(#[source] SchedulerError),
    /// Strict Crucible artifact reconstruction failed.
    #[error("fresh campaign artifact projection failed: {0}")]
    Artifact(#[source] Box<CrucibleArtifactError>),
    /// A private candidate continued through a validated default guest choice.
    #[error("finding replay candidate continued through a default guest selection")]
    FindingCandidateSelectionContinued,
    /// Campaign canonical construction failed.
    #[error("fresh campaign observation projection failed: {0}")]
    Campaign(#[source] CampaignCodecError),
    /// Offline property evaluation rejected the complete retained event log.
    #[error("fresh campaign property evaluation failed: {0}")]
    Assertions(#[source] Box<OfflineAssertionCheckError>),
    /// Measurement evaluation or campaign binding rejected the retained run.
    #[error("fresh campaign measurement evaluation failed: {0}")]
    Measurements(#[source] CrucibleMeasurementError),
    /// Prepared semantic result construction rejected the complete closure.
    #[error("fresh campaign prepared-result projection failed: {0}")]
    PreparedResult(#[source] Box<PreparedSemanticResultCodecError>),
    /// A bound supplemental property oracle could not evaluate the child configuration.
    #[error("fresh campaign supplemental property evaluation failed: {0}")]
    SupplementalFinding(#[source] GuardedCampaignFindingOracleError),
    /// Full-signature triage evidence could not be reconstructed from the replay.
    #[error("fresh campaign triage replay evidence failed: {0}")]
    Triage(#[source] Box<EngineError>),
    /// A guest measurement or semantic-marker message violated the scenario contract.
    #[error("fresh campaign guest measurement protocol failed at sequence {sequence}: {reason}")]
    GuestMeasurementProtocol {
        /// Exact scheduler sequence carrying the invalid message.
        sequence: u64,
        /// Stable validation diagnostic.
        reason: String,
    },
    /// The lifecycle returned a child configuration for another scenario.
    #[error("fresh campaign lifecycle returned a configuration for another scenario")]
    ScenarioMismatch,
    /// The lifecycle reported failure without any modeled failure reason.
    #[error("fresh campaign lifecycle returned an empty scenario failure")]
    EmptyScenarioFailure,
    /// A repeated opportunity ID carried conflicting canonical bodies.
    #[error("fresh campaign lifecycle returned conflicting bodies for opportunity `{0}`")]
    ConflictingChoice(ChoiceOpportunityId),
    /// A paused guest selectable request violated the scenario or reply contract.
    #[error("fresh campaign guest selectable failed: {0}")]
    GuestSelectable(#[source] GuestSelectableError),
    /// Retained event or property-evaluation work exceeded the driver bound.
    #[error("fresh campaign modeled projection exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
    },
    /// Physical driving exhausted the execution-wide quantum reservation.
    #[error("fresh campaign resource refusal: {0}")]
    ResourceRefusal(#[source] crate::executor_worker::ExecutionQuantumBudgetError),
    /// A modeled stop was reported while network output remained uncommitted.
    #[error("fresh campaign stop retained {0} uncommitted network outputs")]
    PendingNetworkOutput(usize),
    /// The authoritative scheduler-quantum coordinate moved backward.
    #[error("fresh campaign scheduler quantum coordinate regressed from {before} to {after}")]
    QuantumCounterRegressed {
        /// Coordinate observed before the operation.
        before: u64,
        /// Coordinate observed after the operation.
        after: u64,
    },
    /// A completed drive did not advance the authoritative quantum coordinate.
    #[error(
        "fresh campaign scheduler quantum coordinate did not advance from {before} after drive (reported {after})"
    )]
    QuantumCounterDidNotAdvance {
        /// Coordinate observed before the drive.
        before: u64,
        /// Coordinate reported after the drive.
        after: u64,
    },
    /// The retained start and live scheduler name different quantum coordinates.
    #[error(
        "fresh campaign start quantum coordinate {materialized} differs from live scheduler coordinate {authoritative}"
    )]
    StartQuantumCoordinateMismatch {
        /// Coordinate carried by the retained start materialization.
        materialized: u64,
        /// Coordinate reported by the live scheduler lifecycle.
        authoritative: u64,
    },
    /// An internal savepoint-replay proof was absent, repeated, or poisoned.
    #[error("savepoint replay proof state is inconsistent")]
    SavepointReplayProof,
    /// A post-quantum observation proof disagreed with its scheduler output.
    #[error("observation stop proof disagrees with the completed quantum")]
    ObservationStopProof,
    /// A policy stop proof disagreed with the retained scheduler coordinate.
    #[error("bounded campaign stop proof disagrees with the completed quantum")]
    BoundedStopProof,
    /// A selected continuation replay did not stop at its claimed boundary.
    #[error("selected continuation origin replay did not match its claimed boundary")]
    SelectedOriginBoundaryMismatch,
    /// The resulting schedule does not preserve the authenticated start.
    #[error("fresh campaign child schedule does not extend its authenticated attempt start")]
    StartSchedulePrefixMismatch,
    /// An attempt start or selected checkpoint lies beyond the immutable attempt stop.
    #[error("attempt start or selected checkpoint lies beyond the attempt stop")]
    SelectedResumeBeyondAttemptStop,
    /// Replay passed or disagreed with a later own checkpoint boundary.
    #[error("selected continuation checkpoint replay did not match its boundary")]
    SelectedResumeBoundaryMismatch,
}

impl From<CrucibleArtifactError> for QemuFreshModeledDriverError {
    fn from(error: CrucibleArtifactError) -> Self {
        Self::Artifact(Box::new(error))
    }
}

impl From<CampaignCodecError> for QemuFreshModeledDriverError {
    fn from(error: CampaignCodecError) -> Self {
        Self::Campaign(error)
    }
}

impl From<OfflineAssertionCheckError> for QemuFreshModeledDriverError {
    fn from(error: OfflineAssertionCheckError) -> Self {
        Self::Assertions(Box::new(error))
    }
}

impl From<PreparedSemanticResultCodecError> for QemuFreshModeledDriverError {
    fn from(error: PreparedSemanticResultCodecError) -> Self {
        Self::PreparedResult(Box::new(error))
    }
}

/// Concrete bounded modeled driver for one fresh campaign QEMU lifecycle.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuFreshModeledDriver;

/// Modeled driver allowed to project private finding-replay evidence.
///
/// This capability is deliberately separate from [`QemuFreshAttemptDriver`]:
/// a driver must reproduce every property source it applies during admitted
/// execution before its runner may authenticate a minimized candidate.
pub(crate) trait QemuFindingReplayDriver:
    QemuFreshAttemptDriver<Pending = QemuFreshPendingObservation, Error = QemuFreshModeledDriverError>
{
    /// Projects one exact candidate after final lifecycle drain.
    ///
    /// # Errors
    ///
    /// Returns an error when the complete candidate boundary cannot be
    /// evaluated with the driver's admitted property sources.
    fn build_finding_candidate_boundary_evidence(
        &self,
        pending: QemuFreshPendingObservation,
        candidate: &ConfigurationArtifact,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<QemuFindingCandidateBoundaryEvidence, QemuFreshModeledDriverError>;
}

/// Fresh modeled driver with one immutable supplemental property oracle.
pub(crate) struct QemuFreshSupplementalModeledDriver {
    oracle: Option<Arc<dyn GuardedCampaignFindingOracle>>,
    source: Option<ContentId>,
}

impl QemuFreshSupplementalModeledDriver {
    /// Binds a supplemental property oracle to its exact retained trace leaf.
    #[must_use]
    pub(crate) fn new(oracle: Option<Arc<dyn GuardedCampaignFindingOracle>>) -> Self {
        let source = oracle.as_ref().map(|oracle| oracle.source().content_id());
        Self { oracle, source }
    }
}

/// Bounded modeled state retained until runner-owned final drain completes.
#[derive(Debug)]
pub struct QemuFreshPendingObservation {
    input: CrucibleAttemptExecution,
    configuration: crucible::Configuration,
    stop: ModeledStop,
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_at: VirtualTime,
    completed_quanta: u64,
    attempt_event_count: usize,
}

impl QemuFreshPendingObservation {
    fn terminal_checkpoint_choices(&self) -> Option<(QemuCheckpointChoiceProvenance, u64)> {
        Some((
            QemuCheckpointChoiceProvenance::new(
                self.configuration.clone(),
                self.discoveries.clone(),
            ),
            u64::try_from(self.event_log.len()).ok()?,
        ))
    }

    fn has_terminal_assertion_failure(&self) -> Result<bool, QemuFreshModeledDriverError> {
        if matches!(&self.stop, ModeledStop::ObservationReached { .. }) {
            return Ok(false);
        }
        let report = check_pending_assertions(self)?;
        Ok(!report.verdict().failures().is_empty())
    }

    fn into_checkpoint_choices(self) -> QemuCheckpointChoiceProvenance {
        QemuCheckpointChoiceProvenance::new(self.configuration, self.discoveries)
    }
}

/// Private evidence evaluated at one exact finding-candidate boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuFindingCandidateBoundaryEvidence {
    replay: CrucibleFindingReplayEvidence,
    measurement_replay_evidence: Vec<CrucibleMeasurementReplayEvidence>,
    final_events: Vec<SchedulerEventLogEntry>,
    triage: QemuFindingCandidateTriageInputs,
    policy_timeout: Option<(StopCondition, PolicyTimeoutKind, BoundedStopProof)>,
    paired_reproduced_coverage: Option<CoverageProjection>,
}

/// Replay-owned failure inputs awaiting an exact reproduction binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuFindingCandidateTriageInputs {
    failures: Vec<FailureClusterReportFailure>,
    causal_entries: Vec<SchedulerEventLogEntry>,
    coverage_fingerprint: ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
    paired_divergence_logs: Option<(Vec<SchedulerEventLogEntry>, Vec<SchedulerEventLogEntry>)>,
}

/// Owned components retained from one candidate replay's triage projection.
pub(crate) type QemuFindingCandidateTriageParts = (
    Vec<FailureClusterReportFailure>,
    Vec<SchedulerEventLogEntry>,
    ContentHash,
    Vec<Vec<u8>>,
    Option<(Vec<SchedulerEventLogEntry>, Vec<SchedulerEventLogEntry>)>,
);

impl QemuFindingCandidateTriageInputs {
    /// Consumes the raw inputs retained from one private QEMU execution.
    pub(crate) fn into_parts(self) -> QemuFindingCandidateTriageParts {
        (
            self.failures,
            self.causal_entries,
            self.coverage_fingerprint,
            self.recorded_event_frames,
            self.paired_divergence_logs,
        )
    }

    /// Builds divergence inputs from two independently retained causal logs.
    ///
    /// Returns `None` when the logs have the same causal projection or contain
    /// no side-specific first-difference coordinate.
    pub(crate) fn from_replay_determinism_mismatch(
        expected: &Self,
        reproduced: &Self,
    ) -> Option<(Self, bool)> {
        let comparison =
            compare_event_log_determinism(&expected.causal_entries, &reproduced.causal_entries);
        let mismatch = comparison.mismatch()?;
        let point = mismatch.first_location()?;
        let selected = if mismatch.expected_location.is_some() {
            expected
        } else {
            reproduced
        };
        let divergence = FailureClusterReportDivergence::from_bisected_first_diff(
            point,
            divergence_entry_summary(mismatch.expected_entry.as_ref()),
            divergence_entry_summary(mismatch.reproduced_entry.as_ref()),
        );

        Some((
            Self {
                failures: vec![FailureClusterReportFailure::divergence(divergence)],
                causal_entries: selected.causal_entries.clone(),
                coverage_fingerprint: selected.coverage_fingerprint,
                recorded_event_frames: selected.recorded_event_frames.clone(),
                paired_divergence_logs: Some((
                    expected.causal_entries.clone(),
                    reproduced.causal_entries.clone(),
                )),
            },
            std::ptr::eq(selected, expected),
        ))
    }

    #[cfg(test)]
    pub(crate) fn replay_for_test(
        causal_entries: Vec<SchedulerEventLogEntry>,
        coverage_fingerprint: ContentHash,
        recorded_event_frames: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            failures: Vec::new(),
            causal_entries,
            coverage_fingerprint,
            recorded_event_frames,
            paired_divergence_logs: None,
        }
    }
}

fn divergence_entry_summary(entry: Option<&SchedulerEventLogEntry>) -> String {
    entry.map_or_else(
        || String::from("entry=absent"),
        |entry| {
            format!(
                "entry.content_hash={};entry.sequence={};entry.kind={}",
                entry.content_hash().to_hex(),
                entry.sequence(),
                entry.event_payload().kind(),
            )
        },
    )
}

impl QemuFindingCandidateBoundaryEvidence {
    pub(crate) fn causal_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.triage.causal_entries
    }

    pub(crate) fn timeout_record(&self) -> Option<&FailureTimeoutRecord> {
        self.triage
            .failures
            .iter()
            .find_map(|failure| match failure {
                FailureClusterReportFailure::Timeout(record) => Some(record),
                FailureClusterReportFailure::Property(_)
                | FailureClusterReportFailure::Divergence(_) => None,
            })
    }

    pub(crate) fn policy_timeout(
        &self,
    ) -> Option<&(StopCondition, PolicyTimeoutKind, BoundedStopProof)> {
        self.policy_timeout.as_ref()
    }

    pub(crate) fn paired_divergence_logs(
        &self,
    ) -> Option<(&[SchedulerEventLogEntry], &[SchedulerEventLogEntry])> {
        self.triage
            .paired_divergence_logs
            .as_ref()
            .map(|(expected, reproduced)| (expected.as_slice(), reproduced.as_slice()))
    }

    /// Returns whether this replay observed a property failure or timeout.
    pub(crate) fn has_higher_priority_failure_source(&self) -> bool {
        self.triage.failures.iter().any(|failure| {
            matches!(
                failure,
                FailureClusterReportFailure::Property(_) | FailureClusterReportFailure::Timeout(_)
            )
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CrucibleFindingReplayEvidence,
        Vec<CrucibleMeasurementReplayEvidence>,
        Vec<SchedulerEventLogEntry>,
        QemuFindingCandidateTriageInputs,
    ) {
        (
            self.replay,
            self.measurement_replay_evidence,
            self.final_events,
            self.triage,
        )
    }

    /// Returns the second replay's coverage after a paired comparison.
    pub(crate) const fn paired_reproduced_coverage(&self) -> Option<&CoverageProjection> {
        self.paired_reproduced_coverage.as_ref()
    }

    /// Replaces ordinary failure inputs when the same candidate replay diverged.
    pub(crate) fn compare_against_expected_replay(mut self, expected: &Self) -> Self {
        if !self.triage.failures.is_empty() {
            return self;
        }
        let reproduced_coverage = self.replay.coverage().clone();
        if let Some((divergence, selected_expected)) =
            QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
                &expected.triage,
                &self.triage,
            )
        {
            if selected_expected {
                self.replay = expected.replay.clone();
                self.measurement_replay_evidence = expected.measurement_replay_evidence.clone();
                self.final_events = expected.final_events.clone();
            }
            self.triage = divergence;
            self.paired_reproduced_coverage = Some(reproduced_coverage);
        }
        self
    }
}

impl QemuFreshPendingObservation {
    /// Converts one nonterminal origin stop into the next replay start.
    pub(crate) fn into_origin_materialization(
        self,
        completed_quanta: u64,
    ) -> Result<(Configuration, QemuFreshStartMaterialization), QemuFreshModeledDriverError> {
        if !matches!(
            self.stop,
            ModeledStop::Reached(_)
                | ModeledStop::BoundedPrimaryReached { .. }
                | ModeledStop::ObservationReached { .. }
        ) {
            return Err(QemuFreshModeledDriverError::SelectedOriginBoundaryMismatch);
        }
        let materialization = QemuFreshStartMaterialization::from_origin_parts(
            self.event_log,
            self.event_log_bytes,
            completed_quanta,
            self.terminal_at,
            self.terminal_quiescence,
        );
        Ok((self.configuration, materialization))
    }

    /// Converts an authenticated private checkpoint target into replay state.
    pub(crate) fn into_checkpoint_replay_materialization(
        self,
        completed_quanta: u64,
    ) -> Result<QemuFreshStartMaterialization, QemuFreshModeledDriverError> {
        if !matches!(self.stop, ModeledStop::ReplayBoundary) {
            return Err(QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch);
        }
        Ok(QemuFreshStartMaterialization::from_origin_parts(
            self.event_log,
            self.event_log_bytes,
            completed_quanta,
            self.terminal_at,
            self.terminal_quiescence,
        )
        .with_attempt_event_count(self.attempt_event_count))
    }
}

/// Compact proof of the modeled boundary reached by an independent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSavepointReplayProof {
    configuration: ContentHash,
    completed_quanta: u64,
    frontier: VirtualTime,
    event_count: u64,
    event_digest: [u8; 32],
    attempt_event_count: Option<u64>,
}

/// Authenticated event prefix reconstructed at an ordinary attempt's start.
///
/// The proof is sealed before lifecycle shutdown, so it covers inherited
/// genesis-to-start evidence and excludes later same-attempt and final-drain
/// events. Exact resume uses that boundary to derive attempt-local progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuAttemptStartReplayProof {
    configuration: ContentHash,
    event_count: u64,
    event_digest: [u8; 32],
}

impl QemuAttemptStartReplayProof {
    pub(crate) fn from_reached_boundary(
        configuration: &Configuration,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(entries.len())
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        Ok(Self {
            configuration: configuration.id(),
            event_count,
            event_digest: savepoint_event_prefix_digest(entries),
        })
    }

    pub(crate) fn attempt_event_count(
        self,
        start: &Configuration,
        entries: &[SchedulerEventLogEntry],
    ) -> Option<usize> {
        let event_count = usize::try_from(self.event_count).ok()?;
        let prefix = entries.get(..event_count)?;
        (self.configuration == start.id()
            && self.event_digest == savepoint_event_prefix_digest(prefix))
        .then_some(entries.len() - event_count)
    }
}

impl QemuSavepointReplayProof {
    /// Binds a reached configuration to its scheduler coordinate and complete
    /// event prefix.
    ///
    /// # Errors
    ///
    /// Returns [`QemuFreshModeledDriverError::SavepointReplayProof`] when the
    /// event count cannot be represented by the portable proof.
    pub fn from_reached_boundary(
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(entries.len())
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        Ok(Self {
            configuration: configuration.id(),
            completed_quanta,
            frontier,
            event_count,
            event_digest: savepoint_event_prefix_digest(entries),
            attempt_event_count: None,
        })
    }

    pub(crate) fn with_attempt_event_count(
        mut self,
        event_count: usize,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let event_count = u64::try_from(event_count)
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?;
        if event_count > self.event_count {
            return Err(QemuFreshModeledDriverError::SavepointReplayProof);
        }
        self.attempt_event_count = Some(event_count);
        Ok(self)
    }

    pub(crate) const fn attempt_event_count(self) -> Option<u64> {
        self.attempt_event_count
    }

    pub(crate) fn same_boundary(self, other: Self) -> bool {
        self.configuration == other.configuration
            && self.completed_quanta == other.completed_quanta
            && self.frontier == other.frontier
            && self.event_count == other.event_count
            && self.event_digest == other.event_digest
    }

    /// Returns whether one restored checkpoint has this exact modeled boundary.
    #[must_use]
    pub fn matches_checkpoint(
        self,
        configuration: &Configuration,
        scheduler: &crucible::SingleSchedulerCheckpoint,
    ) -> bool {
        self.matches_boundary(
            configuration,
            scheduler.quanta(),
            scheduler.frontier(),
            scheduler.retained_event_log_base_events(),
            scheduler.retained_event_log_entries(),
        )
    }

    /// Returns the cumulative scheduler work required to reconstruct the boundary.
    #[must_use]
    pub const fn completed_quanta(self) -> u64 {
        self.completed_quanta
    }

    pub(crate) fn matches_boundary(
        self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        event_base: u64,
        entries: &[SchedulerEventLogEntry],
    ) -> bool {
        let Ok(event_count) = u64::try_from(entries.len()) else {
            return false;
        };
        self.configuration == configuration.id()
            && self.completed_quanta == completed_quanta
            && self.frontier == frontier
            && event_base == 0
            && self.event_count == event_count
            && self.event_digest == savepoint_event_prefix_digest(entries)
    }
}

/// Modeled driver that records the reached boundary while producing no durable result.
pub(crate) struct QemuSavepointReplayProbe {
    proof: Arc<Mutex<Option<QemuSavepointReplayProof>>>,
}

/// Read side of one independent savepoint replay probe.
pub(crate) struct QemuSavepointReplayReceipt {
    proof: Arc<Mutex<Option<QemuSavepointReplayProof>>>,
}

impl QemuSavepointReplayProbe {
    /// Creates one single-use replay driver and its disjoint proof receipt.
    pub(crate) fn new() -> (Self, QemuSavepointReplayReceipt) {
        let proof = Arc::new(Mutex::new(None));
        (
            Self {
                proof: Arc::clone(&proof),
            },
            QemuSavepointReplayReceipt { proof },
        )
    }
}

impl QemuSavepointReplayReceipt {
    /// Consumes the exact boundary proof recorded before lifecycle shutdown.
    pub(crate) fn take(self) -> Result<QemuSavepointReplayProof, QemuFreshModeledDriverError> {
        self.proof
            .lock()
            .map_err(|_| QemuFreshModeledDriverError::SavepointReplayProof)?
            .take()
            .ok_or(QemuFreshModeledDriverError::SavepointReplayProof)
    }
}

#[derive(Debug)]
enum ModeledStop {
    Reached(StopCondition),
    BoundedPrimaryReached {
        stop: StopCondition,
        proof: BoundedStopProof,
    },
    BoundedPrimaryTimeout {
        stop: StopCondition,
        proof: BoundedStopProof,
    },
    PolicyTimeout {
        stop: StopCondition,
        kind: PolicyTimeoutKind,
        proof: BoundedStopProof,
    },
    ObservationReached {
        proof: Box<ObservationStopProof>,
        evidence: CrucibleObservationBoundaryEvidence,
    },
    ModeledTimeout(String),
    ReplayBoundary,
    TerminalPassed,
    TerminalFailed(Vec<String>),
}

/// Authenticated private target used only to verify a later own checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuSelectedResumeBoundary {
    configuration: Configuration,
    proof: QemuSavepointReplayProof,
}

impl QemuSelectedResumeBoundary {
    /// Binds the complete decoded configuration to its scheduler/evidence proof.
    #[must_use]
    pub const fn new(configuration: Configuration, proof: QemuSavepointReplayProof) -> Self {
        Self {
            configuration,
            proof,
        }
    }

    /// Returns the authenticated full configuration at the checkpoint boundary.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the compact scheduler and event-prefix proof for the boundary.
    #[must_use]
    pub const fn proof(&self) -> QemuSavepointReplayProof {
        self.proof
    }

    fn matches(
        &self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        entries: &[SchedulerEventLogEntry],
    ) -> bool {
        self.configuration == *configuration
            && self
                .proof
                .matches_boundary(configuration, completed_quanta, frontier, 0, entries)
    }

    fn was_passed(&self, completed_quanta: u64, frontier: VirtualTime) -> bool {
        completed_quanta > self.proof.completed_quanta || frontier > self.proof.frontier
    }

    fn matches_pre_choice_quantum(
        &self,
        configuration: &Configuration,
        completed_quanta: u64,
        frontier: VirtualTime,
        prior_entries: &[SchedulerEventLogEntry],
        quantum_entries: &[SchedulerEventLogEntry],
    ) -> bool {
        let Some(event_count) = prior_entries.len().checked_add(quantum_entries.len()) else {
            return false;
        };
        let Ok(portable_event_count) = u64::try_from(event_count) else {
            return false;
        };
        self.configuration == *configuration
            && self.proof.configuration == configuration.id()
            && self.proof.completed_quanta == completed_quanta
            && self.proof.frontier == frontier
            && self.proof.event_count == portable_event_count
            && self.proof.event_digest
                == savepoint_event_prefix_digest_iter(
                    event_count,
                    prior_entries.iter().chain(quantum_entries),
                )
    }
}

impl QemuFreshModeledDriver {
    /// Creates the stateless fresh-attempt driver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Scheduler progress needed by the materialization-independent modeled core.
///
/// Fresh execution and exact resume have different process and checkpoint
/// owners, but they must interpret an admitted attempt and project its result
/// identically. This narrow boundary keeps that semantic loop independent of
/// how the live scheduler was materialized while exposing no shutdown,
/// checkpoint-publication, or resource-release authority.
/// Process-owner-neutral scheduler operations required by modeled campaign execution.
///
/// Implementations expose semantic progress, selectable delivery, quiescence,
/// and network settlement without exposing process termination, resource
/// release, VMState restore, or template recovery authority. Fresh, exact, and
/// hot materialization must implement this same boundary before the common
/// modeled driver can produce campaign evidence.
pub trait QemuModeledAttemptLifecycle {
    /// Installs the exact nonterminal scheduler frontier for this attempt.
    ///
    /// Passing `None` clears the prior attempt's frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the lifecycle cannot install the
    /// frontier without crossing its current scheduler boundary.
    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError>;

    /// Advances exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the guarded scheduler cannot complete
    /// the requested quantum.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;

    /// Returns the absolute scheduler-quantum coordinate at the current boundary.
    #[must_use]
    fn completed_quanta(&self) -> u64;

    /// Observes the current modeled terminal verdict, if any.
    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict>;

    /// Returns whether every live node is at an exact checkpoint boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when quiescence cannot be authenticated.
    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError>;

    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the selectable transport is malformed.
    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError>;

    /// Applies one exact host-authorized selectable reply at the scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the request is stale or the reply is
    /// incompatible with its retained reservation.
    fn apply_selectable_reply(
        &mut self,
        parent: &crucible::Configuration,
        decision: SelectionDecision,
        selected: &crucible::Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError>;

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    fn pending_network_output_count(&self) -> usize;

    /// Samples one node's concrete execution fingerprint for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the stopped node's live state cannot be
    /// read consistently.
    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError>;
}

impl QemuModeledAttemptLifecycle for QemuFreshAttemptLifecycle<'_> {
    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        QemuFreshAttemptLifecycle::set_attempt_stop_frontier(self, frontier)
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        QemuFreshAttemptLifecycle::drive_quantum(self, request)
    }

    fn completed_quanta(&self) -> u64 {
        QemuFreshAttemptLifecycle::completed_quanta(self)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        QemuFreshAttemptLifecycle::terminal_verdict_for_stop(self)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        QemuFreshAttemptLifecycle::exact_checkpoint_ready(self)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        QemuFreshAttemptLifecycle::drain_pending_selectable_requests(self)
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &crucible::Configuration,
        decision: SelectionDecision,
        selected: &crucible::Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        QemuFreshAttemptLifecycle::apply_selectable_reply(
            self, parent, decision, selected, pending, reply,
        )
    }

    fn pending_network_output_count(&self) -> usize {
        QemuFreshAttemptLifecycle::pending_network_output_count(self)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        QemuFreshAttemptLifecycle::sample_fingerprint(self, node)
    }
}

impl QemuFreshAttemptDriver for QemuFreshModeledDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn terminal_checkpoint_choices(
        &self,
        pending: &Self::Pending,
    ) -> Option<(QemuCheckpointChoiceProvenance, u64)> {
        pending.terminal_checkpoint_choices()
    }

    fn has_terminal_assertion_failure(&self, pending: &Self::Pending) -> Result<bool, Self::Error> {
        pending.has_terminal_assertion_failure()
    }

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        drive_modeled_attempt(lifecycle, input, context, materialization)
    }

    fn seal(
        &mut self,
        mut pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        append_event_entries(
            &mut pending.event_log,
            &mut pending.event_log_bytes,
            final_events,
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        build_observation_candidate(pending).map_err(AttemptWorkerFailure::Terminal)
    }
}

impl QemuFindingReplayDriver for QemuFreshModeledDriver {
    fn build_finding_candidate_boundary_evidence(
        &self,
        pending: QemuFreshPendingObservation,
        candidate: &ConfigurationArtifact,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<QemuFindingCandidateBoundaryEvidence, QemuFreshModeledDriverError> {
        build_finding_candidate_boundary_evidence(pending, candidate, final_events, None)
    }
}

impl QemuFreshAttemptDriver for QemuFreshSupplementalModeledDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn terminal_checkpoint_choices(
        &self,
        pending: &Self::Pending,
    ) -> Option<(QemuCheckpointChoiceProvenance, u64)> {
        pending.terminal_checkpoint_choices()
    }

    fn has_terminal_assertion_failure(&self, pending: &Self::Pending) -> Result<bool, Self::Error> {
        pending.has_terminal_assertion_failure()
    }

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        drive_modeled_attempt(lifecycle, input, context, materialization)
    }

    fn seal(
        &mut self,
        mut pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        append_event_entries(
            &mut pending.event_log,
            &mut pending.event_log_bytes,
            final_events,
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        match (self.oracle.as_deref(), self.source) {
            (Some(oracle), Some(source)) => {
                build_observation_candidate_with_supplemental(pending, oracle, source)
            }
            (None, None) => build_observation_candidate(pending),
            (Some(_), None) | (None, Some(_)) => Err(QemuFreshModeledDriverError::ScenarioMismatch),
        }
        .map_err(AttemptWorkerFailure::Terminal)
    }
}

impl QemuFindingReplayDriver for QemuFreshSupplementalModeledDriver {
    fn build_finding_candidate_boundary_evidence(
        &self,
        pending: QemuFreshPendingObservation,
        candidate: &ConfigurationArtifact,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<QemuFindingCandidateBoundaryEvidence, QemuFreshModeledDriverError> {
        match (self.oracle.as_deref(), self.source) {
            (Some(oracle), Some(source)) => build_finding_candidate_boundary_evidence(
                pending,
                candidate,
                final_events,
                Some((oracle, source)),
            ),
            (None, None) => {
                build_finding_candidate_boundary_evidence(pending, candidate, final_events, None)
            }
            (Some(_), None) | (None, Some(_)) => Err(QemuFreshModeledDriverError::ScenarioMismatch),
        }
    }
}

impl QemuFreshAttemptDriver for QemuSavepointReplayProbe {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        let outcome = drive_modeled_attempt(lifecycle, input, context, materialization)?;
        if let QemuFreshDriveOutcome::Observation(pending) = &outcome {
            let proof = QemuSavepointReplayProof::from_reached_boundary(
                &pending.configuration,
                lifecycle.completed_quanta(),
                pending.terminal_at,
                &pending.event_log,
            )
            .map_err(AttemptWorkerFailure::Terminal)?;
            let mut slot = self.proof.lock().map_err(|_| {
                AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::SavepointReplayProof)
            })?;
            if slot.replace(proof).is_some() {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::SavepointReplayProof,
                ));
            }
        }
        Ok(outcome)
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        QemuFreshModeledDriver.seal(pending, final_events)
    }
}

fn savepoint_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> [u8; 32] {
    savepoint_event_prefix_digest_iter(entries.len(), entries.iter())
}

fn savepoint_event_prefix_digest_iter<'a>(
    count: usize,
    entries: impl Iterator<Item = &'a SchedulerEventLogEntry>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
    hasher.update(&(count as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.sequence().to_be_bytes());
        hasher.update(&entry.content_hash().bytes);
    }
    *hasher.finalize().as_bytes()
}

/// Drives one already-materialized attempt through its declared modeled stop.
pub(crate) fn drive_modeled_attempt(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    materialization: QemuFreshStartMaterialization,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    drive_modeled_attempt_inner(lifecycle, input, context, materialization, None)
}

/// Replays one attempt to a private authenticated checkpoint boundary.
pub(crate) fn replay_modeled_attempt_to_boundary(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    materialization: QemuFreshStartMaterialization,
    target: &QemuSelectedResumeBoundary,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    drive_modeled_attempt_inner(lifecycle, input, context, materialization, Some(target))
}

fn drive_modeled_attempt_inner(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    mut materialization: QemuFreshStartMaterialization,
    replay_target: Option<&QemuSelectedResumeBoundary>,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    let scenario = input.scenario().scenario_def();
    let mut observed_event_count = materialization.attempt_event_count();
    let replayed_discoveries = materialization.take_replayed_discoveries();
    let mut configuration = materialization
        .restored_configuration()
        .unwrap_or_else(|| input.start().configuration())
        .clone();
    if configuration.def != scenario {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::ScenarioMismatch,
        ));
    }

    let (
        mut event_log,
        mut event_log_bytes,
        mut completed_quanta,
        frontier,
        mut terminal_quiescence,
        terminal_verdict,
    ) = materialization.into_parts();
    let authoritative_quanta = lifecycle.completed_quanta();
    if completed_quanta != authoritative_quanta {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::StartQuantumCoordinateMismatch {
                materialized: completed_quanta,
                authoritative: authoritative_quanta,
            },
        ));
    }
    lifecycle
        .set_attempt_stop_frontier(None)
        .map_err(classify_scheduler_error)?;
    let mut terminal_at = frontier;
    let mut discoveries = RetainedChoiceDiscoveries::from_replayed(replayed_discoveries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    check_cancellation(context)?;
    if let Some(verdict) = terminal_verdict {
        let stop = modeled_terminal_stop(verdict).map_err(AttemptWorkerFailure::Terminal)?;
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
    // A policy deadline already reached at the start remains a modeled timeout.
    // Otherwise a choice-or-quanta fallback can be authenticated only at its
    // exact quantum; an attempt starting past it has no valid primary proof.
    if policy_timeout_at(input.attempt().stop(), terminal_at, completed_quanta).is_none()
        && matches!(
            input.attempt().stop().primary(),
            StopCondition::NextChoiceOrExecutionQuanta { execution_quanta }
                if completed_quanta > *execution_quanta
        )
    {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::SelectedResumeBeyondAttemptStop,
        ));
    }
    if replay_target.is_some_and(|target| {
        target.matches(&configuration, completed_quanta, terminal_at, &event_log)
    }) {
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: ModeledStop::ReplayBoundary,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
    if let Some(initial_stop) = initial_requested_stop(
        input.attempt().stop(),
        terminal_at,
        completed_quanta,
        observed_event_count,
    ) {
        if replay_target.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::SelectedResumeBeyondAttemptStop,
            ));
        }
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: initial_stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
    if checkpoint_is_ready(lifecycle, context)? {
        return Ok(QemuFreshDriveOutcome::CheckpointRequested(
            QemuCheckpointChoiceProvenance::new(configuration, discoveries.discoveries),
        ));
    }

    let initial_choice_count = discoveries.discoveries.len();
    let initial_reply_entries = resolve_pending_guest_choices_at_configuration(
        lifecycle,
        input,
        context,
        &mut configuration,
        &mut discoveries,
    )?;
    observed_event_count = observed_event_count
        .checked_add(initial_reply_entries.len())
        .ok_or(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-event-log-entry-count",
            },
        ))?;
    append_event_entries(&mut event_log, &mut event_log_bytes, initial_reply_entries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    if replay_target.is_some_and(|target| {
        target.matches(&configuration, completed_quanta, terminal_at, &event_log)
    }) {
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: ModeledStop::ReplayBoundary,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
    if input.attempt().stop().accepts_next_choice()
        && discoveries.discoveries.len() > initial_choice_count
    {
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: primary_stop_at(input.attempt().stop(), terminal_at, completed_quanta),
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
    if matches!(
        input.attempt().stop().primary(),
        StopCondition::EventCount(count)
            if u64::try_from(observed_event_count).is_ok_and(|events| events >= *count)
    ) {
        if replay_target.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::SelectedResumeBeyondAttemptStop,
            ));
        }
        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop: primary_stop_at(input.attempt().stop(), terminal_at, completed_quanta),
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }

    if let Some(frontier) = requested_attempt_stop_frontier(input.attempt().stop()) {
        lifecycle
            .set_attempt_stop_frontier(Some(frontier))
            .map_err(classify_scheduler_error)?;
    }

    loop {
        if check_operational_signals(lifecycle, context)? {
            return Ok(QemuFreshDriveOutcome::CheckpointRequested(
                QemuCheckpointChoiceProvenance::new(configuration, discoveries.discoveries),
            ));
        }
        context.charge_execution_quantum().map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::ResourceRefusal(error))
        })?;
        let quantum_start_completed_quanta = completed_quanta;
        let mut outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            })
            .map_err(classify_scheduler_error)?;
        let next_completed_quanta = lifecycle.completed_quanta();
        if next_completed_quanta < completed_quanta {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::QuantumCounterRegressed {
                    before: completed_quanta,
                    after: next_completed_quanta,
                },
            ));
        }
        completed_quanta = next_completed_quanta;
        if outcome.configuration.def != scenario {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::ScenarioMismatch,
            ));
        }

        check_cancellation(context)?;
        let terminal_stop = match lifecycle.terminal_verdict_for_stop() {
            Some(QuantumTerminalVerdict::Passed) => Some(ModeledStop::TerminalPassed),
            Some(verdict @ QuantumTerminalVerdict::Failed(_)) => {
                Some(modeled_terminal_stop(verdict).map_err(AttemptWorkerFailure::Terminal)?)
            }
            None => None,
        };
        if terminal_stop.is_none()
            && replay_target.is_some_and(|target| {
                target.matches_pre_choice_quantum(
                    &outcome.configuration,
                    completed_quanta,
                    terminal_at.max(outcome.frontier),
                    &event_log,
                    &outcome.event_log_entries,
                )
            })
        {
            let attempt_event_count = observed_event_count
                .checked_add(outcome.event_log_entries.len())
                .ok_or(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::LimitExceeded {
                        limit: "fresh-campaign-event-log-entry-count",
                    },
                ))?;
            configuration = append_quantum(
                &mut event_log,
                &mut event_log_bytes,
                &mut discoveries,
                &mut terminal_quiescence,
                &mut terminal_at,
                false,
                outcome,
            )?;
            require_settled_network(lifecycle)?;
            return modeled_stop_outcome(
                lifecycle,
                context,
                QemuFreshPendingObservation {
                    input: input.clone(),
                    configuration,
                    stop: ModeledStop::ReplayBoundary,
                    event_log,
                    event_log_bytes,
                    discoveries: discoveries.discoveries,
                    terminal_quiescence,
                    terminal_at,
                    completed_quanta,
                    attempt_event_count,
                },
            );
        }
        let policy_stop = terminal_stop
            .is_none()
            .then(|| policy_timeout_at(input.attempt().stop(), outcome.frontier, completed_quanta))
            .flatten();
        let observation_stop = if terminal_stop.is_none()
            && policy_stop.is_none()
            && matches!(
                input.attempt().stop().primary(),
                StopCondition::Observation(_)
            ) {
            let evidence = QuantumStopEvidence {
                properties: input.scenario().properties(),
                outcome: &outcome,
                observed_event_count,
                quantum_start_completed_quanta,
                completed_quanta,
                discoveries: &discoveries.discoveries,
                prior_entries: &event_log,
            };
            reached_requested_stop(input.attempt().stop(), &evidence)
                .map_err(AttemptWorkerFailure::Terminal)?
        } else {
            None
        };
        if terminal_stop.is_none() && policy_stop.is_none() && observation_stop.is_none() {
            resolve_pending_guest_choices(
                lifecycle,
                input,
                context,
                &mut outcome,
                &mut discoveries,
            )?;
        }
        let stop = if let Some(stop) = terminal_stop {
            Some(stop)
        } else if policy_stop.is_some() {
            policy_stop
        } else if observation_stop.is_some() {
            observation_stop
        } else {
            let evidence = QuantumStopEvidence {
                properties: input.scenario().properties(),
                outcome: &outcome,
                observed_event_count,
                quantum_start_completed_quanta,
                completed_quanta,
                discoveries: &discoveries.discoveries,
                prior_entries: &event_log,
            };
            reached_requested_stop(input.attempt().stop(), &evidence)
                .map_err(AttemptWorkerFailure::Terminal)?
        };
        observed_event_count = observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .ok_or(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::LimitExceeded {
                    limit: "fresh-campaign-event-log-entry-count",
                },
            ))?;
        let retain_signal_fault_discoveries = matches!(
            stop.as_ref(),
            Some(ModeledStop::Reached(stop))
                if stop == input.attempt().stop().primary() && stop.accepts_next_choice()
        ) || matches!(
            stop.as_ref(),
            Some(ModeledStop::BoundedPrimaryReached { stop, .. })
                if stop.primary().accepts_next_choice()
        );
        configuration = append_quantum(
            &mut event_log,
            &mut event_log_bytes,
            &mut discoveries,
            &mut terminal_quiescence,
            &mut terminal_at,
            retain_signal_fault_discoveries,
            outcome,
        )?;
        if let Some(target) = replay_target {
            if target.matches(&configuration, completed_quanta, terminal_at, &event_log) {
                require_settled_network(lifecycle)?;
                return modeled_stop_outcome(
                    lifecycle,
                    context,
                    QemuFreshPendingObservation {
                        input: input.clone(),
                        configuration,
                        stop: ModeledStop::ReplayBoundary,
                        event_log,
                        event_log_bytes,
                        discoveries: discoveries.discoveries,
                        terminal_quiescence,
                        terminal_at,
                        completed_quanta,
                        attempt_event_count: observed_event_count,
                    },
                );
            }
            if stop.is_some() {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::SelectedResumeBeyondAttemptStop,
                ));
            }
            if target.was_passed(completed_quanta, terminal_at) {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch,
                ));
            }
        }
        let Some(stop) = stop else {
            if checkpoint_is_ready(lifecycle, context)? {
                return Ok(QemuFreshDriveOutcome::CheckpointRequested(
                    QemuCheckpointChoiceProvenance::new(configuration, discoveries.discoveries),
                ));
            }
            continue;
        };

        require_settled_network(lifecycle)?;
        return modeled_stop_outcome(
            lifecycle,
            context,
            QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
                completed_quanta,
                attempt_event_count: observed_event_count,
            },
        );
    }
}

fn requested_attempt_stop_frontier(requested: &StopCondition) -> Option<VirtualTime> {
    match requested {
        StopCondition::Bounded {
            primary,
            virtual_time_nanoseconds,
            ..
        } => requested_attempt_stop_frontier(primary)
            .map(|frontier| frontier.ticks)
            .into_iter()
            .chain(*virtual_time_nanoseconds)
            .min()
            .map(|ticks| VirtualTime { ticks }),
        StopCondition::VirtualTimeNanoseconds(deadline) => Some(VirtualTime { ticks: *deadline }),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            ..
        } => Some(VirtualTime {
            ticks: *virtual_time_nanoseconds,
        }),
        StopCondition::NextChoice
        | StopCondition::NextChoiceOrExecutionQuanta { .. }
        | StopCondition::NamedBoundary(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal
        | StopCondition::ExecutionQuanta(_)
        | StopCondition::Observation(_) => None,
    }
}

fn modeled_stop_outcome(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
    pending: QemuFreshPendingObservation,
) -> Result<
    QemuFreshDriveOutcome<QemuFreshPendingObservation>,
    AttemptWorkerFailure<QemuFreshModeledDriverError>,
> {
    if !matches!(
        context.start_mode(),
        AttemptStartMode::SavepointCapture { .. }
    ) {
        return Ok(QemuFreshDriveOutcome::Observation(pending));
    }
    if !context.checkpoint_request().is_requested() {
        return Err(classify_scheduler_error(
            SchedulerError::BoundaryViolation {
                message: String::from(
                    "savepoint capture reached its stop without a checkpoint request",
                ),
            },
        ));
    }
    if !lifecycle
        .exact_checkpoint_ready()
        .map_err(classify_scheduler_error)?
    {
        return Err(classify_scheduler_error(
            SchedulerError::BoundaryViolation {
                message: String::from("savepoint capture stop is not checkpoint ready"),
            },
        ));
    }
    Ok(QemuFreshDriveOutcome::CheckpointRequested(
        pending.into_checkpoint_choices(),
    ))
}

fn resolve_pending_guest_choices(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    outcome: &mut QuantumOutcome,
    discoveries: &mut RetainedChoiceDiscoveries,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let entries = resolve_pending_guest_choices_at_configuration(
        lifecycle,
        input,
        context,
        &mut outcome.configuration,
        discoveries,
    )?;
    outcome.event_log_entries.extend(entries);
    Ok(())
}

fn resolve_pending_guest_choices_at_configuration(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    configuration: &mut Configuration,
    discoveries: &mut RetainedChoiceDiscoveries,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let pending = lifecycle
        .drain_pending_selectable_requests()
        .map_err(classify_scheduler_error)?;
    let mut continuations = Vec::with_capacity(pending.len());
    for pending in pending {
        let discovery = resolve_guest_selectable(
            input.lineage().scenario(),
            input.scenario(),
            pending.node(),
            pending.pending(),
        )
        .map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(error))
        })?;
        let fingerprint = if context.guest_selectable_boundary_diagnostic_sample_permitted() {
            lifecycle.sample_fingerprint(pending.node().clone()).ok()
        } else {
            None
        };
        record_guest_selectable_boundary_diagnostic(
            context,
            input.attempt(),
            GuestSelectableBoundaryDiagnosticStage::SourceDiscovery,
            configuration.schedule.len(),
            pending.node(),
            pending.pending(),
            &discovery,
            None,
            fingerprint,
        );
        discoveries
            .insert(discovery.clone())
            .map_err(AttemptWorkerFailure::Terminal)?;
        if !input.attempt().stop().accepts_next_choice() {
            let selection = Selection::new(
                discovery.opportunity(),
                discovery.domain(),
                discovery.opportunity().default().clone(),
                SelectionOrigin::Default,
            )
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(
                    GuestSelectableError::Campaign(error),
                ))
            })?;
            let reply = selected_guest_reply(pending.pending(), &discovery, &selection).map_err(
                |error| {
                    AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::GuestSelectable(
                        error,
                    ))
                },
            )?;
            continuations.push((pending, reply, SelectionDecision::new(&selection)));
        }
    }
    let mut entries = Vec::new();
    for (pending, reply, decision) in continuations {
        let parent = configuration.clone();
        let selected =
            try_step(&parent, Decision::Selection(decision.clone())).map_err(|source| {
                classify_scheduler_error(SchedulerError::BoundaryViolation {
                    message: format!("guest selection violated the scenario model: {source}"),
                })
            })?;
        let reply_entries = lifecycle
            .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
            .map_err(classify_scheduler_error)?;
        *configuration = selected;
        entries.extend(reply_entries);
    }
    Ok(entries)
}

fn require_settled_network(
    lifecycle: &(impl QemuModeledAttemptLifecycle + ?Sized),
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let pending = lifecycle.pending_network_output_count();
    if pending == 0 {
        Ok(())
    } else {
        Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::PendingNetworkOutput(pending),
        ))
    }
}

fn check_operational_signals(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    check_cancellation(context)?;
    checkpoint_is_ready(lifecycle, context)
}

fn check_cancellation(
    context: &AttemptExecutionContext,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if context.cancellation().is_canceled() {
        return Err(AttemptWorkerFailure::Canceled(
            QemuFreshModeledDriverError::Canceled,
        ));
    }
    Ok(())
}

fn checkpoint_is_ready(
    lifecycle: &mut (impl QemuModeledAttemptLifecycle + ?Sized),
    context: &AttemptExecutionContext,
) -> Result<bool, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if matches!(
        context.start_mode(),
        AttemptStartMode::SavepointCapture { .. }
    ) {
        return Ok(false);
    }
    if context.checkpoint_request().is_requested() {
        return lifecycle
            .exact_checkpoint_ready()
            .map_err(classify_scheduler_error);
    }
    Ok(false)
}

fn classify_scheduler_error(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshModeledDriverError> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshModeledDriverError::Scheduler(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_signal_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<crucible::Configuration, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let QuantumOutcome {
        configuration,
        discovered_choices,
        event_log_entries,
        scheduler_quiescence,
        frontier,
        ..
    } = outcome;
    append_event_entries(event_log, event_log_bytes, event_log_entries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    for discovery in discovered_choices {
        if is_signal_fault_discovery(&discovery) && !retain_signal_fault_discoveries {
            continue;
        }
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn is_signal_fault_discovery(discovery: &ChoiceDiscovery) -> bool {
    matches!(
        discovery.opportunity().source(),
        crucible_campaign::ChoiceSource::Environment { adapter, .. }
            if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
    )
}

fn append_event_entries(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    retained_bytes: &mut usize,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<(), QemuFreshModeledDriverError> {
    let total = event_log.len().checked_add(entries.len()).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        },
    )?;
    if total > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        });
    }
    let added_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry.canonical_material_len()).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            },
        )
    })?;
    let total_bytes = retained_bytes.checked_add(added_bytes).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        },
    )?;
    if total_bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        });
    }
    event_log.extend(entries);
    *retained_bytes = total_bytes;
    Ok(())
}

#[derive(Default)]
struct RetainedChoiceDiscoveries {
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    charged_records: BTreeSet<ContentId>,
    charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    fn from_replayed(
        replayed: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let mut discoveries = Self::default();
        for discovery in replayed.into_values() {
            discoveries.insert(discovery)?;
        }
        Ok(discoveries)
    }

    fn insert(
        &mut self,
        mut discovery: ChoiceDiscovery,
    ) -> Result<(), QemuFreshModeledDriverError> {
        let declaration = discovery.opportunity().declaration();
        let domain = discovery.opportunity().domain();
        let opportunity = discovery.opportunity().id()?;
        let contract = (declaration, domain);
        if let Some(validated) = self.representatives.get(&contract) {
            discovery.share_dependencies_from(validated)?;
        } else {
            self.charge(
                declaration.content_id(),
                discovery.declaration().canonical_bytes().len(),
            )?;
            self.charge(
                domain.content_id(),
                discovery.domain().canonical_bytes().len(),
            )?;
            self.representatives.insert(contract, discovery.clone());
        }

        if let Some(existing) = self.discoveries.get(&opportunity) {
            if existing.opportunity() != discovery.opportunity() {
                return Err(QemuFreshModeledDriverError::ConflictingChoice(opportunity));
            }
            return Ok(());
        }
        if self.discoveries.len() == MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-count",
            });
        }
        self.charge(
            opportunity.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        )?;
        self.discoveries.insert(opportunity, discovery);
        Ok(())
    }

    fn charge(&mut self, id: ContentId, bytes: usize) -> Result<(), QemuFreshModeledDriverError> {
        if !self.charged_records.insert(id) {
            return Ok(());
        }
        let total = self.charged_bytes.checked_add(bytes).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            },
        )?;
        if total > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            });
        }
        self.charged_bytes = total;
        Ok(())
    }
}

struct QuantumStopEvidence<'a> {
    properties: &'a crucible::Properties,
    outcome: &'a QuantumOutcome,
    observed_event_count: usize,
    quantum_start_completed_quanta: u64,
    completed_quanta: u64,
    discoveries: &'a BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    prior_entries: &'a [SchedulerEventLogEntry],
}

fn reached_requested_stop(
    requested: &StopCondition,
    evidence: &QuantumStopEvidence<'_>,
) -> Result<Option<ModeledStop>, QemuFreshModeledDriverError> {
    if let StopCondition::Bounded { primary, .. } = requested {
        let proof =
            BoundedStopProof::new(evidence.outcome.frontier.ticks, evidence.completed_quanta);
        if let Some(timeout) = policy_timeout_at(
            requested,
            evidence.outcome.frontier,
            evidence.completed_quanta,
        ) {
            return Ok(Some(timeout));
        }
        return reached_requested_stop(primary, evidence).map(|stop| {
            stop.map(|stop| match stop {
                ModeledStop::Reached(_) => ModeledStop::BoundedPrimaryReached {
                    stop: requested.clone(),
                    proof,
                },
                ModeledStop::ModeledTimeout(_) => ModeledStop::BoundedPrimaryTimeout {
                    stop: requested.clone(),
                    proof,
                },
                other => other,
            })
        });
    }

    let QuantumStopEvidence {
        outcome,
        observed_event_count,
        completed_quanta,
        discoveries,
        ..
    } = evidence;
    let reached = match requested {
        StopCondition::NextChoice => {
            !discoveries.is_empty() || !outcome.discovered_choices.is_empty()
        }
        StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => {
            // A choice is eligible only before the intrinsic quantum fallback.
            // At the completed fallback quantum the timeout wins the tie.
            if *completed_quanta >= *execution_quanta {
                return Ok(Some(ModeledStop::ModeledTimeout(String::from(
                    "execution-quanta",
                ))));
            }
            if !discoveries.is_empty() || !outcome.discovered_choices.is_empty() {
                return Ok(Some(ModeledStop::Reached(requested.clone())));
            }
            return Ok(None);
        }
        StopCondition::NamedBoundary(name) => outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                    marker,
                    ..
                }) if marker.name == *name
            )
        }),
        StopCondition::VirtualTimeNanoseconds(deadline) => outcome.frontier.ticks >= *deadline,
        StopCondition::EventCount(count) => observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .and_then(|events| u64::try_from(events).ok())
            .is_some_and(|events| events >= *count),
        StopCondition::Terminal => false,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => {
            outcome.frontier.ticks >= *virtual_time_nanoseconds
                || completed_quanta >= execution_quanta
        }
        StopCondition::Observation(condition) => {
            return observation_stop_proof(
                condition,
                evidence.properties,
                evidence.outcome,
                evidence.quantum_start_completed_quanta,
                evidence.completed_quanta,
                evidence.prior_entries,
            )
            .map(|reached| {
                reached.map(|(proof, evidence)| ModeledStop::ObservationReached {
                    proof: Box::new(proof),
                    evidence,
                })
            });
        }
        StopCondition::Bounded { .. } => {
            return Err(QemuFreshModeledDriverError::BoundedStopProof);
        }
    };
    Ok(reached.then(|| ModeledStop::Reached(requested.clone())))
}

fn policy_timeout_at(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> Option<ModeledStop> {
    let StopCondition::Bounded {
        virtual_time_nanoseconds,
        execution_quanta,
        ..
    } = requested
    else {
        return None;
    };
    let proof = BoundedStopProof::new(frontier.ticks, completed_quanta);
    let kind = if virtual_time_nanoseconds.is_some_and(|deadline| frontier.ticks >= deadline) {
        PolicyTimeoutKind::VirtualTime
    } else if execution_quanta.is_some_and(|deadline| completed_quanta >= deadline) {
        PolicyTimeoutKind::ExecutionQuanta
    } else {
        return None;
    };
    Some(ModeledStop::PolicyTimeout {
        stop: requested.clone(),
        kind,
        proof,
    })
}

fn observation_stop_proof(
    condition: &ObservationCondition,
    properties: &crucible::Properties,
    outcome: &QuantumOutcome,
    quantum_start_completed_quanta: u64,
    completed_quanta: u64,
    prior_entries: &[SchedulerEventLogEntry],
) -> Result<
    Option<(ObservationStopProof, CrucibleObservationBoundaryEvidence)>,
    QemuFreshModeledDriverError,
> {
    let (satisfaction, assertion_witness) = match condition {
        ObservationCondition::SchedulerQuiescent => {
            if !outcome
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
            {
                return Ok(None);
            }
            (ObservationStopSatisfaction::SchedulerQuiescent, None)
        }
        ObservationCondition::AssertionViolationTransition(assertion) => {
            let Some(entry) = outcome.event_log_entries.iter().find(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged { name, state }
                    ) if name.name == *assertion
                        && *state == AssertionPhase::Violated
                        && assertion_is_declared(properties, &name.name)
                )
            }) else {
                return Ok(None);
            };
            (
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(AssertionViolationWitness::new(
                    assertion.clone(),
                    entry.sequence(),
                    CampaignHash::from_bytes(entry.content_hash().bytes),
                )?),
            )
        }
        ObservationCondition::AnyAssertionViolationTransition => {
            let Some((entry, assertion)) = outcome.event_log_entries.iter().find_map(|entry| {
                let SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::AssertionStateChanged { name, state },
                ) = entry.payload()
                else {
                    return None;
                };
                (*state == AssertionPhase::Violated
                    && assertion_is_declared(properties, &name.name))
                .then_some((entry, name.name.as_str()))
            }) else {
                return Ok(None);
            };
            (
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(AssertionViolationWitness::new(
                    assertion,
                    entry.sequence(),
                    CampaignHash::from_bytes(entry.content_hash().bytes),
                )?),
            )
        }
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
            if outcome
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
            {
                (ObservationStopSatisfaction::SchedulerQuiescent, None)
            } else if completed_quanta >= *execution_quanta {
                (ObservationStopSatisfaction::ExecutionQuanta, None)
            } else {
                return Ok(None);
            }
        }
    };
    if completed_quanta <= quantum_start_completed_quanta {
        return Err(QemuFreshModeledDriverError::QuantumCounterDidNotAdvance {
            before: quantum_start_completed_quanta,
            after: completed_quanta,
        });
    }
    let event_count = prior_entries
        .len()
        .checked_add(outcome.event_log_entries.len())
        .ok_or(QemuFreshModeledDriverError::LimitExceeded {
            limit: "observation-stop-event-count",
        })?;
    let portable_event_count =
        u64::try_from(event_count).map_err(|_| QemuFreshModeledDriverError::LimitExceeded {
            limit: "observation-stop-event-count",
        })?;
    if outcome.event_log_offset.events != portable_event_count {
        return Err(QemuFreshModeledDriverError::ObservationStopProof);
    }
    let offset = outcome.event_log_offset;
    let event_log = ObservationEventLogProof::new(
        CampaignHash::from_bytes(offset.prefix.bytes),
        offset
            .appended_segment
            .map(|hash| CampaignHash::from_bytes(hash.bytes)),
        offset.bytes,
        offset.events,
        CampaignHash::from_bytes(savepoint_event_prefix_digest_iter(
            event_count,
            prior_entries.iter().chain(&outcome.event_log_entries),
        )),
    );
    let quantum_start_events = u64::try_from(prior_entries.len()).map_err(|_| {
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "observation-stop-event-count",
        }
    })?;
    let boundary = ObservationQuantumBoundary::new(
        outcome.frontier.ticks,
        quantum_start_completed_quanta,
        completed_quanta,
        quantum_start_events,
    )?;
    let retained_boundary = CrucibleObservationBoundaryEvidence::new(
        outcome.frontier,
        quantum_start_completed_quanta,
        completed_quanta,
        quantum_start_events,
        outcome.event_log_offset,
        outcome
            .scheduler_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    )
    .map_err(QemuFreshModeledDriverError::Measurements)?;
    let proof = ObservationStopProof::new(
        condition.clone(),
        satisfaction,
        ConfigurationId::from_hash(CampaignHash::from_bytes(outcome.configuration.id().bytes)),
        boundary,
        event_log,
        assertion_witness,
    )?;
    Ok(Some((proof, retained_boundary)))
}

fn assertion_is_declared(properties: &crucible::Properties, assertion: &str) -> bool {
    properties
        .assertions()
        .iter()
        .any(|declaration| declaration.id.name == assertion)
}

fn initial_requested_stop(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
    observed_event_count: usize,
) -> Option<ModeledStop> {
    if let StopCondition::Bounded { primary, .. } = requested {
        let proof = BoundedStopProof::new(frontier.ticks, completed_quanta);
        if let Some(timeout) = policy_timeout_at(requested, frontier, completed_quanta) {
            return Some(timeout);
        }
        return initial_requested_stop(primary, frontier, completed_quanta, observed_event_count)
            .map(|stop| match stop {
                ModeledStop::Reached(_) => ModeledStop::BoundedPrimaryReached {
                    stop: requested.clone(),
                    proof,
                },
                ModeledStop::ModeledTimeout(_) => ModeledStop::BoundedPrimaryTimeout {
                    stop: requested.clone(),
                    proof,
                },
                other => other,
            });
    }

    let reached = match requested {
        StopCondition::VirtualTimeNanoseconds(deadline) => frontier.ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => frontier.ticks >= *virtual_time_nanoseconds || completed_quanta >= *execution_quanta,
        StopCondition::EventCount(count) => {
            u64::try_from(observed_event_count).is_ok_and(|observed| observed >= *count)
        }
        StopCondition::NextChoice
        | StopCondition::NamedBoundary(_)
        | StopCondition::Terminal
        | StopCondition::Observation(_) => false,
        StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => {
            return (completed_quanta >= *execution_quanta)
                .then(|| ModeledStop::ModeledTimeout(String::from("execution-quanta")));
        }
        StopCondition::Bounded { .. } => return None,
    };
    reached.then(|| ModeledStop::Reached(requested.clone()))
}

fn primary_stop_at(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> ModeledStop {
    if matches!(requested, StopCondition::Bounded { .. }) {
        ModeledStop::BoundedPrimaryReached {
            stop: requested.clone(),
            proof: BoundedStopProof::new(frontier.ticks, completed_quanta),
        }
    } else {
        ModeledStop::Reached(requested.clone())
    }
}

fn build_observation_candidate(
    pending: QemuFreshPendingObservation,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, None)
}

fn build_observation_candidate_with_supplemental(
    pending: QemuFreshPendingObservation,
    oracle: &dyn GuardedCampaignFindingOracle,
    source: ContentId,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, Some((oracle, source)))
}

fn build_observation_candidate_inner(
    pending: QemuFreshPendingObservation,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    let projection = project_boundary(pending, true, supplemental_oracle)?;
    let observation = Observation::new(
        projection.input.attempt().id()?,
        Observation::outcome(
            projection.child.configuration(),
            projection.child.id()?,
            projection.input.path().id()?,
            projection
                .stop
                .ok_or(QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch)?,
            projection.measurements.id()?,
            projection.properties.id()?,
            projection.coverage.id()?,
        ),
        projection.discovered_ids,
    )?;
    let candidate = ObservationCandidate::new(
        projection.child,
        projection.measurements,
        projection.properties,
        projection.coverage,
        projection.discovered_choices,
        observation,
    )
    .and_then(|candidate| candidate.with_produced_selections(projection.produced_selections))?;
    let result =
        PreparedSemanticAttemptResult::new(candidate, vec![projection.measurement_evidence], None)?;
    Ok(AttemptExecutionProduct::prepared_semantic(result))
}

struct QemuBoundaryProjection {
    input: CrucibleAttemptExecution,
    child: ConfigurationArtifact,
    measurement_evidence: CrucibleMeasurementReplayEvidence,
    measurements: crucible_campaign::MeasurementSet,
    properties: PropertyVerdictSet,
    failures: Vec<FailureClusterReportFailure>,
    coverage: CoverageProjection,
    discovered_choices: Vec<ChoiceDiscovery>,
    discovered_ids: BTreeSet<ChoiceOpportunityId>,
    produced_selections: Vec<Selection>,
    stop: Option<StopOutcome>,
}

fn check_pending_assertions(
    pending: &QemuFreshPendingObservation,
) -> Result<crucible::HostAssertionReport, QemuFreshModeledDriverError> {
    let assertion_count = pending
        .input
        .scenario()
        .properties()
        .assertions()
        .len()
        .max(1);
    let assertion_visits = pending.event_log.len().checked_mul(assertion_count).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        },
    )?;
    if assertion_visits > MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        });
    }

    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(pending.input.scenario().world());
    if let Some(quiescence) = pending.terminal_quiescence.clone() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    checker
        .check_run(pending.input.scenario().properties(), &pending.event_log)
        .map_err(Into::into)
}

fn project_boundary(
    mut pending: QemuFreshPendingObservation,
    project_stop: bool,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
) -> Result<QemuBoundaryProjection, QemuFreshModeledDriverError> {
    let timeout = retain_modeled_timeout(&mut pending)?;
    let report = check_pending_assertions(&pending)?;
    let supplemental = supplemental_oracle
        .map(|(oracle, source)| {
            oracle
                .evaluate(&pending.configuration)
                .map(|evaluation| evaluation.map(|evaluation| (evaluation, source)))
        })
        .transpose()
        .map_err(QemuFreshModeledDriverError::SupplementalFinding)?
        .flatten();
    if let Some((evaluation, _)) = &supplemental
        && !report
            .outcomes()
            .iter()
            .any(|outcome| outcome.assertion.name == evaluation.property())
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let properties = property_verdicts(&report, supplemental.as_ref())?;
    let mut failures: Vec<_> = report
        .violations()
        .iter()
        .cloned()
        .map(FailurePropertyViolationRecord::new)
        .map(FailureClusterReportFailure::property)
        .collect();
    if let Some((evaluation, _)) = &supplemental {
        failures.retain(|failure| {
            !matches!(
                failure,
                FailureClusterReportFailure::Property(record)
                    if record.violation.assertion.name == evaluation.property()
            )
        });
        failures.push(FailureClusterReportFailure::property(
            FailurePropertyViolationRecord::new(evaluation.violation().clone()),
        ));
    }
    if let Some(timeout) = timeout {
        failures.push(FailureClusterReportFailure::timeout(timeout));
    }

    let scenario_artifact = encode_crucible_scenario_artifact(pending.input.scenario())?;
    if scenario_artifact.id()? != pending.input.lineage().scenario_content()
        || scenario_artifact.scenario() != pending.input.lineage().scenario()
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let child = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &pending.configuration.schedule,
    )?;
    let measurement_publication = campaign_measurements(&pending, child.configuration())?;
    let (measurement_evidence, _, measurements) = measurement_publication.into_parts();
    let mut stop = project_stop
        .then(|| stop_outcome(pending.stop, &report))
        .transpose()?;
    if report.verdict().failures().is_empty()
        && let Some((evaluation, _)) = &supplemental
        && let Some(stop) = &mut stop
    {
        *stop = StopOutcome::AssertionFailure(evaluation.property().to_owned());
    }
    let coverage = coverage_projection(&pending.event_log)?;
    let discovered_choices = pending.discoveries.into_values().collect::<Vec<_>>();
    let discovered_ids = discovered_choices
        .iter()
        .map(|discovery| discovery.opportunity().id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let produced_selections = produced_selections_after_start(
        pending.input.start().configuration(),
        &pending.configuration,
        &discovered_ids,
    )?;
    Ok(QemuBoundaryProjection {
        input: pending.input,
        child,
        measurement_evidence,
        measurements,
        properties,
        failures,
        coverage,
        discovered_choices,
        discovered_ids,
        produced_selections,
        stop,
    })
}

fn retain_modeled_timeout(
    pending: &mut QemuFreshPendingObservation,
) -> Result<Option<FailureTimeoutRecord>, QemuFreshModeledDriverError> {
    if let ModeledStop::PolicyTimeout { proof, .. } = &pending.stop
        && (proof.frontier_nanoseconds() != pending.terminal_at.ticks
            || proof.completed_quanta() != pending.completed_quanta)
    {
        return Err(QemuFreshModeledDriverError::BoundedStopProof);
    }
    let Some((budget_kind, configured_limit)) = modeled_timeout_limit(pending) else {
        return Ok(None);
    };
    let observed = match budget_kind {
        FailureTimeoutBudgetKind::ExecutionQuanta => pending.completed_quanta,
        FailureTimeoutBudgetKind::VirtualTime => pending.terminal_at.ticks,
    };
    if observed < configured_limit {
        return Ok(None);
    }

    let budget_name = match budget_kind {
        FailureTimeoutBudgetKind::ExecutionQuanta => "execution-quanta",
        FailureTimeoutBudgetKind::VirtualTime => "virtual-time",
    };

    let retained_marker = pending.event_log.iter().rev().find(|entry| {
        entry.event_payload().kind() == "execution_budget_exhausted"
            && entry.event_payload().string("budget_kind") == Some(budget_name)
            && entry.at() == pending.terminal_at
    });
    let marker = if let Some(marker) = retained_marker {
        marker.clone()
    } else {
        let sequence = pending
            .event_log
            .last()
            .map_or(Some(0), |entry| entry.sequence().checked_add(1))
            .ok_or(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-event-log-sequence",
            })?;
        let boundary = pending
            .event_log
            .last()
            .map_or(pending.terminal_at, |entry| {
                pending.terminal_at.max(entry.at())
            });
        let marker =
            SchedulerEventLogEntry::execution_budget_exhausted(sequence, boundary, budget_name);
        append_event_entries(
            &mut pending.event_log,
            &mut pending.event_log_bytes,
            vec![marker.clone()],
        )?;
        marker
    };

    Ok(Some(FailureTimeoutRecord::new(
        budget_kind,
        Some(configured_limit),
        pending.completed_quanta,
        marker.at(),
        marker
            .time()
            .icount
            .node
            .as_ref()
            .map(|_| marker.time().icount.icount),
        marker.time().icount.node.clone(),
        ContentHash::default(),
    )))
}

fn modeled_timeout_limit(
    pending: &QemuFreshPendingObservation,
) -> Option<(FailureTimeoutBudgetKind, u64)> {
    if let ModeledStop::ObservationReached { proof, .. } = &pending.stop {
        if proof.satisfaction() != ObservationStopSatisfaction::ExecutionQuanta {
            return None;
        }
        return match proof.condition() {
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
                Some((FailureTimeoutBudgetKind::ExecutionQuanta, *execution_quanta))
            }
            ObservationCondition::SchedulerQuiescent
            | ObservationCondition::AssertionViolationTransition(_)
            | ObservationCondition::AnyAssertionViolationTransition => None,
        };
    }

    let stop = match &pending.stop {
        ModeledStop::ReplayBoundary => pending.input.attempt().stop(),
        ModeledStop::Reached(stop) => stop,
        ModeledStop::PolicyTimeout {
            stop,
            kind: PolicyTimeoutKind::ExecutionQuanta,
            ..
        } => {
            return stop
                .bounded_deadlines()
                .and_then(|(_, execution_quanta)| execution_quanta)
                .map(|limit| (FailureTimeoutBudgetKind::ExecutionQuanta, limit));
        }
        ModeledStop::PolicyTimeout {
            stop,
            kind: PolicyTimeoutKind::VirtualTime,
            ..
        } => {
            return stop
                .bounded_deadlines()
                .and_then(|(virtual_time, _)| virtual_time)
                .map(|limit| (FailureTimeoutBudgetKind::VirtualTime, limit));
        }
        ModeledStop::BoundedPrimaryReached { stop, .. } => {
            return match stop.primary() {
                StopCondition::NextChoiceOrExecutionQuanta { .. } => None,
                primary => configured_execution_quanta_limit(primary)
                    .map(|limit| (FailureTimeoutBudgetKind::ExecutionQuanta, limit)),
            };
        }
        ModeledStop::BoundedPrimaryTimeout { .. } => return None,
        ModeledStop::ObservationReached { .. }
        | ModeledStop::ModeledTimeout(_)
        | ModeledStop::TerminalPassed
        | ModeledStop::TerminalFailed(_) => return None,
    };
    if let StopCondition::Bounded {
        primary,
        virtual_time_nanoseconds,
        execution_quanta,
    } = stop
    {
        // A virtual deadline wins over a quantum deadline at one boundary.
        // Primary stops retain only the timeout evidence they actually reached.
        if virtual_time_nanoseconds.is_some_and(|deadline| pending.terminal_at.ticks >= deadline) {
            return None;
        }
        if let Some(deadline) = execution_quanta
            && pending.completed_quanta >= *deadline
        {
            return Some((FailureTimeoutBudgetKind::ExecutionQuanta, *deadline));
        }
        return configured_execution_quanta_limit(primary)
            .map(|limit| (FailureTimeoutBudgetKind::ExecutionQuanta, limit));
    }
    configured_execution_quanta_limit(stop)
        .map(|limit| (FailureTimeoutBudgetKind::ExecutionQuanta, limit))
}

fn configured_execution_quanta_limit(stop: &StopCondition) -> Option<u64> {
    match stop {
        StopCondition::Bounded { primary, .. } => configured_execution_quanta_limit(primary),
        StopCondition::ExecutionQuanta(limit) => Some(*limit),
        StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => Some(*execution_quanta),
        StopCondition::VirtualTimeOrExecutionQuanta {
            execution_quanta, ..
        } => Some(*execution_quanta),
        StopCondition::Observation(ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta,
        }) => Some(*execution_quanta),
        StopCondition::NextChoice
        | StopCondition::NamedBoundary(_)
        | StopCondition::VirtualTimeNanoseconds(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal
        | StopCondition::Observation(_) => None,
    }
}

pub(crate) fn build_finding_candidate_boundary_evidence(
    mut pending: QemuFreshPendingObservation,
    candidate: &ConfigurationArtifact,
    final_events: Vec<SchedulerEventLogEntry>,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
) -> Result<QemuFindingCandidateBoundaryEvidence, QemuFreshModeledDriverError> {
    let policy_timeout = match &pending.stop {
        ModeledStop::PolicyTimeout { stop, kind, proof } => Some((stop.clone(), *kind, *proof)),
        _ => None,
    };
    append_event_entries(
        &mut pending.event_log,
        &mut pending.event_log_bytes,
        final_events.clone(),
    )?;
    // The runner first binds `candidate` to the exact encoded target. Reduced
    // candidates can expose later guest defaults; only validated continuations
    // may be rejected as non-preserving replay trials.
    let default_choice_continuation = match pending.input.start() {
        CrucibleResolvedAttemptStart::Discover {
            configuration: target,
        } => {
            let target_decisions = target.schedule.decisions();
            let reached_decisions = pending.configuration.schedule.decisions();
            let target_id = ConfigurationId::from_hash(CampaignHash::from_bytes(target.id().bytes));

            candidate.configuration() == target_id
                && reached_decisions.len() > target_decisions.len()
                && reached_decisions.starts_with(target_decisions)
                && reached_decisions[target_decisions.len()..]
                    .iter()
                    .all(|decision| {
                        let Decision::Selection(decision) = decision else {
                            return false;
                        };
                        decision.selection().is_ok_and(|selection| {
                            selection.origin() == SelectionOrigin::Default
                                && pending
                                    .discoveries
                                    .get(&selection.opportunity())
                                    .is_some_and(|discovery| {
                                        matches!(
                                            discovery.declaration().source(),
                                            crucible_campaign::ChoiceSource::Guest { .. }
                                        ) && selection
                                            .validate_replay(
                                                discovery.opportunity(),
                                                discovery.domain(),
                                            )
                                            .is_ok()
                                    })
                        })
                    })
        }
        CrucibleResolvedAttemptStart::AfterAttempt { .. }
        | CrucibleResolvedAttemptStart::Branch { .. } => false,
    };
    let projection = project_boundary(pending, false, supplemental_oracle)?;
    if projection.child != *candidate {
        if default_choice_continuation
            && projection.child.scenario_artifact() == candidate.scenario_artifact()
        {
            return Err(QemuFreshModeledDriverError::FindingCandidateSelectionContinued);
        }
        return Err(QemuFreshModeledDriverError::Artifact(Box::new(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "finding replay candidate configuration",
            },
        )));
    }
    let replay = CrucibleFindingReplayEvidence::new(
        None,
        projection.child,
        projection.measurements,
        projection.properties.clone(),
        projection.coverage,
        projection.discovered_choices,
        projection.produced_selections,
    )?;
    let causal_entries = projection.measurement_evidence.entries().to_vec();
    let coverage_fingerprint = coverage_fingerprint_from_event_log(&causal_entries);
    Ok(QemuFindingCandidateBoundaryEvidence {
        replay,
        measurement_replay_evidence: vec![projection.measurement_evidence],
        final_events,
        triage: QemuFindingCandidateTriageInputs {
            failures: projection.failures,
            causal_entries,
            coverage_fingerprint,
            // Native QEMU execution has no transport-frame source. Raw frames
            // remain empty rather than synthesizing them from scheduler entries.
            recorded_event_frames: Vec::new(),
            paired_divergence_logs: None,
        },
        policy_timeout,
        paired_reproduced_coverage: None,
    })
}

fn campaign_measurements(
    pending: &QemuFreshPendingObservation,
    configuration: crucible_campaign::ConfigurationId,
) -> Result<crate::CrucibleMeasurementPublication, QemuFreshModeledDriverError> {
    let definitions = pending.input.scenario().measurements();
    let mut node_icounts = BTreeMap::new();
    for entry in &pending.event_log {
        if let Some(node) = &entry.time().icount.node {
            node_icounts
                .entry(node.clone())
                .and_modify(|value: &mut crucible::Icount| {
                    *value = (*value).max(entry.time().icount.icount);
                })
                .or_insert(entry.time().icount.icount);
        }
    }
    let terminal = MeasurementTerminalState {
        scenario_ready_at: pending
            .event_log
            .iter()
            .find(|entry| entry.event_payload().kind() == "scenario_ready")
            .map(SchedulerEventLogEntry::at),
        at: pending
            .event_log
            .last()
            .map_or(pending.terminal_at, |entry| {
                pending.terminal_at.max(entry.at())
            }),
        node_icounts,
        scheduler_quiescent: pending
            .terminal_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    };
    let publication = match &pending.stop {
        ModeledStop::ObservationReached { evidence, .. } => {
            evaluate_crucible_observation_measurement_publication(
                pending.input.lineage().scenario(),
                configuration,
                definitions,
                pending.event_log.clone(),
                terminal,
                *evidence,
                MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
            )
        }
        _ => evaluate_crucible_measurement_publication(
            pending.input.lineage().scenario(),
            configuration,
            definitions,
            pending.event_log.clone(),
            terminal,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
        ),
    };
    publication.map_err(QemuFreshModeledDriverError::Measurements)
}

fn property_verdicts(
    report: &crucible::HostAssertionReport,
    supplemental: Option<&(GuardedCampaignFindingOracleEvaluation, ContentId)>,
) -> Result<PropertyVerdictSet, QemuFreshModeledDriverError> {
    let mut properties = BTreeMap::new();
    for outcome in report.outcomes() {
        let verdict = match outcome.kind {
            HostAssertionOutcomeKind::Passed | HostAssertionOutcomeKind::Satisfied => {
                PropertyVerdict::Passed
            }
            HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
                PropertyVerdict::Failed
            }
            HostAssertionOutcomeKind::Warning
            | HostAssertionOutcomeKind::NeverEvaluated
            | HostAssertionOutcomeKind::NeverTriggered
            | HostAssertionOutcomeKind::NeverReachedWarn => PropertyVerdict::Inconclusive,
        };
        let evidence = PropertyEvidence::new(verdict, BTreeSet::new())?;
        if properties
            .insert(outcome.assertion.name.clone(), evidence)
            .is_some()
        {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-duplicate-property-outcome",
            });
        }
    }
    if let Some((evaluation, source)) = supplemental {
        properties.insert(
            evaluation.property().to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::from([*source]))?,
        );
    }
    PropertyVerdictSet::new(properties).map_err(Into::into)
}

fn stop_outcome(
    stop: ModeledStop,
    report: &crucible::HostAssertionReport,
) -> Result<StopOutcome, QemuFreshModeledDriverError> {
    let assertion_failure = report
        .verdict()
        .failures()
        .first()
        .map(|failure| StopOutcome::AssertionFailure(failure.assertion.name.clone()));
    match stop {
        ModeledStop::ObservationReached { proof, .. } => Ok(StopOutcome::ObservationReached(proof)),
        ModeledStop::Reached(stop) => Ok(assertion_failure.unwrap_or(StopOutcome::Reached(stop))),
        ModeledStop::BoundedPrimaryReached { stop, proof } => {
            Ok(assertion_failure.unwrap_or(StopOutcome::BoundedPrimaryReached { stop, proof }))
        }
        ModeledStop::BoundedPrimaryTimeout { stop, proof } => {
            Ok(assertion_failure.unwrap_or(StopOutcome::BoundedPrimaryTimeout { stop, proof }))
        }
        ModeledStop::PolicyTimeout { stop, kind, proof } => {
            Ok(assertion_failure.unwrap_or(StopOutcome::PolicyTimeout { stop, kind, proof }))
        }
        ModeledStop::ModeledTimeout(name) => {
            Ok(assertion_failure.unwrap_or(StopOutcome::ModeledTimeout(name)))
        }
        ModeledStop::TerminalPassed => {
            Ok(assertion_failure.unwrap_or(StopOutcome::TerminalSuccess))
        }
        ModeledStop::TerminalFailed(reasons) => {
            Ok(assertion_failure.unwrap_or(StopOutcome::ScenarioFailure(reasons)))
        }
        ModeledStop::ReplayBoundary => assertion_failure.map_or_else(
            || Err(QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch),
            Ok,
        ),
    }
}

fn modeled_terminal_stop(
    verdict: QuantumTerminalVerdict,
) -> Result<ModeledStop, QemuFreshModeledDriverError> {
    match verdict {
        QuantumTerminalVerdict::Passed => Ok(ModeledStop::TerminalPassed),
        QuantumTerminalVerdict::Failed(reasons) if reasons.is_empty() => {
            Err(QemuFreshModeledDriverError::EmptyScenarioFailure)
        }
        QuantumTerminalVerdict::Failed(reasons) => Ok(ModeledStop::TerminalFailed(reasons)),
    }
}

fn coverage_projection(
    event_log: &[SchedulerEventLogEntry],
) -> Result<CoverageProjection, QemuFreshModeledDriverError> {
    let projection = crucible::event_log_coverage_projection(event_log);
    let identities = projection
        .entries()
        .iter()
        .map(|entry| coverage_identity(&entry.observation))
        .collect();
    CoverageProjection::new(identities, BTreeSet::new()).map_err(Into::into)
}

fn coverage_identity(observation: &EventLogCoverageObservation) -> CampaignHash {
    CampaignHash::from_bytes(observation.content_hash().bytes)
}

#[cfg(test)]
mod tests;
