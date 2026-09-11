//! Repository-backed local attempt execution and canonical completion handoff.
//!
//! The worker resolves opaque campaign records into one authenticated execution
//! input, delegates guest execution to an injected execution-model adapter, and
//! publishes the returned immutable observation bundle before asking the
//! supervisor to complete its operational execution record. QEMU/session types
//! remain behind [`AttemptExecutionModel`]; campaign storage stays language and
//! runtime neutral.

use crucible::ContentHash;
use crucible_campaign::{
    Attempt, AttemptContinuationInput, AttemptResourceLimits, AttemptRetentionPolicyBasis,
    AttemptStart, AttemptStartMode, BranchPath, CampaignExecutorStore, CampaignHash,
    CampaignLineage, CampaignRepositoryError, ConfigurationArtifact, ExactCheckpointId,
    ExecutionId, ExecutionRetentionIntent, ExecutorRejection, FindingExactPins,
    FindingExactRetention, FindingExactRetentionDisposition, FindingExactRetentionIncomplete,
    ObservationCandidate, ObservationId, ResolvedSelection, RetentionPolicy, ScenarioArtifact,
    StopOutcome, SubmitAttemptRequest,
};
use crucible_cas::content_store::ObjectKind;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};

const MAX_SELECTED_ORIGIN_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONFIGURATION_ARTIFACT_LOAD_BYTES: u64 = 32 * 1024 * 1024 + 1024;
const SELECTED_ORIGIN_STRUCTURAL_BYTES: u64 = 4096;

use crate::exact_checkpoint_store::AttemptCheckpointResultState;
use crate::executor_supervisor::ExecutionCheckpointHandoff;
use crate::guest_selectable::{
    GuestSelectableBoundaryDiagnosticEvent, GuestSelectableBoundaryDiagnosticRecorder,
};
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptCheckpointPublication,
    AttemptCheckpointResult, AttemptExecutionOrigin, CancellationOutcome,
    CapturedAttemptCheckpoint, CheckpointCompletionOutcome, CheckpointHandoffFailure,
    CheckpointPublicationOutcome, CompletionOutcome, DirectoryPreparedResultJournal,
    ExactCheckpointStore, ExactCheckpointStoreError, ExecutionCancellation,
    ExecutionCheckpointRequest, LocalExecutorError, LocalExecutorSupervisor,
    ObservationPublicationOutcome, PreparedAttemptCheckpoint, PreparedCrucibleFindingCandidate,
    PreparedResultJournalCreateDisposition, PreparedResultJournalError,
    PreparedSemanticAttemptResult, PreparedSemanticResultCodecError, QueuedAttempt,
    TerminalFailureOutcome,
};

/// Fully authenticated discovery or branch start supplied to an execution model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAttemptStart {
    /// Executes an existing configuration until its declared stop boundary.
    Discover {
        /// Exact starting configuration artifact.
        configuration: ConfigurationArtifact,
    },
    /// Applies one exact campaign selection at an authenticated parent.
    Branch {
        /// Exact parent configuration artifact.
        parent: ConfigurationArtifact,
        /// Selection, opportunity, and effective domain authenticated together.
        selection: Box<ResolvedSelection>,
    },
    /// Replays an authenticated attempt ancestry to one selected boundary.
    AfterAttempt {
        /// Oldest discovery or branch start from which replay begins.
        base: Box<ResolvedAttemptStart>,
        /// Origin attempts and their claimed reached boundaries, oldest first.
        origins: Box<ResolvedAttemptOrigins>,
    },
}

impl ResolvedAttemptStart {
    /// Returns the exact artifact at the semantic execution boundary.
    #[must_use]
    pub fn configuration(&self) -> &ConfigurationArtifact {
        match self {
            Self::Discover { configuration } => configuration,
            Self::Branch { parent, .. } => parent,
            Self::AfterAttempt { origins, .. } => origins.last().reached(),
        }
    }
}

/// Nonempty oldest-first selected continuation ancestry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAttemptOrigins {
    first: ResolvedAttemptOrigin,
    rest: Vec<ResolvedAttemptOrigin>,
}

impl ResolvedAttemptOrigins {
    /// Binds one required origin and any later descendants.
    #[must_use]
    pub fn new(first: ResolvedAttemptOrigin, rest: Vec<ResolvedAttemptOrigin>) -> Self {
        Self { first, rest }
    }

    /// Returns the final origin that establishes the semantic start boundary.
    #[must_use]
    pub fn last(&self) -> &ResolvedAttemptOrigin {
        self.rest.last().unwrap_or(&self.first)
    }

    /// Iterates through origins from the authenticated base toward the boundary.
    pub fn iter(&self) -> impl Iterator<Item = &ResolvedAttemptOrigin> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }

    /// Returns the number of retained origin attempts.
    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Returns false because a selected continuation always has an origin.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// One origin attempt paired with the boundary it claims to have reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAttemptOrigin {
    attempt: Attempt,
    reached: ConfigurationArtifact,
    source_stop: Option<StopOutcome>,
    source_stop_bytes: u64,
}

impl ResolvedAttemptOrigin {
    /// Returns the immutable origin attempt whose stop must be replayed.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the exact claimed configuration at the origin stop.
    #[must_use]
    pub const fn reached(&self) -> &ConfigurationArtifact {
        &self.reached
    }

    /// Returns the authenticated source outcome for controlled continuation.
    #[must_use]
    pub const fn source_stop(&self) -> Option<&StopOutcome> {
        self.source_stop.as_ref()
    }

    /// Returns the retained canonical source-proof charge in bytes.
    #[must_use]
    pub const fn source_stop_bytes(&self) -> u64 {
        self.source_stop_bytes
    }
}

/// Immutable repository-resolved input for one local guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptExecutionInput {
    lineage: CampaignLineage,
    scenario: ScenarioArtifact,
    attempt: Attempt,
    path: BranchPath,
    start: ResolvedAttemptStart,
}

/// Exact process-local reservation basis for one operational execution.
///
/// This value is never part of modeled input or canonical evidence. It lets a
/// process owner bind cleanup and publication reconciliation to the same
/// lineage-qualified attempt and execution incarnation retained by the local
/// supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptExecutionRuntimeBasis {
    key: crate::AttemptExecutionKey,
    execution: ExecutionId,
}

/// Authenticated admission policy available to automatic finding retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptFindingRetentionPolicy {
    basis: AttemptRetentionPolicyBasis,
    retention: Option<RetentionPolicy>,
}

impl AttemptFindingRetentionPolicy {
    pub(crate) const fn new(
        basis: AttemptRetentionPolicyBasis,
        retention: Option<RetentionPolicy>,
    ) -> Self {
        Self { basis, retention }
    }

    /// Returns the exact execution-basis admission and policy identity.
    #[must_use]
    pub const fn basis(self) -> AttemptRetentionPolicyBasis {
        self.basis
    }

    /// Returns the policy's semantic retention settings when canonically bound.
    #[must_use]
    pub const fn retention(self) -> Option<RetentionPolicy> {
        self.retention
    }
}

/// Linear automatic exact-retention handoff produced with one finding.
///
/// A captured checkpoint remains attempt-local until the executor pool prepares
/// and publishes it under the same guard used for replay captures and candidate
/// staging. Incomplete captures remain owned here so the pool can retire their
/// native production catalogs rather than silently leaking operational state.
#[derive(Debug)]
pub enum PreparedFindingExactRetention {
    /// The authenticated policy does not request exact finding retention.
    Disabled {
        /// Admission and policy identity authenticated for this execution.
        basis: AttemptRetentionPolicyBasis,
    },
    /// Exact retention could not complete, while thin evidence remains valid.
    Incomplete {
        /// Admission and policy identity authenticated for this execution.
        basis: AttemptRetentionPolicyBasis,
        /// Stable localized reason retained in the finding candidate.
        reason: FindingExactRetentionIncomplete,
        /// Unusable capture retained solely for explicit native-source retirement.
        discarded_checkpoint: Option<CapturedAttemptCheckpoint>,
    },
    /// One canonical safe-stop capture awaits guarded publication and selection.
    Captured {
        /// Admission and policy identity authenticated for this execution.
        basis: AttemptRetentionPolicyBasis,
        /// Linear unpublished exact checkpoint.
        checkpoint: CapturedAttemptCheckpoint,
    },
}

impl PreparedFindingExactRetention {
    /// Returns the authenticated admission and policy identity.
    #[must_use]
    pub const fn basis(&self) -> AttemptRetentionPolicyBasis {
        match self {
            Self::Disabled { basis }
            | Self::Incomplete { basis, .. }
            | Self::Captured { basis, .. } => *basis,
        }
    }

    /// Returns whether this handoff owns a checkpoint requiring retirement.
    #[must_use]
    pub const fn checkpoint(&self) -> Option<&CapturedAttemptCheckpoint> {
        match self {
            Self::Incomplete {
                discarded_checkpoint,
                ..
            } => discarded_checkpoint.as_ref(),
            Self::Captured { checkpoint, .. } => Some(checkpoint),
            Self::Disabled { .. } => None,
        }
    }
}

impl AttemptExecutionRuntimeBasis {
    /// Binds one semantic attempt to its process-local execution incarnation.
    #[must_use]
    pub const fn new(key: crate::AttemptExecutionKey, execution: ExecutionId) -> Self {
        Self { key, execution }
    }

    /// Returns the exact lineage-qualified semantic attempt.
    #[must_use]
    pub const fn key(self) -> crate::AttemptExecutionKey {
        self.key
    }

    /// Returns the supervisor's process-local execution incarnation.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
    }
}

impl AttemptExecutionInput {
    /// Returns the authenticated campaign compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the exact canonical execution-model scenario payload.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioArtifact {
        &self.scenario
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the authenticated semantic edge path.
    #[must_use]
    pub const fn path(&self) -> &BranchPath {
        &self.path
    }

    /// Returns the resolved discovery or one-selection branch start.
    #[must_use]
    pub const fn start(&self) -> &ResolvedAttemptStart {
        &self.start
    }
}

/// Resolves one lineage-qualified attempt into complete immutable model input.
///
/// The function authenticates the lineage, scenario, attempt, path,
/// configuration, and any branch selection through the executor's narrow
/// repository facade. It performs no writes and is shared by ordinary worker
/// dispatch and paused-checkpoint restart recovery.
///
/// # Errors
///
/// Returns [`CampaignRepositoryError`] when any record is unavailable,
/// malformed, semantically inconsistent, or belongs to another lineage.
pub fn resolve_attempt_execution_input(
    store: &CampaignExecutorStore,
    key: crate::AttemptExecutionKey,
) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
    resolve_attempt_execution_input_with_origin_limit(
        store,
        key,
        MAX_SELECTED_ORIGIN_ARTIFACT_BYTES,
    )
}

/// Resolves one attempt while charging retained origin artifacts to its memory ceiling.
///
/// # Errors
///
/// Returns the same errors as [`resolve_attempt_execution_input`] and rejects
/// continuation ancestry whose aggregate payload exceeds the admitted resident
/// byte limit.
pub fn resolve_attempt_execution_input_with_resources(
    store: &CampaignExecutorStore,
    key: crate::AttemptExecutionKey,
    resources: AttemptResourceLimits,
) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
    resolve_attempt_execution_input_with_origin_limit(
        store,
        key,
        resources.maximum_resident_bytes(),
    )
}

fn resolve_attempt_execution_input_with_origin_limit(
    store: &CampaignExecutorStore,
    key: crate::AttemptExecutionKey,
    maximum_resident_bytes: u64,
) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
    let lineage = store.load_lineage(key.lineage())?;
    let scenario = store.load_scenario_artifact(lineage.scenario_content())?;
    let mut attempt_chain = store.load_attempt_origin_chain(key.attempt())?;
    let attempt = attempt_chain
        .first()
        .cloned()
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-is-empty",
        })?;
    let path = store.load_branch_path(attempt.path())?;
    let mut origin_bytes = 0_u64;
    let start = match attempt.start() {
        AttemptStart::Discover { configuration } => {
            let configuration = store.load_configuration_artifact(configuration)?;
            ResolvedAttemptStart::Discover { configuration }
        }
        AttemptStart::Branch {
            parent, selection, ..
        } => {
            let parent = store.load_configuration_artifact(parent)?;
            ResolvedAttemptStart::Branch {
                parent,
                selection: Box::new(store.resolve_selection(selection)?),
            }
        }
        AttemptStart::AfterAttempt { .. } => {
            let maximum_origin_bytes = maximum_resident_bytes
                .min(MAX_SELECTED_ORIGIN_ARTIFACT_BYTES)
                .checked_sub(MAX_CONFIGURATION_ARTIFACT_LOAD_BYTES)
                .ok_or(CampaignRepositoryError::InvalidRequest {
                    reason: "selected-origin-resident-limit-cannot-load-one-artifact",
                })?;
            let base_attempt = attempt_chain
                .pop()
                .ok_or(CampaignRepositoryError::Integrity {
                    reason: "attempt-origin-chain-is-empty",
                })?;
            let base = match base_attempt.start() {
                AttemptStart::Discover { configuration } => {
                    let configuration = store.load_configuration_artifact(configuration)?;
                    account_origin_artifact(
                        &configuration,
                        &mut origin_bytes,
                        maximum_origin_bytes,
                    )?;
                    ResolvedAttemptStart::Discover { configuration }
                }
                AttemptStart::Branch {
                    parent, selection, ..
                } => {
                    let parent = store.load_configuration_artifact(parent)?;
                    account_origin_artifact(&parent, &mut origin_bytes, maximum_origin_bytes)?;
                    ResolvedAttemptStart::Branch {
                        parent,
                        selection: Box::new(store.resolve_selection(selection)?),
                    }
                }
                AttemptStart::AfterAttempt { .. } => {
                    return Err(CampaignRepositoryError::Integrity {
                        reason: "attempt-origin-chain-has-no-base",
                    });
                }
            };
            let mut origins = Vec::with_capacity(attempt_chain.len());
            let mut origin_attempt = base_attempt;
            for descendant in attempt_chain.into_iter().rev() {
                let AttemptStart::AfterAttempt { origin, reached } = descendant.start() else {
                    return Err(CampaignRepositoryError::Integrity {
                        reason: "attempt-origin-chain-has-interior-base",
                    });
                };
                if origin_attempt.id()? != origin {
                    return Err(CampaignRepositoryError::Integrity {
                        reason: "attempt-origin-chain-link-mismatch",
                    });
                }
                let reached = store.load_configuration_artifact(reached)?;
                account_origin_artifact(&reached, &mut origin_bytes, maximum_origin_bytes)?;
                let (source_stop, source_stop_bytes) = match descendant.continuation_input() {
                    Some(continuation_input) => {
                        let (stop, bytes) = resolve_continuation_source_stop(
                            store,
                            continuation_input,
                            &origin_attempt,
                            &reached,
                        )?;
                        account_origin_bytes(bytes, &mut origin_bytes, maximum_origin_bytes)?;
                        let bytes = u64::try_from(bytes).map_err(|_| {
                            CampaignRepositoryError::Integrity {
                                reason: "attempt-origin-artifact-byte-count-overflow",
                            }
                        })?;
                        (Some(stop), bytes)
                    }
                    None => (None, 0),
                };
                origins.push(ResolvedAttemptOrigin {
                    attempt: origin_attempt,
                    reached,
                    source_stop,
                    source_stop_bytes,
                });
                origin_attempt = descendant;
            }
            let mut origins = origins.into_iter();
            let first = origins.next().ok_or(CampaignRepositoryError::Integrity {
                reason: "attempt-origin-chain-has-no-boundary",
            })?;
            ResolvedAttemptStart::AfterAttempt {
                base: Box::new(base),
                origins: Box::new(ResolvedAttemptOrigins::new(first, origins.collect())),
            }
        }
    };

    let starting_configuration = match &start {
        ResolvedAttemptStart::Discover { configuration } => configuration,
        ResolvedAttemptStart::Branch { parent, .. } => parent,
        ResolvedAttemptStart::AfterAttempt { origins, .. } => origins.last().reached(),
    };
    if starting_configuration.scenario() != lineage.scenario()
        || starting_configuration.scenario_artifact() != lineage.scenario_content()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-start-lineage-mismatch",
        });
    }
    if let ResolvedAttemptStart::Branch { selection, .. } = &start
        && selection.opportunity().scenario() != lineage.scenario()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-opportunity-lineage-mismatch",
        });
    }
    if let ResolvedAttemptStart::AfterAttempt { base, origins } = &start {
        let base_selection = match base.as_ref() {
            ResolvedAttemptStart::Branch { selection, .. } => Some(selection),
            ResolvedAttemptStart::Discover { .. } => None,
            ResolvedAttemptStart::AfterAttempt { .. } => {
                return Err(CampaignRepositoryError::Integrity {
                    reason: "attempt-origin-chain-has-nested-base",
                });
            }
        };
        if base_selection
            .is_some_and(|selection| selection.opportunity().scenario() != lineage.scenario())
            || origins.iter().any(|origin| {
                origin.reached().scenario() != lineage.scenario()
                    || origin.reached().scenario_artifact() != lineage.scenario_content()
                    || origin.attempt().path() != attempt.path()
            })
        {
            return Err(CampaignRepositoryError::Integrity {
                reason: "attempt-origin-chain-lineage-mismatch",
            });
        }
    }

    Ok(AttemptExecutionInput {
        lineage,
        scenario,
        attempt,
        path,
        start,
    })
}

fn account_origin_artifact(
    artifact: &ConfigurationArtifact,
    total: &mut u64,
    limit: u64,
) -> Result<(), CampaignRepositoryError> {
    let payload_bytes = u64::try_from(artifact.payload().len()).map_err(|_| {
        CampaignRepositoryError::Integrity {
            reason: "attempt-origin-artifact-byte-count-overflow",
        }
    })?;
    // Decoded schedules and replay-plan prefixes are charged by the typed
    // Crucible adapter. This phase retains only canonical envelopes and keeps
    // headroom for one subsequent bounded artifact load.
    let bytes = payload_bytes
        .checked_add(SELECTED_ORIGIN_STRUCTURAL_BYTES)
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-artifact-byte-count-overflow",
        })?;
    *total = total
        .checked_add(bytes)
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-artifact-byte-count-overflow",
        })?;
    if *total > limit {
        return Err(CampaignRepositoryError::InvalidRequest {
            reason: "attempt-origin-artifacts-exceed-resource-limit",
        });
    }
    Ok(())
}

fn resolve_continuation_source_stop(
    store: &CampaignExecutorStore,
    continuation_input: &AttemptContinuationInput,
    source_attempt: &Attempt,
    reached: &ConfigurationArtifact,
) -> Result<(StopOutcome, usize), CampaignRepositoryError> {
    let observation = store.load_observation(continuation_input.source_observation())?;
    if observation.attempt() != source_attempt.id()? {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-origin-mismatch",
        });
    }
    if observation.child_content() != reached.id()?
        || observation.child() != reached.configuration()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-reached-mismatch",
        });
    }
    if !observation.stop().reaches(source_attempt.stop()) {
        return Err(CampaignRepositoryError::Integrity {
            reason: "attempt-continuation-source-observation-stop-mismatch",
        });
    }

    let bytes = observation.canonical_bytes().len();
    Ok((observation.stop().clone(), bytes))
}

fn account_origin_bytes(
    encoded_bytes: usize,
    total: &mut u64,
    limit: u64,
) -> Result<(), CampaignRepositoryError> {
    let bytes = u64::try_from(encoded_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(SELECTED_ORIGIN_STRUCTURAL_BYTES))
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-artifact-byte-count-overflow",
        })?;
    *total = total
        .checked_add(bytes)
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-artifact-byte-count-overflow",
        })?;
    if *total > limit {
        return Err(CampaignRepositoryError::InvalidRequest {
            reason: "attempt-origin-artifacts-exceed-resource-limit",
        });
    }
    Ok(())
}

/// Operational limits, control state, and restore root for one guest execution.
///
/// This context is deliberately separate from [`AttemptExecutionInput`]. It
/// contains no assignment ID or daemon epoch and must not influence canonical
/// child or observation bytes. The runner uses it only to enforce local
/// resource ceilings, interrupt work, and select the exact durable checkpoint
/// for a resumed incarnation. The packaged QEMU runner also receives an opaque
/// pool-owned handoff that can prepare and durably stage a captured root; it is
/// not exposed as modeled input and cannot affect canonical evidence. A model
/// MUST either restore
/// [`Self::resume_checkpoint`] exactly or fail before beginning guest work; it
/// must never silently restart a resumed attempt from its original
/// configuration.
#[derive(Clone, Debug)]
pub struct AttemptExecutionContext {
    runtime_basis: Option<AttemptExecutionRuntimeBasis>,
    start_mode: AttemptStartMode,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    finding_retention: Option<AttemptFindingRetentionPolicy>,
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
    resume_checkpoint: Option<ExactCheckpointId>,
    checkpoint_scenario: Option<ContentHash>,
    checkpoint_handoff: Option<ExecutionCheckpointHandoff>,
    execution_quanta: ExecutionQuantumBudget,
    origin: AttemptExecutionOrigin,
    guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
}

/// Clone-shared physical-work budget for one execution incarnation.
#[derive(Clone, Debug)]
struct ExecutionQuantumBudget {
    consumed: Arc<AtomicU64>,
}

impl ExecutionQuantumBudget {
    fn new() -> Self {
        Self {
            consumed: Arc::new(AtomicU64::new(0)),
        }
    }

    fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Acquire)
    }

    fn try_charge(&self, maximum: u64) -> Result<(), ExecutionQuantumBudgetError> {
        self.consumed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |consumed| {
                (consumed < maximum)
                    .then(|| consumed.checked_add(1))
                    .flatten()
            })
            .map(|_| ())
            .map_err(|_| ExecutionQuantumBudgetError)
    }
}

/// The execution has no physical replay or driving quantum remaining.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("execution exhausted its admitted physical quantum budget")]
pub struct ExecutionQuantumBudgetError;

impl AttemptExecutionContext {
    /// Creates an operational context without coordinator assignment identity.
    #[must_use]
    pub fn new(
        resources: AttemptResourceLimits,
        retention: ExecutionRetentionIntent,
        cancellation: ExecutionCancellation,
        checkpoint_request: ExecutionCheckpointRequest,
    ) -> Self {
        Self {
            runtime_basis: None,
            start_mode: AttemptStartMode::Execute,
            resources,
            retention,
            finding_retention: None,
            cancellation,
            checkpoint_request,
            resume_checkpoint: None,
            checkpoint_scenario: None,
            checkpoint_handoff: None,
            execution_quanta: ExecutionQuantumBudget::new(),
            origin: AttemptExecutionOrigin::Initial,
            guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder::default(),
        }
    }

    /// Derives a non-capturing context for mandatory resume-basis replay.
    ///
    /// Cancellation and resource ceilings remain shared with the assignment.
    /// A sticky checkpoint request is deferred until the semantic continuation
    /// boundary has been independently reconstructed. The same context also
    /// authenticates an ordinary EventCount attempt's immutable start prefix.
    pub(crate) fn for_origin_replay(&self) -> Self {
        let mut context = self.clone();
        context.start_mode = AttemptStartMode::Execute;
        context.checkpoint_request = ExecutionCheckpointRequest::default();
        context.resume_checkpoint = None;
        context.checkpoint_handoff = None;
        context
    }

    /// Derives a cold execution context when the preferred selected source is absent.
    ///
    /// Only the physical restore input is cleared. The immutable selected-source
    /// certificate remains available for provenance and retention, while the
    /// cancellation signal, sticky checkpoint request, handoff, and physical
    /// quantum budget remain shared with the accepted execution.
    pub(crate) fn for_absent_selected_source(&self) -> Self {
        let mut context = self.clone();
        context.resume_checkpoint = None;
        context
    }

    /// Charges one physical scheduler quantum to this execution incarnation.
    pub(crate) fn charge_execution_quantum(&self) -> Result<(), ExecutionQuantumBudgetError> {
        self.execution_quanta
            .try_charge(self.resources.maximum_execution_quanta())
    }

    /// Returns physical work consumed across every lifecycle in this execution.
    #[must_use]
    pub(crate) fn consumed_execution_quanta(&self) -> u64 {
        self.execution_quanta.consumed()
    }

    /// Returns whether another physical replay can begin within this reservation.
    #[must_use]
    pub(crate) fn has_remaining_execution_quanta(&self) -> bool {
        self.consumed_execution_quanta() < self.resources.maximum_execution_quanta()
    }

    pub(crate) fn record_guest_selectable_boundary_diagnostic(
        &self,
        event: &GuestSelectableBoundaryDiagnosticEvent,
    ) {
        self.guest_selectable_diagnostics.record(event);
    }

    pub(crate) const fn guest_selectable_boundary_diagnostics_enabled(&self) -> bool {
        self.guest_selectable_diagnostics.is_enabled()
    }

    pub(crate) const fn diagnostic_execution_id(&self) -> Option<ExecutionId> {
        match self.runtime_basis {
            Some(basis) => Some(basis.execution()),
            None => None,
        }
    }

    #[must_use]
    pub(crate) fn with_guest_selectable_boundary_diagnostics(
        mut self,
        diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
    ) -> Self {
        self.guest_selectable_diagnostics = diagnostics;
        self
    }

    /// Returns the resource limits available to a newly launched process owner.
    ///
    /// The semantic ceiling remains available through [`Self::resources`]. A
    /// second lifecycle used after independent replay receives only the
    /// unspent quantum allowance.
    pub(crate) fn process_resources(
        &self,
    ) -> Result<AttemptResourceLimits, ExecutionQuantumBudgetError> {
        let remaining_quanta = self
            .resources
            .maximum_execution_quanta()
            .checked_sub(self.consumed_execution_quanta())
            .filter(|remaining| *remaining != 0)
            .ok_or(ExecutionQuantumBudgetError)?;
        AttemptResourceLimits::new(
            self.resources.maximum_vcpus(),
            self.resources.maximum_resident_bytes(),
            self.resources.maximum_disk_bytes(),
            remaining_quanta,
        )
        .map_err(|_| ExecutionQuantumBudgetError)
    }

    /// Attaches the exact process-local reservation owned by this execution.
    #[must_use]
    pub(crate) const fn with_runtime_basis(mut self, basis: AttemptExecutionRuntimeBasis) -> Self {
        self.runtime_basis = Some(basis);
        self
    }

    #[must_use]
    pub(crate) fn with_finding_retention_policy(
        mut self,
        finding_retention: Option<AttemptFindingRetentionPolicy>,
    ) -> Self {
        self.finding_retention = finding_retention;
        self
    }

    /// Returns the authenticated policy basis for automatic finding retention.
    #[must_use]
    pub const fn finding_retention_policy(&self) -> Option<AttemptFindingRetentionPolicy> {
        self.finding_retention
    }

    /// Attaches the authenticated behavior requested at start materialization.
    #[must_use]
    pub(crate) const fn with_start_mode(mut self, start_mode: AttemptStartMode) -> Self {
        self.start_mode = start_mode;
        self
    }

    /// Returns the authenticated behavior requested at start materialization.
    #[must_use]
    pub const fn start_mode(&self) -> AttemptStartMode {
        self.start_mode
    }

    /// Returns the process-local reservation basis when this is worker work.
    ///
    /// Standalone checkpoint preparation contexts intentionally have no
    /// supervisor reservation and therefore return `None`.
    #[must_use]
    pub const fn runtime_basis(&self) -> Option<AttemptExecutionRuntimeBasis> {
        self.runtime_basis
    }

    /// Attaches the exact durable root from which this execution must resume.
    #[must_use]
    pub(crate) const fn with_resume_checkpoint(
        mut self,
        checkpoint: Option<ExactCheckpointId>,
    ) -> Self {
        self.resume_checkpoint = checkpoint;
        self
    }

    /// Attaches the durable initial-source or later-resume certificate.
    #[must_use]
    pub(crate) const fn with_execution_origin(mut self, origin: AttemptExecutionOrigin) -> Self {
        self.resume_checkpoint = origin.checkpoint();
        self.origin = origin;
        self
    }

    /// Returns the durable execution origin for routing and source validation.
    #[must_use]
    pub const fn execution_origin(&self) -> AttemptExecutionOrigin {
        self.origin
    }

    pub(crate) fn with_checkpoint_handoff(
        mut self,
        scenario: ContentHash,
        handoff: Option<ExecutionCheckpointHandoff>,
    ) -> Self {
        self.checkpoint_scenario = Some(scenario);
        self.checkpoint_handoff = handoff;
        self
    }

    /// Returns the hard resource ceilings admitted for this execution.
    #[must_use]
    pub const fn resources(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the operational artifact-retention intent.
    #[must_use]
    pub const fn retention(&self) -> ExecutionRetentionIntent {
        self.retention
    }

    /// Returns the process-local cancellation signal.
    #[must_use]
    pub const fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    /// Returns the process-local exact-checkpoint request signal.
    #[must_use]
    pub const fn checkpoint_request(&self) -> &ExecutionCheckpointRequest {
        &self.checkpoint_request
    }

    /// Returns the exact restore root for a resumed execution incarnation.
    #[must_use]
    pub const fn resume_checkpoint(&self) -> Option<ExactCheckpointId> {
        self.resume_checkpoint
    }

    pub(crate) fn prepare_and_stage_checkpoint(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<AttemptCheckpointResult, AttemptWorkerFailure<CheckpointHandoffFailure>> {
        if self.cancellation.is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                CheckpointHandoffFailure::Canceled,
            ));
        }
        if self
            .checkpoint_scenario
            .is_some_and(|scenario| capture.scenario() != scenario)
        {
            return Err(AttemptWorkerFailure::Terminal(
                CheckpointHandoffFailure::Terminal,
            ));
        }
        let Some(handoff) = &self.checkpoint_handoff else {
            return Ok(capture.reopenable_copy().into());
        };
        match handoff.prepare_and_stage(capture) {
            Ok(prepared) => Ok(AttemptCheckpointResult::from_prepared(prepared)),
            Err(CheckpointHandoffFailure::Retryable) => Err(AttemptWorkerFailure::Retryable(
                CheckpointHandoffFailure::Retryable,
            )),
            Err(CheckpointHandoffFailure::Canceled) => Err(AttemptWorkerFailure::Canceled(
                CheckpointHandoffFailure::Canceled,
            )),
            Err(CheckpointHandoffFailure::Terminal) => Err(AttemptWorkerFailure::Terminal(
                CheckpointHandoffFailure::Terminal,
            )),
        }
    }

    /// Returns whether another context names the exact same execution contract.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.runtime_basis == other.runtime_basis
            && self.start_mode == other.start_mode
            && self.resources == other.resources
            && self.retention == other.retention
            && self.resume_checkpoint == other.resume_checkpoint
            && self.consumed_execution_quanta() == other.consumed_execution_quanta()
            && self.origin == other.origin
            && self.checkpoint_scenario == other.checkpoint_scenario
            && self.cancellation.same_incarnation(&other.cancellation)
            && self
                .checkpoint_request
                .same_incarnation(&other.checkpoint_request)
            && match (&self.checkpoint_handoff, &other.checkpoint_handoff) {
                (Some(left), Some(right)) => left.same_incarnation(right),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

/// Execution-model boundary used by the local campaign worker.
pub trait AttemptExecutionModel {
    /// Model-specific operational execution failure.
    type Error;

    /// Executes one authenticated attempt and returns its complete immutable result.
    ///
    /// Implementations may choose hot fork, exact restore, or thin replay. The
    /// choice is operational and must not change the canonical candidate. When
    /// `context.resume_checkpoint()` is present, the implementation must begin
    /// from that exact authenticated root or return an error before guest work.
    ///
    /// # Errors
    ///
    /// Returns a model-specific error for unavailable materialization, guest
    /// process failure, cancellation, or inability to reach the modeled stop.
    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>;

    /// Takes native checkpoint cleanup authority retained by the last failed execution.
    ///
    /// The default is valid for models that never capture a production checkpoint.
    fn take_abandoned_native_checkpoint(&mut self) -> Option<NativeCheckpointCleanup> {
        None
    }

    /// Reconciles model-owned operational authority after semantic completion.
    ///
    /// The worker calls this only after a successful [`Self::execute`] result
    /// reaches a durable supervisor disposition. Implementations that retain a
    /// process, template, or publication lease must authenticate the exact
    /// disposition and release or quarantine that authority before returning.
    /// An execution that returns an error must instead finish or quarantine
    /// its operational owner before returning that error; this prevents a
    /// retry from overlapping the failed incarnation.
    /// Models without post-execution authority use the default no-op.
    ///
    /// # Errors
    ///
    /// Returns a classified operational failure while retaining retry or
    /// quarantine authority according to the failure class.
    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }
}

/// Pool-owned disposition for a native checkpoint catalog abandoned by execution.
#[derive(Debug)]
pub enum NativeCheckpointCleanup {
    /// The producing lifecycle stopped, so catalog retirement may run now.
    Retire(crucible_api::ProductionExactCheckpointRetirement),
    /// Shutdown did not attest process exit, so the authority must remain quarantined.
    Quarantine(crucible_api::ProductionExactCheckpointRetirement),
    /// Multiple independently owned catalogs require the same pool-owned cleanup pass.
    Batch(Vec<NativeCheckpointCleanup>),
}

impl NativeCheckpointCleanup {
    pub(crate) fn retain(slot: &mut Option<Self>, cleanup: Self) {
        let Some(existing) = slot.take() else {
            *slot = Some(cleanup);
            return;
        };

        let mut retained = match existing {
            Self::Batch(retained) => retained,
            cleanup => vec![cleanup],
        };
        match cleanup {
            Self::Batch(mut cleanup) => retained.append(&mut cleanup),
            cleanup => retained.push(cleanup),
        }
        *slot = Some(Self::Batch(retained));
    }

    pub(crate) fn retain_for_process_lifetime(self) {
        let quarantine = UNWIND_NATIVE_CHECKPOINT_QUARANTINE.get_or_init(Default::default);
        let mut quarantine = quarantine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.push_quarantined(&mut quarantine);
    }

    fn push_quarantined(self, quarantine: &mut Vec<Self>) {
        match self {
            Self::Retire(retirement) | Self::Quarantine(retirement) => {
                quarantine.push(Self::Quarantine(retirement));
            }
            Self::Batch(cleanups) => {
                for cleanup in cleanups {
                    cleanup.push_quarantined(quarantine);
                }
            }
        }
    }
}

static UNWIND_NATIVE_CHECKPOINT_QUARANTINE: OnceLock<Mutex<Vec<NativeCheckpointCleanup>>> =
    OnceLock::new();

#[cfg(test)]
pub(crate) fn native_checkpoint_process_quarantine_len_for_test() -> usize {
    let quarantine = UNWIND_NATIVE_CHECKPOINT_QUARANTINE.get_or_init(Default::default);
    quarantine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len()
}

/// Keeps a newly captured native catalog quarantined until ownership transfers.
#[derive(Debug)]
pub(crate) struct NativeCheckpointUnwindGuard {
    retirement: Option<crucible_api::ProductionExactCheckpointRetirement>,
}

impl NativeCheckpointUnwindGuard {
    pub(crate) const fn new_empty() -> Self {
        Self { retirement: None }
    }

    pub(crate) fn new(checkpoint: &CapturedAttemptCheckpoint) -> Self {
        Self {
            retirement: checkpoint.native_retirement(),
        }
    }

    pub(crate) fn take(&mut self) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        self.retirement.take()
    }

    pub(crate) fn disarm(&mut self) {
        self.retirement = None;
    }
}

impl Drop for NativeCheckpointUnwindGuard {
    fn drop(&mut self) {
        let Some(retirement) = self.retirement.take() else {
            return;
        };
        NativeCheckpointCleanup::Quarantine(retirement).retain_for_process_lifetime();
    }
}

/// Canonical completion or exact paused capture returned by an execution model.
#[derive(Debug)]
pub enum AttemptExecutionProduct {
    /// The attempt reached its modeled stop and produced immutable evidence.
    Observation(Box<ObservationCandidate>),
    /// The attempt produced an observation and a verified finding closure.
    ObservationWithFinding {
        /// Canonical observation candidate from the admitted execution.
        observation: Box<ObservationCandidate>,
        /// Prepared private-replay evidence and finding root.
        finding: Box<PreparedCrucibleFindingCandidate>,
    },
    /// The complete observation/finding closure with raw measurement evidence.
    PreparedSemantic(Box<PreparedSemanticAttemptResult>),
    /// A semantic finding plus its linear automatic exact-retention handoff.
    PreparedSemanticWithExactRetention {
        /// Complete observation and private-replay evidence.
        result: Box<PreparedSemanticAttemptResult>,
        /// Policy-bound exact-retention decision and optional raw capture.
        retention: Box<PreparedFindingExactRetention>,
    },
    /// A durable checkpoint request won at an exact scheduler boundary.
    ExactCheckpoint(Box<AttemptCheckpointResult>),
}

impl AttemptExecutionProduct {
    /// Wraps one canonical observation candidate.
    #[must_use]
    pub fn observation(candidate: ObservationCandidate) -> Self {
        Self::Observation(Box::new(candidate))
    }

    /// Wraps an observation and its fully prepared finding candidate.
    #[must_use]
    pub fn observation_with_finding(
        observation: ObservationCandidate,
        finding: PreparedCrucibleFindingCandidate,
    ) -> Self {
        Self::ObservationWithFinding {
            observation: Box::new(observation),
            finding: Box::new(finding),
        }
    }

    /// Wraps a complete semantic result with its raw measurement leaves.
    #[must_use]
    pub fn prepared_semantic(result: PreparedSemanticAttemptResult) -> Self {
        Self::PreparedSemantic(Box::new(result))
    }

    /// Wraps a semantic finding with its automatic exact-retention handoff.
    #[must_use]
    pub fn prepared_semantic_with_exact_retention(
        result: PreparedSemanticAttemptResult,
        retention: PreparedFindingExactRetention,
    ) -> Self {
        Self::PreparedSemanticWithExactRetention {
            result: Box::new(result),
            retention: Box::new(retention),
        }
    }

    /// Wraps one complete attempt checkpoint capture.
    #[must_use]
    pub fn exact_checkpoint(capture: impl Into<AttemptCheckpointResult>) -> Self {
        Self::ExactCheckpoint(Box::new(capture.into()))
    }

    pub(crate) fn into_abandoned_retirement(
        self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        match self {
            Self::PreparedSemanticWithExactRetention { retention, .. } => retention
                .checkpoint()
                .and_then(CapturedAttemptCheckpoint::native_retirement),
            Self::ExactCheckpoint(checkpoint) => match checkpoint.into_state() {
                AttemptCheckpointResultState::Captured(checkpoint) => {
                    checkpoint.native_retirement()
                }
                AttemptCheckpointResultState::Prepared(checkpoint) => {
                    checkpoint.native_retirement()
                }
            },
            Self::Observation(_)
            | Self::ObservationWithFinding { .. }
            | Self::PreparedSemantic(_) => None,
        }
    }
}

/// Stable disposition of one local execution failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptWorkerFailure<E> {
    /// A transient operational failure permits the same accepted work to retry.
    Retryable(E),
    /// Execution observed cancellation and must not restart automatically.
    Canceled(E),
    /// A deterministic semantic or compatibility failure is quarantined.
    Terminal(E),
}

impl<E: std::fmt::Display> std::fmt::Display for AttemptWorkerFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(error) => write!(formatter, "retryable execution failure: {error}"),
            Self::Canceled(error) => write!(formatter, "canceled execution: {error}"),
            Self::Terminal(error) => write!(formatter, "terminal execution failure: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for AttemptWorkerFailure<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Retryable(error) | Self::Canceled(error) | Self::Terminal(error) => Some(error),
        }
    }
}

/// Durable semantic disposition supplied to model-owned operational cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptExecutionDisposition {
    /// The exact observation became the accepted or idempotent completion.
    Observation(ObservationId),
    /// The exact paused checkpoint became the durable execution origin.
    ExactCheckpoint(ExactCheckpointId),
    /// Cancellation won before a modeled result became authoritative.
    Canceled,
    /// Execution failed or its result was rejected before becoming authoritative.
    ///
    /// The supervisor may retry the semantic attempt when the originating
    /// failure was transient, but every operational owner from this execution
    /// incarnation must reconcile before that worker accepts more work.
    Failed,
}

/// Progress made by one bounded post-execution reconciliation callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptExecutionReconciliationStep {
    /// One monotonic subphase completed and the callback must run again.
    Progressed,
    /// Every model-owned authority for this execution is reconciled.
    Complete,
}

/// Worker boundary consumed by the bounded local supervisor driver.
pub trait LocalAttemptWorker {
    /// Operational or semantic worker failure.
    type Error;

    /// Executes one accepted assignment and returns its immutable result bundle.
    ///
    /// # Errors
    ///
    /// Returns a worker-specific error before durable completion reconciliation.
    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error>;

    /// Takes native checkpoint cleanup retained by the most recent worker callback.
    fn take_abandoned_native_checkpoint(&mut self) -> Option<NativeCheckpointCleanup> {
        None
    }

    /// Reconciles operational authority retained by one successful execution.
    ///
    /// The pool invokes this for exactly one disposition, repeatedly until
    /// completion, before this worker may execute another assignment. Retryable
    /// failures are called again with the same disposition; terminal or
    /// canceled failures must already have transferred remaining authority to
    /// quarantine. Every attempt-charged process and resource must already be
    /// stopped before [`Self::execute`] returns successfully; this callback
    /// retains only the source-side or publication authority whose release is
    /// ordered after the durable semantic disposition.
    /// [`Self::execute`] errors are not passed to this callback: their
    /// operational owner must already be finished or quarantined when the
    /// error is returned, before the supervisor can requeue the attempt.
    ///
    /// # Errors
    ///
    /// Returns a classified cleanup failure while preserving the worker's
    /// owned reconciliation state.
    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }
}

/// Linear worker return carrying the sole reconciliation token and model result.
#[derive(Debug)]
pub struct AttemptWorkResult<E> {
    queued: QueuedAttempt,
    result: Result<AttemptExecutionProduct, AttemptWorkerFailure<E>>,
    abandoned_checkpoint: Option<NativeCheckpointCleanup>,
}

impl<E> AttemptWorkResult<E> {
    /// Binds one consumed execution token to its single worker result.
    #[must_use]
    pub fn new(
        queued: QueuedAttempt,
        result: Result<AttemptExecutionProduct, AttemptWorkerFailure<E>>,
    ) -> Self {
        Self {
            queued,
            result,
            abandoned_checkpoint: None,
        }
    }

    /// Consumes the worker return into its linear token and classified result.
    pub fn into_parts(
        self,
    ) -> (
        QueuedAttempt,
        Result<AttemptExecutionProduct, AttemptWorkerFailure<E>>,
        Option<NativeCheckpointCleanup>,
    ) {
        (self.queued, self.result, self.abandoned_checkpoint)
    }

    pub(crate) fn with_abandoned_checkpoint(
        mut self,
        checkpoint: Option<NativeCheckpointCleanup>,
    ) -> Self {
        self.abandoned_checkpoint = checkpoint;
        self
    }
}

/// Failure while resolving, executing, or publishing one local attempt.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryAttemptWorkerError<E> {
    /// Immutable campaign input or output publication failed validation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Immutable replay preparation exceeds the admitted execution resources.
    #[error("attempt execution resource refusal: {resource}")]
    ResourceRefusal {
        /// Stable resource category that refused preparation.
        resource: &'static str,
    },
    /// The execution-model adapter failed before publishing a completion.
    #[error("attempt execution model failed")]
    Model {
        /// Model-specific execution failure.
        #[source]
        source: E,
        /// Native checkpoint cleanup authority retained by the failed execution.
        checkpoint: Option<NativeCheckpointCleanup>,
    },
    /// The model returned a result for a different immutable execution basis.
    #[error("attempt execution model returned an incompatible result: {reason}")]
    IncompatibleResult {
        /// Stable fail-closed mismatch category.
        reason: &'static str,
        /// Native capture authority retained until pool-owned retirement.
        retirement: Option<crucible_api::ProductionExactCheckpointRetirement>,
    },
}

/// Local worker that resolves campaign records and publishes immutable results.
pub struct RepositoryAttemptWorker<M> {
    store: CampaignExecutorStore,
    model: M,
    guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
}

impl<M> RepositoryAttemptWorker<M> {
    /// Creates a local worker over a repository and execution-model adapter.
    #[must_use]
    pub fn new(store: CampaignExecutorStore, model: M) -> Self {
        Self {
            store,
            model,
            guest_selectable_diagnostics: GuestSelectableBoundaryDiagnosticRecorder::default(),
        }
    }

    #[must_use]
    pub(crate) fn with_guest_selectable_boundary_diagnostics(
        mut self,
        diagnostics: GuestSelectableBoundaryDiagnosticRecorder,
    ) -> Self {
        self.guest_selectable_diagnostics = diagnostics;
        self
    }

    /// Returns the execution-model adapter for diagnostics and configuration.
    #[must_use]
    pub const fn model(&self) -> &M {
        &self.model
    }

    /// Returns mutable access to the execution-model adapter.
    #[must_use]
    pub fn model_mut(&mut self) -> &mut M {
        &mut self.model
    }

    /// Returns the owned model after worker shutdown.
    #[must_use]
    pub fn into_model(self) -> M {
        self.model
    }
}

impl<M> RepositoryAttemptWorker<M>
where
    M: AttemptExecutionModel,
{
    /// Executes one accepted assignment and returns its immutable observation candidate.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryAttemptWorkerError`] when immutable input cannot be
    /// authenticated, model execution fails, the result names another basis,
    /// or candidate publication fails.
    pub fn execute(
        &mut self,
        queued: QueuedAttempt,
    ) -> AttemptWorkResult<RepositoryAttemptWorkerError<M::Error>> {
        let mut result = self.execute_borrowed(&queued);
        let mut abandoned_checkpoint = self.model.take_abandoned_native_checkpoint();
        let result_checkpoint = match &mut result {
            Err(AttemptWorkerFailure::Retryable(RepositoryAttemptWorkerError::Model {
                checkpoint,
                ..
            }))
            | Err(AttemptWorkerFailure::Canceled(RepositoryAttemptWorkerError::Model {
                checkpoint,
                ..
            }))
            | Err(AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::Model {
                checkpoint,
                ..
            })) => checkpoint.take(),
            Err(AttemptWorkerFailure::Terminal(
                RepositoryAttemptWorkerError::IncompatibleResult { retirement, .. },
            )) => retirement.take().map(NativeCheckpointCleanup::Retire),
            _ => None,
        };
        abandoned_checkpoint =
            merge_native_checkpoint_cleanup(abandoned_checkpoint, result_checkpoint);
        AttemptWorkResult {
            queued,
            result,
            abandoned_checkpoint,
        }
    }

    fn execute_borrowed(
        &mut self,
        queued: &QueuedAttempt,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<RepositoryAttemptWorkerError<M::Error>>>
    {
        let input = self
            .resolve_input(queued.request())
            .map_err(repository_worker_failure)?;
        let capture_validation =
            capture_start_validation_reason(input.start(), queued.request().start_mode())
                .map_err(CampaignRepositoryError::from)
                .map_err(repository_worker_failure)?;
        if let Some(reason) = capture_validation {
            return Err(AttemptWorkerFailure::Terminal(
                RepositoryAttemptWorkerError::IncompatibleResult {
                    reason,
                    retirement: None,
                },
            ));
        }
        let finding_retention = queued
            .request()
            .retention_policy_basis()
            .map(|basis| {
                self.store
                    .validate_attempt_retention_policy_basis(
                        queued.request().lineage(),
                        queued.request().attempt(),
                        basis,
                    )
                    .map(|retention| AttemptFindingRetentionPolicy::new(basis, retention))
            })
            .transpose()
            .map_err(repository_worker_failure)?;
        let expected_scenario = ContentHash {
            bytes: input.lineage().scenario().as_hash().as_bytes(),
        };
        let context = AttemptExecutionContext::new(
            queued.request().resources(),
            queued.request().retention(),
            queued.cancellation().clone(),
            queued.checkpoint_request().clone(),
        )
        .with_finding_retention_policy(finding_retention)
        .with_start_mode(queued.request().start_mode())
        .with_runtime_basis(AttemptExecutionRuntimeBasis::new(
            crate::AttemptExecutionKey::for_request(queued.request()),
            queued.execution(),
        ))
        .with_execution_origin(queued.origin())
        .with_checkpoint_handoff(expected_scenario, queued.checkpoint_handoff().cloned())
        .with_guest_selectable_boundary_diagnostics(self.guest_selectable_diagnostics.clone());
        let product = match self.model.execute(&input, &context) {
            Ok(product) => product,
            Err(failure) => {
                return Err(map_worker_failure(failure, |source| {
                    RepositoryAttemptWorkerError::Model {
                        source,
                        checkpoint: None,
                    }
                }));
            }
        };
        if let Err(reason) =
            validate_execution_product(&product, &context, queued, &input, expected_scenario)
        {
            let retirement = product.into_abandoned_retirement();
            return Err(AttemptWorkerFailure::Terminal(
                RepositoryAttemptWorkerError::IncompatibleResult { reason, retirement },
            ));
        }

        Ok(product)
    }

    fn resolve_input(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
        resolve_attempt_execution_input_with_resources(
            &self.store,
            crate::AttemptExecutionKey::for_request(request),
            request.resources(),
        )
    }
}

fn validate_execution_product(
    product: &AttemptExecutionProduct,
    context: &AttemptExecutionContext,
    queued: &QueuedAttempt,
    input: &AttemptExecutionInput,
    expected_scenario: ContentHash,
) -> Result<(), &'static str> {
    let policy_basis = context
        .finding_retention_policy()
        .map(AttemptFindingRetentionPolicy::basis);
    match product {
        AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, retention } => {
            if policy_basis != Some(retention.basis()) {
                return Err("finding exact retention differs from authenticated execution policy");
            }
            let Some(finding) = result.finding() else {
                return Err("finding exact retention has no finding");
            };
            if finding.bundle().exact_retention().is_some() {
                return Err("finding exact retention was already bound before worker handoff");
            }
            if let PreparedFindingExactRetention::Captured { checkpoint, .. } = &**retention {
                if checkpoint.scenario() != expected_scenario {
                    return Err("finding exact retention checkpoint differs from finding scenario");
                }
                let configuration = finding.original_configuration().configuration();
                if checkpoint.configuration().bytes != configuration.as_hash().as_bytes() {
                    return Err(
                        "finding exact retention checkpoint differs from finding configuration",
                    );
                }
            }
        }
        AttemptExecutionProduct::ObservationWithFinding { .. } if policy_basis.is_some() => {
            return Err("policy-bound finding omitted exact-retention handoff");
        }
        AttemptExecutionProduct::PreparedSemantic(result)
            if policy_basis.is_some() && result.finding().is_some() =>
        {
            return Err("policy-bound finding omitted exact-retention handoff");
        }
        AttemptExecutionProduct::Observation(_)
        | AttemptExecutionProduct::ObservationWithFinding { .. }
        | AttemptExecutionProduct::PreparedSemantic(_)
        | AttemptExecutionProduct::ExactCheckpoint(_) => {}
    }

    match product {
        AttemptExecutionProduct::Observation(candidate)
        | AttemptExecutionProduct::ObservationWithFinding {
            observation: candidate,
            ..
        } => validate_semantic_observation(candidate, queued, input),
        AttemptExecutionProduct::PreparedSemantic(result)
        | AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, .. } => {
            validate_semantic_observation(result.observation(), queued, input)
        }
        AttemptExecutionProduct::ExactCheckpoint(checkpoint) => {
            if !queued.checkpoint_request().is_requested() {
                return Err("execution returned an unsolicited exact checkpoint");
            }
            if checkpoint.scenario() != expected_scenario {
                return Err("exact checkpoint differs from assignment scenario");
            }
            Ok(())
        }
    }
}

fn validate_semantic_observation(
    candidate: &ObservationCandidate,
    queued: &QueuedAttempt,
    input: &AttemptExecutionInput,
) -> Result<(), &'static str> {
    if queued.request().execution_scope() != crucible_campaign::AttemptExecutionScope::Semantic {
        return Err("savepoint capture returned a semantic observation");
    }
    if candidate.observation().attempt() != queued.request().attempt() {
        return Err("observation attempt differs from assignment");
    }
    if candidate.child().scenario() != input.lineage().scenario()
        || candidate.child().scenario_artifact() != input.lineage().scenario_content()
    {
        return Err("child configuration differs from assignment lineage");
    }
    Ok(())
}

fn capture_start_validation_reason(
    start: &ResolvedAttemptStart,
    start_mode: AttemptStartMode,
) -> Result<Option<&'static str>, crucible_campaign::CampaignCodecError> {
    match start_mode {
        AttemptStartMode::Execute => Ok(None),
        AttemptStartMode::CaptureMaterializedStart { configuration } => {
            let ResolvedAttemptStart::Discover {
                configuration: resolved,
            } = start
            else {
                return Ok(Some(
                    "materialized-start capture requires a discovery attempt",
                ));
            };
            if resolved.id()? != configuration {
                return Ok(Some(
                    "materialized-start capture configuration differs from resolved discovery start",
                ));
            }
            Ok(None)
        }
        AttemptStartMode::SavepointCapture { configuration, .. } => {
            let resolved = start.configuration();
            if resolved.id()? != configuration {
                return Ok(Some(
                    "savepoint capture configuration differs from resolved attempt start",
                ));
            }
            Ok(None)
        }
        AttemptStartMode::SelectedSavepoint { .. } => {
            if matches!(start, ResolvedAttemptStart::AfterAttempt { .. }) {
                Ok(None)
            } else {
                Ok(Some(
                    "selected-savepoint start requires a continuation attempt",
                ))
            }
        }
    }
}

impl<M> LocalAttemptWorker for RepositoryAttemptWorker<M>
where
    M: AttemptExecutionModel,
{
    type Error = RepositoryAttemptWorkerError<M::Error>;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        RepositoryAttemptWorker::execute(self, queued)
    }

    fn take_abandoned_native_checkpoint(&mut self) -> Option<NativeCheckpointCleanup> {
        self.model.take_abandoned_native_checkpoint()
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        match self.model.reconcile_execution(disposition) {
            Ok(step) => Ok(step),
            Err(failure) => Err(map_worker_failure(failure, |source| {
                RepositoryAttemptWorkerError::Model {
                    source,
                    checkpoint: None,
                }
            })),
        }
    }
}

fn map_worker_failure<E, F, M>(failure: AttemptWorkerFailure<E>, map: M) -> AttemptWorkerFailure<F>
where
    M: FnOnce(E) -> F,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
    }
}

fn merge_native_checkpoint_cleanup(
    first: Option<NativeCheckpointCleanup>,
    second: Option<NativeCheckpointCleanup>,
) -> Option<NativeCheckpointCleanup> {
    match (first, second) {
        (Some(first), Some(second)) => Some(NativeCheckpointCleanup::Batch(vec![first, second])),
        (Some(cleanup), None) | (None, Some(cleanup)) => Some(cleanup),
        (None, None) => None,
    }
}

fn repository_worker_failure<E>(
    error: CampaignRepositoryError,
) -> AttemptWorkerFailure<RepositoryAttemptWorkerError<E>> {
    if matches!(
        error,
        CampaignRepositoryError::InvalidRequest {
            reason: "selected-origin-resident-limit-cannot-load-one-artifact"
                | "attempt-origin-artifacts-exceed-resource-limit"
        }
    ) {
        return AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::ResourceRefusal {
            resource: "selected-origin-resident-bytes",
        });
    }
    let error = RepositoryAttemptWorkerError::Repository(error);
    match &error {
        RepositoryAttemptWorkerError::Repository(repository)
            if repository.executor_rejection() == ExecutorRejection::UnavailableInput =>
        {
            AttemptWorkerFailure::Retryable(error)
        }
        RepositoryAttemptWorkerError::Repository(_)
        | RepositoryAttemptWorkerError::Model { .. }
        | RepositoryAttemptWorkerError::ResourceRefusal { .. }
        | RepositoryAttemptWorkerError::IncompatibleResult { .. } => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

/// Result of reconciling one finished worker operation with supervision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptWorkerReconcileOutcome {
    /// An immutable observation was published and reconciled with supervision.
    Reconciled {
        /// Published canonical observation candidate.
        observation: ObservationId,
        /// Durable operational completion race outcome.
        completion: CompletionOutcome,
    },
    /// Publication was skipped because cancellation or staleness already won.
    Discarded {
        /// Deterministic candidate identity that was not written by this phase.
        observation: ObservationId,
        /// Cancellation or stale-execution disposition.
        completion: CompletionOutcome,
    },
}

/// Already-executed candidate retained for publication retry without guest work.
#[derive(Debug)]
pub struct PendingAttemptResult {
    queued: QueuedAttempt,
    result: PendingAttemptResultOwner,
    finding_exact_retention: Option<PreparedFindingExactRetention>,
}

#[derive(Debug)]
enum PendingAttemptResultOwner {
    Legacy {
        observation: ObservationCandidate,
        finding: Option<PreparedCrucibleFindingCandidate>,
    },
    Prepared(PreparedSemanticAttemptResult),
}

impl PendingAttemptResultOwner {
    const fn observation(&self) -> &ObservationCandidate {
        match self {
            Self::Legacy { observation, .. } => observation,
            Self::Prepared(result) => result.observation(),
        }
    }

    const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        match self {
            Self::Legacy { finding, .. } => finding.as_ref(),
            Self::Prepared(result) => result.finding(),
        }
    }

    fn prepare(&self) -> Result<PreparedSemanticAttemptResult, PreparedSemanticResultCodecError> {
        match self {
            Self::Legacy {
                observation,
                finding,
            } => PreparedSemanticAttemptResult::new(observation.clone(), finding.clone()),
            Self::Prepared(result) => Ok(result.clone()),
        }
    }
}

/// Captured checkpoint retained for no-write preparation retry.
#[derive(Debug)]
pub struct PendingCheckpointResult {
    queued: QueuedAttempt,
    checkpoint: AttemptCheckpointResult,
}

impl PendingCheckpointResult {
    /// Returns the exact execution whose capture awaits preparation.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the captured metadata and opaque VMState source.
    #[must_use]
    pub const fn checkpoint(&self) -> &AttemptCheckpointResult {
        &self.checkpoint
    }

    /// Consumes the pending value into its execution token and capture.
    #[must_use]
    pub fn into_parts(self) -> (QueuedAttempt, AttemptCheckpointResult) {
        (self.queued, self.checkpoint)
    }
}

/// Read-only-preflighted result ready for a short publication-root CAS.
#[derive(Debug)]
pub struct PreparedAttemptResult {
    queued: QueuedAttempt,
    result: PreparedAttemptResultOwner,
    observation: ObservationId,
    finding_candidate: Option<crucible_campaign::FindingCandidateBundleId>,
    finding_exact_retention: Option<PreparedFindingExactRetention>,
}

#[derive(Debug)]
enum PreparedAttemptResultOwner {
    Volatile(Box<PreparedSemanticAttemptResult>),
    Journal(Box<DirectoryPreparedResultJournal>),
}

impl PreparedAttemptResultOwner {
    const fn result(&self) -> &PreparedSemanticAttemptResult {
        match self {
            Self::Volatile(result) => result,
            Self::Journal(journal) => journal.result(),
        }
    }

    fn into_journal(self) -> Option<DirectoryPreparedResultJournal> {
        match self {
            Self::Volatile(_) => None,
            Self::Journal(journal) => Some(*journal),
        }
    }
}

impl PreparedAttemptResult {
    /// Returns the exact execution token.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the preflighted immutable observation identity.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the finding root that must be staged with the observation.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<crucible_campaign::FindingCandidateBundleId> {
        self.finding_candidate
    }

    /// Returns portable replay capture roots already bound into the candidate.
    #[must_use]
    pub fn finding_replay_captures(&self) -> Option<crucible_campaign::FindingReplayCaptureSet> {
        self.result()
            .finding()
            .and_then(|finding| finding.bundle().replay_captures())
    }

    /// Returns selected exact roots that must survive candidate publication.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] if automatic selection
    /// produced more roots than the daemon's three canonical boundary roles.
    pub fn finding_exact_retention_roots(
        &self,
    ) -> Result<[Option<ExactCheckpointId>; 3], PreparedSemanticResultCodecError> {
        let Some(bundle) = self.result().finding().map(|finding| finding.bundle()) else {
            return Ok([None; 3]);
        };
        if !bundle.exact_retention().is_some_and(|retention| {
            retention.disposition() == FindingExactRetentionDisposition::Complete
        }) {
            return Ok([None; 3]);
        }

        let mut roots = [None; 3];
        for (index, checkpoint) in bundle.exact_pins().all().iter().copied().enumerate() {
            let Some(slot) = roots.get_mut(index) else {
                return Err(PreparedSemanticResultCodecError::Inconsistent {
                    component: "automatic finding exact retention root count",
                });
            };
            *slot = Some(checkpoint);
        }
        Ok(roots)
    }

    /// Returns the pending automatic exact-retention handoff, when present.
    #[must_use]
    pub const fn finding_exact_retention(&self) -> Option<&PreparedFindingExactRetention> {
        self.finding_exact_retention.as_ref()
    }

    /// Removes the linear automatic exact-retention handoff for guarded processing.
    pub(crate) fn take_finding_exact_retention(&mut self) -> Option<PreparedFindingExactRetention> {
        self.finding_exact_retention.take()
    }

    /// Encodes transient production captures before any repository write.
    ///
    /// # Errors
    ///
    /// Returns an error when a complete capture no longer authenticates or
    /// exceeds its scenario-derived encoding bound.
    pub(crate) fn production_replay_capture_inputs(
        &self,
    ) -> Result<
        Option<[crate::FindingReplayCaptureInput; 4]>,
        crate::FindingProductionReplayCaptureError,
    > {
        self.result().production_replay_capture_inputs()
    }

    /// Rebuilds a volatile prepared finding around durable capture roots.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this token already
    /// owns a journal or the rebuilt finding candidate is inconsistent.
    pub(crate) fn bind_production_replay_captures(
        &mut self,
        captures: crucible_campaign::FindingReplayCaptureSet,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let PreparedAttemptResultOwner::Volatile(current) = &self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay captures attached after journaling",
            });
        };
        let finding = current.prepare_bound_production_replay_finding(captures)?;
        let finding_candidate = Some(finding.id()?);

        let PreparedAttemptResultOwner::Volatile(result) = &mut self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding replay capture owner changed during binding",
            });
        };
        result.commit_bound_production_replay_finding(finding);
        self.finding_candidate = finding_candidate;
        Ok(())
    }

    /// Rebuilds the volatile finding around selected exact pins and retention evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when this token already
    /// owns a journal or the rebuilt finding is inconsistent.
    pub(crate) fn bind_finding_exact_retention(
        &mut self,
        exact_pins: FindingExactPins,
        retention: FindingExactRetention,
        evidence: Option<crucible_campaign::FindingExactRetentionEvidence>,
    ) -> Result<(), PreparedSemanticResultCodecError> {
        let PreparedAttemptResultOwner::Volatile(current) = &self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding exact retention attached after journaling",
            });
        };
        let finding =
            current.prepare_bound_finding_exact_retention(exact_pins, retention, evidence)?;
        let finding_candidate = Some(finding.id()?);

        let PreparedAttemptResultOwner::Volatile(result) = &mut self.result else {
            return Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "finding exact retention owner changed during binding",
            });
        };
        result.commit_bound_production_replay_finding(finding);
        self.finding_candidate = finding_candidate;
        Ok(())
    }

    /// Returns the exact prepared semantic closure.
    #[must_use]
    pub const fn result(&self) -> &PreparedSemanticAttemptResult {
        self.result.result()
    }

    /// Returns the digest that binds the complete prepared recovery payload.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedSemanticResultCodecError`] when the result cannot be
    /// encoded under its format ceiling.
    pub(crate) fn prepared_result_digest(
        &self,
    ) -> Result<CampaignHash, PreparedSemanticResultCodecError> {
        match &self.result {
            PreparedAttemptResultOwner::Volatile(result) => Ok(CampaignHash::derive(
                "crucible.executor.prepared-result-ledger-binding.v1",
                &result.canonical_bytes()?,
            )),
            PreparedAttemptResultOwner::Journal(journal) => Ok(journal.prepared_result_digest()),
        }
    }

    /// Recovers the execution token when durable journal ownership was never acquired.
    pub(crate) fn into_queued_without_journal(self) -> Result<QueuedAttempt, Box<Self>> {
        let Self {
            queued,
            result,
            observation,
            finding_candidate,
            finding_exact_retention,
        } = self;
        match result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(queued),
            PreparedAttemptResultOwner::Journal(journal) => Err(Box::new(Self {
                queued,
                result: PreparedAttemptResultOwner::Journal(journal),
                observation,
                finding_candidate,
                finding_exact_retention,
            })),
        }
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        match &self.result {
            PreparedAttemptResultOwner::Volatile(_) => Ok(()),
            PreparedAttemptResultOwner::Journal(journal) => journal.remove(),
        }
    }

    /// Promotes a hidden prepared-result journal after publication-root staging.
    pub(crate) fn commit_staged_journal(mut self) -> Result<Self, AttemptResultJournalError> {
        if let PreparedAttemptResultOwner::Journal(journal) = &mut self.result
            && let Err(source) = journal.commit_staged()
        {
            return Err(AttemptResultJournalError {
                prepared: Box::new(self),
                source,
            });
        }
        Ok(self)
    }
}

/// Result of probing durable prepared-result recovery before guest execution.
#[derive(Debug)]
pub enum PreparedAttemptRecoveryOutcome {
    /// No complete journal exists; the fresh execution token remains runnable.
    Missing(Box<QueuedAttempt>),
    /// A producer result was recovered and must be published without guest work.
    Prepared(Box<PreparedAttemptResult>),
}

/// Durable journal creation failure retaining the complete prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local prepared-result journal creation failed")]
pub struct AttemptResultJournalError {
    /// Prepared result retained for exact journal creation retry.
    pub prepared: Box<PreparedAttemptResult>,
    /// Durable journal failure.
    pub source: PreparedResultJournalError,
}

/// Durable prepared-result recovery failure retaining the fresh execution token.
#[derive(Debug, thiserror::Error)]
#[error("local prepared-result journal recovery failed")]
pub struct AttemptResultRecoveryError {
    /// Fresh supervisor execution token that has not run guest work.
    pub queued: Box<QueuedAttempt>,
    /// Journal or semantic authentication failure.
    pub source: AttemptResultRecoveryFailure,
}

/// Failure while reopening and authenticating one durable prepared result.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultRecoveryFailure {
    /// Durable journal authentication failed.
    #[error(transparent)]
    Journal(#[from] PreparedResultJournalError),
    /// Recovered semantic content failed repository or scenario authentication.
    #[error(transparent)]
    Preparation(#[from] AttemptResultPreparationFailure),
    /// Portable capture manifests or chunks were absent or inconsistent.
    #[error(transparent)]
    CaptureStore(#[from] crate::FindingReplayCaptureStoreError),
    /// Reassembled production replay bytes failed canonical authentication.
    #[error(transparent)]
    ProductionReplay(#[from] crate::FindingProductionReplayCaptureError),
}

/// Candidate whose immutable objects were published outside the supervisor actor.
#[derive(Debug)]
pub struct PublishedAttemptResult {
    queued: QueuedAttempt,
    observation: ObservationId,
    finding_candidate: Option<crucible_campaign::FindingCandidateBundleId>,
    journal: Option<DirectoryPreparedResultJournal>,
}

/// Linear token proving the durable publication root was installed first.
#[derive(Debug)]
pub struct StagedAttemptResult {
    prepared: PreparedAttemptResult,
}

#[cfg(test)]
impl StagedAttemptResult {
    pub(crate) fn from_test_parts(
        queued: QueuedAttempt,
        result: PreparedSemanticAttemptResult,
    ) -> Self {
        let observation = result
            .observation()
            .observation()
            .id()
            .expect("test staged observation ID");
        let finding_candidate = result
            .finding()
            .map(PreparedCrucibleFindingCandidate::id)
            .transpose()
            .expect("test staged finding candidate ID");
        Self {
            prepared: PreparedAttemptResult {
                queued,
                result: PreparedAttemptResultOwner::Volatile(Box::new(result)),
                observation,
                finding_candidate,
                finding_exact_retention: None,
            },
        }
    }
}

/// Prepared exact checkpoint bound to the sole execution reconciliation token.
#[derive(Debug)]
pub struct PreparedCheckpointResult {
    queued: QueuedAttempt,
    checkpoint: PreparedAttemptCheckpoint,
}

/// Read-only-prepared worker result ready for its short supervisor phase.
#[derive(Debug)]
pub enum PreparedAttemptWorkResult {
    /// Canonical observation candidate ready for publication-root staging.
    Observation(Box<PreparedAttemptResult>),
    /// Exact checkpoint root ready for checkpoint-publication staging.
    ExactCheckpoint(Box<PreparedCheckpointResult>),
}

impl PreparedCheckpointResult {
    /// Binds a no-write checkpoint preparation to its consumed worker token.
    #[must_use]
    pub const fn new(queued: QueuedAttempt, checkpoint: PreparedAttemptCheckpoint) -> Self {
        Self { queued, checkpoint }
    }

    /// Returns the exact execution token.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the exact root that must be staged before publication.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.checkpoint.root()
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        self.checkpoint.native_retirement()
    }
}

/// Linear proof that a checkpoint publication root is durable.
#[derive(Debug)]
pub struct StagedCheckpointResult {
    prepared: PreparedCheckpointResult,
}

impl StagedCheckpointResult {
    /// Returns the exact execution token owned by this publication phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.prepared.queued
    }

    /// Returns the exact staged checkpoint root.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.prepared.root()
    }
}

/// Complete durable checkpoint awaiting the final paused-state CAS.
#[derive(Debug)]
pub struct PublishedCheckpointResult {
    queued: QueuedAttempt,
    publication: AttemptCheckpointPublication,
}

impl PublishedCheckpointResult {
    /// Returns the exact execution token owned by paused-state reconciliation.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the complete durable exact-checkpoint root.
    #[must_use]
    pub const fn root(&self) -> crucible_campaign::ExactCheckpointId {
        self.publication.root()
    }
}

/// Actor result of consuming one prepared exact checkpoint.
#[derive(Debug)]
pub enum CheckpointResultStageOutcome {
    /// Immutable publication may proceed outside the supervisor actor.
    Publish(Box<StagedCheckpointResult>),
    /// Another idempotent or terminal state won without further writes.
    Finished {
        /// Prepared token retained so redundant native state can be retired.
        prepared: Box<PreparedCheckpointResult>,
        /// Exact deterministic checkpoint root that was not republished.
        checkpoint: crucible_campaign::ExactCheckpointId,
        /// Durable stage disposition.
        outcome: CheckpointPublicationOutcome,
    },
}

/// Checkpoint-root staging failure retaining the sole prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint root staging failed")]
pub struct CheckpointResultStagingError<L> {
    /// Prepared checkpoint retained for exact actor retry.
    pub prepared: Box<PreparedCheckpointResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Checkpoint publication failure retaining the staged token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint publication failed")]
pub struct CheckpointResultPublicationError {
    /// Staged checkpoint retained for direct publication retry.
    pub staged: Box<StagedCheckpointResult>,
    /// Immutable-store failure.
    pub source: ExactCheckpointStoreError,
}

/// Paused-state reconciliation failure retaining the published root token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint reconciliation failed")]
pub struct CheckpointResultReconcileError<L> {
    /// Published checkpoint retained for exact actor retry.
    pub published: Box<PublishedCheckpointResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Any post-capture checkpoint phase that can be explicitly abandoned.
#[derive(Debug)]
pub enum CheckpointResultAbortToken {
    /// The checkpoint is prepared but has no durable publication root.
    Prepared(Box<PreparedCheckpointResult>),
    /// The root is durable but immutable publication is incomplete.
    Staged(Box<StagedCheckpointResult>),
    /// Immutable publication completed but paused-state reconciliation did not.
    Published(Box<PublishedCheckpointResult>),
}

impl CheckpointResultAbortToken {
    fn queued(&self) -> &QueuedAttempt {
        match self {
            Self::Prepared(prepared) => prepared.queued(),
            Self::Staged(staged) => staged.queued(),
            Self::Published(published) => published.queued(),
        }
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        match self {
            Self::Prepared(prepared) => prepared.native_retirement(),
            Self::Staged(staged) => staged.prepared.native_retirement(),
            Self::Published(_) => None,
        }
    }
}

/// Explicit checkpoint-abort failure retaining the complete phase token.
#[derive(Debug, thiserror::Error)]
#[error("local exact-checkpoint abort failed")]
pub struct CheckpointResultAbortError<L> {
    /// Captured checkpoint retained for exact cancellation retry.
    pub token: CheckpointResultAbortToken,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

impl StagedAttemptResult {
    /// Returns the exact execution token owned by this publication phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        self.prepared.queued()
    }

    /// Returns the prepared token after an early publication-root transition.
    #[must_use]
    pub(crate) fn into_prepared(self) -> PreparedAttemptResult {
        self.prepared
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        self.prepared.remove_journal()
    }
}

impl PublishedAttemptResult {
    /// Returns the exact execution token owned by this completion phase.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the published finding candidate retained with completion.
    #[must_use]
    pub const fn finding_candidate(&self) -> Option<crucible_campaign::FindingCandidateBundleId> {
        self.finding_candidate
    }

    pub(crate) fn remove_journal(&self) -> Result<(), PreparedResultJournalError> {
        match &self.journal {
            Some(journal) => journal.remove(),
            None => Ok(()),
        }
    }
}

/// Actor result of consuming one prepared candidate.
#[derive(Debug)]
pub enum AttemptResultStageOutcome {
    /// Immutable publication may now proceed outside the actor.
    Publish(Box<StagedAttemptResult>),
    /// Publication must not run because another operational outcome won.
    Finished {
        /// Prepared ownership retained until journal cleanup is durable.
        prepared: Box<PreparedAttemptResult>,
        /// Stable operational outcome that prevented publication.
        outcome: AttemptWorkerReconcileOutcome,
    },
}

impl PendingAttemptResult {
    /// Returns the exact execution whose result awaits publication.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        &self.queued
    }

    /// Returns the already-modeled immutable candidate.
    #[must_use]
    pub const fn candidate(&self) -> &ObservationCandidate {
        self.result.observation()
    }

    /// Returns the prepared finding closure retained with the observation.
    #[must_use]
    pub const fn finding(&self) -> Option<&PreparedCrucibleFindingCandidate> {
        self.result.finding()
    }

    /// Consumes the pending value into its linear token, candidate, and capture owner.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        QueuedAttempt,
        ObservationCandidate,
        Option<PreparedFindingExactRetention>,
    ) {
        let candidate = match self.result {
            PendingAttemptResultOwner::Legacy { observation, .. } => observation,
            PendingAttemptResultOwner::Prepared(result) => result.into_parts().0,
        };
        (self.queued, candidate, self.finding_exact_retention)
    }
}

/// Failure while reconciling a worker result with its supervisor.
#[derive(Debug, thiserror::Error)]
pub enum AttemptWorkerReconcileError<W, L> {
    /// A retryable guest failure left the accepted assignment queued.
    #[error("local attempt worker failed")]
    Worker(AttemptWorkerFailure<W>),
    /// A canceled or terminal failure was durably stopped without retry.
    #[error("local attempt worker stopped without retry")]
    Stopped {
        /// Stable worker-failure classification and diagnostic payload.
        failure: AttemptWorkerFailure<W>,
        /// Durable operational cancellation race outcome.
        cancellation: CancellationOutcome,
    },
    /// A non-retryable failure was durably retained without retry.
    #[error("local attempt worker failed terminally without retry")]
    TerminalStopped {
        /// Stable worker-failure classification and diagnostic payload.
        failure: AttemptWorkerFailure<W>,
        /// Durable terminal-state publication race outcome.
        terminal_failure: TerminalFailureOutcome,
    },
    /// Failure-stop staging did not take ownership; retry with this exact token.
    #[error("local executor failure reconciliation is pending")]
    FailurePending {
        /// Linear execution token not yet owned by supervisor pending state.
        queued: Box<QueuedAttempt>,
        /// Stable worker failure that must not be lost or rerun incorrectly.
        failure: AttemptWorkerFailure<W>,
        /// Supervisor or operational-ledger failure.
        source: L,
    },
    /// Completion staging did not finish; retry with this exact published token.
    #[error("local executor completion reconciliation is pending")]
    CompletionPending {
        /// Published result retained for exact completion retry.
        published: Box<PublishedAttemptResult>,
        /// Supervisor or operational-ledger failure.
        source: L,
    },
    /// Completion is durable but prepared-result journal cleanup must retry.
    #[error("local prepared-result journal cleanup is pending")]
    JournalCleanupPending {
        /// Published result retaining the journal lock for exact cleanup retry.
        published: Box<PublishedAttemptResult>,
        /// Durable journal removal failure.
        source: PreparedResultJournalError,
    },
}

/// Read-only candidate preflight failure before the supervisor actor is borrowed.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPreparationError<W> {
    /// Guest execution failed and still needs short actor reconciliation.
    #[error("local attempt worker failed")]
    Worker {
        /// Exact execution token returned by the worker.
        queued: Box<QueuedAttempt>,
        /// Stable retry, cancellation, or terminal classification.
        failure: AttemptWorkerFailure<W>,
        /// Native capture authority rejected after model execution.
        retirement: Option<NativeCheckpointCleanup>,
    },
    /// Candidate preflight failed without writing immutable objects.
    #[error("local attempt result preflight failed")]
    Candidate {
        /// Already-executed candidate retained for direct retry.
        pending: Box<PendingAttemptResult>,
        /// Repository failure from the read-only preflight.
        source: AttemptResultPreparationFailure,
    },
    /// Exact capture preparation failed without publishing immutable objects.
    #[error("local exact-checkpoint preparation failed")]
    Checkpoint {
        /// Captured checkpoint retained for direct preparation retry.
        pending: Box<PendingCheckpointResult>,
        /// Exact-checkpoint store failure from the no-write preparation phase.
        source: ExactCheckpointStoreError,
    },
}

/// Failure to authenticate a prepared semantic closure before publication.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPreparationFailure {
    /// Required immutable campaign input was unavailable or inconsistent.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Authenticated Crucible scenario decoding failed.
    #[error(transparent)]
    Artifact(#[from] crate::CrucibleArtifactError),
    /// A retained raw measurement leaf has an invalid canonical identity.
    #[error(transparent)]
    Measurement(#[from] crate::CrucibleMeasurementError),
    /// Crucible scenario or prepared-result replay validation failed.
    #[error(transparent)]
    Result(#[from] PreparedSemanticResultCodecError),
}

impl AttemptResultPreparationFailure {
    /// Returns the stable executor classification for this preflight failure.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Repository(error) => error.executor_rejection(),
            Self::Artifact(_) | Self::Measurement(_) | Self::Result(_) => {
                ExecutorRejection::Incompatible
            }
        }
    }
}

/// Immutable publication failure retaining the preflighted candidate.
#[derive(Debug, thiserror::Error)]
#[error("local attempt result publication failed")]
pub struct AttemptResultPublicationError {
    /// Staged candidate retained for direct publication retry.
    pub staged: Box<StagedAttemptResult>,
    /// Repository failure from immutable publication.
    pub source: AttemptResultPublicationFailure,
}

/// Failure while publishing a verified prepared-result closure.
#[derive(Debug, thiserror::Error)]
pub enum AttemptResultPublicationFailure {
    /// Immutable repository publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained raw leaf could not reproduce its canonical identity.
    #[error(transparent)]
    Measurement(#[from] crate::CrucibleMeasurementError),
}

impl AttemptResultPublicationFailure {
    /// Returns the stable executor classification for this publication failure.
    #[must_use]
    pub fn executor_rejection(&self) -> ExecutorRejection {
        match self {
            Self::Repository(error) => error.executor_rejection(),
            Self::Measurement(_) => ExecutorRejection::Incompatible,
        }
    }

    /// Returns whether the exact publication can be retried without guest work.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Repository(error)
                if error.executor_rejection() == ExecutorRejection::UnavailableInput
        )
    }
}

/// Publication-root staging failure retaining the sole prepared token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt publication-root staging failed")]
pub struct AttemptResultStagingError<L> {
    /// Preflighted candidate retained for exact actor retry.
    pub prepared: Box<PreparedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Stable publication-abort failure retaining the staged candidate token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt publication abort failed")]
pub struct AttemptResultAbortError<L> {
    /// Staged candidate retained for an exact cancellation retry.
    pub staged: Box<StagedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Stable completion-abort failure retaining the published candidate token.
#[derive(Debug, thiserror::Error)]
#[error("local attempt completion abort failed")]
pub struct PublishedAttemptResultAbortError<L> {
    /// Published candidate retained for an exact cancellation retry.
    pub published: Box<PublishedAttemptResult>,
    /// Supervisor or operational-ledger failure.
    pub source: L,
}

/// Installs the durable checkpoint root with a short supervisor CAS.
///
/// The consumed token is returned on every actor failure, so a ledger error
/// never forces QEMU execution or checkpoint capture to repeat.
///
/// # Errors
///
/// Returns [`CheckpointResultStagingError`] with the complete prepared token
/// when the operational ledger cannot safely establish the root.
pub fn stage_prepared_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedCheckpointResult,
) -> Result<CheckpointResultStageOutcome, CheckpointResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = prepared.root();
    let stage = match supervisor.stage_checkpoint_publication(prepared.queued(), checkpoint) {
        Ok(stage) => stage,
        Err(source) => {
            return Err(CheckpointResultStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        CheckpointPublicationOutcome::Staged | CheckpointPublicationOutcome::AlreadyStaged => Ok(
            CheckpointResultStageOutcome::Publish(Box::new(StagedCheckpointResult { prepared })),
        ),
        CheckpointPublicationOutcome::AlreadyPaused | CheckpointPublicationOutcome::NotCurrent => {
            Ok(CheckpointResultStageOutcome::Finished {
                prepared: Box::new(prepared),
                checkpoint,
                outcome: stage,
            })
        }
    }
}

/// Publishes every exact-checkpoint child and its root outside actor ownership.
///
/// # Errors
///
/// Returns [`CheckpointResultPublicationError`] with the staged token when any
/// exact durable placement or authentication step fails.
pub fn publish_staged_checkpoint_result(
    store: &ExactCheckpointStore,
    staged: StagedCheckpointResult,
) -> Result<PublishedCheckpointResult, CheckpointResultPublicationError> {
    let publication = match store.publish_attempt_checkpoint(&staged.prepared.checkpoint) {
        Ok(publication) => publication,
        Err(source) => {
            return Err(CheckpointResultPublicationError {
                staged: Box::new(staged),
                source,
            });
        }
    };
    if let PreparedAttemptCheckpoint::Production(prepared) = &staged.prepared.checkpoint
        && let Err(source) = prepared.retire_native_source()
    {
        return Err(CheckpointResultPublicationError {
            staged: Box::new(staged),
            source,
        });
    }
    Ok(PublishedCheckpointResult {
        queued: staged.prepared.queued,
        publication,
    })
}

/// Promotes one fully published checkpoint to durable paused state.
///
/// The worker/session owner must call this only after QEMU teardown has
/// attested physical process exit. Capacity is released by the successful or
/// idempotent paused-state transition, never merely by publishing bytes.
///
/// # Errors
///
/// Returns [`CheckpointResultReconcileError`] with the published token when
/// the operational ledger cannot safely reconcile the paused state.
pub fn reconcile_published_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedCheckpointResult,
) -> Result<CheckpointCompletionOutcome, CheckpointResultReconcileError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = published.root();
    match supervisor.complete_checkpoint(&published.queued, checkpoint) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultReconcileError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Explicitly abandons one captured checkpoint without re-running the guest.
///
/// Cancellation removes any staged checkpoint root only after the worker has
/// physically returned. Partial immutable objects then become ordinary
/// collection candidates; no active capacity or linear result token is lost.
///
/// # Errors
///
/// Returns [`CheckpointResultAbortError`] with the complete phase token when
/// durable cancellation cannot be reconciled safely.
pub fn abort_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    token: CheckpointResultAbortToken,
) -> Result<CancellationOutcome, CheckpointResultAbortError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(token.queued()) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultAbortError { token, source }),
    }
}

/// Preflights one independently executed worker result outside supervision.
///
/// The caller first obtains [`QueuedAttempt`] with
/// [`LocalExecutorSupervisor::next_queued`], moves that value to a worker
/// thread, and later calls this function without borrowing the supervisor.
/// Repository closure traversal can therefore never block submission or
/// cancellation handling on the actor thread.
///
/// # Errors
///
/// Returns the linear worker token with either its classified worker failure or
/// its candidate when read-only preflight fails.
pub fn prepare_attempt_result<W>(
    store: &CampaignExecutorStore,
    checkpoints: &ExactCheckpointStore,
    work: AttemptWorkResult<W>,
) -> Result<PreparedAttemptWorkResult, AttemptResultPreparationError<W>> {
    let AttemptWorkResult {
        queued,
        result,
        abandoned_checkpoint,
    } = work;
    let product = match result {
        Ok(product) => product,
        Err(failure) => {
            return Err(AttemptResultPreparationError::Worker {
                queued: Box::new(queued),
                failure,
                retirement: abandoned_checkpoint,
            });
        }
    };
    match product {
        AttemptExecutionProduct::Observation(candidate) => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Legacy {
                    observation: *candidate,
                    finding: None,
                },
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::ObservationWithFinding {
            observation,
            finding,
        } => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Legacy {
                    observation: *observation,
                    finding: Some(*finding),
                },
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::PreparedSemantic(result) => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Prepared(*result),
                finding_exact_retention: None,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, retention } => {
            prepare_pending_attempt_result(
                store,
                PendingAttemptResult {
                    queued,
                    result: PendingAttemptResultOwner::Prepared(*result),
                    finding_exact_retention: Some(*retention),
                },
            )
            .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared)))
        }
        AttemptExecutionProduct::ExactCheckpoint(capture) => prepare_pending_checkpoint_result(
            checkpoints,
            PendingCheckpointResult {
                queued,
                checkpoint: *capture,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::ExactCheckpoint(Box::new(prepared))),
    }
}

/// Retries read-only preflight of an already-executed candidate.
///
/// # Errors
///
/// Returns the same candidate error with the linear pending token retained.
pub fn retry_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    prepare_pending_attempt_result(store, pending)
}

/// Persists a preflighted semantic result before publication can be staged.
///
/// An existing journal must contain the exact same result and producer
/// execution. The returned token owns the per-attempt journal lock until
/// completion or cancellation becomes durable.
///
/// # Errors
///
/// Returns [`AttemptResultJournalError`] with the complete prepared token when
/// journal creation, reopening, authentication, or durability fails.
pub fn journal_prepared_attempt_result(
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let (prepared, disposition) =
        stage_prepared_attempt_result_journal(namespace, maximum_payload_bytes, prepared)?;
    Ok((prepared.commit_staged_journal()?, disposition))
}

pub(crate) fn stage_prepared_attempt_result_journal(
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    mut prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let key = crate::AttemptExecutionKey::for_request(prepared.queued.request());
    let execution = prepared.queued.execution();
    let result = prepared.result().clone();
    let (journal, disposition) = match DirectoryPreparedResultJournal::prepare_staged(
        namespace,
        key,
        execution,
        maximum_payload_bytes,
        result,
    ) {
        Ok(created) => created,
        Err(source) => {
            return Err(AttemptResultJournalError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    prepared.result = PreparedAttemptResultOwner::Journal(Box::new(journal));
    Ok((prepared, disposition))
}

/// Reopens a complete producer journal before allowing fresh guest execution.
///
/// The fresh `queued` token remains the supervisor reconciliation authority;
/// the journal retains its separately authenticated producer execution ID.
/// Recovered semantic bytes are rechecked against immutable repository input
/// and authenticated scenario measurement definitions.
///
/// # Errors
///
/// Returns [`AttemptResultRecoveryError`] with the fresh execution token when
/// journal or semantic authentication fails.
pub fn recover_prepared_attempt_result(
    store: &CampaignExecutorStore,
    namespace: impl AsRef<Path>,
    maximum_payload_bytes: usize,
    queued: QueuedAttempt,
) -> Result<PreparedAttemptRecoveryOutcome, AttemptResultRecoveryError> {
    let key = crate::AttemptExecutionKey::for_request(queued.request());
    let journal = match DirectoryPreparedResultJournal::open_for_recovery(
        namespace,
        key,
        maximum_payload_bytes,
    ) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Ok(PreparedAttemptRecoveryOutcome::Missing(Box::new(queued))),
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: source.into(),
            });
        }
    };
    let observation = match journal.result().observation().observation().id() {
        Ok(observation) => observation,
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: AttemptResultPreparationFailure::Repository(
                    CampaignRepositoryError::Codec(source),
                )
                .into(),
            });
        }
    };
    let finding_candidate = match journal.result().finding() {
        Some(finding) => match finding.id() {
            Ok(finding) => Some(finding),
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: AttemptResultPreparationFailure::Repository(
                        CampaignRepositoryError::Codec(source),
                    )
                    .into(),
                });
            }
        },
        None => None,
    };
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        journal.result(),
    ) {
        return Err(AttemptResultRecoveryError {
            queued: Box::new(queued),
            source: source.into(),
        });
    }
    if let Some(captures) = journal
        .result()
        .finding()
        .and_then(|finding| finding.bundle().replay_captures())
    {
        let guard = match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => guard,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: crate::FindingReplayCaptureStoreError::from(source).into(),
                });
            }
        };
        let loaded = match crate::FindingReplayCaptureStore::load_set(&guard, captures) {
            Ok(loaded) => loaded,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: source.into(),
                });
            }
        };
        if let Err(source) = validate_recovered_finding_replay_captures(journal.result(), &loaded) {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source,
            });
        }
    }

    Ok(PreparedAttemptRecoveryOutcome::Prepared(Box::new(
        PreparedAttemptResult {
            queued,
            result: PreparedAttemptResultOwner::Journal(Box::new(journal)),
            observation,
            finding_candidate,
            finding_exact_retention: None,
        },
    )))
}

fn validate_recovered_finding_replay_captures(
    result: &PreparedSemanticAttemptResult,
    loaded: &[crate::LoadedFindingReplayCapture; 4],
) -> Result<(), AttemptResultRecoveryFailure> {
    let finding = result.finding().ok_or({
        AttemptResultPreparationFailure::Result(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay captures without finding",
        })
    })?;
    let limits = finding
        .production_replay_capture_limits()
        .map_err(AttemptResultPreparationFailure::Result)?;
    let bindings = finding
        .production_replay_capture_bindings()
        .map_err(CampaignRepositoryError::Codec)
        .map_err(AttemptResultPreparationFailure::Repository)?;

    for (capture, (reproduction, observed_signature)) in loaded.iter().zip(bindings) {
        let crate::LoadedFindingReplayCapture::Complete {
            bytes,
            content_hash,
        } = capture
        else {
            continue;
        };
        let capture = crate::FindingProductionReplayCapture::from_canonical_bytes(bytes, limits)?;
        if capture.content_hash(limits)? != *content_hash {
            return Err(crate::FindingProductionReplayCaptureError::CaptureBinding.into());
        }
        capture.validate_binding(reproduction, observed_signature)?;
    }
    Ok(())
}

/// Retries no-write preparation of an already-captured exact checkpoint.
///
/// # Errors
///
/// Returns the same checkpoint error with the linear capture token retained.
pub fn retry_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    prepare_pending_checkpoint_result(checkpoints, pending)
}

fn prepare_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    let observation = match pending.candidate().observation().id() {
        Ok(observation) => observation,
        Err(error) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: CampaignRepositoryError::Codec(error).into(),
            });
        }
    };
    let finding_candidate = match pending.finding() {
        Some(finding) => {
            if finding.bundle().observation() != observation {
                return Err(AttemptResultPreparationError::Candidate {
                    pending: Box::new(pending),
                    source: CampaignRepositoryError::Integrity {
                        reason: "prepared-finding-observation-mismatch",
                    }
                    .into(),
                });
            }
            match finding.id() {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    return Err(AttemptResultPreparationError::Candidate {
                        pending: Box::new(pending),
                        source: CampaignRepositoryError::Codec(error).into(),
                    });
                }
            }
        }
        None => None,
    };
    let result = match pending.result.prepare() {
        Ok(result) => result,
        Err(source) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: source.into(),
            });
        }
    };
    let PendingAttemptResult {
        queued,
        result: _,
        finding_exact_retention,
    } = pending;
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        &result,
    ) {
        return Err(AttemptResultPreparationError::Candidate {
            pending: Box::new(PendingAttemptResult {
                queued,
                result: PendingAttemptResultOwner::Prepared(result),
                finding_exact_retention,
            }),
            source,
        });
    }
    Ok(PreparedAttemptResult {
        queued,
        result: PreparedAttemptResultOwner::Volatile(Box::new(result)),
        observation,
        finding_candidate,
        finding_exact_retention,
    })
}

fn validate_prepared_observation_candidate(
    store: &CampaignExecutorStore,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    let observation_trace_leaves = result
        .observation()
        .measurements()
        .evaluation()
        .into_iter()
        .flat_map(|evaluation| evaluation.evidence().iter().copied())
        .filter(|content| content.kind() == ObjectKind::Trace)
        .collect::<BTreeSet<_>>();
    let owned_trace_leaves = result
        .measurement_replay_evidence()
        .iter()
        .filter_map(|evidence| match evidence.id() {
            Ok(content) if observation_trace_leaves.contains(&content) => Some(
                evidence
                    .canonical_bytes()
                    .map(|bytes| (content, evidence.schema_version(), bytes)),
            ),
            Ok(_) => None,
            Err(source) => Some(Err(source)),
        })
        .collect::<Result<Vec<_>, crate::CrucibleMeasurementError>>()?;
    let owned_trace_leaf_bytes = owned_trace_leaves
        .iter()
        .map(|(content, schema_version, bytes)| (*content, *schema_version, bytes.as_slice()))
        .collect::<Vec<_>>();
    store.validate_observation_candidate_with_owned_trace_leaf_bytes(
        result.observation(),
        &owned_trace_leaf_bytes,
    )?;
    Ok(())
}

/// Authenticates one prepared semantic result against its exact execution key.
///
/// # Errors
///
/// Returns an error when the key is not semantic, the observation differs from
/// the assigned attempt or lineage, or any scenario, measurement, or closure
/// dependency fails authentication.
pub(crate) fn validate_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    expected: crate::AttemptExecutionKey,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    if expected.scope() != crucible_campaign::AttemptExecutionScope::Semantic {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-nonsemantic-scope",
        }
        .into());
    }
    let lineage = store.load_lineage(expected.lineage())?;
    let observation = result.observation();
    if observation.observation().attempt() != expected.attempt() {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-attempt-mismatch",
        }
        .into());
    }
    if observation.child().scenario() != lineage.scenario()
        || observation.child().scenario_artifact() != lineage.scenario_content()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-lineage-mismatch",
        }
        .into());
    }
    authenticate_prepared_measurements(store, &lineage, result)?;
    validate_prepared_observation_candidate(store, result)
}

fn authenticate_prepared_measurements(
    store: &CampaignExecutorStore,
    lineage: &CampaignLineage,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    let artifact = store.load_scenario_artifact(lineage.scenario_content())?;
    let scenario = crate::decode_crucible_scenario_artifact(&artifact)?;
    result.verify_measurement_publications(&scenario)?;
    result.verify_terminal_fingerprints(&scenario)?;
    Ok(())
}

fn prepare_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    if !pending.queued.checkpoint_request().is_requested() {
        return Err(AttemptResultPreparationError::Checkpoint {
            pending: Box::new(pending),
            source: ExactCheckpointStoreError::InvalidRoot {
                reason: "execution returned an unsolicited exact checkpoint",
            },
        });
    }
    let PendingCheckpointResult { queued, checkpoint } = pending;
    match checkpoint.into_state() {
        AttemptCheckpointResultState::Prepared(checkpoint) => {
            Ok(PreparedCheckpointResult::new(queued, checkpoint))
        }
        AttemptCheckpointResultState::Captured(capture) => {
            match checkpoints.prepare_attempt_checkpoint(capture.reopenable_copy()) {
                Ok(checkpoint) => Ok(PreparedCheckpointResult::new(queued, checkpoint)),
                Err(source) => Err(AttemptResultPreparationError::Checkpoint {
                    pending: Box::new(PendingCheckpointResult {
                        queued,
                        checkpoint: capture.into(),
                    }),
                    source,
                }),
            }
        }
    }
}

/// Reconciles a worker failure using only short supervisor operations.
///
/// # Errors
///
/// Returns the classified worker failure after requeue or durable stop, or a
/// supervisor error if operational reconciliation fails.
pub fn reconcile_attempt_failure<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    queued: QueuedAttempt,
    failure: AttemptWorkerFailure<W>,
) -> Result<(), AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            let failure = AttemptWorkerFailure::Retryable(error);
            if queued.cancellation().is_canceled() {
                let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
                let cancellation = match cancellation {
                    Ok(cancellation) => cancellation,
                    Err(source) => {
                        return Err(AttemptWorkerReconcileError::FailurePending {
                            queued: Box::new(queued),
                            failure,
                            source,
                        });
                    }
                };
                return Err(AttemptWorkerReconcileError::Stopped {
                    failure,
                    cancellation,
                });
            }
            supervisor.requeue(queued);
            Err(AttemptWorkerReconcileError::Worker(failure))
        }
        failure @ AttemptWorkerFailure::Canceled(_) => {
            let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
            let cancellation = match cancellation {
                Ok(cancellation) => cancellation,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::Stopped {
                failure,
                cancellation,
            })
        }
        failure @ AttemptWorkerFailure::Terminal(_) => {
            let terminal_failure = supervisor.stage_and_reconcile_terminal_failure(&queued);
            let terminal_failure = match terminal_failure {
                Ok(terminal_failure) => terminal_failure,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::TerminalStopped {
                failure,
                terminal_failure,
            })
        }
    }
}

/// Establishes the durable publication root with a short supervisor CAS.
///
/// # Errors
///
/// Returns [`LocalExecutorError`] for stale, conflicting, or unavailable
/// operational ledger state.
pub fn stage_prepared_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedAttemptResult,
) -> Result<AttemptResultStageOutcome, AttemptResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let observation = prepared.observation();
    let finding_candidate = prepared.finding_candidate();
    let finding_replay_captures = prepared.finding_replay_captures();
    if finding_candidate.is_none() && finding_replay_captures.is_some() {
        return Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source: LocalExecutorError::LedgerInvariant {
                reason: "finding replay captures have no finding candidate",
            },
        });
    }
    let finding_exact_retention_roots = match prepared.finding_exact_retention_roots() {
        Ok(roots) => roots,
        Err(_) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source: LocalExecutorError::LedgerInvariant {
                    reason: "automatic finding exact retention exceeds publication root bound",
                },
            });
        }
    };
    let prepared_result_digest = match prepared.prepared_result_digest() {
        Ok(digest) => Some(digest),
        Err(_) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source: LocalExecutorError::LedgerInvariant {
                    reason: "prepared result cannot produce a recovery binding",
                },
            });
        }
    };
    if finding_candidate.is_none() && finding_exact_retention_roots != [None; 3] {
        return Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source: LocalExecutorError::LedgerInvariant {
                reason: "finding exact retention roots have no finding candidate",
            },
        });
    }
    let stage_result = supervisor.stage_observation_publication_with_candidate(
        prepared.queued(),
        observation,
        finding_candidate,
        finding_replay_captures,
        finding_exact_retention_roots,
        prepared_result_digest,
    );
    let stage = match stage_result {
        Ok(stage) => stage,
        Err(source) => {
            return Err(AttemptResultStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        ObservationPublicationOutcome::Staged | ObservationPublicationOutcome::AlreadyStaged => Ok(
            AttemptResultStageOutcome::Publish(Box::new(StagedAttemptResult { prepared })),
        ),
        ObservationPublicationOutcome::Canceled => Ok(AttemptResultStageOutcome::Finished {
            prepared: Box::new(prepared),
            outcome: AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::Canceled,
            },
        }),
        ObservationPublicationOutcome::NotCurrent => Ok(AttemptResultStageOutcome::Finished {
            prepared: Box::new(prepared),
            outcome: AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::NotCurrent,
            },
        }),
        ObservationPublicationOutcome::AlreadyCompleted => {
            Ok(AttemptResultStageOutcome::Finished {
                prepared: Box::new(prepared),
                outcome: AttemptWorkerReconcileOutcome::Reconciled {
                    observation,
                    completion: CompletionOutcome::AlreadyCompleted,
                },
            })
        }
    }
}

/// Publishes a preflighted candidate without borrowing the supervisor actor.
///
/// # Errors
///
/// Returns [`AttemptResultPublicationError`] with the complete prepared bundle
/// when immutable storage is temporarily or stably unavailable.
pub fn publish_prepared_attempt_result(
    store: &CampaignExecutorStore,
    staged: Box<StagedAttemptResult>,
) -> Result<PublishedAttemptResult, AttemptResultPublicationError> {
    let _gc_exclusion = if staged.prepared.result().finding().is_some_and(|finding| {
        finding.bundle().replay_captures().is_some() || finding.bundle().exact_retention().is_some()
    }) {
        match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => Some(guard),
            Err(source) => {
                return Err(AttemptResultPublicationError {
                    staged,
                    source: source.into(),
                });
            }
        }
    } else {
        None
    };
    if let Err(source) = publish_prepared_semantic_attempt_result(store, staged.prepared.result()) {
        return Err(AttemptResultPublicationError { staged, source });
    }
    let StagedAttemptResult { prepared } = *staged;
    Ok(PublishedAttemptResult {
        queued: prepared.queued,
        observation: prepared.observation,
        finding_candidate: prepared.finding_candidate,
        journal: prepared.result.into_journal(),
    })
}

/// Publishes a preflighted semantic closure in dependency order.
///
/// Callers must first complete [`validate_prepared_semantic_attempt_result`].
/// Packaged callers retain the staged publication owner while this function
/// writes; the synchronous standalone caller owns its private repository.
///
/// # Errors
///
/// Returns an error when raw evidence cannot derive its declared identity or
/// any trace, observation, or finding object cannot be published exactly.
pub(crate) fn publish_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    result: &PreparedSemanticAttemptResult,
) -> Result<ObservationId, AttemptResultPublicationFailure> {
    for evidence in result.measurement_replay_evidence() {
        let expected = match evidence.id() {
            Ok(expected) => expected,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        let bytes = match evidence.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        store.publish_executor_trace_leaf(expected, evidence.schema_version(), &bytes)?;
    }
    let observation = store.publish_observation_candidate(result.observation())?;
    if let Some(finding) = result.finding() {
        finding.publish_for_executor(store)?;
    }
    Ok(observation)
}

/// Aborts a stably conflicting prepared publication before immutable writes.
///
/// # Errors
///
/// Returns [`AttemptResultStagingError`] with the linear prepared token when
/// durable cancellation cannot yet be reconciled.
pub fn abort_prepared_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedAttemptResult,
) -> Result<
    (CancellationOutcome, PreparedAttemptResult),
    AttemptResultStagingError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(prepared.queued()) {
        Ok(outcome) => Ok((outcome, prepared)),
        Err(source) => Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source,
        }),
    }
}

/// Result of attempting to cancel one staged result without losing its owner.
pub type AttemptResultAbortOutcome<E> = Result<
    (CancellationOutcome, Box<StagedAttemptResult>),
    AttemptResultAbortError<LocalExecutorError<E>>,
>;

/// Aborts a stably failed staged publication without re-running the guest.
///
/// # Errors
///
/// Returns [`AttemptResultAbortError`] with the linear staged token when the
/// durable cancellation cannot yet be reconciled.
pub fn abort_staged_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    staged: Box<StagedAttemptResult>,
) -> AttemptResultAbortOutcome<L::Error>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(staged.prepared.queued()) {
        Ok(outcome) => Ok((outcome, staged)),
        Err(source) => Err(AttemptResultAbortError { staged, source }),
    }
}

/// Aborts a published result after stable completion reconciliation failure.
///
/// The immutable candidate remains content-addressed and may be collected when
/// its canceled publication root is no longer retained. This operation changes
/// only operational execution state and never fabricates campaign meaning.
///
/// # Errors
///
/// Returns [`PublishedAttemptResultAbortError`] with the linear published token
/// when durable cancellation cannot yet be reconciled.
pub fn abort_published_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<
    (CancellationOutcome, PublishedAttemptResult),
    PublishedAttemptResultAbortError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(&published.queued) {
        Ok(outcome) => Ok((outcome, published)),
        Err(source) => Err(PublishedAttemptResultAbortError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Reconciles one already-published result with a short supervisor operation.
///
/// # Errors
///
/// Returns [`AttemptWorkerReconcileError::CompletionPending`] when durable
/// completion validation or ledger reconciliation fails.
pub fn reconcile_published_attempt_result<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<
    AttemptWorkerReconcileOutcome,
    AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let observation = published.observation;
    let completion = match supervisor.stage_and_reconcile_completion_with_finding_candidate(
        &published.queued,
        published.observation,
        published.finding_candidate,
    ) {
        Ok(completion) => completion,
        Err(source) => {
            return Err(AttemptWorkerReconcileError::CompletionPending {
                published: Box::new(published),
                source,
            });
        }
    };
    if let Err(source) = published.remove_journal() {
        return Err(AttemptWorkerReconcileError::JournalCleanupPending {
            published: Box::new(published),
            source,
        });
    }
    Ok(AttemptWorkerReconcileOutcome::Reconciled {
        observation,
        completion,
    })
}

#[cfg(test)]
mod tests;
