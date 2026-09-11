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

mod result;

pub use result::*;

#[cfg(test)]
mod tests;
