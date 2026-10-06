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
    Attempt, AttemptContinuationInput, AttemptResourceLimits, AttemptRetentionPolicyDisposition,
    AttemptStart, AttemptStartMode, BranchPath, CampaignExecutorStore, CampaignLineage,
    CampaignRepositoryError, ConfigurationArtifact, ExactCheckpointId, ExecutionId,
    ExecutionRetentionIntent, ExecutorRejection, FindingExactCheckpointAuthenticator,
    ObservationCandidate, ObservationId, ResolvedSelection, ScenarioArtifact, StopOutcome,
    SubmitAttemptRequest,
};
use std::sync::Arc;
use std::time::Duration;

const MAX_SELECTED_ORIGIN_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONFIGURATION_ARTIFACT_LOAD_BYTES: u64 = 32 * 1024 * 1024 + 1024;
const SELECTED_ORIGIN_STRUCTURAL_BYTES: u64 = 4096;

use crate::exact_checkpoint_store::AttemptCheckpointResultState;
use crate::executor_supervisor::ExecutionCheckpointHandoff;
use crate::guest_selectable::{
    GuestSelectableBoundaryDiagnosticEvent, GuestSelectableBoundaryDiagnosticRecorder,
};
#[cfg(test)]
use crate::supervision::AssignmentHostWatchdogGuard;
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptCheckpointResult, AttemptExecutionOrigin,
    CancellationOutcome, CapturedAttemptCheckpoint, CheckpointCompletionOutcome,
    CheckpointHandoffFailure, CheckpointPublicationOutcome, CompletionOutcome,
    DirectoryPreparedResultJournal, ExactCheckpointStore, ExactCheckpointStoreError,
    ExecutionCancellation, ExecutionCheckpointRequest, LocalExecutorError, LocalExecutorSupervisor,
    PreparedAttemptCheckpoint, PreparedCrucibleFindingCandidate,
    PreparedResultJournalCreateDisposition, PreparedResultJournalError,
    PreparedResultJournalNamespace, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError, ProductionExactCheckpointPublication, QueuedAttempt,
    TerminalFailureOutcome,
};

mod context;
mod result;

pub use context::{AttemptExecutionContext, ExecutionQuantumBudgetError};
pub use result::*;
pub(crate) use result::{bind_admitted_semantic_replay_captures, stage_admitted_prepared_result};

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
    _decode_custody: crucible::owned_decode::DecodeCustody,
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

    pub(crate) fn enter_decode_scope(&self) -> Option<crucible::owned_decode::DecodeScope> {
        self._decode_custody.enter()
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
    let budget = if crucible::owned_decode::current_budget().is_some() {
        None
    } else {
        match store.metadata_resources() {
            Ok(authority) => Some(
                crucible::owned_decode::DecodeBudget::for_store(authority).map_err(|source| {
                    crucible_cas::content_store::StoreError::Supervision {
                        source: Box::new(source),
                    }
                })?,
            ),
            Err(crucible_cas::content_store::StoreError::Unsupported { .. }) => None,
            Err(error) => return Err(error.into()),
        }
    };
    let _scope = budget
        .as_ref()
        .map(crucible::owned_decode::DecodeBudget::enter);
    let result = resolve_owned_attempt_input(store, key, maximum_resident_bytes);
    if let Some(account) = crucible::owned_decode::current_budget() {
        account.check().map_err(
            |source| crucible_cas::content_store::StoreError::Supervision {
                source: Box::new(source),
            },
        )?;
    }
    result
}

fn resolve_owned_attempt_input(
    store: &CampaignExecutorStore,
    key: crate::AttemptExecutionKey,
    maximum_resident_bytes: u64,
) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
    let lineage = store.load_lineage(key.lineage())?;
    let scenario = store.load_scenario_artifact(lineage.scenario_content())?;
    let mut attempt_chain = store.load_attempt_origin_chain(key.attempt())?;
    let attempt = attempt_chain
        .first()
        .ok_or(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-is-empty",
        })?
        .clone_admitted()?;
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
                selection: {
                    crucible::owned_decode::charge_array::<crucible_campaign::ResolvedSelection>(1)
                        .map_err(crucible_campaign::CampaignCodecError::from)?;
                    Box::new(store.resolve_selection(selection)?)
                },
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
                        selection: {
                            crucible::owned_decode::charge_array::<
                                crucible_campaign::ResolvedSelection,
                            >(1)
                            .map_err(crucible_campaign::CampaignCodecError::from)?;
                            Box::new(store.resolve_selection(selection)?)
                        },
                    }
                }
                AttemptStart::AfterAttempt { .. } => {
                    return Err(CampaignRepositoryError::Integrity {
                        reason: "attempt-origin-chain-has-no-base",
                    });
                }
            };
            crucible::owned_decode::charge_array::<ResolvedAttemptOrigin>(attempt_chain.len())
                .map_err(crucible_campaign::CampaignCodecError::from)?;
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
            crucible::owned_decode::charge_array::<ResolvedAttemptStart>(1)
                .map_err(crucible_campaign::CampaignCodecError::from)?;
            crucible::owned_decode::charge_array::<ResolvedAttemptOrigins>(1)
                .map_err(crucible_campaign::CampaignCodecError::from)?;
            crucible::owned_decode::charge_array::<ResolvedAttemptOrigin>(origins.len())
                .map_err(crucible_campaign::CampaignCodecError::from)?;
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
        _decode_custody: crucible::owned_decode::current_custody().unwrap_or_default(),
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
    Ok((observation.stop().clone_admitted()?, bytes))
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

#[cfg(test)]
fn complete_host_watchdog<T, E>(
    result: Result<T, AttemptWorkerFailure<RepositoryAttemptWorkerError<E>>>,
    watchdog: Option<&mut AssignmentHostWatchdogGuard>,
    milliseconds: Option<u64>,
) -> Result<T, AttemptWorkerFailure<RepositoryAttemptWorkerError<E>>> {
    if watchdog.is_some_and(AssignmentHostWatchdogGuard::stop) {
        return Err(AttemptWorkerFailure::Terminal(
            RepositoryAttemptWorkerError::HostWatchdogExpired {
                milliseconds: milliseconds.unwrap_or_default(),
            },
        ));
    }
    result
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

/// Canonical completion or exact paused capture returned by an execution model.
#[derive(Debug)]
pub enum AttemptExecutionProduct {
    /// The complete observation/finding closure with raw measurement evidence.
    PreparedSemantic(Box<PreparedSemanticAttemptResult>),
    /// A durable checkpoint request won at an exact scheduler boundary.
    ExactCheckpoint(Box<AttemptCheckpointResult>),
}

impl AttemptExecutionProduct {
    /// Wraps a complete semantic result with its raw measurement leaves.
    #[must_use]
    pub fn prepared_semantic(result: PreparedSemanticAttemptResult) -> Self {
        Self::PreparedSemantic(Box::new(result))
    }

    /// Wraps one complete attempt checkpoint capture.
    #[must_use]
    pub fn exact_checkpoint(capture: impl Into<AttemptCheckpointResult>) -> Self {
        Self::ExactCheckpoint(Box::new(capture.into()))
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
}

impl<E> AttemptWorkResult<E> {
    /// Binds one consumed execution token to its single worker result.
    #[must_use]
    pub fn new(
        queued: QueuedAttempt,
        result: Result<AttemptExecutionProduct, AttemptWorkerFailure<E>>,
    ) -> Self {
        Self { queued, result }
    }

    /// Consumes the worker return into its linear token and classified result.
    pub fn into_parts(
        self,
    ) -> (
        QueuedAttempt,
        Result<AttemptExecutionProduct, AttemptWorkerFailure<E>>,
    ) {
        (self.queued, self.result)
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
    Model(#[source] E),
    /// The model returned a result for a different immutable execution basis.
    #[error("attempt execution model returned an incompatible result: {reason}")]
    IncompatibleResult {
        /// Stable fail-closed mismatch category.
        reason: &'static str,
    },
    /// The assignment exceeded its policy-keyed host safety deadline.
    #[error("attempt infrastructure host watchdog expired after {milliseconds} ms")]
    HostWatchdogExpired {
        /// Configured wall-clock ceiling for this assignment.
        milliseconds: u64,
    },
    /// The assignment's host safety timer could not be installed.
    #[error("install attempt infrastructure host watchdog: {0}")]
    HostWatchdogStart(#[source] std::io::Error),
    /// Existing live operational ownership could not be registered safely.
    #[error("register attempt host operational authority: {0}")]
    HostOperational(#[source] crucible_api::host_operational::HostOperationalError),
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
        let result = self.execute_borrowed(&queued);
        AttemptWorkResult { queued, result }
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
                RepositoryAttemptWorkerError::IncompatibleResult { reason },
            ));
        }
        let expected_scenario = ContentHash {
            bytes: input.lineage().scenario().as_hash().as_bytes(),
        };
        let host_watchdog_ms = match queued.request().retention_policy() {
            AttemptRetentionPolicyDisposition::Required(basis) => self
                .store
                .load_attempt_timeout_policy(
                    queued.request().lineage(),
                    queued.request().attempt(),
                    basis,
                )
                .map_err(repository_worker_failure)?
                .and_then(|policy| policy.host_completion_watchdog_ms()),
            AttemptRetentionPolicyDisposition::Disabled => None,
        };
        let mut context = AttemptExecutionContext::new(
            queued.request().resources(),
            queued.request().retention(),
            queued.cancellation().clone(),
            queued.checkpoint_request().clone(),
            queued.request().retention_policy(),
        )
        .with_start_mode(queued.request().start_mode())
        .with_runtime_basis(AttemptExecutionRuntimeBasis::new(
            crate::AttemptExecutionKey::for_request(queued.request()),
            queued.execution(),
        ))
        .with_execution_origin(queued.origin())
        .with_checkpoint_handoff(expected_scenario, queued.checkpoint_handoff().cloned())
        .with_guest_selectable_boundary_diagnostics(self.guest_selectable_diagnostics.clone());
        let (watchdog, first_start) = queued
            .start_host_watchdog(
                host_watchdog_ms,
                context.cancellation().clone(),
                queued.host_operation_budgets().ok_or_else(|| {
                    AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::HostWatchdogStart(
                        std::io::Error::other("missing authored host operation budgets"),
                    ))
                })?,
            )
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::HostWatchdogStart(
                    error,
                ))
            })?;
        context = context.with_host_watchdog(watchdog.clone());
        {
            let registry = queued.host_operational_registry();
            let target = crucible_api::host_operational::HostOuterCapTarget {
                daemon_epoch: queued.host_daemon_epoch(),
                owner: crucible_api::host_operational::HostOuterCapOwner::Execution(
                    crate::host_operational_registry::operational_identity(
                        queued.execution().as_bytes(),
                    ),
                ),
                owner_generation: 1,
                cap_id: watchdog.supervisor().cap_id(),
            };
            if first_start {
                registry
                    .register_cap(
                        target,
                        crucible_api::host_operational::HostOuterCapClass::Assignment,
                        watchdog.supervisor().clone(),
                    )
                    .map_err(|error| {
                        AttemptWorkerFailure::Terminal(
                            RepositoryAttemptWorkerError::HostOperational(error),
                        )
                    })?;
            }
            context.host_operational_registry = Some(registry);
            context.host_outer_cap_owner = Some(target.owner);
            context.host_daemon_epoch = queued.host_daemon_epoch();
        }
        context = context.install_selected_checkpoint(queued.take_selected_checkpoint());
        // Every model launch and copy shares the already authenticated input's
        // original account; the input retains its credits through reconciliation.
        let _decode_scope = input.enter_decode_scope();
        let product = self
            .model
            .execute(&input, &context)
            .map_err(|failure| map_worker_failure(failure, RepositoryAttemptWorkerError::Model));
        if let Some(selected) = context.take_selected_checkpoint() {
            queued.restore_selected_checkpoint(selected);
        }
        // Expiry wins even if guest work returned a candidate concurrently.
        if watchdog.expired() {
            return Err(AttemptWorkerFailure::Terminal(
                RepositoryAttemptWorkerError::HostWatchdogExpired {
                    milliseconds: host_watchdog_ms.unwrap_or_default(),
                },
            ));
        }
        let product = product?;
        match &product {
            AttemptExecutionProduct::PreparedSemantic(result) => {
                let candidate = result.observation();
                if queued.request().execution_scope()
                    != crucible_campaign::AttemptExecutionScope::Semantic
                {
                    return Err(AttemptWorkerFailure::Terminal(
                        RepositoryAttemptWorkerError::IncompatibleResult {
                            reason: "savepoint capture returned a semantic observation",
                        },
                    ));
                }
                if candidate.observation().attempt() != queued.request().attempt() {
                    return Err(AttemptWorkerFailure::Terminal(
                        RepositoryAttemptWorkerError::IncompatibleResult {
                            reason: "observation attempt differs from assignment",
                        },
                    ));
                }
                if candidate.child().scenario() != input.lineage().scenario()
                    || candidate.child().scenario_artifact() != input.lineage().scenario_content()
                {
                    return Err(AttemptWorkerFailure::Terminal(
                        RepositoryAttemptWorkerError::IncompatibleResult {
                            reason: "child configuration differs from assignment lineage",
                        },
                    ));
                }
            }
            AttemptExecutionProduct::ExactCheckpoint(checkpoint) => {
                if !queued.checkpoint_request().is_requested() {
                    return Err(AttemptWorkerFailure::Terminal(
                        RepositoryAttemptWorkerError::IncompatibleResult {
                            reason: "execution returned an unsolicited exact checkpoint",
                        },
                    ));
                }
                if checkpoint.scenario() != expected_scenario {
                    return Err(AttemptWorkerFailure::Terminal(
                        RepositoryAttemptWorkerError::IncompatibleResult {
                            reason: "exact checkpoint differs from assignment scenario",
                        },
                    ));
                }
            }
        }

        queued.begin_publication().map_err(|error| {
            AttemptWorkerFailure::Terminal(RepositoryAttemptWorkerError::HostWatchdogStart(error))
        })?;
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

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.model
            .reconcile_execution(disposition)
            .map_err(|failure| map_worker_failure(failure, RepositoryAttemptWorkerError::Model))
    }
}

fn map_worker_failure<E, F, M>(failure: AttemptWorkerFailure<E>, map: M) -> AttemptWorkerFailure<F>
where
    M: Fn(E) -> F,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
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
        | RepositoryAttemptWorkerError::Model(_)
        | RepositoryAttemptWorkerError::ResourceRefusal { .. }
        | RepositoryAttemptWorkerError::IncompatibleResult { .. }
        | RepositoryAttemptWorkerError::HostWatchdogExpired { .. }
        | RepositoryAttemptWorkerError::HostWatchdogStart(_)
        | RepositoryAttemptWorkerError::HostOperational(_) => AttemptWorkerFailure::Terminal(error),
    }
}

#[cfg(test)]
mod tests;
