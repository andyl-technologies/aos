//! Repository-backed local attempt execution and canonical completion handoff.
//!
//! The worker resolves opaque campaign records into one authenticated execution
//! input, delegates guest execution to an injected execution-model adapter, and
//! publishes the returned immutable observation bundle before asking the
//! supervisor to complete its operational execution record. QEMU/session types
//! remain behind [`AttemptExecutionModel`]; campaign storage stays language and
//! runtime neutral.

use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignExecutorStore,
    CampaignLineage, CampaignRepositoryError, ConfigurationArtifact, ExecutionRetentionIntent,
    ExecutorRejection, ObservationCandidate, ObservationId, ResolvedSelection, ScenarioArtifact,
    SubmitAttemptRequest,
};

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, CancellationOutcome, CompletionOutcome,
    ExecutionCancellation, LocalExecutorError, LocalExecutorSupervisor,
    ObservationPublicationOutcome, QueuedAttempt,
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

/// Operational limits and cancellation state for one guest execution.
///
/// This context is deliberately separate from [`AttemptExecutionInput`]. It
/// contains no assignment ID or daemon epoch and must not influence canonical
/// child or observation bytes. The runner uses it only to enforce local
/// resource ceilings and interrupt work.
#[derive(Clone, Debug)]
pub struct AttemptExecutionContext {
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
    cancellation: ExecutionCancellation,
}

impl AttemptExecutionContext {
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
}

/// Execution-model boundary used by the local campaign worker.
pub trait AttemptExecutionModel {
    /// Model-specific operational execution failure.
    type Error;

    /// Executes one authenticated attempt and returns its complete immutable result.
    ///
    /// Implementations may choose hot fork, exact restore, or thin replay. The
    /// choice is operational and must not change the canonical candidate.
    ///
    /// # Errors
    ///
    /// Returns a model-specific error for unavailable materialization, guest
    /// process failure, cancellation, or inability to reach the modeled stop.
    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>>;
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
}

/// Linear worker return carrying the sole reconciliation token and model result.
#[derive(Debug)]
pub struct AttemptWorkResult<E> {
    queued: QueuedAttempt,
    result: Result<ObservationCandidate, AttemptWorkerFailure<E>>,
}

impl<E> AttemptWorkResult<E> {
    /// Binds one consumed execution token to its single worker result.
    #[must_use]
    pub fn new(
        queued: QueuedAttempt,
        result: Result<ObservationCandidate, AttemptWorkerFailure<E>>,
    ) -> Self {
        Self { queued, result }
    }
}

/// Failure while resolving, executing, or publishing one local attempt.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryAttemptWorkerError<E> {
    /// Immutable campaign input or output publication failed validation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// The execution-model adapter failed before publishing a completion.
    #[error("attempt execution model failed")]
    Model(E),
    /// The model returned a result for a different immutable execution basis.
    #[error("attempt execution model returned an incompatible result: {reason}")]
    IncompatibleResult {
        /// Stable fail-closed mismatch category.
        reason: &'static str,
    },
}

/// Local worker that resolves campaign records and publishes immutable results.
pub struct RepositoryAttemptWorker<M> {
    store: CampaignExecutorStore,
    model: M,
}

impl<M> RepositoryAttemptWorker<M> {
    /// Creates a local worker over a repository and execution-model adapter.
    #[must_use]
    pub fn new(store: CampaignExecutorStore, model: M) -> Self {
        Self { store, model }
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
        let result = self.execute_borrowed(&queued);
        AttemptWorkResult { queued, result }
    }

    fn execute_borrowed(
        &mut self,
        queued: &QueuedAttempt,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<RepositoryAttemptWorkerError<M::Error>>>
    {
        let input = self
            .resolve_input(queued.request())
            .map_err(repository_worker_failure)?;
        let context = AttemptExecutionContext {
            resources: queued.request().resources(),
            retention: queued.request().retention(),
            cancellation: queued.cancellation().clone(),
        };
        let candidate = self
            .model
            .execute(&input, &context)
            .map_err(|failure| map_worker_failure(failure, RepositoryAttemptWorkerError::Model))?;

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

        Ok(candidate)
    }

    fn resolve_input(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<AttemptExecutionInput, CampaignRepositoryError> {
        let lineage = self.store.load_lineage(request.lineage())?;
        let scenario = self
            .store
            .load_scenario_artifact(lineage.scenario_content())?;
        let attempt = self.store.load_attempt(request.attempt())?;
        let path = self.store.load_branch_path(attempt.path())?;
        let start = match attempt.start() {
            AttemptStart::Discover { configuration } => ResolvedAttemptStart::Discover {
                configuration: self.store.load_configuration_artifact(configuration)?,
            },
            AttemptStart::Branch {
                parent, selection, ..
            } => ResolvedAttemptStart::Branch {
                parent: self.store.load_configuration_artifact(parent)?,
                selection: Box::new(self.store.resolve_selection(selection)?),
            },
        };

        let starting_configuration = match &start {
            ResolvedAttemptStart::Discover { configuration } => configuration,
            ResolvedAttemptStart::Branch { parent, .. } => parent,
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

        Ok(AttemptExecutionInput {
            lineage,
            scenario,
            attempt,
            path,
            start,
        })
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
    let error = RepositoryAttemptWorkerError::Repository(error);
    match &error {
        RepositoryAttemptWorkerError::Repository(repository)
            if repository.executor_rejection() == ExecutorRejection::UnavailableInput =>
        {
            AttemptWorkerFailure::Retryable(error)
        }
        RepositoryAttemptWorkerError::Repository(_)
        | RepositoryAttemptWorkerError::Model(_)
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
    candidate: ObservationCandidate,
}

/// Read-only-preflighted result ready for a short publication-root CAS.
#[derive(Debug)]
pub struct PreparedAttemptResult {
    pending: PendingAttemptResult,
    observation: ObservationId,
}

impl PreparedAttemptResult {
    /// Returns the exact execution token.
    #[must_use]
    pub const fn queued(&self) -> &QueuedAttempt {
        self.pending.queued()
    }

    /// Returns the preflighted immutable observation identity.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }
}

/// Candidate whose immutable objects were published outside the supervisor actor.
#[derive(Debug)]
pub struct PublishedAttemptResult {
    queued: QueuedAttempt,
    observation: ObservationId,
}

/// Linear token proving the durable publication root was installed first.
#[derive(Debug)]
pub struct StagedAttemptResult {
    prepared: PreparedAttemptResult,
}

/// Actor result of consuming one prepared candidate.
#[derive(Debug)]
pub enum AttemptResultStageOutcome {
    /// Immutable publication may now proceed outside the actor.
    Publish(Box<StagedAttemptResult>),
    /// Publication must not run because another operational outcome won.
    Finished(AttemptWorkerReconcileOutcome),
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
        &self.candidate
    }

    /// Consumes the pending value into its linear execution token and candidate.
    #[must_use]
    pub fn into_parts(self) -> (QueuedAttempt, ObservationCandidate) {
        (self.queued, self.candidate)
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
    },
    /// Candidate preflight failed without writing immutable objects.
    #[error("local attempt result preflight failed")]
    Candidate {
        /// Already-executed candidate retained for direct retry.
        pending: Box<PendingAttemptResult>,
        /// Repository failure from the read-only preflight.
        source: CampaignRepositoryError,
    },
}

/// Immutable publication failure retaining the preflighted candidate.
#[derive(Debug, thiserror::Error)]
#[error("local attempt result publication failed")]
pub struct AttemptResultPublicationError {
    /// Staged candidate retained for direct publication retry.
    pub staged: Box<StagedAttemptResult>,
    /// Repository failure from immutable publication.
    pub source: CampaignRepositoryError,
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
    work: AttemptWorkResult<W>,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    let AttemptWorkResult { queued, result } = work;
    let candidate = match result {
        Ok(candidate) => candidate,
        Err(failure) => {
            return Err(AttemptResultPreparationError::Worker {
                queued: Box::new(queued),
                failure,
            });
        }
    };
    prepare_pending_attempt_result(store, PendingAttemptResult { queued, candidate })
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

fn prepare_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    if let Err(source) = store.validate_observation_candidate(&pending.candidate) {
        return Err(AttemptResultPreparationError::Candidate {
            pending: Box::new(pending),
            source,
        });
    }
    let observation = match pending.candidate.observation().id() {
        Ok(observation) => observation,
        Err(error) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: CampaignRepositoryError::Codec(error),
            });
        }
    };
    Ok(PreparedAttemptResult {
        pending,
        observation,
    })
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
        failure @ (AttemptWorkerFailure::Canceled(_) | AttemptWorkerFailure::Terminal(_)) => {
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
    let stage = match supervisor.stage_observation_publication(prepared.queued(), observation) {
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
        ObservationPublicationOutcome::Canceled => Ok(AttemptResultStageOutcome::Finished(
            AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::Canceled,
            },
        )),
        ObservationPublicationOutcome::NotCurrent => Ok(AttemptResultStageOutcome::Finished(
            AttemptWorkerReconcileOutcome::Discarded {
                observation,
                completion: CompletionOutcome::NotCurrent,
            },
        )),
        ObservationPublicationOutcome::AlreadyCompleted => Ok(AttemptResultStageOutcome::Finished(
            AttemptWorkerReconcileOutcome::Reconciled {
                observation,
                completion: CompletionOutcome::AlreadyCompleted,
            },
        )),
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
    if let Err(source) = store.publish_observation_candidate(&staged.prepared.pending.candidate) {
        return Err(AttemptResultPublicationError { staged, source });
    }
    let StagedAttemptResult { prepared } = *staged;
    Ok(PublishedAttemptResult {
        queued: prepared.pending.queued,
        observation: prepared.observation,
    })
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
) -> Result<CancellationOutcome, AttemptResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(prepared.queued()) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source,
        }),
    }
}

/// Aborts a stably failed staged publication without re-running the guest.
///
/// # Errors
///
/// Returns [`AttemptResultAbortError`] with the linear staged token when the
/// durable cancellation cannot yet be reconciled.
pub fn abort_staged_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    staged: Box<StagedAttemptResult>,
) -> Result<CancellationOutcome, AttemptResultAbortError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(staged.prepared.queued()) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(AttemptResultAbortError { staged, source }),
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
    let completion =
        match supervisor.stage_and_reconcile_completion(&published.queued, published.observation) {
            Ok(completion) => completion,
            Err(source) => {
                return Err(AttemptWorkerReconcileError::CompletionPending {
                    published: Box::new(published),
                    source,
                });
            }
        };
    Ok(AttemptWorkerReconcileOutcome::Reconciled {
        observation,
        completion,
    })
}

#[cfg(test)]
mod tests;
