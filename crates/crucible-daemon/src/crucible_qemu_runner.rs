//! Exact-restore and thin-replay QEMU runner for local campaign attempts.
//!
//! This module connects the campaign execution boundary to the existing QEMU
//! realization coordinator. It deliberately does not emulate hot fork: the
//! GPL-side fork protocol must land and pass its safety gates before a runner
//! may report [`CrucibleMaterializationTier::HotFork`].

use crucible::{Configuration, SingleSchedulerCheckpoint};
use crucible_campaign::{AttemptResourceLimits, ExactCheckpointId};
use crucible_qemu::{
    QemuExactSnapshotPolicy, QemuVmRealization, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmRealizationKind, QemuVmRealizationStore, QemuVmSnapshot, instantiate_qemu_vm,
};

use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure,
    CapturedExactCheckpoint, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, CrucibleMaterializationTier, CrucibleResolvedAttemptStart,
    ExecutionCancellation, QemuExactCheckpointRealization,
};

/// Cancellation-aware checkpoint reads used by one campaign realization.
///
/// Implementations must bound each blocking store operation and observe the
/// supplied signal while it is in progress. Returning only after an unbounded
/// backend call completes is not a conforming implementation.
pub trait QemuCrucibleRealizationStore {
    /// Returns an exact cached snapshot for `config`, when available.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] for cancellation, temporary
    /// unavailability, or invalid store state.
    fn exact_snapshot(
        &mut self,
        config: &Configuration,
        cancellation: &ExecutionCancellation,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError>;

    /// Returns the nearest cached ancestor on `config`'s schedule path.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] for cancellation, temporary
    /// unavailability, or invalid store state.
    fn nearest_cached_ancestor(
        &mut self,
        config: &Configuration,
        cancellation: &ExecutionCancellation,
    ) -> Result<Option<crucible_qemu::QemuCachedAncestor>, QemuVmRealizationError>;

    /// Returns the baked deterministic genesis snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] for cancellation, temporary
    /// unavailability, or invalid store state.
    fn baked_genesis(
        &mut self,
        world: &crucible::World,
        def: &crucible::ScenarioDef,
        cancellation: &ExecutionCancellation,
    ) -> Result<crucible_qemu::QemuBakedGenesisSnapshot, QemuVmRealizationError>;
}

/// Attempt-scoped QEMU realization and live-execution capability.
///
/// A session is created from the exact admitted resource limits and
/// cancellation signal. Every implementation must enforce those limits for
/// process launch, restore, replay, and post-materialization driving. It must
/// also observe cancellation during blocking operations and between bounded
/// replay or execution quanta.
pub trait QemuCrucibleAttemptSession: QemuVmRealizationExecutor {
    /// Driver-specific modeled-execution or result-construction failure.
    type Error;

    /// Returns the exact resource ceilings installed before process launch.
    #[must_use]
    fn resource_limits(&self) -> AttemptResourceLimits;

    /// Checks cancellation and the session's remaining execution-quanta budget.
    ///
    /// The realization methods and [`Self::run_attempt`] must invoke the same
    /// check during blocking operations and between bounded guest quanta.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Canceled`] after cancellation and a
    /// terminal resource error after the admitted quantum budget is exhausted.
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Restores one durable attempt checkpoint under this session's guard.
    ///
    /// `initial` is the configuration realized before a branch selection. A
    /// branch attempt also supplies `post_selection`; a checkpoint may name
    /// either exact boundary depending on whether the sticky pause request won
    /// before or after selection application. Implementations must authenticate
    /// the complete `checkpoint` root, stream and authenticate its VMState into
    /// pinned staging, and launch only through this session's resource guard.
    /// They must establish source-bound replay-oracle evidence before
    /// production admission or reject the root. They must never substitute an
    /// ordinary exact-cache or thin-replay start. The returned binding must
    /// name the same immutable `checkpoint`; the runner checks it before
    /// modeled guest work.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the root is unavailable or
    /// corrupt, names any other configuration, cannot be materialized, or
    /// guarded restore fails.
    fn resume_exact_checkpoint(
        &mut self,
        checkpoint: ExactCheckpointId,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
    ) -> Result<QemuExactCheckpointRealization, QemuVmRealizationError>;

    /// Applies a branch selection when present and runs to the attempt stop.
    ///
    /// The realized runtime denotes [`CrucibleResolvedAttemptStart::Discover`],
    /// the exact branch parent, or a resumed branch's post-selection boundary.
    /// The session retains the live backend instead of handing modeled code a
    /// detached [`crucible::RuntimeState`]. It applies the typed selection only
    /// when the realized configuration is the branch parent; a post-selection
    /// resume must continue without applying the edge twice. `scheduler` is the
    /// complete authenticated continuation for an exact resume and is `None`
    /// for fresh or thin materialization. It enforces the operational context
    /// and constructs the complete immutable observation candidate.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal driver failure.
    fn run_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        realization: QemuVmRealization,
        scheduler: Option<SingleSchedulerCheckpoint>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>;

    /// Captures one exact paused checkpoint under the active resource guard.
    ///
    /// Modeled drivers do not receive this authority. The returned capture owns
    /// a reopenable, byte-stable VMState source only after the live process has
    /// completed its final observable drain and reap. [`Self::finish`] then
    /// releases the still-installed host resource guard before the worker pool
    /// performs no-write preparation and durable publication, while the
    /// supervisor keeps the execution reservation charged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] on cancellation, live-basis mismatch,
    /// observation sealing failure, or exact VMState/host-I/O capture failure.
    fn capture_exact_checkpoint(
        &mut self,
        checkpoint: crucible::Checkpoint,
    ) -> Result<CapturedExactCheckpoint, QemuVmRealizationError>;

    /// Reclaims every process, file, and resource reservation owned by the session.
    ///
    /// This operation is mandatory on successful, failed, and canceled
    /// attempts. Success attests that the kill-and-reap ladder completed before
    /// resource release. A failed-reap error instead attests that the exact
    /// resource guard was transferred to supervisor-owned quarantine and the
    /// executor remains poisoned until reap is proven. Implementations must
    /// provide the same cleanup from `Drop` as an unwind backstop; normal control
    /// flow uses this consuming method so cleanup failures remain observable.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] for cleanup diagnostics or when reap
    /// failed and ownership was transferred to quarantine.
    fn finish(self) -> Result<(), QemuVmRealizationError>;
}

/// Factory for one attempt-scoped, resource-enforcing QEMU session.
pub trait QemuCrucibleSessionFactory {
    /// Stable driver error shared by every borrowed session.
    type Error;

    /// Borrowed live-session type created for one attempt.
    type Session<'a>: QemuCrucibleAttemptSession<Error = Self::Error>
    where
        Self: 'a;

    /// Opens a live session bound to the attempt's operational contract.
    ///
    /// Implementations must install the CPU, resident-memory, writable-disk,
    /// and execution-quantum ceilings before any QEMU process can launch. The
    /// returned session owns the live backend capability needed by the driver;
    /// it must not expose assignment IDs or daemon epochs to modeled code.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when resource admission, process
    /// supervision setup, or cancellation setup fails. An error return must
    /// leave no launched process or retained resource reservation because no
    /// session exists for the runner to finish.
    fn begin_attempt<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<Self::Session<'a>, QemuVmRealizationError>;
}

/// QEMU runner using exact restore with deterministic thin-replay fallback.
pub struct QemuExactThinExecutionRunner<S, F> {
    store: S,
    sessions: F,
    policy: QemuExactSnapshotPolicy,
}

impl<S, F> QemuExactThinExecutionRunner<S, F> {
    /// Creates a runner using the production exact-snapshot admission policy.
    #[must_use]
    pub const fn new(store: S, sessions: F) -> Self {
        Self {
            store,
            sessions,
            policy: QemuExactSnapshotPolicy::production(),
        }
    }

    /// Returns the QEMU realization store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Returns the attempt-scoped QEMU session factory.
    #[must_use]
    pub const fn session_factory(&self) -> &F {
        &self.sessions
    }

    /// Consumes the runner into its realization store and session factory.
    #[must_use]
    pub fn into_parts(self) -> (S, F) {
        (self.store, self.sessions)
    }
}

/// Failure from QEMU realization or post-materialization attempt execution.
#[derive(Debug, thiserror::Error)]
pub enum QemuExactThinRunnerError<E> {
    /// Work was canceled before QEMU realization began.
    #[error("campaign attempt was canceled before QEMU realization")]
    Canceled,
    /// Exact restore and thin replay could not realize the starting configuration.
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
    /// The post-materialization attempt driver failed.
    #[error("QEMU campaign attempt driver failed")]
    Driver(E),
}

impl<S, F> CrucibleExecutionRunner for QemuExactThinExecutionRunner<S, F>
where
    S: QemuCrucibleRealizationStore,
    F: QemuCrucibleSessionFactory,
{
    type Error = QemuExactThinRunnerError<F::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuExactThinRunnerError::Canceled,
            ));
        }
        let (configuration, post_selection) = attempt_resume_configurations(input);
        let mut session = self
            .sessions
            .begin_attempt(context)
            .map_err(classify_realization_failure)?;
        let result = if session.resource_limits() == context.resources() {
            if let Some(checkpoint) = context.resume_checkpoint() {
                resume_in_session(
                    &mut session,
                    input,
                    checkpoint,
                    configuration,
                    post_selection,
                )
            } else {
                run_in_session(
                    &mut self.store,
                    &mut session,
                    input,
                    context,
                    configuration,
                    self.policy,
                )
            }
        } else {
            Err(AttemptWorkerFailure::Terminal(
                QemuExactThinRunnerError::Realization(QemuVmRealizationError::Executor {
                    operation: "admit campaign QEMU session resources",
                    message: String::from(
                        "attempt session did not install the exact admitted resource limits",
                    ),
                }),
            ))
        };
        finish_attempt_session(session, result)
    }
}

fn attempt_resume_configurations(
    input: &CrucibleAttemptExecution,
) -> (&Configuration, Option<&Configuration>) {
    match input.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => (configuration, None),
        CrucibleResolvedAttemptStart::Branch {
            parent, selected, ..
        } => (parent, Some(selected)),
    }
}

fn finish_attempt_session<S, T>(
    session: S,
    result: Result<T, AttemptWorkerFailure<QemuExactThinRunnerError<S::Error>>>,
) -> Result<T, AttemptWorkerFailure<QemuExactThinRunnerError<S::Error>>>
where
    S: QemuCrucibleAttemptSession,
{
    let cleanup = session.finish();
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(failure), Ok(())) => Err(failure),
        (_, Err(error)) => Err(classify_realization_failure(error)),
    }
}

fn run_in_session<S, E>(
    store: &mut S,
    session: &mut E,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    configuration: &Configuration,
    policy: QemuExactSnapshotPolicy,
) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<QemuExactThinRunnerError<E::Error>>>
where
    S: QemuCrucibleRealizationStore,
    E: QemuCrucibleAttemptSession,
{
    session
        .check_operational_boundary()
        .map_err(classify_realization_failure)?;
    let mut store = CancellableRealizationStore::new(store, context);
    let realization = instantiate_qemu_vm(
        input.scenario().world(),
        configuration,
        &mut store,
        session,
        policy,
    )
    .map_err(classify_realization_failure)?;
    session
        .check_operational_boundary()
        .map_err(classify_realization_failure)?;
    let materialization = match realization.branch {
        QemuVmRealizationKind::ExactSnapshotLoadvm { .. } => {
            CrucibleMaterializationTier::ExactRestore
        }
        QemuVmRealizationKind::AncestorReplay { .. }
        | QemuVmRealizationKind::BakedGenesisLoad { .. } => CrucibleMaterializationTier::ThinReplay,
    };
    let product = session
        .run_attempt(input, realization, None)
        .map_err(map_driver_failure)?;
    Ok(CrucibleExecutionOutcome::new(product, materialization))
}

fn resume_in_session<E>(
    session: &mut E,
    input: &CrucibleAttemptExecution,
    checkpoint: ExactCheckpointId,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<QemuExactThinRunnerError<E::Error>>>
where
    E: QemuCrucibleAttemptSession,
{
    session
        .check_operational_boundary()
        .map_err(classify_realization_failure)?;
    let resumed = session
        .resume_exact_checkpoint(checkpoint, initial, post_selection)
        .map_err(classify_realization_failure)?;
    validate_resumed_realization(&resumed, checkpoint, initial, post_selection)
        .map_err(classify_realization_failure)?;
    session
        .check_operational_boundary()
        .map_err(classify_realization_failure)?;
    let (realization, scheduler) = resumed.into_parts();
    let product = session
        .run_attempt(input, realization, Some(scheduler))
        .map_err(map_driver_failure)?;
    Ok(CrucibleExecutionOutcome::new(
        product,
        CrucibleMaterializationTier::ExactRestore,
    ))
}

fn validate_resumed_realization(
    resumed: &QemuExactCheckpointRealization,
    expected_checkpoint: ExactCheckpointId,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
) -> Result<(), QemuVmRealizationError> {
    let realization = resumed.realization();
    let scheduler_configuration = resumed
        .scheduler()
        .configuration_for(&realization.configuration.def)
        .map_err(|error| QemuVmRealizationError::InvalidCheckpoint {
            role: "attempt scheduler continuation",
            message: error.to_string(),
        })?;
    let configuration_is_allowed = &realization.configuration == initial
        || post_selection.is_some_and(|selected| &realization.configuration == selected);
    let checkpoint_matches = match &realization.branch {
        QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint } => {
            checkpoint.configuration == realization.configuration.id()
                && checkpoint.id == realization.configuration.id()
                && checkpoint.kind == crucible::CheckpointKind::Fat
                && resumed.scheduler().frontier() == checkpoint.virtual_time
        }
        QemuVmRealizationKind::AncestorReplay { .. }
        | QemuVmRealizationKind::BakedGenesisLoad { .. } => false,
    };
    if resumed.checkpoint() != expected_checkpoint
        || realization.operation != crucible_qemu::QemuVmRealizationOperation::Resume
        || !configuration_is_allowed
        || !checkpoint_matches
        || realization.runtime.configuration != realization.configuration.id()
        || scheduler_configuration != realization.configuration
        || resumed.scheduler().scheduler_state().map_err(|error| {
            QemuVmRealizationError::InvalidCheckpoint {
                role: "attempt scheduler continuation",
                message: error.to_string(),
            }
        })? != realization.runtime.scheduler
        || resumed.scheduler().event_log_offset() != realization.runtime.event_log
    {
        return Err(QemuVmRealizationError::Executor {
            operation: "validate exact-checkpoint resumed realization",
            message: String::from(
                "resumed realization does not match the exact attempt checkpoint basis",
            ),
        });
    }
    Ok(())
}

struct CancellableRealizationStore<'a, S> {
    store: &'a mut S,
    context: &'a AttemptExecutionContext,
}

impl<'a, S> CancellableRealizationStore<'a, S> {
    const fn new(store: &'a mut S, context: &'a AttemptExecutionContext) -> Self {
        Self { store, context }
    }

    fn check(&self, operation: &'static str) -> Result<(), QemuVmRealizationError> {
        if self.context.cancellation().is_canceled() {
            Err(QemuVmRealizationError::Canceled { operation })
        } else {
            Ok(())
        }
    }
}

impl<S> QemuVmRealizationStore for CancellableRealizationStore<'_, S>
where
    S: QemuCrucibleRealizationStore,
{
    fn exact_snapshot(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
        self.check("query exact snapshot")?;
        let result = self
            .store
            .exact_snapshot(config, self.context.cancellation())?;
        self.check("finish exact snapshot query")?;
        Ok(result)
    }

    fn nearest_cached_ancestor(
        &mut self,
        config: &Configuration,
    ) -> Result<Option<crucible_qemu::QemuCachedAncestor>, QemuVmRealizationError> {
        self.check("query nearest cached ancestor")?;
        let result = self
            .store
            .nearest_cached_ancestor(config, self.context.cancellation())?;
        self.check("finish nearest cached ancestor query")?;
        Ok(result)
    }

    fn baked_genesis(
        &mut self,
        world: &crucible::World,
        def: &crucible::ScenarioDef,
    ) -> Result<crucible_qemu::QemuBakedGenesisSnapshot, QemuVmRealizationError> {
        self.check("query baked genesis")?;
        let result = self
            .store
            .baked_genesis(world, def, self.context.cancellation())?;
        self.check("finish baked genesis query")?;
        Ok(result)
    }
}

fn classify_realization_failure<E>(
    error: QemuVmRealizationError,
) -> AttemptWorkerFailure<QemuExactThinRunnerError<E>> {
    let error = QemuExactThinRunnerError::Realization(error);
    match &error {
        QemuExactThinRunnerError::Realization(
            QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => AttemptWorkerFailure::Retryable(error),
        QemuExactThinRunnerError::Realization(QemuVmRealizationError::Canceled { .. })
        | QemuExactThinRunnerError::Canceled => AttemptWorkerFailure::Canceled(error),
        QemuExactThinRunnerError::Realization(_) | QemuExactThinRunnerError::Driver(_) => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_driver_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<QemuExactThinRunnerError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuExactThinRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuExactThinRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuExactThinRunnerError::Driver(error))
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
    #![allow(clippy::expect_used)]

    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crucible::{
        Checkpoint, CheckpointKind, ContentHash, OverrideDecision, RuntimeState, ScenarioDef,
        SchedulerLivenessScenario, SchedulerState, Shift, SimInstant, SingleScheduler, VirtualTime,
    };
    use crucible_qemu::{
        QemuBakedGenesisRestoreAdmission, QemuLoadvmCommandAuthorization,
        QemuLoadvmRealizationAdmission, QemuVmReplayRequest,
    };

    use super::*;

    struct FinishTrackingSession {
        finishes: Arc<AtomicUsize>,
        cleanup_error: bool,
        resources: AttemptResourceLimits,
    }

    impl QemuVmRealizationExecutor for FinishTrackingSession {
        fn load_exact_snapshot(
            &mut self,
            _config: &Configuration,
            _snapshot: &QemuVmSnapshot,
            _authorization: QemuLoadvmCommandAuthorization,
            _admission: QemuLoadvmRealizationAdmission,
        ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
            unreachable!("finish-only test session does not realize QEMU")
        }

        fn load_exact_snapshot_for_replay_oracle_probe(
            &mut self,
            _config: &Configuration,
            _snapshot: &QemuVmSnapshot,
            _authorization: QemuLoadvmCommandAuthorization,
        ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
            unreachable!("finish-only test session does not realize QEMU")
        }

        fn load_baked_genesis(
            &mut self,
            _config: &Configuration,
            _admission: QemuBakedGenesisRestoreAdmission<'_>,
        ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
            unreachable!("finish-only test session does not realize QEMU")
        }

        fn replay_one_quantum(
            &mut self,
            _runtime: crucible::RuntimeState,
            _request: QemuVmReplayRequest,
        ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
            unreachable!("finish-only test session does not realize QEMU")
        }
    }

    impl QemuCrucibleAttemptSession for FinishTrackingSession {
        type Error = ();

        fn resource_limits(&self) -> AttemptResourceLimits {
            self.resources
        }

        fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
            Ok(())
        }

        fn resume_exact_checkpoint(
            &mut self,
            _checkpoint: ExactCheckpointId,
            _initial: &Configuration,
            _post_selection: Option<&Configuration>,
        ) -> Result<QemuExactCheckpointRealization, QemuVmRealizationError> {
            unreachable!("finish-only test session does not resume QEMU")
        }

        fn run_attempt(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _realization: QemuVmRealization,
            _scheduler: Option<SingleSchedulerCheckpoint>,
        ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
            unreachable!("finish-only test session does not drive QEMU")
        }

        fn capture_exact_checkpoint(
            &mut self,
            _checkpoint: crucible::Checkpoint,
        ) -> Result<CapturedExactCheckpoint, QemuVmRealizationError> {
            unreachable!("finish-only test session does not capture QEMU")
        }

        fn finish(self) -> Result<(), QemuVmRealizationError> {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            if self.cleanup_error {
                Err(QemuVmRealizationError::ReapQuarantined {
                    operation: "finish test QEMU session",
                    message: String::from("injected failed reap"),
                })
            } else {
                Ok(())
            }
        }
    }

    fn finish_session(finishes: Arc<AtomicUsize>, cleanup_error: bool) -> FinishTrackingSession {
        let Ok(resources) = AttemptResourceLimits::new(1, 1, 0, 1) else {
            panic!("test resource limits must be valid");
        };
        FinishTrackingSession {
            finishes,
            cleanup_error,
            resources,
        }
    }

    #[test]
    fn realization_failures_preserve_retryability_boundary() {
        let store = QemuVmRealizationError::StoreUnavailable {
            operation: "exact snapshot",
            message: String::from("temporarily unavailable"),
        };
        assert!(matches!(
            classify_realization_failure::<()>(store),
            AttemptWorkerFailure::Retryable(QemuExactThinRunnerError::Realization(_))
        ));

        let invalid = QemuVmRealizationError::InvalidAncestor {
            message: String::from("not a prefix"),
        };
        assert!(matches!(
            classify_realization_failure::<()>(invalid),
            AttemptWorkerFailure::Terminal(QemuExactThinRunnerError::Realization(_))
        ));

        let stable_executor = QemuVmRealizationError::Executor {
            operation: "restore exact snapshot",
            message: String::from("snapshot is incompatible with this executor"),
        };
        assert!(matches!(
            classify_realization_failure::<()>(stable_executor),
            AttemptWorkerFailure::Terminal(QemuExactThinRunnerError::Realization(_))
        ));
    }

    #[test]
    fn attempt_session_finishes_after_every_result_disposition() {
        type Result = std::result::Result<(), AttemptWorkerFailure<QemuExactThinRunnerError<()>>>;

        let finishes = Arc::new(AtomicUsize::new(0));
        let results: [Result; 4] = [
            Ok(()),
            Err(AttemptWorkerFailure::Retryable(
                QemuExactThinRunnerError::Driver(()),
            )),
            Err(AttemptWorkerFailure::Canceled(
                QemuExactThinRunnerError::Driver(()),
            )),
            Err(AttemptWorkerFailure::Terminal(
                QemuExactThinRunnerError::Realization(QemuVmRealizationError::InvalidAncestor {
                    message: String::from("injected invalid ancestor"),
                }),
            )),
        ];
        for result in results {
            let _ = finish_attempt_session(finish_session(finishes.clone(), false), result);
        }
        assert_eq!(finishes.load(Ordering::SeqCst), 4);

        let cleanup = finish_attempt_session(
            finish_session(finishes.clone(), true),
            Ok::<_, AttemptWorkerFailure<QemuExactThinRunnerError<()>>>(()),
        );
        assert!(matches!(
            cleanup,
            Err(AttemptWorkerFailure::Terminal(
                QemuExactThinRunnerError::Realization(
                    QemuVmRealizationError::ReapQuarantined { .. }
                )
            ))
        ));
        assert_eq!(finishes.load(Ordering::SeqCst), 5);

        let combined = finish_attempt_session(
            finish_session(finishes.clone(), true),
            Err::<(), _>(AttemptWorkerFailure::Terminal(
                QemuExactThinRunnerError::Driver(()),
            )),
        );
        assert!(matches!(
            combined,
            Err(AttemptWorkerFailure::Terminal(
                QemuExactThinRunnerError::Realization(
                    QemuVmRealizationError::ReapQuarantined { .. }
                )
            ))
        ));
        assert_eq!(finishes.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn resumed_realization_must_match_an_exact_legal_attempt_boundary() {
        let initial = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.qemu-runner-resume",
            "initial",
        ));
        let decision = crucible::Decision::Override(OverrideDecision {
            point: crucible::SchedulingPoint {
                key: String::from("resume-point"),
            },
            choice: crucible::ChoiceTag {
                name: String::from("selected"),
            },
        });
        let selected = crucible::step(&initial, decision.clone());
        let root = exact_checkpoint_id(b"valid-resume-root");
        let scheduler = scheduler_for(&initial, vec![decision]);
        let mut realization = resumed_realization(&selected, &selected, Some(&initial));
        realization.runtime.scheduler = scheduler.scheduler_state().expect("scheduler projection");
        realization.runtime.event_log = scheduler.event_log_offset();
        let QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint } = &mut realization.branch
        else {
            unreachable!("resume fixture is exact")
        };
        checkpoint.virtual_time = scheduler.frontier();
        let valid = QemuExactCheckpointRealization::new(root, realization, scheduler);

        assert!(validate_resumed_realization(&valid, root, &initial, Some(&selected)).is_ok());
        assert!(validate_resumed_realization(&valid, root, &selected, None).is_ok());

        let foreign_root = exact_checkpoint_id(b"foreign-resume-root");
        assert!(
            validate_resumed_realization(&valid, foreign_root, &initial, Some(&selected)).is_err()
        );

        let foreign = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.qemu-runner-resume",
            "foreign",
        ));
        assert!(validate_resumed_realization(&valid, root, &foreign, None).is_err());

        let mut wrong_operation = valid.realization().clone();
        wrong_operation.operation = crucible_qemu::QemuVmRealizationOperation::Instantiate;
        let wrong_operation =
            QemuExactCheckpointRealization::new(root, wrong_operation, valid.scheduler().clone());
        assert!(
            validate_resumed_realization(&wrong_operation, root, &initial, Some(&selected))
                .is_err()
        );

        let wrong_checkpoint = QemuExactCheckpointRealization::new(
            root,
            resumed_realization(&selected, &initial, None),
            valid.scheduler().clone(),
        );
        assert!(
            validate_resumed_realization(&wrong_checkpoint, root, &initial, Some(&selected))
                .is_err()
        );

        let mut wrong_checkpoint_identity = valid.realization().clone();
        let QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint } =
            &mut wrong_checkpoint_identity.branch
        else {
            unreachable!("resume fixture is exact")
        };
        checkpoint.id = initial.id();
        let wrong_checkpoint_identity = QemuExactCheckpointRealization::new(
            root,
            wrong_checkpoint_identity,
            valid.scheduler().clone(),
        );
        assert!(
            validate_resumed_realization(
                &wrong_checkpoint_identity,
                root,
                &initial,
                Some(&selected),
            )
            .is_err()
        );

        let mut wrong_runtime = resumed_realization(&selected, &selected, Some(&initial));
        wrong_runtime.runtime.configuration = initial.id();
        let wrong_runtime =
            QemuExactCheckpointRealization::new(root, wrong_runtime, valid.scheduler().clone());
        assert!(
            validate_resumed_realization(&wrong_runtime, root, &initial, Some(&selected)).is_err()
        );

        let mut thin = valid.realization().clone();
        thin.branch = QemuVmRealizationKind::AncestorReplay {
            ancestor_configuration: initial.id(),
            replayed_decisions: 1,
        };
        let thin = QemuExactCheckpointRealization::new(root, thin, valid.scheduler().clone());
        assert!(validate_resumed_realization(&thin, root, &initial, Some(&selected)).is_err());
    }

    fn exact_checkpoint_id(material: &[u8]) -> ExactCheckpointId {
        ExactCheckpointId::try_from(crucible_cas::content_store::ContentId::for_bytes(
            crucible_cas::content_store::ObjectKind::ExactManifest,
            2,
            material,
        ))
        .expect("exact checkpoint root")
    }

    fn resumed_realization(
        configuration: &Configuration,
        checkpoint_configuration: &Configuration,
        checkpoint_parent: Option<&Configuration>,
    ) -> QemuVmRealization {
        let checkpoint = Checkpoint::from_recorded_configuration(
            checkpoint_configuration,
            checkpoint_parent,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .expect("resume checkpoint");
        QemuVmRealization {
            operation: crucible_qemu::QemuVmRealizationOperation::Resume,
            configuration: configuration.clone(),
            runtime: RuntimeState {
                id: ContentHash::from_canonical_material(
                    "crucible.test.qemu-runner-resume",
                    "runtime",
                ),
                configuration: configuration.id(),
                node_blobs: BTreeMap::new(),
                node_icounts: BTreeMap::new(),
                scheduler: SchedulerState::from_schedule(&configuration.schedule),
                event_log: Default::default(),
            },
            branch: QemuVmRealizationKind::ExactSnapshotLoadvm { checkpoint },
        }
    }

    fn scheduler_for(
        configuration: &Configuration,
        decisions: Vec<crucible::Decision>,
    ) -> SingleSchedulerCheckpoint {
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "qemu-runner-resume",
            Shift::new(0).expect("zero shift"),
            1,
            SimInstant { nanos: 1 },
            Vec::new(),
            Vec::new(),
        )
        .with_scenario_def(configuration.def.clone());
        let mut scheduler = SingleScheduler::new(scenario).expect("build resume scheduler");
        scheduler
            .append_branch_prefix_overrides(decisions)
            .expect("append resume branch prefix");
        scheduler.checkpoint().expect("capture resume scheduler")
    }
}
