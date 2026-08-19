//! Exact-restore and thin-replay QEMU runner for local campaign attempts.
//!
//! This module connects the campaign execution boundary to the existing QEMU
//! realization coordinator. It deliberately does not emulate hot fork: the
//! GPL-side fork protocol must land and pass its safety gates before a runner
//! may report [`CrucibleMaterializationTier::HotFork`].

use crucible::Configuration;
use crucible_campaign::{AttemptResourceLimits, ObservationCandidate};
use crucible_qemu::{
    QemuExactSnapshotPolicy, QemuVmRealization, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmRealizationKind, QemuVmRealizationStore, QemuVmSnapshot, instantiate_qemu_vm,
};

use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CrucibleAttemptExecution,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart, ExecutionCancellation,
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

    /// Applies a branch selection when present and runs to the attempt stop.
    ///
    /// The realized runtime denotes [`CrucibleResolvedAttemptStart::Discover`]
    /// or the exact branch parent. The session retains the live backend instead
    /// of handing modeled code a detached [`crucible::RuntimeState`]. It applies
    /// the typed selection, enforces the operational context, and constructs
    /// the complete immutable observation candidate.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal driver failure.
    fn run_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        realization: QemuVmRealization,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>>;

    /// Reclaims every process, file, and resource reservation owned by the session.
    ///
    /// This operation is mandatory on successful, failed, and canceled
    /// attempts. Even when it returns an error, the implementation must have
    /// completed its kill-and-reap ladder so no guest process remains charged
    /// outside the local executor supervisor. Implementations must provide the
    /// same cleanup from `Drop` as an unwind backstop; normal control flow uses
    /// this consuming method so cleanup failures remain observable.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when cleanup completed with an
    /// operational diagnostic failure.
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
        let configuration = match input.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration,
            CrucibleResolvedAttemptStart::Branch { parent, .. } => parent,
        };
        let mut session = self
            .sessions
            .begin_attempt(context)
            .map_err(classify_realization_failure)?;
        let result = if session.resource_limits() == context.resources() {
            run_in_session(
                &mut self.store,
                &mut session,
                input,
                context,
                configuration,
                self.policy,
            )
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
        (Err(failure), _) => Err(failure),
        (Ok(_), Err(error)) => Err(classify_realization_failure(error)),
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
    let candidate = session
        .run_attempt(input, context, realization)
        .map_err(map_driver_failure)?;
    Ok(CrucibleExecutionOutcome::new(candidate, materialization))
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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

        fn run_attempt(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
            _realization: QemuVmRealization,
        ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>> {
            unreachable!("finish-only test session does not drive QEMU")
        }

        fn finish(self) -> Result<(), QemuVmRealizationError> {
            self.finishes.fetch_add(1, Ordering::SeqCst);
            if self.cleanup_error {
                Err(QemuVmRealizationError::ExecutorUnavailable {
                    operation: "finish test QEMU session",
                    message: String::from("injected cleanup diagnostic"),
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
            Err(AttemptWorkerFailure::Retryable(
                QemuExactThinRunnerError::Realization(
                    QemuVmRealizationError::ExecutorUnavailable { .. }
                )
            ))
        ));
        assert_eq!(finishes.load(Ordering::SeqCst), 5);
    }
}
