//! Enforced composition of hot-checkpoint accounting and source ownership.
//!
//! This owner is the only mutable route to its retained-template pool. It
//! checks the operational manager before installation, proves every planned
//! victim idle before transferring authority, and requires a demotion sink to
//! attest source reap while the exact/thin fallback remains available. Actual
//! child starts consume the manager's process-wide fork-rate budget before the
//! source factory can launch.

use std::time::Instant;

use crate::{
    AttemptExecutionContext, AttemptExecutionRuntimeBasis, AttemptWorkerFailure,
    CrucibleAttemptExecution, HotCheckpointAdmissionCommit, HotCheckpointAdmissionCommitError,
    HotCheckpointAdmissionRejection, HotCheckpointCandidate, HotCheckpointDemotion,
    HotCheckpointDemotionReason, HotCheckpointFallback, HotCheckpointForkRateError,
    HotCheckpointInventoryError, HotCheckpointLimits, HotCheckpointManager,
    HotCheckpointPlannedDemotion, HotCheckpointStatus, QemuHotForkAttemptLifecycleFactory,
    QemuHotForkAttemptLifecycleRecoveryError, QemuHotForkKeyedLifecycleFactory,
    QemuHotForkLifecycleQuarantine, QemuHotForkTemplateKey, QemuHotForkTemplatePool,
    QemuHotForkTemplatePoolCapacityError, QemuHotForkTemplatePoolError,
    QemuHotForkTemplatePoolLifecycle, QemuHotForkTemplatePoolRetirementError,
};

/// Sink that completes an orderly hot-to-exact/thin source transition.
///
/// Success attests that the source process and hot-only host resources were
/// reaped/released while the planned fallback remains authenticated and
/// available. A failure must return the source factory, retaining any
/// partially progressed shutdown authority inside it, so this owner can
/// reinstall the exact stable coordinate; quarantine without resource release
/// is not successful demotion.
pub trait HotCheckpointTemplateDemotionSink<F> {
    /// Stable demotion or source-shutdown failure.
    type Error;

    /// Preflights one exact fallback without changing source ownership.
    ///
    /// This check must prove that an exact root remains complete and retained,
    /// or that the named thin configuration and its realization base remain
    /// available. It is run for a new candidate and for every planned victim
    /// before the first source transfer. [`Self::demote`] must reauthenticate
    /// the fallback at the actual release boundary so a later availability
    /// change cannot permit source teardown.
    ///
    /// # Errors
    ///
    /// Returns the stable authentication or availability diagnostic without
    /// changing source, fallback, or manager state.
    fn validate_fallback(
        &mut self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error>;

    /// Demotes one retired idle source exactly as planned.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointTemplateDemotionFailure`] retaining the source
    /// factory whenever reap, resource release, or fallback validation fails.
    fn demote(
        &mut self,
        factory: F,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<F, Self::Error>>;
}

/// Failed orderly demotion retaining the exact source authority.
#[must_use = "restore the source coordinate or transfer the authority to quarantine"]
pub struct HotCheckpointTemplateDemotionFailure<F, E> {
    factory: Box<F>,
    error: E,
}

impl<F, E> HotCheckpointTemplateDemotionFailure<F, E> {
    /// Constructs a failure from its retained source and diagnostic.
    pub fn new(factory: F, error: E) -> Self {
        Self {
            factory: Box::new(factory),
            error,
        }
    }

    /// Consumes the failure into its retained source and diagnostic.
    pub fn into_parts(self) -> (F, E) {
        (*self.factory, self.error)
    }
}

impl<F, E> std::fmt::Debug for HotCheckpointTemplateDemotionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HotCheckpointTemplateDemotionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// One process-wide managed retained-template pool.
pub struct ManagedQemuHotForkTemplatePool<F, Q, D>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
{
    manager: HotCheckpointManager,
    pool: QemuHotForkTemplatePool<F, Q>,
    demotions: D,
    clock_origin: Instant,
}

impl<F, Q, D> ManagedQemuHotForkTemplatePool<F, Q, D>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
{
    /// Creates an empty owner with one fixed manager/pool capacity contract.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkTemplatePoolConstructionError`] if the pool
    /// rejects the already-validated manager template ceiling.
    pub fn new(
        limits: HotCheckpointLimits,
        quarantine: Q,
        demotions: D,
    ) -> Result<Self, ManagedQemuHotForkTemplatePoolConstructionError> {
        let pool = QemuHotForkTemplatePool::empty(limits.maximum_templates(), quarantine)
            .map_err(ManagedQemuHotForkTemplatePoolConstructionError::Pool)?;
        Ok(Self {
            manager: HotCheckpointManager::new(limits),
            pool,
            demotions,
            clock_origin: hot_checkpoint_now(),
        })
    }

    /// Returns the enforced operational manager view.
    #[must_use]
    pub const fn manager(&self) -> &HotCheckpointManager {
        &self.manager
    }

    /// Returns the immutable retained-template pool view.
    #[must_use]
    pub const fn pool(&self) -> &QemuHotForkTemplatePool<F, Q> {
        &self.pool
    }

    /// Returns the orderly-demotion sink view.
    #[must_use]
    pub const fn demotion_sink(&self) -> &D {
        &self.demotions
    }

    /// Updates one retained source's explainable hotness and pin signals.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError`] when the exact coordinate is
    /// absent or the inventory generation cannot advance.
    pub fn update_signals(
        &mut self,
        slot: crate::QemuHotForkTemplatePoolSlot,
        signals: crate::HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointStatus, HotCheckpointInventoryError> {
        self.manager.update_signals(slot, signals)
    }

    /// Demotes one exact idle source after securing its configured fallback.
    ///
    /// The pool coordinate remains owned until the demotion sink attests that
    /// the source process and hot-only resources have been released. A sink
    /// failure restores the unchanged source at that exact coordinate. A
    /// successful sink transfer is committed to manager accounting even though
    /// the source factory itself has been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedHotCheckpointDemotionFailure`] when the manager no
    /// longer recognizes the coordinate, the source is busy or missing, the
    /// sink cannot secure the fallback and reap the source, exact restoration
    /// fails, or manager accounting cannot commit the completed removal.
    pub fn demote_template(
        &mut self,
        slot: crate::QemuHotForkTemplatePoolSlot,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointDemotion, ManagedHotCheckpointDemotionFailure<F, D::Error>> {
        let plan = self
            .manager
            .plan_orderly_demotion(slot, reason)
            .map_err(|source| {
                ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::ManagerPlan(source),
                )
            })?;
        self.demotions
            .validate_fallback(slot.template_key(), plan.status().fallback())
            .map_err(|source| {
                ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::FallbackValidation(source),
                )
            })?;
        match self.pool.slot_available(slot) {
            Some(true) => {}
            Some(false) => {
                return Err(ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::VictimBusy,
                ));
            }
            None => {
                return Err(ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::VictimMissing,
                ));
            }
        }

        let factory = self.pool.retire_idle(slot).map_err(|source| {
            ManagedHotCheckpointDemotionFailure::without_factory(
                ManagedHotCheckpointDemotionError::PoolRetirement(source),
            )
        })?;
        let sink_plan = HotCheckpointPlannedDemotion::new(plan.status(), plan.reason());
        if let Err(failure) = self.demotions.demote(factory, sink_plan) {
            let (factory, source) = failure.into_parts();
            return match self.pool.restore_retired(slot, factory) {
                Ok(()) => Err(ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::Demotion(source),
                )),
                Err(factory) => Err(ManagedHotCheckpointDemotionFailure::with_factory(
                    factory,
                    ManagedHotCheckpointDemotionError::RestoreInvariant,
                )),
            };
        }

        self.manager
            .commit_orderly_demotion(plan)
            .map_err(|source| {
                ManagedHotCheckpointDemotionFailure::without_factory(
                    ManagedHotCheckpointDemotionError::ManagerCommit(source),
                )
            })
    }

    /// Admits one source, demoting every required idle colder source first.
    ///
    /// Every victim is checked idle before the first transfer. Successful
    /// demotions remain valid if a later source demotion fails; the manager is
    /// reconciled to those completed removals, the failed source is restored to
    /// its exact coordinate, and the candidate is returned unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedHotCheckpointAdmissionFailure`] retaining the candidate
    /// factory when its key differs, manager planning rejects it, a victim is
    /// busy/missing, the demotion sink fails, pool installation fails, or an
    /// internal pool/manager invariant fails. `stranded_factory` is populated
    /// only if an invariant prevents exact source-coordinate restoration.
    pub fn admit_template(
        &mut self,
        factory: F,
        candidate: HotCheckpointCandidate,
    ) -> Result<HotCheckpointAdmissionCommit, ManagedHotCheckpointAdmissionFailure<F, D::Error>>
    {
        if factory.template_key() != candidate.template_key() {
            return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                factory,
                ManagedHotCheckpointAdmissionError::CandidateKeyMismatch,
            ));
        }
        let plan = match self.manager.plan_admission(candidate) {
            Ok(plan) => plan,
            Err(source) => {
                return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                    factory,
                    ManagedHotCheckpointAdmissionError::Rejected(source),
                ));
            }
        };
        if let Err(source) = self
            .demotions
            .validate_fallback(candidate.template_key(), candidate.fallback())
        {
            return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                factory,
                ManagedHotCheckpointAdmissionError::FallbackValidation(source),
            ));
        }

        for demotion in plan.demotions() {
            if let Err(source) = self
                .demotions
                .validate_fallback(demotion.slot().template_key(), demotion.fallback())
            {
                return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                    factory,
                    ManagedHotCheckpointAdmissionError::FallbackValidation(source),
                ));
            }
            match self.pool.slot_available(demotion.slot()) {
                Some(true) => {}
                Some(false) => {
                    return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                        factory,
                        ManagedHotCheckpointAdmissionError::VictimBusy,
                    ));
                }
                None => {
                    return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                        factory,
                        ManagedHotCheckpointAdmissionError::VictimMissing,
                    ));
                }
            }
        }

        let mut completed = Vec::with_capacity(plan.demotions().len());
        for demotion in plan.demotions().iter().copied() {
            let retired = match self.pool.retire_idle(demotion.slot()) {
                Ok(retired) => retired,
                Err(source) => {
                    let reconciliation = self.commit_completed_demotions(&completed);
                    return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                        factory,
                        ManagedHotCheckpointAdmissionError::PoolRetirement {
                            source,
                            reconciliation,
                        },
                    ));
                }
            };
            if let Err(failure) = self.demotions.demote(retired, demotion) {
                let (retired, source) = failure.into_parts();
                if let Err(stranded) = self.pool.restore_retired(demotion.slot(), retired) {
                    let reconciliation = self.commit_completed_demotions(&completed);
                    return Err(ManagedHotCheckpointAdmissionFailure::with_stranded(
                        factory,
                        stranded,
                        ManagedHotCheckpointAdmissionError::RestoreInvariant { reconciliation },
                    ));
                }
                let reconciliation = self.commit_completed_demotions(&completed);
                return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                    factory,
                    ManagedHotCheckpointAdmissionError::Demotion {
                        source,
                        reconciliation,
                    },
                ));
            }
            completed.push(demotion);
        }

        let installed_slot = match self.pool.insert(factory) {
            Ok(slot) => slot,
            Err(source) => {
                let reconciliation = self.commit_completed_demotions(&completed);
                return Err(ManagedHotCheckpointAdmissionFailure::candidate(
                    source.into_factory(),
                    ManagedHotCheckpointAdmissionError::PoolInsertion { reconciliation },
                ));
            }
        };
        match self.manager.commit_admission(plan, installed_slot) {
            Ok(commit) => Ok(commit),
            Err(source) => match self.pool.retire_idle(installed_slot) {
                Ok(factory) => {
                    let reconciliation = self.commit_completed_demotions(&completed);
                    Err(ManagedHotCheckpointAdmissionFailure::candidate(
                        factory,
                        ManagedHotCheckpointAdmissionError::ManagerCommit {
                            source,
                            reconciliation,
                        },
                    ))
                }
                Err(retirement) => Err(ManagedHotCheckpointAdmissionFailure::without_candidate(
                    ManagedHotCheckpointAdmissionError::InstalledRollback { source, retirement },
                )),
            },
        }
    }

    fn commit_completed_demotions(
        &mut self,
        completed: &[HotCheckpointPlannedDemotion],
    ) -> Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError> {
        self.manager.commit_completed_demotions(completed)
    }

    fn monotonic_nanos(&self) -> u64 {
        let elapsed = hot_checkpoint_now().saturating_duration_since(self.clock_origin);
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

impl<F, Q, D> QemuHotForkAttemptLifecycleFactory for ManagedQemuHotForkTemplatePool<F, Q, D>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
{
    type Lifecycle = QemuHotForkTemplatePoolLifecycle<F::Lifecycle>;
    type Error = ManagedHotCheckpointStartError<F::Error>;

    fn start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let tick = self.monotonic_nanos();
        let _permit = self
            .manager
            .admit_fork(tick)
            .map_err(|source| AttemptWorkerFailure::Retryable(Self::Error::ForkRate(source)))?;
        self.pool
            .start(input, context, runtime_basis)
            .map_err(map_start_failure)
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        self.pool.recover(lifecycle).map_err(|failure| {
            let (lifecycle, source) = failure.into_parts();
            QemuHotForkAttemptLifecycleRecoveryError::new(lifecycle, map_start_failure(source))
        })
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        self.pool.quarantine(lifecycle);
    }
}

fn map_start_failure<E>(
    failure: AttemptWorkerFailure<QemuHotForkTemplatePoolError<E>>,
) -> AttemptWorkerFailure<ManagedHotCheckpointStartError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(source) => {
            AttemptWorkerFailure::Retryable(ManagedHotCheckpointStartError::Pool(source))
        }
        AttemptWorkerFailure::Canceled(source) => {
            AttemptWorkerFailure::Canceled(ManagedHotCheckpointStartError::Pool(source))
        }
        AttemptWorkerFailure::Terminal(source) => {
            AttemptWorkerFailure::Terminal(ManagedHotCheckpointStartError::Pool(source))
        }
    }
}

/// Invalid managed-pool construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManagedQemuHotForkTemplatePoolConstructionError {
    /// The underlying pool rejected the manager's static template ceiling.
    #[error("managed hot-checkpoint pool rejected its configured capacity")]
    Pool(QemuHotForkTemplatePoolCapacityError),
}

/// Classified failure to start or recover one managed hot-fork child.
#[derive(Debug, thiserror::Error)]
pub enum ManagedHotCheckpointStartError<E> {
    /// The fixed operational rate window has no remaining fork permit.
    #[error("managed hot-checkpoint fork-rate admission failed")]
    ForkRate(HotCheckpointForkRateError),
    /// Exact template selection, launch, or recovery failed.
    #[error("managed hot-checkpoint source pool failed")]
    Pool(QemuHotForkTemplatePoolError<E>),
}

/// Failed explicit hot-source demotion with any unowned authority retained.
#[must_use = "recover any stranded source authority before discarding the diagnostic"]
pub struct ManagedHotCheckpointDemotionFailure<F, E> {
    stranded_factory: Option<Box<F>>,
    error: ManagedHotCheckpointDemotionError<E>,
}

impl<F, E> ManagedHotCheckpointDemotionFailure<F, E> {
    fn without_factory(error: ManagedHotCheckpointDemotionError<E>) -> Self {
        Self {
            stranded_factory: None,
            error,
        }
    }

    fn with_factory(factory: F, error: ManagedHotCheckpointDemotionError<E>) -> Self {
        Self {
            stranded_factory: Some(Box::new(factory)),
            error,
        }
    }

    /// Consumes the failure into any stranded source and its diagnostic.
    ///
    /// The source is absent when no transfer occurred, restoration succeeded,
    /// or the demotion sink already attested source reap and resource release.
    pub fn into_parts(self) -> (Option<F>, ManagedHotCheckpointDemotionError<E>) {
        (self.stranded_factory.map(|factory| *factory), self.error)
    }
}

impl<F, E> std::fmt::Debug for ManagedHotCheckpointDemotionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedHotCheckpointDemotionFailure")
            .field("has_stranded_factory", &self.stranded_factory.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// Exact reason an explicit managed hot-source demotion failed.
#[derive(Debug, thiserror::Error)]
pub enum ManagedHotCheckpointDemotionError<E> {
    /// The manager no longer recognizes the requested exact coordinate.
    #[error("hot-checkpoint manager rejected the demotion plan")]
    ManagerPlan(HotCheckpointInventoryError),
    /// The exact fallback is no longer authenticated or available.
    #[error("hot-checkpoint fallback validation failed")]
    FallbackValidation(E),
    /// The exact source currently owns a child lifecycle.
    #[error("requested hot-checkpoint demotion victim is busy")]
    VictimBusy,
    /// The exact source is absent from the owned pool.
    #[error("requested hot-checkpoint demotion victim is missing")]
    VictimMissing,
    /// Pool retirement changed despite exclusive owner access.
    #[error("requested hot-checkpoint source retirement failed")]
    PoolRetirement(QemuHotForkTemplatePoolRetirementError),
    /// Exact/thin fallback or orderly source reap failed.
    #[error("requested hot-checkpoint fallback demotion failed")]
    Demotion(E),
    /// A failed source could not be restored to its exact vacant coordinate.
    #[error("failed hot-checkpoint source could not be restored to its exact coordinate")]
    RestoreInvariant,
    /// Manager accounting could not commit an already completed removal.
    #[error("hot-checkpoint manager could not account an already completed demotion")]
    ManagerCommit(HotCheckpointInventoryError),
}

/// Failed managed admission retaining every authority not held by the owner.
#[must_use = "recover the candidate and any stranded source authority"]
pub struct ManagedHotCheckpointAdmissionFailure<F, E> {
    candidate: Option<Box<F>>,
    stranded_factory: Option<Box<F>>,
    error: Box<ManagedHotCheckpointAdmissionError<E>>,
}

impl<F, E> ManagedHotCheckpointAdmissionFailure<F, E> {
    fn candidate(factory: F, error: ManagedHotCheckpointAdmissionError<E>) -> Self {
        Self {
            candidate: Some(Box::new(factory)),
            stranded_factory: None,
            error: Box::new(error),
        }
    }

    fn with_stranded(
        candidate: F,
        stranded_factory: F,
        error: ManagedHotCheckpointAdmissionError<E>,
    ) -> Self {
        Self {
            candidate: Some(Box::new(candidate)),
            stranded_factory: Some(Box::new(stranded_factory)),
            error: Box::new(error),
        }
    }

    fn without_candidate(error: ManagedHotCheckpointAdmissionError<E>) -> Self {
        Self {
            candidate: None,
            stranded_factory: None,
            error: Box::new(error),
        }
    }

    /// Consumes the failure into retained factories and its diagnostic.
    ///
    /// `candidate` is absent only when an internal invariant left the newly
    /// installed candidate owned by the managed pool. `stranded_factory` is
    /// present only when an earlier source could not be restored to its exact
    /// stable coordinate.
    pub fn into_parts(self) -> (Option<F>, Option<F>, ManagedHotCheckpointAdmissionError<E>) {
        (
            self.candidate.map(|factory| *factory),
            self.stranded_factory.map(|factory| *factory),
            *self.error,
        )
    }
}

// Monotonic host time bounds only operational fork admission and never enters
// campaign content, modeled execution, or deterministic scheduling state.
// crucible-lint: allow clippy-disallowed-method -- the bounded host operation is operational only and cannot enter modeled state.
#[allow(clippy::disallowed_methods)]
fn hot_checkpoint_now() -> Instant {
    Instant::now()
}

impl<F, E> std::fmt::Debug for ManagedHotCheckpointAdmissionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedHotCheckpointAdmissionFailure")
            .field("has_candidate", &self.candidate.is_some())
            .field("has_stranded_factory", &self.stranded_factory.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// Exact reason a managed source admission failed.
#[derive(Debug, thiserror::Error)]
pub enum ManagedHotCheckpointAdmissionError<E> {
    /// Factory and candidate name different exact lineage/configuration keys.
    #[error("hot-checkpoint candidate key differs from its source factory")]
    CandidateKeyMismatch,
    /// A candidate or planned victim lacks its exact authenticated fallback.
    #[error("hot-checkpoint fallback validation failed")]
    FallbackValidation(E),
    /// Operational manager policy rejected the candidate without mutation.
    #[error("hot-checkpoint manager rejected candidate admission")]
    Rejected(HotCheckpointAdmissionRejection),
    /// A planned exact victim is currently running a child.
    #[error("planned hot-checkpoint demotion victim is busy")]
    VictimBusy,
    /// A planned exact victim is absent from the owned source pool.
    #[error("planned hot-checkpoint demotion victim is missing")]
    VictimMissing,
    /// Pool retirement changed despite exclusive owner access.
    #[error("planned hot-checkpoint source retirement failed")]
    PoolRetirement {
        /// Exact pool retirement failure.
        source: QemuHotForkTemplatePoolRetirementError,
        /// Reconciliation of any earlier successful demotions.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// Exact/thin fallback or orderly source reap failed.
    #[error("planned hot-checkpoint fallback demotion failed")]
    Demotion {
        /// Demotion-sink failure.
        source: E,
        /// Reconciliation of any earlier successful demotions.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// A failed source could not be restored to its exact vacant coordinate.
    #[error("failed hot-checkpoint source could not be restored to its exact coordinate")]
    RestoreInvariant {
        /// Reconciliation of any earlier successful demotions.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// Candidate insertion failed after planned source demotions completed.
    #[error("managed hot-checkpoint candidate insertion failed")]
    PoolInsertion {
        /// Reconciliation of already completed demotions.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// Manager commit failed after candidate installation.
    #[error("managed hot-checkpoint inventory commit failed")]
    ManagerCommit {
        /// Exact manager commit failure.
        source: HotCheckpointAdmissionCommitError,
        /// Reconciliation of already completed demotions.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// An installed candidate could not be rolled back after manager failure.
    #[error("managed hot-checkpoint candidate rollback failed")]
    InstalledRollback {
        /// Exact manager commit failure.
        source: HotCheckpointAdmissionCommitError,
        /// Exact pool retirement failure retaining the candidate internally.
        retirement: QemuHotForkTemplatePoolRetirementError,
    },
}

#[cfg(test)]
mod tests;
