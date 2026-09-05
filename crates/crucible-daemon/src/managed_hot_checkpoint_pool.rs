//! Enforced composition of hot-checkpoint accounting and source ownership.
//!
//! This owner is the only mutable route to its retained-template pool. It
//! checks the operational manager before installation, proves every planned
//! victim idle before transferring authority, and requires a demotion sink to
//! attest source reap while the exact/thin fallback remains available. Actual
//! child starts consume the manager's process-wide fork-rate budget before the
//! source factory can launch.

use crate::supervision::ForkRateClock;

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
    QemuHotForkTemplatePoolSlot,
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
    fork_rate_clock: ForkRateClock,
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
            fork_rate_clock: ForkRateClock::new(),
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
                    installed_slot,
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
        self.fork_rate_clock.elapsed_nanos()
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

mod error;
pub use error::{
    ManagedHotCheckpointAdmissionError, ManagedHotCheckpointAdmissionFailure,
    ManagedHotCheckpointDemotionError, ManagedHotCheckpointDemotionFailure,
    ManagedHotCheckpointStartError, ManagedQemuHotForkTemplatePoolConstructionError,
};

#[cfg(test)]
mod tests;
