//! Failure-retaining admission, demotion, and fork-start result contracts.

use super::*;

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
    pub(super) stranded_factory: Option<Box<F>>,
    pub(super) error: ManagedHotCheckpointDemotionError<E>,
}

impl<F, E> ManagedHotCheckpointDemotionFailure<F, E> {
    pub(super) fn without_factory(error: ManagedHotCheckpointDemotionError<E>) -> Self {
        Self {
            stranded_factory: None,
            error,
        }
    }

    pub(super) fn with_factory(factory: F, error: ManagedHotCheckpointDemotionError<E>) -> Self {
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
    pub(super) candidate: Option<Box<F>>,
    pub(super) stranded_factory: Option<Box<F>>,
    pub(super) internally_retained_slot: Option<QemuHotForkTemplatePoolSlot>,
    pub(super) error: Box<ManagedHotCheckpointAdmissionError<E>>,
}

impl<F, E> ManagedHotCheckpointAdmissionFailure<F, E> {
    pub(super) fn candidate(factory: F, error: ManagedHotCheckpointAdmissionError<E>) -> Self {
        Self {
            candidate: Some(Box::new(factory)),
            stranded_factory: None,
            internally_retained_slot: None,
            error: Box::new(error),
        }
    }

    pub(super) fn with_stranded(
        candidate: F,
        stranded_factory: F,
        error: ManagedHotCheckpointAdmissionError<E>,
    ) -> Self {
        Self {
            candidate: Some(Box::new(candidate)),
            stranded_factory: Some(Box::new(stranded_factory)),
            internally_retained_slot: None,
            error: Box::new(error),
        }
    }

    pub(super) fn without_candidate(
        internally_retained_slot: QemuHotForkTemplatePoolSlot,
        error: ManagedHotCheckpointAdmissionError<E>,
    ) -> Self {
        Self {
            candidate: None,
            stranded_factory: None,
            internally_retained_slot: Some(internally_retained_slot),
            error: Box::new(error),
        }
    }

    /// Returns the exact pool coordinate retaining the candidate internally.
    ///
    /// This is present only when manager commit failed and the defensive
    /// rollback could not retire the newly installed source. Callers must keep
    /// its durable fallback rooted until the complete owner is quarantined or
    /// the source is recovered from this coordinate.
    #[must_use]
    pub const fn internally_retained_slot(&self) -> Option<QemuHotForkTemplatePoolSlot> {
        self.internally_retained_slot
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

impl<F, E> std::fmt::Debug for ManagedHotCheckpointAdmissionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedHotCheckpointAdmissionFailure")
            .field("has_candidate", &self.candidate.is_some())
            .field("has_stranded_factory", &self.stranded_factory.is_some())
            .field("internally_retained_slot", &self.internally_retained_slot)
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
