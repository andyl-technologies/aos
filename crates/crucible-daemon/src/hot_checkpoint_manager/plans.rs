//! Immutable admission, demotion, fallback, and inventory-result contracts.

use super::*;

/// Durable realization tier preserved after a hot source is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointFallbackTier {
    /// Preserve or use the authenticated exact checkpoint closure.
    Exact,
    /// Reconstruct from the authenticated thin replay path.
    Thin,
}

/// Exact authenticated realization basis preserved after hot demotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointFallback {
    /// Preserve one complete authenticated exact-checkpoint closure.
    Exact(ExactCheckpointId),
    /// Preserve one verified configuration artifact for deterministic replay.
    Thin(ConfigurationArtifactId),
}

impl HotCheckpointFallback {
    /// Returns the durable realization tier represented by this exact basis.
    #[must_use]
    pub const fn tier(self) -> HotCheckpointFallbackTier {
        match self {
            Self::Exact(_) => HotCheckpointFallbackTier::Exact,
            Self::Thin(_) => HotCheckpointFallbackTier::Thin,
        }
    }

    /// Returns the exact-checkpoint closure root, when this is an exact fallback.
    #[must_use]
    pub const fn exact_checkpoint(self) -> Option<ExactCheckpointId> {
        match self {
            Self::Exact(checkpoint) => Some(checkpoint),
            Self::Thin(_) => None,
        }
    }

    /// Returns the verified configuration artifact, when this is a thin fallback.
    #[must_use]
    pub const fn thin_configuration(self) -> Option<ConfigurationArtifactId> {
        match self {
            Self::Exact(_) => None,
            Self::Thin(configuration) => Some(configuration),
        }
    }
}

/// Candidate metadata considered for hot retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointCandidate {
    pub(super) key: QemuHotForkTemplateKey,
    pub(super) resources: HotCheckpointResourceProfile,
    pub(super) signals: HotCheckpointHotnessSignals,
    pub(super) fallback: HotCheckpointFallback,
}

impl HotCheckpointCandidate {
    /// Describes one exact source proposed for hot retention.
    #[must_use]
    pub const fn new(
        key: QemuHotForkTemplateKey,
        resources: HotCheckpointResourceProfile,
        signals: HotCheckpointHotnessSignals,
        fallback: HotCheckpointFallback,
    ) -> Self {
        Self {
            key,
            resources,
            signals,
            fallback,
        }
    }

    /// Returns the exact lineage/configuration key.
    #[must_use]
    pub const fn template_key(self) -> QemuHotForkTemplateKey {
        self.key
    }

    /// Returns the measured retained-resource profile.
    #[must_use]
    pub const fn resources(self) -> HotCheckpointResourceProfile {
        self.resources
    }

    /// Returns the normalized operational scoring inputs.
    #[must_use]
    pub const fn signals(self) -> HotCheckpointHotnessSignals {
        self.signals
    }

    /// Returns the authenticated fallback selected if hot retention ends.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallback {
        self.fallback
    }
}

/// Reason one hot checkpoint remains in the retained inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointRetentionReason {
    /// The source fit without removing another retained source.
    WithinBudget,
    /// Lower-value sources were demoted to make room.
    ReplacedColderSources,
    /// Operational signals or pin state were refreshed in place.
    SignalsUpdated,
}

/// Current explainable state of one retained hot checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointStatus {
    pub(super) slot: QemuHotForkTemplatePoolSlot,
    pub(super) resources: HotCheckpointResourceProfile,
    pub(super) signals: HotCheckpointHotnessSignals,
    pub(super) fallback: HotCheckpointFallback,
    pub(super) reason: HotCheckpointRetentionReason,
}

impl HotCheckpointStatus {
    /// Returns the stable source-pool coordinate.
    #[must_use]
    pub const fn slot(self) -> QemuHotForkTemplatePoolSlot {
        self.slot
    }

    /// Returns the accounted resource profile.
    #[must_use]
    pub const fn resources(self) -> HotCheckpointResourceProfile {
        self.resources
    }

    /// Returns the current operational scoring inputs.
    #[must_use]
    pub const fn signals(self) -> HotCheckpointHotnessSignals {
        self.signals
    }

    /// Returns the computed signed operational score.
    #[must_use]
    pub const fn score(self) -> HotCheckpointScore {
        self.signals.score()
    }

    /// Returns the exact authenticated fallback basis used on demotion.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallback {
        self.fallback
    }

    /// Returns why this source was most recently retained.
    #[must_use]
    pub const fn reason(self) -> HotCheckpointRetentionReason {
        self.reason
    }
}

/// Planned removal of one colder source before candidate installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointPlannedDemotion {
    pub(super) status: HotCheckpointStatus,
    pub(super) reason: HotCheckpointDemotionReason,
}

impl HotCheckpointPlannedDemotion {
    pub(crate) const fn new(
        status: HotCheckpointStatus,
        reason: HotCheckpointDemotionReason,
    ) -> Self {
        Self { status, reason }
    }

    /// Returns the exact retained source that must be retired.
    #[must_use]
    pub const fn status(self) -> HotCheckpointStatus {
        self.status
    }

    /// Returns the exact pool coordinate to retire while idle.
    #[must_use]
    pub const fn slot(self) -> QemuHotForkTemplatePoolSlot {
        self.status.slot
    }

    /// Returns the exact durable realization basis that must remain available.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallback {
        self.status.fallback
    }

    /// Returns why this source was selected for demotion.
    #[must_use]
    pub const fn reason(self) -> HotCheckpointDemotionReason {
        self.reason
    }
}

/// Operational reason a hot source leaves the retained tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointDemotionReason {
    /// A strictly hotter or explicitly pinned candidate required capacity.
    CapacityPressure,
    /// An operator explicitly requested orderly demotion.
    OperatorRequest,
    /// Daemon shutdown is draining an idle source.
    DaemonShutdown,
    /// Runtime invalidation made the retained source ineligible for reuse.
    SourceInvalidated,
}

/// Explainable completed removal from the hot tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointDemotion {
    pub(super) status: HotCheckpointStatus,
    pub(super) reason: HotCheckpointDemotionReason,
}

/// Read-only generation-bound plan for orderly removal from the hot tier.
#[must_use = "retire the exact idle source and commit, or discard the read-only plan"]
#[derive(Debug)]
pub struct HotCheckpointOrderlyDemotionPlan {
    pub(super) manager: Arc<()>,
    pub(super) generation: u64,
    pub(super) status: HotCheckpointStatus,
    pub(super) reason: HotCheckpointDemotionReason,
}

impl HotCheckpointOrderlyDemotionPlan {
    /// Returns the exact source status that must remain unchanged until commit.
    #[must_use]
    pub const fn status(&self) -> HotCheckpointStatus {
        self.status
    }

    /// Returns why the source is being removed from the hot tier.
    #[must_use]
    pub const fn reason(&self) -> HotCheckpointDemotionReason {
        self.reason
    }
}

impl HotCheckpointDemotion {
    /// Returns the source status immediately before removal.
    #[must_use]
    pub const fn status(self) -> HotCheckpointStatus {
        self.status
    }

    /// Returns why the source left the hot tier.
    #[must_use]
    pub const fn reason(self) -> HotCheckpointDemotionReason {
        self.reason
    }
}

/// Read-only generation-bound plan for admitting one hot source.
#[must_use = "retire the planned idle sources and commit, or discard the read-only plan"]
#[derive(Debug)]
pub struct HotCheckpointAdmissionPlan {
    pub(super) manager: Arc<()>,
    pub(super) generation: u64,
    pub(super) candidate: HotCheckpointCandidate,
    pub(super) demotions: Vec<HotCheckpointPlannedDemotion>,
}

impl HotCheckpointAdmissionPlan {
    /// Returns the exact proposed source metadata.
    #[must_use]
    pub const fn candidate(&self) -> HotCheckpointCandidate {
        self.candidate
    }

    /// Returns deterministic colder-source demotions in required order.
    #[must_use]
    pub fn demotions(&self) -> &[HotCheckpointPlannedDemotion] {
        &self.demotions
    }
}

/// Successful committed hot-retention inventory transition.
#[derive(Debug, PartialEq, Eq)]
pub struct HotCheckpointAdmissionCommit {
    pub(super) retained: HotCheckpointStatus,
    pub(super) demoted: Vec<HotCheckpointDemotion>,
}

impl HotCheckpointAdmissionCommit {
    /// Returns the newly retained source status.
    #[must_use]
    pub const fn retained(&self) -> HotCheckpointStatus {
        self.retained
    }

    /// Returns every source removed after its fallback was secured.
    #[must_use]
    pub fn demoted(&self) -> &[HotCheckpointDemotion] {
        &self.demoted
    }
}

/// Admission refusal that leaves the manager unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointAdmissionRejection {
    /// No further inventory transition can be identified without ambiguity.
    #[error("hot-checkpoint inventory generation is exhausted")]
    GenerationExhausted,
    /// The candidate alone exceeds one or more process-wide ceilings.
    #[error("hot-checkpoint candidate exceeds an individual resource ceiling")]
    IndividualLimit {
        /// Exact dimensions over limit.
        pressure: HotCheckpointPressure,
    },
    /// Pinned or equally/higher-valued sources prevent sufficient demotion.
    #[error("hot-checkpoint candidate has insufficient demotable capacity")]
    InsufficientDemotableCapacity {
        /// Dimensions still over limit after all eligible demotions.
        pressure: HotCheckpointPressure,
        /// Number of hard-pinned retained sources.
        pinned_sources: usize,
    },
    /// Checked aggregate accounting could not represent an intermediate sum.
    #[error("hot-checkpoint aggregate accounting overflow")]
    AccountingOverflow,
}

/// Failure to commit an admission plan exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointAdmissionCommitError {
    /// The plan was minted by another manager.
    #[error("hot-checkpoint admission plan belongs to another manager")]
    ForeignPlan,
    /// Inventory changed after the plan was computed.
    #[error("hot-checkpoint admission plan generation {planned} is stale at {current}")]
    StalePlan {
        /// Inventory generation used during planning.
        planned: u64,
        /// Current inventory generation.
        current: u64,
    },
    /// The installed slot has a different exact template key.
    #[error("installed hot-checkpoint slot does not match the planned exact key")]
    WrongInstalledKey,
    /// The installed coordinate still belongs to an unplanned retained source.
    #[error("installed hot-checkpoint coordinate is already retained")]
    OccupiedSlot,
    /// A planned victim is no longer present with the exact planned metadata.
    #[error("planned hot-checkpoint demotion victim is missing or changed")]
    MissingPlannedVictim,
    /// Checked aggregate accounting overflowed.
    #[error("hot-checkpoint aggregate accounting overflow")]
    AccountingOverflow,
    /// The resulting inventory would violate a configured hard ceiling.
    #[error("hot-checkpoint admission would violate a hard resource ceiling")]
    LimitViolation,
    /// The inventory generation cannot advance without ambiguity.
    #[error("hot-checkpoint inventory generation is exhausted")]
    GenerationExhausted,
}

/// Failure to update or remove retained operational inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointInventoryError {
    /// The plan was minted by another manager.
    #[error("hot-checkpoint orderly-demotion plan belongs to another manager")]
    ForeignPlan,
    /// Inventory changed after the orderly-demotion plan was computed.
    #[error("hot-checkpoint orderly-demotion plan generation {planned} is stale at {current}")]
    StalePlan {
        /// Inventory generation used during planning.
        planned: u64,
        /// Current inventory generation.
        current: u64,
    },
    /// The exact stable pool coordinate is not retained.
    #[error("hot-checkpoint inventory has no such retained pool slot")]
    MissingSlot,
    /// Internal aggregate accounting did not contain the retained profile.
    #[error("hot-checkpoint aggregate accounting is inconsistent")]
    AccountingInconsistent,
    /// The inventory generation cannot advance without ambiguity.
    #[error("hot-checkpoint inventory generation is exhausted")]
    GenerationExhausted,
}

/// One non-cloneable permit for an actual child-fork attempt.
#[must_use = "consume the admitted fork opportunity in the hot-fork launcher"]
pub struct HotCheckpointForkPermit {
    pub(super) manager: Arc<()>,
    pub(super) window: u64,
    pub(super) ordinal: u32,
}

impl HotCheckpointForkPermit {
    /// Returns the operational rate-window ordinal.
    #[must_use]
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// Returns the one-based admitted fork ordinal within the window.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns whether this permit was minted by the given manager instance.
    #[must_use]
    pub fn belongs_to(&self, manager: &HotCheckpointManager) -> bool {
        Arc::ptr_eq(&self.manager, &manager.identity)
    }
}

/// Fork-rate admission failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointForkRateError {
    /// A caller attempted to roll the monotonic operational clock backward.
    #[error("hot-checkpoint monotonic nanoseconds {requested} are stale at {current}")]
    StaleClock {
        /// Rejected monotonic nanosecond reading.
        requested: u64,
        /// Latest manager monotonic nanosecond reading.
        current: u64,
    },
    /// This window already admitted the configured number of starts.
    #[error("hot-checkpoint fork-rate limit {maximum} is exhausted in window {window}")]
    RateLimited {
        /// Current window ordinal.
        window: u64,
        /// Configured starts per window.
        maximum: u32,
    },
}
