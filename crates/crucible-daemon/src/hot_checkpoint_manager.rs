//! Bounded operational admission for retained QEMU hot checkpoints.
//!
//! The manager accounts every retained source across the process, ranks
//! operational reuse value, and prepares deterministic demotion plans when a
//! new source would exceed a configured host ceiling. Plans are read-only and
//! generation-bound: callers first retire the named idle pool slots and secure
//! their exact/thin fallback, then atomically commit the matching inventory
//! change. Hotness never enters campaign evidence or semantic scheduling.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{
    MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS, QemuHotForkTemplateKey, QemuHotForkTemplatePoolSlot,
};

/// Maximum normalized contribution accepted for one hotness component.
pub const MAX_HOT_CHECKPOINT_SCORE_COMPONENT: u64 = 1_000_000_000_000;

/// Exact resource cost attributed to one retained hot checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointResourceProfile {
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
}

impl HotCheckpointResourceProfile {
    /// Constructs one nonempty retained-template resource profile.
    ///
    /// Expected dirty bytes and overlay count may be zero. A live retained
    /// template must account at least one byte, process, virtual CPU, and
    /// descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointResourceProfileError`] when a required resource
    /// dimension is zero.
    pub const fn new(
        template_bytes: u64,
        expected_private_dirty_bytes: u64,
        process_count: u32,
        virtual_cpu_count: u32,
        descriptor_count: u32,
        overlay_count: u32,
    ) -> Result<Self, HotCheckpointResourceProfileError> {
        if template_bytes == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroTemplateBytes);
        }
        if process_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroProcesses);
        }
        if virtual_cpu_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroVirtualCpus);
        }
        if descriptor_count == 0 {
            return Err(HotCheckpointResourceProfileError::ZeroDescriptors);
        }
        Ok(Self {
            template_bytes,
            expected_private_dirty_bytes,
            process_count,
            virtual_cpu_count,
            descriptor_count,
            overlay_count,
        })
    }

    /// Returns retained source-template bytes.
    #[must_use]
    pub const fn template_bytes(self) -> u64 {
        self.template_bytes
    }

    /// Returns expected private dirty bytes across admitted children.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> u64 {
        self.expected_private_dirty_bytes
    }

    /// Returns retained process count.
    #[must_use]
    pub const fn process_count(self) -> u32 {
        self.process_count
    }

    /// Returns retained virtual CPU count.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> u32 {
        self.virtual_cpu_count
    }

    /// Returns retained descriptor count.
    #[must_use]
    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }

    /// Returns retained writable-overlay count.
    #[must_use]
    pub const fn overlay_count(self) -> u32 {
        self.overlay_count
    }
}

/// Invalid retained-template resource profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointResourceProfileError {
    /// A retained template must occupy nonzero measured storage.
    #[error("hot-checkpoint template byte cost is zero")]
    ZeroTemplateBytes,
    /// A retained template must own at least one process.
    #[error("hot-checkpoint process count is zero")]
    ZeroProcesses,
    /// A retained template must account at least one virtual CPU.
    #[error("hot-checkpoint virtual-CPU count is zero")]
    ZeroVirtualCpus,
    /// A retained template must account at least one descriptor.
    #[error("hot-checkpoint descriptor count is zero")]
    ZeroDescriptors,
}

/// Process-wide ceilings for retained hot checkpoints and fork starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointLimits {
    maximum_templates: usize,
    maximum_resources: HotCheckpointResourceProfile,
    maximum_forks_per_window: u32,
    fork_rate_window_ticks: u64,
}

impl HotCheckpointLimits {
    /// Constructs reviewed process-wide hot-checkpoint ceilings.
    ///
    /// The resource profile supplies aggregate maxima rather than the cost of
    /// an individual template.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointLimitsError`] when the template ceiling is zero
    /// or above the daemon's static worker bound, or when the fork-rate ceiling
    /// or monotonic window width is zero.
    pub const fn new(
        maximum_templates: usize,
        maximum_resources: HotCheckpointResourceProfile,
        maximum_forks_per_window: u32,
        fork_rate_window_ticks: u64,
    ) -> Result<Self, HotCheckpointLimitsError> {
        if maximum_templates == 0 {
            return Err(HotCheckpointLimitsError::ZeroTemplates);
        }
        if maximum_templates > MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS {
            return Err(HotCheckpointLimitsError::TooManyTemplates {
                requested: maximum_templates,
            });
        }
        if maximum_forks_per_window == 0 {
            return Err(HotCheckpointLimitsError::ZeroForkRate);
        }
        if fork_rate_window_ticks == 0 {
            return Err(HotCheckpointLimitsError::ZeroForkRateWindow);
        }
        Ok(Self {
            maximum_templates,
            maximum_resources,
            maximum_forks_per_window,
            fork_rate_window_ticks,
        })
    }

    /// Returns the retained-template count ceiling.
    #[must_use]
    pub const fn maximum_templates(self) -> usize {
        self.maximum_templates
    }

    /// Returns all aggregate retained-resource ceilings.
    #[must_use]
    pub const fn maximum_resources(self) -> HotCheckpointResourceProfile {
        self.maximum_resources
    }

    /// Returns the fork-start ceiling within one caller-defined rate window.
    #[must_use]
    pub const fn maximum_forks_per_window(self) -> u32 {
        self.maximum_forks_per_window
    }

    /// Returns the configured fixed window width in monotonic clock ticks.
    #[must_use]
    pub const fn fork_rate_window_ticks(self) -> u64 {
        self.fork_rate_window_ticks
    }
}

/// Invalid process-wide hot-checkpoint limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointLimitsError {
    /// At least one hot-template slot is required.
    #[error("hot-checkpoint template limit is zero")]
    ZeroTemplates,
    /// The requested ceiling exceeds the daemon's static worker bound.
    #[error(
        "hot-checkpoint template limit {requested} exceeds {MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS}"
    )]
    TooManyTemplates {
        /// Rejected requested template count.
        requested: usize,
    },
    /// A rate window must admit at least one fork start.
    #[error("hot-checkpoint fork-rate limit is zero")]
    ZeroForkRate,
    /// A rate window must span at least one monotonic clock tick.
    #[error("hot-checkpoint fork-rate window is zero ticks")]
    ZeroForkRateWindow,
}

/// Normalized operational inputs to retained-template hotness.
///
/// Every numeric component is expressed in deployment-defined score units.
/// Positive reuse signals are added and pressure/already-paid costs are
/// subtracted. The hard pin bit separately prevents automatic demotion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointHotnessSignals {
    pending_attempts: u64,
    expected_future_widening: u64,
    descendant_continuations: u64,
    interactive_or_finding_value: u64,
    dirty_memory_pressure: u64,
    descriptor_pressure: u64,
    restore_or_replay_cost_paid_elsewhere: u64,
    pinned: bool,
}

impl HotCheckpointHotnessSignals {
    /// Constructs zero-valued, unpinned operational signals.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending_attempts: 0,
            expected_future_widening: 0,
            descendant_continuations: 0,
            interactive_or_finding_value: 0,
            dirty_memory_pressure: 0,
            descriptor_pressure: 0,
            restore_or_replay_cost_paid_elsewhere: 0,
            pinned: false,
        }
    }

    /// Sets normalized pending-attempt value.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_pending_attempts(mut self, value: u64) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(HotCheckpointHotnessComponent::PendingAttempts, value)?;
        self.pending_attempts = value;
        Ok(self)
    }

    /// Sets normalized expected-future-widening value.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_expected_future_widening(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(HotCheckpointHotnessComponent::ExpectedFutureWidening, value)?;
        self.expected_future_widening = value;
        Ok(self)
    }

    /// Sets normalized descendant-continuation value.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_descendant_continuations(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(
            HotCheckpointHotnessComponent::DescendantContinuations,
            value,
        )?;
        self.descendant_continuations = value;
        Ok(self)
    }

    /// Sets normalized interactive or finding-pin value.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_interactive_or_finding_value(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(
            HotCheckpointHotnessComponent::InteractiveOrFindingValue,
            value,
        )?;
        self.interactive_or_finding_value = value;
        Ok(self)
    }

    /// Sets normalized dirty-memory pressure.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_dirty_memory_pressure(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(HotCheckpointHotnessComponent::DirtyMemoryPressure, value)?;
        self.dirty_memory_pressure = value;
        Ok(self)
    }

    /// Sets normalized descriptor pressure.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_descriptor_pressure(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(HotCheckpointHotnessComponent::DescriptorPressure, value)?;
        self.descriptor_pressure = value;
        Ok(self)
    }

    /// Sets normalized restore/replay cost already paid by another tier.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointHotnessError`] above the per-component bound.
    pub fn with_restore_or_replay_cost_paid_elsewhere(
        mut self,
        value: u64,
    ) -> Result<Self, HotCheckpointHotnessError> {
        validate_score_component(
            HotCheckpointHotnessComponent::RestoreOrReplayCostPaidElsewhere,
            value,
        )?;
        self.restore_or_replay_cost_paid_elsewhere = value;
        Ok(self)
    }

    /// Sets whether automatic pressure demotion is forbidden.
    #[must_use]
    pub const fn with_pin(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    /// Returns the complete signed operational score.
    #[must_use]
    pub const fn score(self) -> HotCheckpointScore {
        let positive = self.pending_attempts as i128
            + self.expected_future_widening as i128
            + self.descendant_continuations as i128
            + self.interactive_or_finding_value as i128;
        let pressure = self.dirty_memory_pressure as i128
            + self.descriptor_pressure as i128
            + self.restore_or_replay_cost_paid_elsewhere as i128;
        HotCheckpointScore(positive - pressure)
    }

    /// Returns whether this checkpoint is protected from automatic demotion.
    #[must_use]
    pub const fn pinned(self) -> bool {
        self.pinned
    }

    /// Returns normalized pending-attempt value.
    #[must_use]
    pub const fn pending_attempts(self) -> u64 {
        self.pending_attempts
    }

    /// Returns normalized expected-future-widening value.
    #[must_use]
    pub const fn expected_future_widening(self) -> u64 {
        self.expected_future_widening
    }

    /// Returns normalized descendant-continuation value.
    #[must_use]
    pub const fn descendant_continuations(self) -> u64 {
        self.descendant_continuations
    }

    /// Returns normalized interactive or finding-pin value.
    #[must_use]
    pub const fn interactive_or_finding_value(self) -> u64 {
        self.interactive_or_finding_value
    }

    /// Returns normalized dirty-memory pressure.
    #[must_use]
    pub const fn dirty_memory_pressure(self) -> u64 {
        self.dirty_memory_pressure
    }

    /// Returns normalized descriptor pressure.
    #[must_use]
    pub const fn descriptor_pressure(self) -> u64 {
        self.descriptor_pressure
    }

    /// Returns normalized restore/replay cost already paid elsewhere.
    #[must_use]
    pub const fn restore_or_replay_cost_paid_elsewhere(self) -> u64 {
        self.restore_or_replay_cost_paid_elsewhere
    }
}

fn validate_score_component(
    component: HotCheckpointHotnessComponent,
    value: u64,
) -> Result<(), HotCheckpointHotnessError> {
    if value > MAX_HOT_CHECKPOINT_SCORE_COMPONENT {
        return Err(HotCheckpointHotnessError { component, value });
    }
    Ok(())
}

/// Named component of the operational hotness formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointHotnessComponent {
    /// Pending attempts sharing the source.
    PendingAttempts,
    /// Expected future branch widening.
    ExpectedFutureWidening,
    /// Descendant continuations sharing the prefix.
    DescendantContinuations,
    /// Interactive or finding retention value.
    InteractiveOrFindingValue,
    /// Private dirty-memory pressure.
    DirtyMemoryPressure,
    /// File-descriptor pressure.
    DescriptorPressure,
    /// Restore or replay cost already paid in another tier.
    RestoreOrReplayCostPaidElsewhere,
}

/// Out-of-range normalized hotness component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("hot-checkpoint {component:?} score component {value} exceeds the static bound")]
pub struct HotCheckpointHotnessError {
    component: HotCheckpointHotnessComponent,
    value: u64,
}

impl HotCheckpointHotnessError {
    /// Returns the rejected component.
    #[must_use]
    pub const fn component(self) -> HotCheckpointHotnessComponent {
        self.component
    }

    /// Returns the rejected normalized value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Signed deterministic operational hotness score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HotCheckpointScore(i128);

impl HotCheckpointScore {
    /// Returns the signed normalized score units.
    #[must_use]
    pub const fn value(self) -> i128 {
        self.0
    }
}

/// Durable realization tier preserved after a hot source is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotCheckpointFallbackTier {
    /// Preserve or use the authenticated exact checkpoint closure.
    Exact,
    /// Reconstruct from the authenticated thin replay path.
    Thin,
}

/// Candidate metadata considered for hot retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotCheckpointCandidate {
    key: QemuHotForkTemplateKey,
    resources: HotCheckpointResourceProfile,
    signals: HotCheckpointHotnessSignals,
    fallback: HotCheckpointFallbackTier,
}

impl HotCheckpointCandidate {
    /// Describes one exact source proposed for hot retention.
    #[must_use]
    pub const fn new(
        key: QemuHotForkTemplateKey,
        resources: HotCheckpointResourceProfile,
        signals: HotCheckpointHotnessSignals,
        fallback: HotCheckpointFallbackTier,
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
    pub const fn fallback(self) -> HotCheckpointFallbackTier {
        self.fallback
    }
}

/// Aggregate resources currently retained by the manager.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointUsage {
    templates: usize,
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
}

impl HotCheckpointUsage {
    /// Returns the retained-template count.
    #[must_use]
    pub const fn templates(self) -> usize {
        self.templates
    }

    /// Returns aggregate source-template bytes.
    #[must_use]
    pub const fn template_bytes(self) -> u64 {
        self.template_bytes
    }

    /// Returns aggregate expected private dirty bytes.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> u64 {
        self.expected_private_dirty_bytes
    }

    /// Returns aggregate retained processes.
    #[must_use]
    pub const fn process_count(self) -> u32 {
        self.process_count
    }

    /// Returns aggregate retained virtual CPUs.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> u32 {
        self.virtual_cpu_count
    }

    /// Returns aggregate retained descriptors.
    #[must_use]
    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }

    /// Returns aggregate retained writable overlays.
    #[must_use]
    pub const fn overlay_count(self) -> u32 {
        self.overlay_count
    }

    fn add(self, profile: HotCheckpointResourceProfile) -> Option<Self> {
        Some(Self {
            templates: self.templates.checked_add(1)?,
            template_bytes: self.template_bytes.checked_add(profile.template_bytes)?,
            expected_private_dirty_bytes: self
                .expected_private_dirty_bytes
                .checked_add(profile.expected_private_dirty_bytes)?,
            process_count: self.process_count.checked_add(profile.process_count)?,
            virtual_cpu_count: self
                .virtual_cpu_count
                .checked_add(profile.virtual_cpu_count)?,
            descriptor_count: self
                .descriptor_count
                .checked_add(profile.descriptor_count)?,
            overlay_count: self.overlay_count.checked_add(profile.overlay_count)?,
        })
    }

    fn remove(self, profile: HotCheckpointResourceProfile) -> Option<Self> {
        Some(Self {
            templates: self.templates.checked_sub(1)?,
            template_bytes: self.template_bytes.checked_sub(profile.template_bytes)?,
            expected_private_dirty_bytes: self
                .expected_private_dirty_bytes
                .checked_sub(profile.expected_private_dirty_bytes)?,
            process_count: self.process_count.checked_sub(profile.process_count)?,
            virtual_cpu_count: self
                .virtual_cpu_count
                .checked_sub(profile.virtual_cpu_count)?,
            descriptor_count: self
                .descriptor_count
                .checked_sub(profile.descriptor_count)?,
            overlay_count: self.overlay_count.checked_sub(profile.overlay_count)?,
        })
    }

    fn fits(self, limits: HotCheckpointLimits) -> bool {
        let resources = limits.maximum_resources;
        self.templates <= limits.maximum_templates
            && self.template_bytes <= resources.template_bytes
            && self.expected_private_dirty_bytes <= resources.expected_private_dirty_bytes
            && self.process_count <= resources.process_count
            && self.virtual_cpu_count <= resources.virtual_cpu_count
            && self.descriptor_count <= resources.descriptor_count
            && self.overlay_count <= resources.overlay_count
    }
}

/// Resource dimensions exceeding the configured hot-retention limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointPressure {
    templates: bool,
    template_bytes: bool,
    expected_private_dirty_bytes: bool,
    process_count: bool,
    virtual_cpu_count: bool,
    descriptor_count: bool,
    overlay_count: bool,
}

impl HotCheckpointPressure {
    fn for_usage(usage: HotCheckpointUsage, limits: HotCheckpointLimits) -> Self {
        let resources = limits.maximum_resources;
        Self {
            templates: usage.templates > limits.maximum_templates,
            template_bytes: usage.template_bytes > resources.template_bytes,
            expected_private_dirty_bytes: usage.expected_private_dirty_bytes
                > resources.expected_private_dirty_bytes,
            process_count: usage.process_count > resources.process_count,
            virtual_cpu_count: usage.virtual_cpu_count > resources.virtual_cpu_count,
            descriptor_count: usage.descriptor_count > resources.descriptor_count,
            overlay_count: usage.overlay_count > resources.overlay_count,
        }
    }

    /// Returns whether retained-template count is over limit.
    #[must_use]
    pub const fn templates(self) -> bool {
        self.templates
    }

    /// Returns whether source-template bytes are over limit.
    #[must_use]
    pub const fn template_bytes(self) -> bool {
        self.template_bytes
    }

    /// Returns whether expected private dirty bytes are over limit.
    #[must_use]
    pub const fn expected_private_dirty_bytes(self) -> bool {
        self.expected_private_dirty_bytes
    }

    /// Returns whether process count is over limit.
    #[must_use]
    pub const fn process_count(self) -> bool {
        self.process_count
    }

    /// Returns whether virtual CPU count is over limit.
    #[must_use]
    pub const fn virtual_cpu_count(self) -> bool {
        self.virtual_cpu_count
    }

    /// Returns whether descriptor count is over limit.
    #[must_use]
    pub const fn descriptor_count(self) -> bool {
        self.descriptor_count
    }

    /// Returns whether writable-overlay count is over limit.
    #[must_use]
    pub const fn overlay_count(self) -> bool {
        self.overlay_count
    }

    /// Returns whether any resource dimension is over limit.
    #[must_use]
    pub const fn any(self) -> bool {
        self.templates
            || self.template_bytes
            || self.expected_private_dirty_bytes
            || self.process_count
            || self.virtual_cpu_count
            || self.descriptor_count
            || self.overlay_count
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
    slot: QemuHotForkTemplatePoolSlot,
    resources: HotCheckpointResourceProfile,
    signals: HotCheckpointHotnessSignals,
    fallback: HotCheckpointFallbackTier,
    reason: HotCheckpointRetentionReason,
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

    /// Returns the fallback tier used on demotion.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallbackTier {
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
    status: HotCheckpointStatus,
    reason: HotCheckpointDemotionReason,
}

impl HotCheckpointPlannedDemotion {
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

    /// Returns the durable realization tier that must remain available.
    #[must_use]
    pub const fn fallback(self) -> HotCheckpointFallbackTier {
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
    status: HotCheckpointStatus,
    reason: HotCheckpointDemotionReason,
}

/// Read-only generation-bound plan for orderly removal from the hot tier.
#[must_use = "retire the exact idle source and commit, or discard the read-only plan"]
#[derive(Debug)]
pub struct HotCheckpointOrderlyDemotionPlan {
    manager: Arc<()>,
    generation: u64,
    status: HotCheckpointStatus,
    reason: HotCheckpointDemotionReason,
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
    manager: Arc<()>,
    generation: u64,
    candidate: HotCheckpointCandidate,
    demotions: Vec<HotCheckpointPlannedDemotion>,
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
    retained: HotCheckpointStatus,
    demoted: Vec<HotCheckpointDemotion>,
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

/// Deterministic operational owner of all retained hot-checkpoint accounting.
pub struct HotCheckpointManager {
    identity: Arc<()>,
    limits: HotCheckpointLimits,
    generation: u64,
    usage: HotCheckpointUsage,
    retained: BTreeMap<QemuHotForkTemplatePoolSlot, HotCheckpointStatus>,
    last_fork_tick: Option<u64>,
    fork_window: Option<u64>,
    forks_in_window: u32,
}

impl HotCheckpointManager {
    /// Creates an empty manager with fixed process-wide limits.
    #[must_use]
    pub fn new(limits: HotCheckpointLimits) -> Self {
        Self {
            identity: Arc::new(()),
            limits,
            generation: 0,
            usage: HotCheckpointUsage::default(),
            retained: BTreeMap::new(),
            last_fork_tick: None,
            fork_window: None,
            forks_in_window: 0,
        }
    }

    /// Returns the fixed process-wide limits.
    #[must_use]
    pub const fn limits(&self) -> HotCheckpointLimits {
        self.limits
    }

    /// Returns current aggregate retained-resource usage.
    #[must_use]
    pub const fn usage(&self) -> HotCheckpointUsage {
        self.usage
    }

    /// Returns the current inventory generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the retained status at an exact stable pool coordinate.
    #[must_use]
    pub fn status(&self, slot: QemuHotForkTemplatePoolSlot) -> Option<HotCheckpointStatus> {
        self.retained.get(&slot).copied()
    }

    /// Iterates retained sources in exact deterministic coordinate order.
    pub fn retained(&self) -> impl ExactSizeIterator<Item = HotCheckpointStatus> + '_ {
        self.retained.values().copied()
    }

    /// Builds a read-only admission and demotion plan.
    ///
    /// Existing unpinned sources are considered in ascending `(score, exact
    /// pool coordinate)` order. An unpinned candidate displaces only strictly
    /// colder sources; existing sources win ties. A hard-pinned candidate may
    /// displace any unpinned source but can never exceed an individual limit.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointAdmissionRejection`] when the candidate alone
    /// exceeds a limit, aggregate accounting overflows, or no eligible set of
    /// colder sources can create enough capacity. Planning never mutates state.
    pub fn plan_admission(
        &self,
        candidate: HotCheckpointCandidate,
    ) -> Result<HotCheckpointAdmissionPlan, HotCheckpointAdmissionRejection> {
        let individual = HotCheckpointUsage::default()
            .add(candidate.resources)
            .ok_or(HotCheckpointAdmissionRejection::AccountingOverflow)?;
        if !individual.fits(self.limits) {
            return Err(HotCheckpointAdmissionRejection::IndividualLimit {
                pressure: HotCheckpointPressure::for_usage(individual, self.limits),
            });
        }

        let mut projected = self.usage;
        let mut demotions = Vec::new();
        let mut candidates = self
            .retained
            .values()
            .copied()
            .filter(|status| !status.signals.pinned())
            .filter(|status| {
                candidate.signals.pinned() || status.score() < candidate.signals.score()
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|status| (status.score(), status.slot));

        if projected
            .add(candidate.resources)
            .is_some_and(|usage| usage.fits(self.limits))
        {
            return Ok(HotCheckpointAdmissionPlan {
                manager: Arc::clone(&self.identity),
                generation: self.generation,
                candidate,
                demotions,
            });
        }

        for status in candidates {
            projected = projected
                .remove(status.resources)
                .ok_or(HotCheckpointAdmissionRejection::AccountingOverflow)?;
            demotions.push(HotCheckpointPlannedDemotion {
                status,
                reason: HotCheckpointDemotionReason::CapacityPressure,
            });
            if projected
                .add(candidate.resources)
                .is_some_and(|usage| usage.fits(self.limits))
            {
                return Ok(HotCheckpointAdmissionPlan {
                    manager: Arc::clone(&self.identity),
                    generation: self.generation,
                    candidate,
                    demotions,
                });
            }
        }

        let combined = saturating_combined_usage(projected, candidate.resources);
        Err(
            HotCheckpointAdmissionRejection::InsufficientDemotableCapacity {
                pressure: HotCheckpointPressure::for_usage(combined, self.limits),
                pinned_sources: self
                    .retained
                    .values()
                    .filter(|status| status.signals.pinned())
                    .count(),
            },
        )
    }

    /// Commits a plan after its exact victims have been retired and protected.
    ///
    /// `installed_slot` must be the stable coordinate returned by installing
    /// the candidate in the source pool. A coordinate formerly occupied by a
    /// planned victim may be reused.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointAdmissionCommitError`] without mutation for a
    /// foreign/stale plan, wrong-key or occupied coordinate, missing planned
    /// victim, accounting overflow, or violated post-plan resource bound.
    pub fn commit_admission(
        &mut self,
        plan: HotCheckpointAdmissionPlan,
        installed_slot: QemuHotForkTemplatePoolSlot,
    ) -> Result<HotCheckpointAdmissionCommit, HotCheckpointAdmissionCommitError> {
        if !Arc::ptr_eq(&self.identity, &plan.manager) {
            return Err(HotCheckpointAdmissionCommitError::ForeignPlan);
        }
        if plan.generation != self.generation {
            return Err(HotCheckpointAdmissionCommitError::StalePlan {
                planned: plan.generation,
                current: self.generation,
            });
        }
        if installed_slot.template_key() != plan.candidate.key {
            return Err(HotCheckpointAdmissionCommitError::WrongInstalledKey);
        }
        let replaces_installed_slot = plan
            .demotions
            .iter()
            .any(|demotion| demotion.slot() == installed_slot);
        if self.retained.contains_key(&installed_slot) && !replaces_installed_slot {
            return Err(HotCheckpointAdmissionCommitError::OccupiedSlot);
        }
        for demotion in &plan.demotions {
            if self.retained.get(&demotion.slot()).copied() != Some(demotion.status) {
                return Err(HotCheckpointAdmissionCommitError::MissingPlannedVictim);
            }
        }

        let mut next_usage = self.usage;
        for demotion in &plan.demotions {
            next_usage = next_usage
                .remove(demotion.status.resources)
                .ok_or(HotCheckpointAdmissionCommitError::AccountingOverflow)?;
        }
        next_usage = next_usage
            .add(plan.candidate.resources)
            .ok_or(HotCheckpointAdmissionCommitError::AccountingOverflow)?;
        if !next_usage.fits(self.limits) {
            return Err(HotCheckpointAdmissionCommitError::LimitViolation);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(HotCheckpointAdmissionCommitError::GenerationExhausted)?;

        let mut demoted = Vec::with_capacity(plan.demotions.len());
        for demotion in plan.demotions {
            self.retained.remove(&demotion.slot());
            demoted.push(HotCheckpointDemotion {
                status: demotion.status,
                reason: demotion.reason,
            });
        }
        let retained = HotCheckpointStatus {
            slot: installed_slot,
            resources: plan.candidate.resources,
            signals: plan.candidate.signals,
            fallback: plan.candidate.fallback,
            reason: if demoted.is_empty() {
                HotCheckpointRetentionReason::WithinBudget
            } else {
                HotCheckpointRetentionReason::ReplacedColderSources
            },
        };
        self.retained.insert(installed_slot, retained);
        self.usage = next_usage;
        self.generation = next_generation;

        Ok(HotCheckpointAdmissionCommit { retained, demoted })
    }

    /// Replaces one retained source's operational score and pin state.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError`] when the coordinate is absent or
    /// the inventory generation can no longer advance.
    pub fn update_signals(
        &mut self,
        slot: QemuHotForkTemplatePoolSlot,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointStatus, HotCheckpointInventoryError> {
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(HotCheckpointInventoryError::GenerationExhausted)?;
        let status = self
            .retained
            .get_mut(&slot)
            .ok_or(HotCheckpointInventoryError::MissingSlot)?;
        status.signals = signals;
        status.reason = HotCheckpointRetentionReason::SignalsUpdated;
        self.generation = next_generation;
        Ok(*status)
    }

    /// Plans an independently secured orderly demotion without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError::MissingSlot`] when the exact
    /// coordinate is not currently retained.
    pub fn plan_orderly_demotion(
        &self,
        slot: QemuHotForkTemplatePoolSlot,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointOrderlyDemotionPlan, HotCheckpointInventoryError> {
        let status = self
            .retained
            .get(&slot)
            .copied()
            .ok_or(HotCheckpointInventoryError::MissingSlot)?;
        Ok(HotCheckpointOrderlyDemotionPlan {
            manager: Arc::clone(&self.identity),
            generation: self.generation,
            status,
            reason,
        })
    }

    /// Commits one plan after the exact idle source authority was retired.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError`] without mutation when the plan
    /// is foreign or stale, the exact source changed, accounting is
    /// inconsistent, or the inventory generation cannot advance.
    pub fn commit_orderly_demotion(
        &mut self,
        plan: HotCheckpointOrderlyDemotionPlan,
    ) -> Result<HotCheckpointDemotion, HotCheckpointInventoryError> {
        if !Arc::ptr_eq(&self.identity, &plan.manager) {
            return Err(HotCheckpointInventoryError::ForeignPlan);
        }
        if plan.generation != self.generation {
            return Err(HotCheckpointInventoryError::StalePlan {
                planned: plan.generation,
                current: self.generation,
            });
        }
        if self.retained.get(&plan.status.slot).copied() != Some(plan.status) {
            return Err(HotCheckpointInventoryError::MissingSlot);
        }
        let next_usage = self
            .usage
            .remove(plan.status.resources)
            .ok_or(HotCheckpointInventoryError::AccountingInconsistent)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(HotCheckpointInventoryError::GenerationExhausted)?;
        self.retained.remove(&plan.status.slot);
        self.usage = next_usage;
        self.generation = next_generation;
        Ok(HotCheckpointDemotion {
            status: plan.status,
            reason: plan.reason,
        })
    }

    /// Admits one actual child-fork start in a monotonic operational window.
    ///
    /// The caller supplies a monotonically increasing reading from the
    /// configured host clock. The manager derives the fixed-width window;
    /// neither the reading nor window becomes campaign evidence. Every
    /// attempted process fork consumes one permit, including attempts that
    /// later fail.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointForkRateError`] for a stale window or after the
    /// configured number of starts has already been admitted in this window.
    pub fn admit_fork(
        &mut self,
        monotonic_tick: u64,
    ) -> Result<HotCheckpointForkPermit, HotCheckpointForkRateError> {
        if let Some(current) = self.last_fork_tick
            && monotonic_tick < current
        {
            return Err(HotCheckpointForkRateError::StaleClock {
                requested: monotonic_tick,
                current,
            });
        }
        self.last_fork_tick = Some(monotonic_tick);
        let window = monotonic_tick / self.limits.fork_rate_window_ticks;
        match self.fork_window {
            Some(current) if window == current => {}
            _ => {
                self.fork_window = Some(window);
                self.forks_in_window = 0;
            }
        }
        if self.forks_in_window >= self.limits.maximum_forks_per_window {
            return Err(HotCheckpointForkRateError::RateLimited {
                window,
                maximum: self.limits.maximum_forks_per_window,
            });
        }
        self.forks_in_window += 1;
        Ok(HotCheckpointForkPermit {
            manager: Arc::clone(&self.identity),
            window,
            ordinal: self.forks_in_window,
        })
    }
}

fn saturating_combined_usage(
    usage: HotCheckpointUsage,
    profile: HotCheckpointResourceProfile,
) -> HotCheckpointUsage {
    HotCheckpointUsage {
        templates: usage.templates.saturating_add(1),
        template_bytes: usage.template_bytes.saturating_add(profile.template_bytes),
        expected_private_dirty_bytes: usage
            .expected_private_dirty_bytes
            .saturating_add(profile.expected_private_dirty_bytes),
        process_count: usage.process_count.saturating_add(profile.process_count),
        virtual_cpu_count: usage
            .virtual_cpu_count
            .saturating_add(profile.virtual_cpu_count),
        descriptor_count: usage
            .descriptor_count
            .saturating_add(profile.descriptor_count),
        overlay_count: usage.overlay_count.saturating_add(profile.overlay_count),
    }
}

/// Admission refusal that leaves the manager unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotCheckpointAdmissionRejection {
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
    manager: Arc<()>,
    window: u64,
    ordinal: u32,
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
    #[error("hot-checkpoint fork-rate clock tick {requested} is stale at {current}")]
    StaleClock {
        /// Rejected monotonic clock tick.
        requested: u64,
        /// Latest manager clock tick.
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

#[cfg(test)]
mod tests;
