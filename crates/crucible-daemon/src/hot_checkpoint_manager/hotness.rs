//! Bounded explainable reuse signals and signed operational hotness scores.

use super::*;

/// Normalized operational inputs to retained-template hotness.
///
/// Every numeric component is expressed in deployment-defined score units.
/// Positive reuse signals are added and pressure/already-paid costs are
/// subtracted. The hard pin bit separately prevents automatic demotion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotCheckpointHotnessSignals {
    pub(super) pending_attempts: u64,
    pub(super) expected_future_widening: u64,
    pub(super) descendant_continuations: u64,
    pub(super) interactive_or_finding_value: u64,
    pub(super) dirty_memory_pressure: u64,
    pub(super) descriptor_pressure: u64,
    pub(super) restore_or_replay_cost_paid_elsewhere: u64,
    pub(super) pinned: bool,
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
    pub(super) component: HotCheckpointHotnessComponent,
    pub(super) value: u64,
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
pub struct HotCheckpointScore(pub(super) i128);

impl HotCheckpointScore {
    /// Returns the signed normalized score units.
    #[must_use]
    pub const fn value(self) -> i128 {
        self.0
    }
}
