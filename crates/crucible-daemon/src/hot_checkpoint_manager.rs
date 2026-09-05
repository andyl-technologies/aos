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

use crucible_campaign::{ConfigurationArtifactId, ExactCheckpointId};

use crate::{
    MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS, QemuHotForkTemplateKey, QemuHotForkTemplatePoolSlot,
};

/// Maximum normalized contribution accepted for one hotness component.
pub const MAX_HOT_CHECKPOINT_SCORE_COMPONENT: u64 = 1_000_000_000_000;

mod resources;
pub use resources::{
    HotCheckpointLimits, HotCheckpointLimitsError, HotCheckpointPressure,
    HotCheckpointResourceProfile, HotCheckpointResourceProfileError, HotCheckpointUsage,
};
mod hotness;
pub use hotness::{
    HotCheckpointHotnessComponent, HotCheckpointHotnessError, HotCheckpointHotnessSignals,
    HotCheckpointScore,
};
mod plans;
pub use plans::{
    HotCheckpointAdmissionCommit, HotCheckpointAdmissionCommitError, HotCheckpointAdmissionPlan,
    HotCheckpointAdmissionRejection, HotCheckpointCandidate, HotCheckpointDemotion,
    HotCheckpointDemotionReason, HotCheckpointFallback, HotCheckpointFallbackTier,
    HotCheckpointForkPermit, HotCheckpointForkRateError, HotCheckpointInventoryError,
    HotCheckpointOrderlyDemotionPlan, HotCheckpointPlannedDemotion, HotCheckpointRetentionReason,
    HotCheckpointStatus,
};

/// Deterministic operational owner of all retained hot-checkpoint accounting.
pub struct HotCheckpointManager {
    identity: Arc<()>,
    limits: HotCheckpointLimits,
    generation: u64,
    usage: HotCheckpointUsage,
    retained: BTreeMap<QemuHotForkTemplatePoolSlot, HotCheckpointStatus>,
    last_fork_nanos: Option<u64>,
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
            last_fork_nanos: None,
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
    /// Returns [`HotCheckpointAdmissionRejection`] when no unambiguous commit
    /// generation remains, the candidate alone exceeds a limit, aggregate
    /// accounting overflows, or no eligible set of colder sources can create
    /// enough capacity. Planning never mutates state.
    pub fn plan_admission(
        &self,
        candidate: HotCheckpointCandidate,
    ) -> Result<HotCheckpointAdmissionPlan, HotCheckpointAdmissionRejection> {
        self.generation
            .checked_add(1)
            .ok_or(HotCheckpointAdmissionRejection::GenerationExhausted)?;
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
    /// coordinate is not currently retained, or
    /// [`HotCheckpointInventoryError::GenerationExhausted`] before external
    /// work when no unambiguous commit generation remains.
    pub fn plan_orderly_demotion(
        &self,
        slot: QemuHotForkTemplatePoolSlot,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointOrderlyDemotionPlan, HotCheckpointInventoryError> {
        self.generation
            .checked_add(1)
            .ok_or(HotCheckpointInventoryError::GenerationExhausted)?;
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

    // Reconciles a physically completed prefix with one atomic generation
    // advance, so partial admission failure cannot expose half-accounting.
    pub(crate) fn commit_completed_demotions(
        &mut self,
        completed: &[HotCheckpointPlannedDemotion],
    ) -> Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError> {
        if completed.is_empty() {
            return Ok(Vec::new());
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(HotCheckpointInventoryError::GenerationExhausted)?;
        let mut next_usage = self.usage;
        for demotion in completed {
            if self.retained.get(&demotion.slot()).copied() != Some(demotion.status()) {
                return Err(HotCheckpointInventoryError::MissingSlot);
            }
            next_usage = next_usage
                .remove(demotion.status().resources())
                .ok_or(HotCheckpointInventoryError::AccountingInconsistent)?;
        }

        let mut committed = Vec::with_capacity(completed.len());
        for demotion in completed {
            self.retained.remove(&demotion.slot());
            committed.push(HotCheckpointDemotion {
                status: demotion.status(),
                reason: demotion.reason(),
            });
        }
        self.usage = next_usage;
        self.generation = next_generation;
        Ok(committed)
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
        monotonic_nanos: u64,
    ) -> Result<HotCheckpointForkPermit, HotCheckpointForkRateError> {
        if let Some(current) = self.last_fork_nanos
            && monotonic_nanos < current
        {
            return Err(HotCheckpointForkRateError::StaleClock {
                requested: monotonic_nanos,
                current,
            });
        }
        self.last_fork_nanos = Some(monotonic_nanos);
        let window = monotonic_nanos / self.limits.fork_rate_window_nanos;
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

#[cfg(test)]
mod tests;
