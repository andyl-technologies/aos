//! Keeps SSH birth denial reachable while its main spawn/receipt owner is lent.
//!
//! The existing Guest timeout actor owns this fixed native destination. No
//! Child, live-map guard or bootstrap socket lock is needed to seal and kill
//! the exact prepared subtree. Direct-child reap remains on the birth owner.

use super::*;
use crate::cgroup::CgroupKillRefusalV1;

#[derive(Clone, Copy)]
enum First {
    Before,
    Seal,
    Kill,
    Population,
    After,
}

/// Retains the exact prepared SSH subtree's standing negative containment.
///
/// Only a fully prepared `GuestSshScopeOriginalV1` can create this owner. It
/// shares that same anchor without duplicating a descriptor, and receives its
/// already-open population monitor by move. It grants no process authority.
pub struct GuestSshStandingOriginalV1 {
    anchor: std::sync::Arc<RetainedCgroupAnchor>,
    population: CgroupPopulationMonitor,
    execution: [u8; 16],
    startup_cutoff: u64,
    execution_cutoff: u64,
    wall_expiry: i64,
    startup_completed: bool,
    before: Option<Box<CgroupActiveOriginalV2>>,
    seal: Option<Box<ControlWriteOriginalV1>>,
    seal_result: Option<Result<()>>,
    kill: Option<Box<CgroupKillAttemptV1>>,
    kill_result: Option<std::result::Result<(), CgroupKillRefusalV1>>,
    observed: Option<Box<CgroupPopulationObservationV1>>,
    population_result: Option<Result<CgroupPopulationState>>,
    after: Option<Box<CgroupActiveOriginalV2>>,
    body: Option<Result<()>>,
    first: Option<First>,
    completed: bool,
}

impl GuestSshStandingOriginalV1 {
    pub(super) fn new(
        anchor: std::sync::Arc<RetainedCgroupAnchor>,
        population: CgroupPopulationMonitor,
        execution: [u8; 16],
        startup_cutoff: u64,
        execution_cutoff: u64,
        wall_expiry: i64,
    ) -> Self {
        Self {
            anchor,
            population,
            execution,
            startup_cutoff,
            execution_cutoff,
            wall_expiry,
            startup_completed: false,
            before: None,
            seal: None,
            seal_result: None,
            kill: None,
            kill_result: None,
            observed: None,
            population_result: None,
            after: None,
            body: None,
            first: None,
            completed: false,
        }
    }

    pub(super) fn belongs_to(
        &self,
        anchor: &std::sync::Arc<RetainedCgroupAnchor>,
        execution: [u8; 16],
    ) -> bool {
        std::sync::Arc::ptr_eq(&self.anchor, anchor) && self.execution == execution
    }

    /// Selects only the already-retained execution cutoff after real startup.
    ///
    /// The native bootstrap must belong to this exact scope and have completed
    /// its actual listener/ACK/EOF/liveness/independent-after conjunction. No
    /// caller supplies a replacement deadline or a fresh duration here.
    ///
    /// # Errors
    /// Refuses an incomplete/foreign bootstrap, prior containment or reentry.
    pub fn complete_startup_once_v1(
        &mut self,
        bootstrap: &crate::seqpacket::descriptor_subject::GuestSshBootstrapOriginalV1,
    ) -> Result<()> {
        if self.startup_completed || self.before.is_some() || self.failure().is_some() {
            return Err(closed());
        }
        bootstrap.require_completed_scope_v1(&self.anchor, self.execution)?;
        self.startup_completed = true;
        Ok(())
    }

    /// Reports the fixed current denial cutoff, never a new native authority.
    #[must_use]
    pub fn current_boottime_cutoff_data_v1(&self) -> u64 {
        if self.startup_completed {
            self.execution_cutoff
        } else {
            self.startup_cutoff
        }
    }

    /// Reports the original admitted absolute WALL endpoint as comparison DATA.
    #[must_use]
    pub fn wall_expiry_data_v1(&self) -> i64 {
        self.wall_expiry
    }

    /// Seals future births, kills the same subtree and observes its population.
    ///
    /// `pids.max=0` precedes `cgroup.kill`. On the selected kernel, the latter
    /// serializes with `CLONE_INTO_CGROUP` through `cgroup_mutex`: an earlier
    /// admitted birth enters the kill pass; a later one fails its pids charge.
    /// The limit write alone deliberately establishes no such conclusion.
    ///
    /// The original timeout or failed startup caller selects this negative
    /// operation. An expired positive clock never suppresses containment.
    /// Pending observations reuse the same fixed destinations after complete
    /// positive posts. Any failed prefix remains sticky and fully retained.
    ///
    /// # Errors
    /// Retains a failed identity, seal, kill, population or independent post.
    /// An empty result proves no direct-child reap or higher-level completion.
    pub fn poll_containment_once_v1(&mut self) -> Result<bool> {
        if self.completed {
            return Ok(true);
        }
        if self.body.as_ref().is_some_and(Result::is_err) {
            return Err(closed());
        }

        if self.before.is_none() {
            self.before = Some(Box::new(CgroupActiveOriginalV2::new()));
            self.body = Some(
                self.before
                    .as_mut()
                    .ok_or_else(closed)?
                    .capture_once_v2(&self.anchor)
                    .map_err(|_| closed()),
            );
            if !matches!(self.body, Some(Ok(()))) {
                self.first = Some(First::Before);
            } else {
                self.seal = Some(Box::new(ControlWriteOriginalV1::new()));
                self.seal_result = Some(
                    self.seal
                        .as_mut()
                        .ok_or_else(closed)?
                        .seal_ssh_birth_once(&self.anchor),
                );
                if !matches!(self.seal_result, Some(Ok(()))) {
                    self.first = Some(First::Seal);
                    self.body = Some(Err(closed()));
                }

                // A failed seal cannot suppress the independent negative kill
                // of this retained scope. It still cannot become completion.
                self.kill = Some(Box::new(CgroupKillAttemptV1::new()));
                self.kill_result = Some(
                    self.kill
                        .as_mut()
                        .ok_or_else(closed)?
                        .capture_once_bounded_v2(&self.anchor),
                );
                if !matches!(self.kill_result, Some(Ok(()))) {
                    self.first.get_or_insert(First::Kill);
                    self.body = Some(Err(closed()));
                }
            }
        }

        self.observed = Some(Box::new(CgroupPopulationObservationV1::new()));
        let observed = self.observed.as_mut().ok_or_else(closed)?;
        let population = self.population.observe_state_retaining_v1(observed);
        self.population_result = Some(
            population
                .map_err(|_| closed())
                .and_then(|_| observed.state().ok_or_else(closed)),
        );
        if self.population_result.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Population);
            self.body = Some(Err(closed()));
        }

        self.after = Some(Box::new(CgroupActiveOriginalV2::new()));
        let after = self
            .after
            .as_mut()
            .ok_or_else(closed)?
            .capture_once_v2(&self.anchor);
        if after.is_err() {
            self.first.get_or_insert(First::After);
            self.body = Some(Err(closed()));
        }
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }

        self.completed = matches!(
            self.population_result,
            Some(Ok(CgroupPopulationState::Empty))
        );
        // No live descriptor is released until this primitive's full post.
        // The original anchor and population monitor stay on this owner.
        drop(self.observed.take());
        drop(self.after.take());
        Ok(self.completed)
    }

    /// Reports only this owner's completed seal, kill and recursive empty.
    #[must_use]
    pub fn completed_v1(&self) -> bool {
        self.completed
    }

    /// Borrows the earliest actual standing native failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before => self.before.as_ref()?.failure().map(|cause| cause as _),
            First::Seal => self.seal.as_ref()?.failure(),
            First::Kill => self.kill.as_ref()?.failure().map(|cause| cause as _),
            First::Population => self.observed.as_ref()?.failure(),
            First::After => self.after.as_ref()?.failure().map(|cause| cause as _),
        }
        .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Prices the complete reachable negative prefix before the original birth.
    ///
    /// The same source invoice and all-open collector use this finite supplier
    /// for standing growth. It grants no kill, subtree or financial authority.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let control = ControlWriteOriginalV1::receiving_obligations_v1()?;
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(control.0)?
            .checked_add(active.0.checked_mul(2)?)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?;
        // Anchor + held events, independent outer before/after, and every
        // reached seal/kill descriptor coexist on their failure paths.
        let files = 2_usize
            .checked_add(active.1.checked_mul(2)?)?
            .checked_add(control.1)?
            .checked_add(CgroupKillAttemptV1::maximum_retained_files_v1())?;
        Some((bytes, files, control.2.checked_add(2)?))
    }
}
