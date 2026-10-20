//! Retains one worker descendant, its active probes and population acquisition.
//!
//! The relative pathname is a bounded locator under a genuinely held anchor.
//! This passive native owner grants no service, worker, payer or effect entry.
//! It reuses the same descendant/active/open recipes as ordinary acquisition.

use super::*;

/// Reports a refused worker-cgroup acquisition whose exact cause stays owned.
#[derive(Debug, thiserror::Error)]
#[error("retained worker cgroup acquisition is incomplete or refused")]
pub struct WorkerCgroupOpeningRefusalV1;

#[derive(Clone, Copy, Debug)]
enum Failure {
    Descendant,
    ParentPost,
    Population,
    Reentry,
}

/// Retains all partial directory, active-file and population-file acquisitions.
#[derive(Debug, Default)]
pub struct WorkerCgroupOpeningV1 {
    child: InitialCgroupChildV5,
    descendant: Option<Result<()>>,
    parent_probe: PendingRegularFileV1,
    parent_post: Option<Result<()>>,
    population_probe: PendingRegularFileV1,
    events_open: PendingRegularFileV1,
    population_result: Option<Result<()>>,
    population: Option<CgroupPopulationMonitor>,
    first: Option<Failure>,
}

impl WorkerCgroupOpeningV1 {
    /// Bounds all simultaneous anchor, active-probe and population-file slots.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = 7;

    /// Returns actual inline storage, bounded locator copies and native errors.
    #[must_use]
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(2 * 4097)?.checked_add(8 * 256)
    }

    /// Creates inert destinations without opening or observing any native file.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves the bounded hint through the original shared descendant engine.
    ///
    /// # Errors
    /// Refuses reentry or the exact original path, directory or active-probe
    /// error. Every reached acquisition remains in this owner.
    pub fn capture_descendant_once(
        &mut self,
        parent: &RetainedCgroupAnchor,
        relative: &Path,
    ) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        if self.first.is_some() || self.descendant.is_some() {
            self.first.get_or_insert(Failure::Reentry);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        self.descendant = Some(parent.resolve_worker_descendant_retaining(relative, &mut self.child));
        if !matches!(self.descendant, Some(Ok(()))) {
            self.first = Some(Failure::Descendant);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        Ok(())
    }

    /// Captures the same descendant under an already validated cgroup root.
    ///
    /// # Errors
    /// Retains the same native originals and failures as
    /// [`Self::capture_descendant_once`]. A root/locator grants no service role.
    pub fn capture_root_descendant_once(
        &mut self,
        root: &CgroupV2Root,
        relative: &Path,
    ) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        self.capture_descendant_once(&root.anchor, relative)
    }

    /// Observes the same root after an actually entered descendant attempt.
    ///
    /// This owed native observation runs after a primary refusal too; it never
    /// clears that refusal or permits extraction of a failed child.
    ///
    /// # Errors
    /// Refuses no prior attempt, repeated post or the actual retained native
    /// active-reference failure. Earlier primary errors remain first.
    pub fn observe_root_parent_after_attempt_once(
        &mut self,
        root: &CgroupV2Root,
    ) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        self.observe_owed_parent_once_v1(&root.anchor)
    }

    /// Borrows the actual returned anchor after complete descendant validation.
    #[must_use]
    pub fn anchor(&self) -> Option<&RetainedCgroupAnchor> {
        matches!(self.descendant, Some(Ok(()))).then_some(())?;
        self.child.anchor.as_ref()
    }

    /// Transfers the fully validated anchor while all acquisition probes stay held.
    ///
    /// This moves actual kernel DATA once. It grants no payer or effect entry.
    #[must_use]
    pub fn take_anchor_once(&mut self) -> Option<RetainedCgroupAnchor> {
        if self.first.is_some() || !matches!(self.descendant, Some(Ok(()))) {
            return None;
        }
        self.child.anchor.take()
    }

    /// Preserves the existing final parent-active observation after membership.
    ///
    /// # Errors
    /// Retains the exact parent/probe failure and refuses repeated entry.
    pub fn observe_parent_once(
        &mut self,
        parent: &RetainedCgroupAnchor,
    ) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        if self.first.is_some() || self.parent_post.is_some()
            || !matches!(self.descendant, Some(Ok(())))
        {
            self.first.get_or_insert(Failure::Reentry);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        self.parent_post = Some(parent.validate_active_retaining(&mut self.parent_probe));
        if !matches!(self.parent_post, Some(Ok(()))) {
            self.first = Some(Failure::ParentPost);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        Ok(())
    }

    /// Observes the held parent after an entered descendant or membership prefix.
    ///
    /// Unlike the ordinary positive-stage accessor, this fixed owed bookend
    /// still runs after a failed descendant capture. Earlier causes remain
    /// first, and the same reserved native probe/result slot cannot be reused.
    ///
    /// # Errors
    /// Retains the actual parent-active refusal or rejects repeated entry.
    pub fn observe_owed_parent_once_v1(
        &mut self,
        parent: &RetainedCgroupAnchor,
    ) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        if self.parent_post.is_some() || self.descendant.is_none() {
            self.first.get_or_insert(Failure::Reentry);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        self.parent_post = Some(parent.validate_active_retaining(&mut self.parent_probe));
        if matches!(self.parent_post, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(Failure::ParentPost);
            Err(WorkerCgroupOpeningRefusalV1)
        }
    }

    /// Captures the original population file only after the parent bookend.
    ///
    /// # Errors
    /// Retains active-file and events-file partials and their returned native
    /// failure; no failed or repeated capture yields a monitor.
    pub fn capture_population_once(&mut self) -> std::result::Result<(), WorkerCgroupOpeningRefusalV1> {
        if self.first.is_some() || self.population_result.is_some()
            || !matches!(self.parent_post, Some(Ok(())))
        {
            self.first.get_or_insert(Failure::Reentry);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        self.population_result = Some((|| {
            let Some(anchor) = self.child.anchor.as_ref() else { std::process::abort() };
            self.population = Some(anchor.population_monitor_retaining(
                &mut self.population_probe, &mut self.events_open,
            )?);
            Ok(())
        })());
        if !matches!(self.population_result, Some(Ok(()))) {
            self.first = Some(Failure::Population);
            return Err(WorkerCgroupOpeningRefusalV1);
        }
        Ok(())
    }

    /// Borrows the same monitor acquired from the held worker directory.
    #[must_use]
    pub fn population(&self) -> Option<&CgroupPopulationMonitor> {
        matches!(self.population_result, Some(Ok(()))).then_some(())?;
        self.population.as_ref()
    }

    /// Borrows the independently owed parent-post cause even after ENOENT.
    ///
    /// This performs no observation and cannot change the primary disposition.
    #[must_use]
    pub fn owed_parent_failure_v5(&self) -> Option<&Error> {
        self.parent_post.as_ref()?.as_ref().err()
    }

    /// Borrows the actual first cause without resampling or formatting it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let result = match self.first? {
            Failure::Descendant => self.descendant.as_ref(),
            Failure::ParentPost => self.parent_post.as_ref(),
            Failure::Population => self.population_result.as_ref(),
            Failure::Reentry => return Some(&WorkerCgroupOpeningRefusalV1),
        };
        result.and_then(|result| result.as_ref().err()).map(|error| error as _)
    }
}
