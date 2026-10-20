//! Aggregates opt-in immutable cohort observations without sampling authority time.
//!
//! Primitive groups include their original validation and syscall work; those
//! internal check and actual primitive components are reported separately. Groups
//! must not be added to outer cohort or caller intervals.
//! Counters describe retained inventory and attempted work, never authority.

use std::{cell::RefCell, collections::BTreeMap, path::Path, time::Duration};

/// Owns one operation-local diagnostic summary, including refusal exits.
pub(super) struct CohortTimings {
    enabled: bool,
    checks: crate::store::native_effect::check_timings::Scope,
    trace: crate::ref_advance::NativeTrace,
    groups: RefCell<BTreeMap<&'static str, (Duration, usize)>>,
    counts: RefCell<BTreeMap<&'static str, usize>>,
}

impl CohortTimings {
    /// Anchors observations to the actual first installation parent or target.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(super) fn new(path: &Path) -> Self {
        let enabled = std::env::var_os("TERRANE_REF_PHASE_TRACE").is_some();
        Self {
            enabled,
            checks: crate::store::native_effect::check_timings::Scope::new(enabled),
            trace: crate::ref_advance::NativeTrace::new(path, "native-immutable-cohort-aggregate"),
            groups: RefCell::new(BTreeMap::new()),
            counts: RefCell::new(BTreeMap::new()),
        }
    }

    /// Starts an inclusive group without consulting the injected clock.
    pub(super) fn span(&self, group: &'static str) -> Span<'_> {
        Span {
            timings: self,
            group,
            started: self.enabled.then(crate::diagnostic_clock::tick),
            #[cfg(feature = "tokio")]
            diagnostic: crate::diagnostic_clock::native_group(
                crate::diagnostic_clock::NativeKind::Cohort,
                group,
            )
            .map(crate::diagnostic_clock::span),
        }
    }

    /// Counts attempted work without recording paths or body contents.
    pub(super) fn count(&self, group: &'static str, amount: usize) {
        #[cfg(feature = "tokio")]
        if let Some(group) = crate::diagnostic_clock::native_group(
            crate::diagnostic_clock::NativeKind::Cohort,
            group,
        ) {
            crate::diagnostic_clock::count(group, amount);
        }
        if self.enabled {
            *self.counts.borrow_mut().entry(group).or_default() += amount;
        }
    }
}

impl Drop for CohortTimings {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let groups: Vec<_> = self
            .groups
            .borrow()
            .iter()
            .map(|(name, (time, calls))| format!("{name}:time={time:?},calls={calls}"))
            .collect();
        let counts: Vec<_> = self
            .counts
            .borrow()
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        self.trace.mark(&format!(
            "aggregate groups=[{}] counts=[{}] {}",
            groups.join(";"),
            counts.join(";"),
            self.checks.summary()
        ));
    }
}

/// Measures one inclusive group, even when its original operation refuses.
pub(super) struct Span<'a> {
    timings: &'a CohortTimings,
    group: &'static str,
    started: Option<crate::diagnostic_clock::Tick>,
    #[cfg(feature = "tokio")]
    diagnostic: Option<crate::diagnostic_clock::Span>,
}

impl Drop for Span<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "tokio")]
        drop(self.diagnostic.take());
        if let Some(started) = self.started {
            let mut groups = self.timings.groups.borrow_mut();
            let (duration, calls) = groups.entry(self.group).or_default();
            *duration += crate::diagnostic_clock::elapsed(started);
            *calls += 1;
        }
    }
}
