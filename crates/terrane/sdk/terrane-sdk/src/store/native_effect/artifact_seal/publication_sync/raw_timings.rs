//! Aggregates opt-in Raw durability observations without sampling authority time.
//!
//! Nested groups, including the separately reported native check components, are
//! inclusive and must not be added to their parent intervals.
//! Counters describe attempted validation work, never successful authority.

use std::{cell::RefCell, collections::BTreeMap, path::Path, time::Duration};

/// Owns one operation-local diagnostic summary, including refusal exits.
pub(super) struct RawTimings {
    enabled: bool,
    checks: crate::store::native_effect::check_timings::Scope,
    trace: crate::ref_advance::NativeTrace,
    groups: RefCell<BTreeMap<&'static str, (Duration, usize)>>,
    counts: RefCell<BTreeMap<&'static str, usize>>,
}

impl RawTimings {
    /// Anchors opt-in observations to an actual retained namespace root.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(super) fn new(root: &Path) -> Self {
        let enabled = std::env::var_os("TERRANE_REF_PHASE_TRACE").is_some();
        Self {
            enabled,
            checks: crate::store::native_effect::check_timings::Scope::new(enabled),
            trace: crate::ref_advance::NativeTrace::new(root, "raw-durability-aggregate"),
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
                crate::diagnostic_clock::NativeKind::Raw,
                group,
            )
            .map(crate::diagnostic_clock::span),
        }
    }

    /// Counts attempted work without recording paths or body contents.
    pub(super) fn count(&self, group: &'static str, amount: usize) {
        #[cfg(feature = "tokio")]
        if let Some(group) =
            crate::diagnostic_clock::native_group(crate::diagnostic_clock::NativeKind::Raw, group)
        {
            crate::diagnostic_clock::count(group, amount);
        }
        if self.enabled {
            *self.counts.borrow_mut().entry(group).or_default() += amount;
        }
    }
}

impl Drop for RawTimings {
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
    timings: &'a RawTimings,
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
