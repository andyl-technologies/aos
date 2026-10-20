//! Aggregates opt-in loader work without sampling request authority clocks.
//!
//! Read spans include byte-cache cloning, scheduling and joined Store work;
//! they do not isolate physical I/O or CPU time. Context spans include traversal
//! and byte retention. Counts describe attempted work, never verified authority.
//! Each Fetcher owns its summary; no observation survives as a content cache.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Groups {
    durations: BTreeMap<&'static str, (Duration, usize)>,
    counts: BTreeMap<&'static str, usize>,
}

/// Owns one loader's aggregate, including error and cancellation exits.
pub(super) struct LoadTimings {
    groups: Option<Arc<Mutex<Groups>>>,
}

impl LoadTimings {
    /// Enables measurements only for the existing phase-trace opt-in.
    pub(super) fn new() -> Self {
        Self {
            groups: std::env::var_os("TERRANE_REF_PHASE_TRACE")
                .is_some()
                .then(|| Arc::new(Mutex::new(Groups::default()))),
        }
    }

    /// Starts a test-local span that never borrows the Fetcher across an await.
    pub(super) fn span(&self, group: &'static str) -> Option<Span> {
        self.groups.as_ref().map(|groups| Span {
            groups: Arc::clone(groups),
            group,
            started: crate::diagnostic_clock::tick(),
        })
    }

    /// Records attempted work without logging identities, paths or body bytes.
    pub(super) fn count(&self, group: &'static str, amount: usize) {
        if let Some(groups) = &self.groups
            && let Ok(mut groups) = groups.lock()
        {
            *groups.counts.entry(group).or_default() += amount;
        }
    }
}

impl Drop for LoadTimings {
    fn drop(&mut self) {
        let Some(groups) = &self.groups else {
            return;
        };
        let Ok(groups) = groups.lock() else {
            eprintln!("index-load-timings aggregate unavailable=poisoned-observation");
            return;
        };
        let durations = groups
            .durations
            .iter()
            .map(|(name, (time, calls))| format!("{name}:time={time:?},calls={calls}"))
            .collect::<Vec<_>>();
        let counts = groups
            .counts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>();
        eprintln!(
            "index-load-timings aggregate groups=[{}] counts=[{}]",
            durations.join(";"),
            counts.join(";")
        );
    }
}

/// Retains only diagnostic storage while the original operation is pending.
pub(super) struct Span {
    groups: Arc<Mutex<Groups>>,
    group: &'static str,
    started: crate::diagnostic_clock::Tick,
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Ok(mut groups) = self.groups.lock() {
            let (duration, calls) = groups.durations.entry(self.group).or_default();
            *duration += crate::diagnostic_clock::elapsed(self.started);
            *calls += 1;
        }
    }
}
