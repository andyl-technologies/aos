//! Aggregates numeric native-check diagnostics inside one physical operation.
//!
//! The optional thread-local sink holds only fixed groups, durations and counts.
//! Scopes restore the previous sink in LIFO order and never retain filesystem or
//! authority evidence. No mutable borrow spans native work. Inclusive groups
//! overlap their child spans and must not be added together or to caller spans.
//! Body-read spans include scratch preparation and the existing bounded read;
//! body-compare spans include presence and optional whole-value equality. Primitive
//! spans surround the original call only, including library wrapper overhead;
//! `write_all` may issue several writes. They exclude projection refreshes.

use std::{cell::RefCell, rc::Rc, time::Duration};

/// Names the bounded set of inclusive check and actual primitive spans.
#[derive(Clone, Copy)]
pub(super) enum Group {
    /// Complete ordered projection refresh.
    Projection,
    /// Retained fences before pairs and preimages.
    FenceBefore,
    /// Retained fences after preimages.
    FenceAfter,
    /// One attempted retained directory fence.
    Directory,
    /// One attempted retained named fence.
    Name,
    /// One attempted retained pair refresh.
    Pair,
    /// One attempted preimage row, including injected refusal.
    Preimage,
    /// Final created-directory incarnation check.
    Created,
    /// Final current authority check.
    Current,
    /// Complete exact-leaf check.
    Leaf,
    /// Exact-leaf structural and fresh parent checks.
    Parents,
    /// Fresh nofollow, nonblocking leaf open.
    Open,
    /// Fresh descriptor metadata, policy and incarnation checks.
    Descriptor,
    /// Scratch preparation and actual expected bytes plus detecting byte.
    BodyRead,
    /// Named metadata, policy and incarnation checks after the body.
    NamedAfter,
    /// Presence and optional whole-body comparison.
    BodyCompare,
    /// Actual write-all primitive call.
    Write,
    /// Actual file-sync primitive call.
    FileSync,
    /// Actual directory-sync primitive call.
    DirectorySync,
    /// Actual no-replace rename primitive call.
    RenameNoReplace,
    /// Actual replacing rename primitive call.
    Rename,
    /// Actual remove primitive call.
    Remove,
    /// One post-effect retained directory check.
    FinalDirectory,
    /// One post-effect retained pair refresh.
    FinalPair,
    /// Final post-effect current authority check.
    FinalCurrent,
}

const GROUP_NAMES: [&str; 25] = [
    "projection",
    "fence-before",
    "fence-after",
    "retained-directory",
    "retained-name",
    "retained-pair",
    "preimage-row",
    "created-directory",
    "current",
    "exact-leaf",
    "parents",
    "fresh-open",
    "descriptor-policy-incarnation",
    "actual-body-read",
    "named-after",
    "actual-body-compare",
    "primitive-write-all",
    "syscall-file-sync",
    "syscall-directory-sync",
    "syscall-rename-no-replace",
    "syscall-rename",
    "syscall-remove",
    "final-directory",
    "final-pair",
    "final-current",
];

#[derive(Default)]
struct Totals {
    groups: [(Duration, usize); GROUP_NAMES.len()],
    expected_bytes: usize,
}

thread_local! {
    static ACTIVE: RefCell<Option<Rc<RefCell<Totals>>>> = const { RefCell::new(None) };
}

/// Installs an optional numeric sink for the current operation's native thread.
///
/// Scopes must be dropped in reverse construction order on their native thread.
/// Restoration assumes this LIFO order; it does not enforce an arbitrary drop
/// order. The operation-local cohort and Raw owners retain that lexical lifetime.
pub(super) struct Scope {
    totals: Option<Rc<RefCell<Totals>>>,
    previous: Option<Rc<RefCell<Totals>>>,
}

impl Scope {
    /// Masks any outer sink while disabled, without taking a clock sample.
    pub(super) fn new(enabled: bool) -> Self {
        let totals = enabled.then(|| Rc::new(RefCell::new(Totals::default())));
        let previous = ACTIVE.with(|active| active.replace(totals.clone()));
        Self { totals, previous }
    }

    /// Formats bounded numeric aggregates without recording paths or bodies.
    pub(super) fn summary(&self) -> String {
        let Some(totals) = &self.totals else {
            return String::new();
        };
        let totals = totals.borrow();
        let groups: Vec<_> = GROUP_NAMES
            .iter()
            .zip(totals.groups)
            .filter(|(_, (_, calls))| *calls != 0)
            .map(|(name, (time, calls))| format!("{name}:time={time:?},calls={calls}"))
            .collect();
        format!(
            "checks=[{}] check-expected-byte-attempts={}",
            groups.join(";"),
            totals.expected_bytes
        )
    }

    /// Returns completed span counts for mechanics assertions.
    #[cfg(unix)]
    pub(super) fn calls(&self, group: Group) -> usize {
        self.totals
            .as_ref()
            .map_or(0, |totals| totals.borrow().groups[group as usize].1)
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.replace(self.previous.take());
        });
    }
}

/// Counts expected bytes for each actual body-read attempt, including failures.
pub(super) fn expected_bytes(amount: usize) {
    #[cfg(feature = "tokio")]
    crate::diagnostic_clock::count(crate::diagnostic_clock::Group::CheckExpectedBytes, amount);
    ACTIVE.with(|active| {
        if let Some(totals) = active.borrow().as_ref() {
            let mut totals = totals.borrow_mut();
            totals.expected_bytes = totals.expected_bytes.saturating_add(amount);
        }
    });
}

/// Starts an optional span without retaining a mutable borrow across native work.
pub(super) fn span(group: Group) -> Span {
    let totals = ACTIVE.with(|active| active.borrow().clone());
    let started = totals.as_ref().map(|_| crate::diagnostic_clock::tick());
    Span {
        totals,
        group,
        started,
        #[cfg(feature = "tokio")]
        diagnostic: crate::diagnostic_clock::check_group(group as usize)
            .map(crate::diagnostic_clock::span),
    }
}

/// Records attempted work on every exit, including physical and authority refusal.
pub(super) struct Span {
    totals: Option<Rc<RefCell<Totals>>>,
    group: Group,
    started: Option<crate::diagnostic_clock::Tick>,
    // The growth collector is thread-safe numeric state; the existing local
    // sink remains confined to this synchronous native operation.
    #[cfg(feature = "tokio")]
    diagnostic: Option<crate::diagnostic_clock::Span>,
}

impl Drop for Span {
    fn drop(&mut self) {
        #[cfg(feature = "tokio")]
        drop(self.diagnostic.take());
        if let (Some(totals), Some(started)) = (&self.totals, self.started) {
            let mut totals = totals.borrow_mut();
            let (duration, calls) = &mut totals.groups[self.group as usize];
            *duration = duration.saturating_add(crate::diagnostic_clock::elapsed(started));
            *calls = calls.saturating_add(1);
        }
    }
}
