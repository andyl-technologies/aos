//! Owns bounded test diagnostics isolated from repository authority and clocks.
//!
//! One growth fixture owns the optional numeric collector and reporter. All
//! intervals are inclusive and can overlap; their totals are not disjoint costs.
//! Unfinished exits do not imply refusal. Native RAII spans have no result
//! carrier, so even their ordinary exits remain unclassified. Lost updates make
//! counts incomplete. Read-projection batch counts describe inventory, including
//! any suffix not checked after refusal. Existing native check spans count actual
//! attempted rows separately.

use crate::store::Clock;
#[cfg(feature = "tokio")]
use std::io;
use std::sync::OnceLock;
#[cfg(feature = "tokio")]
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Supplies diagnostic time without binding repository or retained authority.
#[derive(Default)]
struct DiagnosticClock {
    origin: OnceLock<Instant>,
    #[cfg(feature = "tokio")]
    cancelled: Mutex<bool>,
    #[cfg(feature = "tokio")]
    wake: Condvar,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl Clock for DiagnosticClock {
    fn now(&self) -> SystemTime {
        // Wall time is unused; this clock can never be an authoring clock.
        SystemTime::UNIX_EPOCH
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "The private test Clock binding is the sole diagnostic monotonic injection boundary."
    )]
    fn monotonic(&self) -> Duration {
        self.origin.get_or_init(Instant::now).elapsed()
    }

    #[cfg(feature = "tokio")]
    async fn sleep(&self, duration: Duration) -> io::Result<()> {
        // This blocking timer is polled only on the dedicated reporter thread.
        // Recompute the remainder after spurious wakes through this Clock alone.
        let started = self.monotonic();
        let mut cancelled = self
            .cancelled
            .lock()
            .map_err(|_| io::Error::other("diagnostic timer unavailable"))?;

        loop {
            if *cancelled {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "diagnostic timer cancelled",
                ));
            }
            let remaining = duration.saturating_sub(self.monotonic().saturating_sub(started));
            if remaining.is_zero() {
                return Ok(());
            }

            let (next, _) = self
                .wake
                .wait_timeout(cancelled, remaining)
                .map_err(|_| io::Error::other("diagnostic timer unavailable"))?;
            cancelled = next;
        }
    }
}

#[cfg(all(feature = "tokio", feature = "surface-sdk", unix))]
impl DiagnosticClock {
    fn cancel(&self) {
        // Recover cancellation state only, never authority or collector state.
        let mut cancelled = match self.cancelled.lock() {
            Ok(cancelled) => cancelled,
            Err(poisoned) => poisoned.into_inner(),
        };
        *cancelled = true;
        self.wake.notify_all();
    }
}

/// Represents a process-local diagnostic monotonic tick.
pub(crate) type Tick = Duration;

/// Samples the private test Clock; callers must preserve their opt-in guard.
pub(crate) fn tick() -> Tick {
    static CLOCK: OnceLock<DiagnosticClock> = OnceLock::new();
    CLOCK.get_or_init(DiagnosticClock::default).monotonic()
}

/// Measures elapsed diagnostic time from a tick of the same private Clock.
pub(crate) fn elapsed(started: Tick) -> Duration {
    tick().saturating_sub(started)
}

#[cfg(feature = "tokio")]
mod bounded {
    use super::{Clock, DiagnosticClock, Duration, Mutex};
    #[cfg(all(feature = "surface-sdk", unix))]
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Weak};

    macro_rules! groups {
        ($($(#[$attribute:meta])* $variant:ident => $name:literal),+ $(,)?) => {
            /// Names the fixed inclusive diagnostic groups.
            #[derive(Clone, Copy)]
            pub(crate) enum Group {
                $($(#[$attribute])*
                #[doc = concat!("Records the inclusive diagnostic group `", $name, "`.")]
                $variant),+
            }

            impl Group {
                // Conditional labels must follow the same discriminant indexes.
                const NAMES: &'static [&'static str] = &[$($(#[$attribute])* $name),+];
            }
        };
    }

    groups! {
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseBaseline => "phase-baseline",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseOracle => "phase-oracle",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseMaintainedBegin => "phase-maintained-begin",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseMaintainedTree => "phase-maintained-tree",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseMaintainedCommit => "phase-maintained-commit",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseReopen => "phase-reopen",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseOutput => "phase-output",
        #[cfg(all(feature = "surface-sdk", unix))]
        PhaseAccounting => "phase-accounting",
        DirectTree => "direct-tree",
        DirectHistory => "direct-history",
        Authorization => "authorization",
        OrdinaryDispatch => "ordinary-dispatch",
        HeldDispatch => "held-dispatch",
        FallbackDispatch => "fallback-dispatch",
        HeldPreparation => "held-preparation",
        HeldClosing => "held-closing",
        HeldPromotion => "held-promotion",
        ReadProjection => "read-projection",
        ReadCurrent => "read-current",
        ReadNamesBefore => "read-name-batches-before",
        ReadPreimages => "read-preimage-batches",
        ReadRanges => "read-range-recipe-batches",
        ReadNamesAfter => "read-name-batches-after",
        ReadCurrentAfter => "read-current-after",
        HistoryCompletion => "history-completion",
        SelectedGet => "selected-get",
        SelectedGetObservation => "selected-get-observation",
        SelectedGetCatalog => "selected-get-catalog",
        SelectedGetClosing => "selected-get-closing",
        PublicationSelection => "publication-selection",
        MemoCommit => "memo-commit",
        MemoTransaction => "memo-transaction",
        MemoSnapshot => "memo-snapshot",
        DecodeCommit => "decode-commit",
        DecodeTransaction => "decode-transaction",
        DecodeSnapshot => "decode-snapshot",
        MemoCommitHit => "memo-commit-hit",
        MemoCommitMiss => "memo-commit-miss",
        MemoTransactionHit => "memo-transaction-hit",
        MemoTransactionMiss => "memo-transaction-miss",
        MemoSnapshotHit => "memo-snapshot-hit",
        MemoSnapshotMiss => "memo-snapshot-miss",
        CatalogDecode => "catalog-decode",
        CatalogArtifactRead => "catalog-artifact-read",
        CatalogArtifactVerify => "catalog-artifact-verify",
        CatalogShardDecode => "catalog-shard-decode",
        CheckProjection => "check-projection",
        CheckFenceBefore => "check-fence-before",
        CheckFenceAfter => "check-fence-after",
        CheckDirectory => "check-directory",
        CheckName => "check-name",
        CheckPair => "check-pair",
        CheckPreimage => "check-preimage",
        CheckCreated => "check-created",
        CheckCurrent => "check-current",
        CheckLeaf => "check-leaf",
        CheckParents => "check-parents",
        CheckOpen => "check-open",
        CheckDescriptor => "check-descriptor",
        CheckBodyRead => "check-body-read",
        CheckNamedAfter => "check-named-after",
        CheckBodyCompare => "check-body-compare",
        CheckWrite => "check-write",
        CheckFileSync => "check-file-sync",
        CheckDirectorySync => "check-directory-sync",
        CheckRenameNoReplace => "check-rename-no-replace",
        CheckRename => "check-rename",
        CheckRemove => "check-remove",
        CheckFinalDirectory => "check-final-directory",
        CheckFinalPair => "check-final-pair",
        CheckFinalCurrent => "check-final-current",
        CheckExpectedBytes => "check-expected-bytes",
        CohortWriteNew => "cohort-write-new",
        CohortStagingRebind => "cohort-staging-rebind",
        CohortSyncFile => "cohort-sync-file",
        CohortRenameNoReplace => "cohort-rename-no-replace",
        CohortTargetRebind => "cohort-target-rebind",
        CohortFinalProjection => "cohort-final-projection",
        CohortActualSend => "cohort-actual-send",
        CohortInitialNames => "cohort-initial-names",
        CohortInitialPreimages => "cohort-initial-preimages",
        CohortInitialPairs => "cohort-initial-pairs",
        CohortPlannedInstalls => "cohort-planned-installs",
        CohortExpectedInstallBytes => "cohort-expected-install-bytes",
        RawInitialRootAndFullRefresh => "raw-initial-root-and-full-refresh",
        RawInventoryConstruction => "raw-inventory-construction",
        RawFileTotal => "raw-file-total",
        RawRecordBodyBefore => "raw-record-body-before",
        RawRecordBodyAfter => "raw-record-body-after",
        RawDirectoriesTotal => "raw-directories-total",
        RawFinalRecordBodies => "raw-final-record-bodies",
        RawFinalFullRefresh => "raw-final-full-refresh",
        RawScopedRefreshTotal => "raw-scoped-refresh-total",
        RawRetainedFencesBefore => "raw-retained-fences-before",
        RawFreshPreimages => "raw-fresh-preimages",
        RawRetainedFencesAfter => "raw-retained-fences-after",
        RawCurrentAuthority => "raw-current-authority",
        RawFileSyncSyscall => "raw-file-sync-syscall",
        RawDirectorySyncSyscall => "raw-directory-sync-syscall",
        RawInventoryTargets => "raw-inventory-targets",
        RawRetainedNames => "raw-retained-names",
        RawRetainedPreimages => "raw-retained-preimages",
        RawInventoryRecords => "raw-inventory-records",
        RawInventoryBodyBytes => "raw-inventory-body-bytes",
        RawInventoryDirectories => "raw-inventory-directories",
        RawFinalRecordBodyAttempts => "raw-final-record-body-attempts",
        RawDeferredOutputRows => "raw-deferred-output-rows",
        RawFreshPreimageAttempts => "raw-fresh-preimage-attempts",
        RawFreshPreimageExpectedBytes => "raw-fresh-preimage-expected-bytes",
        RawCurrentTargetAttempts => "raw-current-target-attempts",
    }

    /// Selects a closed native timing vocabulary, never an arbitrary output label.
    #[derive(Clone, Copy)]
    pub(crate) enum NativeKind {
        /// Selects immutable installation cohort timings and inventory counts.
        Cohort,
        /// Selects Raw publication durability timings and inventory counts.
        Raw,
    }

    /// Maps the existing fixed check enum to the collector's fixed groups.
    pub(crate) fn check_group(index: usize) -> Option<Group> {
        const CHECKS: &[Group] = &[
            Group::CheckProjection,
            Group::CheckFenceBefore,
            Group::CheckFenceAfter,
            Group::CheckDirectory,
            Group::CheckName,
            Group::CheckPair,
            Group::CheckPreimage,
            Group::CheckCreated,
            Group::CheckCurrent,
            Group::CheckLeaf,
            Group::CheckParents,
            Group::CheckOpen,
            Group::CheckDescriptor,
            Group::CheckBodyRead,
            Group::CheckNamedAfter,
            Group::CheckBodyCompare,
            Group::CheckWrite,
            Group::CheckFileSync,
            Group::CheckDirectorySync,
            Group::CheckRenameNoReplace,
            Group::CheckRename,
            Group::CheckRemove,
            Group::CheckFinalDirectory,
            Group::CheckFinalPair,
            Group::CheckFinalCurrent,
        ];
        CHECKS.get(index).copied()
    }

    /// Maps existing numeric groups without retaining names, paths or evidence.
    pub(crate) fn native_group(kind: NativeKind, name: &str) -> Option<Group> {
        match (kind, name) {
            (NativeKind::Cohort, "write-new") => Some(Group::CohortWriteNew),
            (NativeKind::Cohort, "staging-rebind") => Some(Group::CohortStagingRebind),
            (NativeKind::Cohort, "sync-file") => Some(Group::CohortSyncFile),
            (NativeKind::Cohort, "rename-no-replace") => Some(Group::CohortRenameNoReplace),
            (NativeKind::Cohort, "target-rebind") => Some(Group::CohortTargetRebind),
            (NativeKind::Cohort, "final-projection") => Some(Group::CohortFinalProjection),
            (NativeKind::Cohort, "actual-send") => Some(Group::CohortActualSend),
            (NativeKind::Cohort, "initial-names") => Some(Group::CohortInitialNames),
            (NativeKind::Cohort, "initial-preimages") => Some(Group::CohortInitialPreimages),
            (NativeKind::Cohort, "initial-pairs") => Some(Group::CohortInitialPairs),
            (NativeKind::Cohort, "planned-installs") => Some(Group::CohortPlannedInstalls),
            (NativeKind::Cohort, "expected-install-bytes") => {
                Some(Group::CohortExpectedInstallBytes)
            }
            (NativeKind::Raw, "initial-root-and-full-refresh") => {
                Some(Group::RawInitialRootAndFullRefresh)
            }
            (NativeKind::Raw, "inventory-construction") => Some(Group::RawInventoryConstruction),
            (NativeKind::Raw, "file-total") => Some(Group::RawFileTotal),
            (NativeKind::Raw, "record-body-before") => Some(Group::RawRecordBodyBefore),
            (NativeKind::Raw, "record-body-after") => Some(Group::RawRecordBodyAfter),
            (NativeKind::Raw, "directories-total") => Some(Group::RawDirectoriesTotal),
            (NativeKind::Raw, "final-record-bodies") => Some(Group::RawFinalRecordBodies),
            (NativeKind::Raw, "final-full-refresh") => Some(Group::RawFinalFullRefresh),
            (NativeKind::Raw, "scoped-refresh-total") => Some(Group::RawScopedRefreshTotal),
            (NativeKind::Raw, "retained-fences-before") => Some(Group::RawRetainedFencesBefore),
            (NativeKind::Raw, "fresh-preimages") => Some(Group::RawFreshPreimages),
            (NativeKind::Raw, "retained-fences-after") => Some(Group::RawRetainedFencesAfter),
            (NativeKind::Raw, "current-authority") => Some(Group::RawCurrentAuthority),
            (NativeKind::Raw, "file-sync-syscall") => Some(Group::RawFileSyncSyscall),
            (NativeKind::Raw, "directory-sync-syscall") => Some(Group::RawDirectorySyncSyscall),
            (NativeKind::Raw, "inventory-targets") => Some(Group::RawInventoryTargets),
            (NativeKind::Raw, "retained-names") => Some(Group::RawRetainedNames),
            (NativeKind::Raw, "retained-preimages") => Some(Group::RawRetainedPreimages),
            (NativeKind::Raw, "inventory-records") => Some(Group::RawInventoryRecords),
            (NativeKind::Raw, "inventory-body-bytes") => Some(Group::RawInventoryBodyBytes),
            (NativeKind::Raw, "inventory-directories") => Some(Group::RawInventoryDirectories),
            (NativeKind::Raw, "final-record-body-attempts") => {
                Some(Group::RawFinalRecordBodyAttempts)
            }
            (NativeKind::Raw, "deferred-output-rows") => Some(Group::RawDeferredOutputRows),
            (NativeKind::Raw, "fresh-preimage-attempts") => Some(Group::RawFreshPreimageAttempts),
            (NativeKind::Raw, "fresh-preimage-expected-bytes") => {
                Some(Group::RawFreshPreimageExpectedBytes)
            }
            (NativeKind::Raw, "current-target-attempts") => Some(Group::RawCurrentTargetAttempts),
            _ => None,
        }
    }

    /// Names the fixture's fixed phase boundaries.
    #[cfg(all(feature = "surface-sdk", unix))]
    #[derive(Clone, Copy)]
    pub(crate) enum Phase {
        /// Covers initial model preparation, publication and output verification.
        Baseline,
        /// Covers replacement model construction and independent work derivation.
        Oracle,
        /// Covers opening the maintained publication session.
        MaintainedBegin,
        /// Covers preparing the maintained tree for publication.
        MaintainedTree,
        /// Covers committing the maintained tree through the original writer.
        MaintainedCommit,
        /// Covers reopening the native repository after maintained publication.
        Reopen,
        /// Covers verification of the reopened immutable outputs and current ref.
        Output,
        /// Covers independent work assertions and unchanged baseline verification.
        Accounting,
    }

    #[cfg(all(feature = "surface-sdk", unix))]
    impl Phase {
        fn group(self) -> Group {
            match self {
                Self::Baseline => Group::PhaseBaseline,
                Self::Oracle => Group::PhaseOracle,
                Self::MaintainedBegin => Group::PhaseMaintainedBegin,
                Self::MaintainedTree => Group::PhaseMaintainedTree,
                Self::MaintainedCommit => Group::PhaseMaintainedCommit,
                Self::Reopen => Group::PhaseReopen,
                Self::Output => Group::PhaseOutput,
                Self::Accounting => Group::PhaseAccounting,
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Baseline => "baseline",
                Self::Oracle => "oracle",
                Self::MaintainedBegin => "maintained-begin",
                Self::MaintainedTree => "maintained-tree",
                Self::MaintainedCommit => "maintained-commit",
                Self::Reopen => "reopen",
                Self::Output => "output",
                Self::Accounting => "accounting",
            }
        }
    }

    #[derive(Clone, Copy, Default)]
    struct Totals {
        attempts: u64,
        completed: u64,
        refused: u64,
        exited: u64,
        in_progress: u64,
        count: u64,
        total: Duration,
        maximum: Duration,
    }

    struct State {
        #[cfg(all(feature = "surface-sdk", unix))]
        phase: Phase,
        #[cfg(all(feature = "surface-sdk", unix))]
        phase_started: Duration,
        groups: [Totals; Group::NAMES.len()],
    }

    struct Collector {
        clock: Arc<DiagnosticClock>,
        state: Mutex<State>,
        lost: AtomicU64,
        #[cfg(all(feature = "surface-sdk", unix))]
        registry_loss_origin: u64,
    }

    static ACTIVE: Mutex<Option<Weak<Collector>>> = Mutex::new(None);
    static REGISTRY_LOSSES: AtomicU64 = AtomicU64::new(0);

    fn active() -> Option<Arc<Collector>> {
        match ACTIVE.try_lock() {
            Ok(active) => active.as_ref().and_then(Weak::upgrade),
            Err(_) => {
                REGISTRY_LOSSES.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    impl Collector {
        fn update(&self, update: impl FnOnce(&mut State)) -> bool {
            match self.state.try_lock() {
                Ok(mut state) => {
                    update(&mut state);
                    true
                }
                Err(_) => {
                    self.lost.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }

        #[cfg(all(feature = "surface-sdk", unix))]
        fn summary(&self, boundary: &str, snapshot: usize) {
            let now = self.clock.monotonic();
            let copied = match self.state.try_lock() {
                Ok(state) => Some((state.phase, state.phase_started, state.groups)),
                Err(_) => {
                    self.lost.fetch_add(1, Ordering::Relaxed);
                    None
                }
            };
            let registry_losses = REGISTRY_LOSSES
                .load(Ordering::Relaxed)
                .saturating_sub(self.registry_loss_origin);
            let lost = self
                .lost
                .load(Ordering::Relaxed)
                .saturating_add(registry_losses);
            let mut stderr = io::stderr().lock();
            let Some((phase, started, groups)) = copied else {
                let _ = writeln!(
                    stderr,
                    "growth-diagnostic boundary={boundary} snapshot={snapshot} unavailable=true lost={lost}"
                );
                return;
            };
            let groups = Group::NAMES
                .iter()
                .zip(groups)
                .filter(|(_, totals)| totals.attempts != 0 || totals.count != 0)
                .map(|(name, totals)| format!(
                    "{name}:attempts={},completed={},refused={},exited-without-completion={},in-progress={},count={},total={:?},max={:?}",
                    totals.attempts, totals.completed, totals.refused, totals.exited,
                    totals.in_progress, totals.count, totals.total, totals.maximum,
                ))
                .collect::<Vec<_>>()
                .join(";");
            let _ = writeln!(
                stderr,
                "growth-diagnostic boundary={boundary} snapshot={snapshot} phase={} elapsed={now:?} phase-elapsed={:?} lost={lost} inclusive-overlap=true groups=[{groups}]",
                phase.name(),
                now.saturating_sub(started),
            );
        }
    }

    /// Holds only numeric state across asynchronous or native work.
    pub(crate) struct Span {
        collector: Option<Arc<Collector>>,
        group: Group,
        started: Duration,
        outcome: Outcome,
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Completed,
        Refused,
        Exited,
    }

    /// Starts a numeric attempt only while the growth fixture is active.
    pub(crate) fn span(group: Group) -> Span {
        let collector = active();
        let started = collector
            .as_ref()
            .map_or(Duration::ZERO, |collector| collector.clock.monotonic());
        let collector = collector.filter(|collector| {
            collector.update(|state| {
                let totals = &mut state.groups[group as usize];
                totals.attempts = totals.attempts.saturating_add(1);
                totals.in_progress = totals.in_progress.saturating_add(1);
            })
        });

        Span {
            collector,
            group,
            started,
            outcome: Outcome::Exited,
        }
    }

    impl Span {
        /// Marks the actual returned Result without retaining it.
        pub(crate) fn finish_result<T, E>(&mut self, result: &Result<T, E>) {
            self.outcome = if result.is_ok() {
                Outcome::Completed
            } else {
                Outcome::Refused
            };
        }

        /// Marks successful arrival at the original operation's return boundary.
        pub(crate) fn complete(&mut self) {
            self.outcome = Outcome::Completed;
        }
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let Some(collector) = &self.collector else {
                return;
            };
            let elapsed = collector.clock.monotonic().saturating_sub(self.started);
            collector.update(|state| {
                let totals = &mut state.groups[self.group as usize];
                totals.in_progress = totals.in_progress.saturating_sub(1);
                match self.outcome {
                    Outcome::Completed => totals.completed = totals.completed.saturating_add(1),
                    Outcome::Refused => totals.refused = totals.refused.saturating_add(1),
                    Outcome::Exited => totals.exited = totals.exited.saturating_add(1),
                }
                totals.total = totals.total.saturating_add(elapsed);
                totals.maximum = totals.maximum.max(elapsed);
            });
        }
    }

    /// Adds a numeric inventory count without reading authority or diagnostic time.
    pub(crate) fn count(group: Group, amount: usize) {
        if let Some(collector) = active() {
            collector.update(|state| {
                let count = &mut state.groups[group as usize].count;
                *count = count.saturating_add(amount as u64);
            });
        }
    }

    /// Owns activation, fixed phase summaries and prompt reporter cancellation.
    #[cfg(all(feature = "surface-sdk", unix))]
    pub(crate) struct FixtureScope {
        collector: Option<Arc<Collector>>,
        reporter: Option<std::thread::JoinHandle<()>>,
        phase_span: Option<Span>,
    }

    #[cfg(all(feature = "surface-sdk", unix))]
    impl FixtureScope {
        /// Opts into only the unchanged 4096 ordinary growth population.
        ///
        /// `TERRANE_GROWTH_DIAGNOSTIC=1` enables bounded numeric output. Absence
        /// preserves the original fixture without clock samples or a reporter.
        pub(crate) fn new(population: usize, adversarial: bool) -> Self {
            let mut scope = Self {
                collector: None,
                reporter: None,
                phase_span: None,
            };
            if population != 4096
                || adversarial
                || std::env::var_os("TERRANE_GROWTH_DIAGNOSTIC").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
            {
                return scope;
            }
            let Ok(mut active) = ACTIVE.try_lock() else {
                return scope;
            };
            if active.as_ref().and_then(Weak::upgrade).is_some() {
                return scope;
            }

            let collector = Arc::new(Collector {
                clock: Arc::new(DiagnosticClock::default()),
                state: Mutex::new(State {
                    phase: Phase::Baseline,
                    phase_started: Duration::ZERO,
                    groups: [Totals::default(); Group::NAMES.len()],
                }),
                lost: AtomicU64::new(0),
                registry_loss_origin: REGISTRY_LOSSES.load(Ordering::Relaxed),
            });
            *active = Some(Arc::downgrade(&collector));
            drop(active);
            scope.collector = Some(collector.clone());
            collector.clock.monotonic();
            scope.phase_span = Some(span(Phase::Baseline.group()));

            // The existing runtime supplies only the block_on entry point. The
            // Clock's cancellable blocking wait occupies this reporter thread alone.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let reporter_collector = collector.clone();
                scope.reporter = std::thread::Builder::new()
                    .name("growth-diagnostic".into())
                    .spawn(move || {
                        for snapshot in 1..=9 {
                            // Absolute diagnostic deadlines avoid accumulating output
                            // overhead. Neither these ticks nor waits enter authority.
                            let deadline = Duration::from_secs(snapshot as u64 * 200);
                            let remaining =
                                deadline.saturating_sub(reporter_collector.clock.monotonic());
                            if handle
                                .block_on(reporter_collector.clock.sleep(remaining))
                                .is_err()
                            {
                                break;
                            }
                            reporter_collector.summary("periodic", snapshot);
                        }
                    })
                    .ok();
            }
            if scope.reporter.is_none() {
                collector.lost.fetch_add(1, Ordering::Relaxed);
            }
            scope
        }

        /// Emits the preceding fixed phase and enters the next fixed phase.
        pub(crate) fn phase(&mut self, phase: Phase) {
            if let Some(mut previous) = self.phase_span.take() {
                previous.complete();
            }
            let Some(collector) = &self.collector else {
                return;
            };
            collector.summary("phase", 0);
            let now = collector.clock.monotonic();
            collector.update(|state| {
                state.phase = phase;
                state.phase_started = now;
            });
            self.phase_span = Some(span(phase.group()));
        }

        /// Marks only the fixture's actual final Result; cancellation stays unfinished.
        pub(crate) fn finish_result<T, E>(&mut self, result: &Result<T, E>) {
            if let Some(phase) = &mut self.phase_span {
                phase.finish_result(result);
            }
        }
    }

    #[cfg(all(feature = "surface-sdk", unix))]
    impl Drop for FixtureScope {
        fn drop(&mut self) {
            let Some(collector) = &self.collector else {
                return;
            };
            drop(self.phase_span.take());
            collector.clock.cancel();
            if let Some(reporter) = self.reporter.take() {
                let _ = reporter.join();
            }

            // Retire only this fixture's own registry entry, including error exits.
            let mut active = match ACTIVE.lock() {
                Ok(active) => active,
                Err(poisoned) => poisoned.into_inner(),
            };
            if active
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|value| Arc::ptr_eq(&value, collector))
            {
                *active = None;
            }
            drop(active);
            collector.summary("fixture-exit", 0);
        }
    }
}

#[cfg(all(feature = "tokio", feature = "surface-sdk", unix))]
pub(crate) use bounded::{FixtureScope, Phase};
#[cfg(feature = "tokio")]
pub(crate) use bounded::{Group, NativeKind, Span, check_group, count, native_group, span};
