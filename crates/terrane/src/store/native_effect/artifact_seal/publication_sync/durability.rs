//! Defers unrelated Raw output reads between complete durability boundaries.
//!
//! Only closed, newly created immutable outputs may defer their unrelated leaf
//! checks around another output's sync. Consumed inputs and current targets stay
//! fresh; complete boundaries verify every output's same retained descriptor.
//! Classification borrows the fixed projection for one synchronization. It
//! retains no successful physical observation and cannot rebind to another worker.

use super::super::super::{
    ExactRead, FencePolicy, NativeEffectFailure, NativeOpenedDirectory, Projection,
};
#[cfg(test)]
use super::raw_timings::RawTimings;
use super::{Target, Worker};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[cfg(test)]
use super::super::super::EffectFault;
#[cfg(all(test, feature = "tokio"))]
use super::super::super::{TestGate, TestGatePhase, wait_test_gate};

/// Binds one fixed classification to its original ordered preimage row.
struct ClassifiedRead<'projection> {
    ordinal: usize,
    read: &'projection ExactRead,
}

/// Borrows producer-proven outputs and all original physical/current dependencies.
struct DurabilityScope<'projection> {
    projection: &'projection Projection,
    consumed: Vec<ClassifiedRead<'projection>>,
    outputs: BTreeMap<&'projection Path, Vec<ClassifiedRead<'projection>>>,
    #[cfg(test)]
    faults: &'projection [EffectFault],
}

impl<'projection> DurabilityScope<'projection> {
    /// Falls back to whole-body checking whenever a retained variant differs.
    ///
    /// # Errors
    /// Refuses a candidate missing from the actual output inventory.
    fn new(
        candidates: &BTreeSet<PathBuf>,
        targets: &BTreeMap<PathBuf, Target>,
        projection: &'projection Projection,
        #[cfg(test)] faults: &'projection [EffectFault],
    ) -> io::Result<Self> {
        let mut by_path: BTreeMap<&Path, Vec<&ExactRead>> = BTreeMap::new();
        for read in &projection.preimages {
            by_path.entry(read.path.as_path()).or_default().push(read);
        }

        let mut outputs = BTreeSet::new();
        for path in candidates {
            let target = targets
                .get(path)
                .ok_or_else(|| io::Error::other("Raw durability output missing"))?;
            if target.protected || target.expected.is_none() {
                continue;
            }
            let mut reads = by_path
                .get(path.as_path())
                .into_iter()
                .flat_map(|reads| reads.iter().copied());
            let Some(first) = reads.next() else {
                continue;
            };
            if matches_output(first, target) && reads.all(|read| matches_output(read, target)) {
                outputs.insert(path.as_path());
            }
        }

        // Keep every duplicate's ordinal in disjoint ordered lists. Only the
        // immutable role predicate is fixed; the current target remains dynamic.
        let mut consumed = Vec::new();
        let mut output_reads: BTreeMap<&Path, Vec<ClassifiedRead<'projection>>> = BTreeMap::new();
        for (ordinal, read) in projection.preimages.iter().enumerate() {
            let classified = ClassifiedRead { ordinal, read };
            if outputs.contains(read.path.as_path()) {
                output_reads
                    .entry(read.path.as_path())
                    .or_default()
                    .push(classified);
            } else {
                consumed.push(classified);
            }
        }

        Ok(Self {
            projection,
            consumed,
            outputs: output_reads,
            #[cfg(test)]
            faults,
        })
    }

    /// Merges only consumed rows and this target's rows in original attempt order.
    fn required_reads(&self, target: Option<&Path>) -> RequiredReads<'_, 'projection> {
        let outputs = target
            .and_then(|path| self.outputs.get(path))
            .map_or(&[][..], Vec::as_slice);
        RequiredReads {
            consumed: self.consumed.iter(),
            outputs: outputs.iter(),
            #[cfg(test)]
            examined_rows: 0,
            #[cfg(test)]
            total_rows: self.projection.preimages.len(),
        }
    }

    /// Preserves the ordinary full refresh at initial and final boundaries.
    fn full_refresh(&self, changed: &[&Path]) -> Result<(), NativeEffectFailure> {
        #[cfg(test)]
        if !self.faults.is_empty() {
            for read in &self.projection.preimages {
                if !changed.contains(&read.path.as_path())
                    && self
                        .faults
                        .contains(&EffectFault::UnavailableRead(read.path.clone()))
                {
                    return Err(io::Error::other("injected creation exact read failure").into());
                }
            }
        }
        self.projection.refresh(changed).inspect_err(|_| {
            #[cfg(test)]
            super::super::super::diagnostic::refusal("worker-projection-refresh", None, None);
        })
    }
}

/// Preserves duplicate attempts without visiting unrelated deferrable output rows.
struct RequiredReads<'scope, 'projection> {
    consumed: std::slice::Iter<'scope, ClassifiedRead<'projection>>,
    outputs: std::slice::Iter<'scope, ClassifiedRead<'projection>>,
    #[cfg(test)]
    examined_rows: usize,
    #[cfg(test)]
    total_rows: usize,
}

/// Associates an actual attempt with its preceding skipped diagnostic gap.
struct RequiredRead<'scope, 'projection> {
    classified: &'scope ClassifiedRead<'projection>,
    #[cfg(test)]
    deferred_before: usize,
}

impl<'scope, 'projection> Iterator for RequiredReads<'scope, 'projection> {
    type Item = RequiredRead<'scope, 'projection>;

    fn next(&mut self) -> Option<Self::Item> {
        let classified = match (
            self.consumed.as_slice().first(),
            self.outputs.as_slice().first(),
        ) {
            (Some(consumed), Some(output)) if consumed.ordinal < output.ordinal => {
                self.consumed.next()
            }
            (_, Some(_)) => self.outputs.next(),
            (Some(_), None) => self.consumed.next(),
            (None, None) => None,
        }?;
        #[cfg(test)]
        let deferred_before = classified.ordinal - self.examined_rows;
        #[cfg(test)]
        {
            self.examined_rows = classified.ordinal + 1;
        }
        Some(RequiredRead {
            classified,
            #[cfg(test)]
            deferred_before,
        })
    }
}

#[cfg(test)]
impl RequiredReads<'_, '_> {
    /// Charges the final skipped gap only after all physical attempts succeeded.
    fn deferred_tail(&self) -> usize {
        self.total_rows - self.examined_rows
    }
}

/// Borrows one ordinary worker or one fixed Raw projection and its test handoffs.
///
/// The Raw constructor splits the same worker's fields without moving them. Its
/// immutable projection borrow prevents row mutation for the entire call, while
/// the disjoint gate borrow preserves the original mutable handoff schedule.
pub(super) struct SyncWorker<'operation> {
    state: WorkerState<'operation>,
}

enum WorkerState<'operation> {
    Ordinary(&'operation mut Worker),
    Raw {
        scope: DurabilityScope<'operation>,
        #[cfg(all(test, feature = "tokio"))]
        gates: &'operation mut Vec<TestGate>,
    },
}

impl<'operation> SyncWorker<'operation> {
    /// Delegates ordinary synchronization to its unchanged worker methods.
    pub(super) fn ordinary(worker: &'operation mut Worker) -> Self {
        Self {
            state: WorkerState::Ordinary(worker),
        }
    }

    /// Classifies one borrowed Raw worker without performing native observations.
    ///
    /// # Errors
    /// Refuses a candidate missing from the actual output inventory.
    pub(super) fn raw(
        candidates: &BTreeSet<PathBuf>,
        targets: &BTreeMap<PathBuf, Target>,
        worker: &'operation mut Worker,
    ) -> io::Result<Self> {
        let Worker {
            projection,
            #[cfg(test)]
            faults,
            #[cfg(all(test, feature = "tokio"))]
            gates,
        } = worker;
        let scope = DurabilityScope::new(
            candidates,
            targets,
            projection,
            #[cfg(test)]
            faults,
        )?;
        Ok(Self {
            state: WorkerState::Raw {
                scope,
                #[cfg(all(test, feature = "tokio"))]
                gates,
            },
        })
    }

    /// Returns the original projection retained for this synchronization.
    pub(super) fn projection(&self) -> &Projection {
        match &self.state {
            WorkerState::Ordinary(worker) => &worker.projection,
            WorkerState::Raw { scope, .. } => scope.projection,
        }
    }

    /// Identifies the existing Raw preparation and diagnostic timing mode.
    pub(super) fn is_raw(&self) -> bool {
        matches!(&self.state, WorkerState::Raw { .. })
    }

    /// Preserves the same worker's test-only handoff.
    ///
    /// # Errors
    /// Refuses a closed handoff channel.
    #[cfg(all(test, feature = "tokio"))]
    pub(super) fn wait_gate(&mut self, phase: TestGatePhase) -> io::Result<()> {
        match &mut self.state {
            WorkerState::Ordinary(worker) => wait_test_gate(&mut worker.gates, phase),
            WorkerState::Raw { gates, .. } => wait_test_gate(gates, phase),
        }
    }

    /// Refreshes every original row, including deferrable outputs, at a boundary.
    ///
    /// # Errors
    /// Preserves ordinary input, fence, fault and current-check refusals.
    pub(super) fn full_refresh(&self, changed: &[&Path]) -> Result<(), NativeEffectFailure> {
        match &self.state {
            WorkerState::Ordinary(worker) => worker.refresh(changed),
            WorkerState::Raw { scope, .. } => scope.full_refresh(changed),
        }
    }

    /// Refreshes consumed inputs and retained fences, sampling current last.
    ///
    /// # Errors
    /// Refuses changed inputs, retained fences and current predicates.
    pub(super) fn refresh(
        &self,
        #[cfg(test)] timings: Option<&RawTimings>,
    ) -> Result<(), NativeEffectFailure> {
        match &self.state {
            WorkerState::Ordinary(worker) => worker.refresh(&[]),
            WorkerState::Raw { scope, .. } => refresh_with_target(
                scope,
                None,
                #[cfg(test)]
                timings,
            ),
        }
    }

    /// Keeps the original file-sync faults, gates, checks and syscall in order.
    ///
    /// # Errors
    /// Refuses changed inputs or authority, handoff failures and sync failures.
    pub(super) fn file_sync(
        &mut self,
        file: &File,
        path: &Path,
        #[cfg(test)] timings: Option<&RawTimings>,
    ) -> Result<(), NativeEffectFailure> {
        match &mut self.state {
            WorkerState::Ordinary(worker) => worker.file_sync(file, &[]),
            WorkerState::Raw {
                scope,
                #[cfg(all(test, feature = "tokio"))]
                gates,
            } => file_sync(
                scope,
                file,
                path,
                #[cfg(all(test, feature = "tokio"))]
                gates,
                #[cfg(test)]
                timings,
            ),
        }
    }

    /// Keeps every directory receipt, gate, current check and actual sync.
    ///
    /// # Errors
    /// Refuses changed receipts or inputs, authority and synchronization failures.
    pub(super) fn directory_sync(
        &mut self,
        directory: &NativeOpenedDirectory,
        #[cfg(test)] timings: Option<&RawTimings>,
    ) -> Result<(), NativeEffectFailure> {
        match &mut self.state {
            WorkerState::Ordinary(worker) => worker.directory_sync(directory, false, &[]),
            WorkerState::Raw {
                scope,
                #[cfg(all(test, feature = "tokio"))]
                gates,
            } => directory_sync(
                scope,
                directory,
                #[cfg(all(test, feature = "tokio"))]
                gates,
                #[cfg(test)]
                timings,
            ),
        }
    }
}

fn matches_output(read: &ExactRead, target: &Target) -> bool {
    read.expected == target.expected
        && read.owner == target.owner
        && matches!(read.policy, FencePolicy::Payload { owner } if owner == target.owner)
        && read
            .metadata
            .is_some_and(|stamp| read.identity == Some(stamp.identity))
}

fn refresh_with_target(
    scope: &DurabilityScope<'_>,
    target: Option<&Path>,
    #[cfg(test)] timings: Option<&RawTimings>,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    // Without configured faults, a prescan would only clone every unrelated
    // output path before the scoped iterator reaches its physical checks.
    if !scope.faults.is_empty() {
        for read in &scope.projection.preimages {
            if scope
                .faults
                .contains(&EffectFault::UnavailableRead(read.path.clone()))
            {
                return Err(io::Error::other("injected creation exact read failure").into());
            }
        }
    }
    #[cfg(test)]
    let _refresh_span = timings.map(|timings| timings.span("scoped-refresh-total"));
    #[cfg(test)]
    let fence_span = timings.map(|timings| timings.span("retained-fences-before"));
    let projection = scope.projection;
    if let Some(directories) = &projection.directories {
        for directory in directories.iter() {
            directory.check()?;
        }
    }
    let mut parent_prefix = PathBuf::new();
    for name in &projection.names {
        name.check_with_parent_scratch(&projection.exclusions, &mut parent_prefix)?;
    }
    for pair in &projection.pairs {
        pair.recheck()?;
    }
    #[cfg(test)]
    drop(fence_span);
    #[cfg(test)]
    let preimages_span = timings.map(|timings| timings.span("fresh-preimages"));
    let mut scratch = Vec::new();
    // Producer provenance excludes consumed present and absent inputs. Unrelated
    // immutable leaves remain checked at complete boundaries; merging preserves
    // every original attempt for consumed rows and the current target.
    let mut required_reads = scope.required_reads(target);
    for required in required_reads.by_ref() {
        let read = required.classified.read;
        #[cfg(test)]
        {
            let deferred = required.deferred_before;
            if let Some(timings) = timings {
                if deferred != 0 {
                    timings.count("deferred-output-rows", deferred);
                }
                timings.count("fresh-preimage-attempts", 1);
                timings.count(
                    "fresh-preimage-expected-bytes",
                    read.expected.as_ref().map_or(0, Vec::len),
                );
                timings.count(
                    "current-target-attempts",
                    usize::from(target == Some(read.path.as_path())),
                );
            }
        }
        read.check_with_parent_scratch(&mut scratch, &mut parent_prefix)
            .inspect_err(|_| {
                #[cfg(test)]
                super::super::super::diagnostic::refusal(
                    "raw-scoped-input-body",
                    Some(&read.path),
                    None,
                );
            })?;
    }
    #[cfg(test)]
    if let Some(timings) = timings
        && required_reads.deferred_tail() != 0
    {
        timings.count("deferred-output-rows", required_reads.deferred_tail());
    }
    #[cfg(test)]
    drop(preimages_span);
    #[cfg(test)]
    let fence_span = timings.map(|timings| timings.span("retained-fences-after"));
    for name in &projection.names {
        name.check_with_parent_scratch(&projection.exclusions, &mut parent_prefix)?;
    }
    #[cfg(test)]
    drop(fence_span);
    #[cfg(test)]
    let _current_span = timings.map(|timings| timings.span("current-authority"));
    if let Some(current) = &projection.final_check {
        current.recheck().inspect_err(|_| {
            #[cfg(test)]
            super::super::super::diagnostic::refusal("raw-scoped-final-current", None, None);
        })?;
    }
    Ok(())
}

/// Retains ordinary syscall faults and handoffs with scoped Raw refreshes.
///
/// Raw preparation omits an earlier duplicate authority sample. Refusal order
/// may change, and transient faults restored before the retained inner checks
/// may be unobserved. Every actual sync still follows fresh authority checks.
///
/// # Errors
/// Refuses changed receipts or inputs, authority denial and syscall failures.
fn file_sync(
    scope: &DurabilityScope<'_>,
    file: &File,
    path: &Path,
    #[cfg(all(test, feature = "tokio"))] gates: &mut Vec<TestGate>,
    #[cfg(test)] timings: Option<&RawTimings>,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    if scope.faults.contains(&EffectFault::BeforeFileSync) {
        return Err(io::Error::other("injected creation file sync failure").into());
    }
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(gates, TestGatePhase::BeforeRawSyncRefresh)?;
    // The current file's same-descriptor whole checks remain in the caller.
    // Also read its full retained preimage before and after the actual syscall.
    refresh_target(
        scope,
        path,
        #[cfg(test)]
        timings,
    )?;
    #[cfg(test)]
    let syscall_span = timings.map(|timings| timings.span("file-sync-syscall"));
    #[cfg(test)]
    FILE_SYNC_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    file.sync_all()?;
    #[cfg(test)]
    drop(syscall_span);
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(gates, TestGatePhase::AfterSourceSync)?;
    refresh_target(
        scope,
        path,
        #[cfg(test)]
        timings,
    )?;
    #[cfg(test)]
    if scope.faults.contains(&EffectFault::AfterFileSync) {
        return Err(io::Error::other("injected creation failure after file sync").into());
    }
    Ok(())
}

fn refresh_target(
    scope: &DurabilityScope<'_>,
    path: &Path,
    #[cfg(test)] timings: Option<&RawTimings>,
) -> Result<(), NativeEffectFailure> {
    refresh_with_target(
        scope,
        Some(path),
        #[cfg(test)]
        timings,
    )
}

/// Retains directory receipts and current dependencies around actual durability.
///
/// # Errors
/// Refuses changed receipts, current inputs, handoff failures or sync failures.
fn directory_sync(
    scope: &DurabilityScope<'_>,
    directory: &NativeOpenedDirectory,
    #[cfg(all(test, feature = "tokio"))] gates: &mut Vec<TestGate>,
    #[cfg(test)] timings: Option<&RawTimings>,
) -> Result<(), NativeEffectFailure> {
    directory.check().inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-initial-check", None, None);
    })?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(gates, TestGatePhase::BeforeDirectorySync)?;
    #[cfg(test)]
    if scope.faults.contains(&EffectFault::BeforeDirectorySync)
        || scope
            .faults
            .contains(&EffectFault::BeforeDirectorySyncAt(directory.path.clone()))
    {
        return Err(io::Error::other("injected creation directory sync failure").into());
    }
    // Handoff may queue. Refresh all authority dependencies and retained
    // directory/name/pair fences before the syscall. Unrelated eligible leaves
    // receive their exhaustive checks at complete durability boundaries.
    refresh_with_target(
        scope,
        None,
        #[cfg(test)]
        timings,
    )
    .inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-before-refresh", None, None);
    })?;
    directory.check().inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-before-sync-check", None, None);
    })?;
    #[cfg(test)]
    let syscall_span = timings.map(|timings| timings.span("directory-sync-syscall"));
    directory.file.sync_all().inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-sync-syscall", None, None);
    })?;
    #[cfg(test)]
    drop(syscall_span);
    directory.check().inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-after-sync-check", None, None);
    })?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(gates, TestGatePhase::AfterDirectorySync)?;
    #[cfg(test)]
    if scope
        .faults
        .contains(&EffectFault::AfterDirectorySyncAt(directory.path.clone()))
    {
        return Err(io::Error::other("injected creation failure after directory sync").into());
    }
    refresh_with_target(
        scope,
        None,
        #[cfg(test)]
        timings,
    )
    .inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-after-refresh", None, None);
    })?;
    directory.check().inspect_err(|_| {
        #[cfg(test)]
        super::super::super::diagnostic::refusal("worker-directory-final-check", None, None);
    })?;
    Ok(())
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "scoped_raw_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "durability_tests.rs"]
mod classification_tests;

#[cfg(test)]
std::thread_local! {
    /// Counts actual scoped sync syscall entries on this worker thread.
    static FILE_SYNC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "tokio", unix))]
fn file_sync_attempts() -> usize {
    FILE_SYNC_ATTEMPTS.with(std::cell::Cell::get)
}
