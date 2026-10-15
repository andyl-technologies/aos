//! Records bounded numeric diagnostics without retaining native observations.

use std::{
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Selects an inclusive numeric group; parent and child totals overlap.
#[derive(Clone, Copy)]
pub(in super::super) enum Group {
    /// Includes all existing association checks and refreshes.
    Association,
    /// Includes only immutable expected-lineage lookup and computation.
    ExpectedLineage,
    /// Includes only hashing exact immutable expected lineage bytes.
    LineageHash,
    /// Includes only the canonical expected-lineage decoder call.
    LineageDecode,
}

#[derive(Clone, Copy, Default)]
struct Aggregate {
    attempts: u64,
    completed: u64,
    refused: u64,
    unclassified: u64,
    bytes: u64,
    elapsed: Duration,
}

#[derive(Default)]
struct Totals {
    groups: [Aggregate; 4],
    sources: usize,
    preimages: usize,
    records: usize,
    directories: usize,
}

struct State {
    totals: Mutex<Totals>,
    lost: AtomicU64,
}

impl State {
    fn update(&self, update: impl FnOnce(&mut Totals)) {
        if let Ok(mut totals) = self.totals.try_lock() {
            update(&mut totals);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Owns one fixed operation summary, with no authority or native evidence.
pub(in super::super) struct Trace {
    active: Option<(crate::diagnostic_clock::Tick, Arc<State>)>,
    role: &'static str,
    boundary: Option<u8>,
    completed: bool,
}

impl Trace {
    /// Starts only the existing stages diagnostic; absence samples no clock.
    pub(in super::super) fn new(role: &'static str, boundary: Option<u8>) -> Self {
        let enabled = std::env::var_os("TERRANE_REF_PHASE_TRACE").as_deref()
            == Some(std::ffi::OsStr::new("stages"));
        let trace = Self {
            active: enabled.then(|| {
                (
                    crate::diagnostic_clock::tick(),
                    Arc::new(State {
                        totals: Mutex::new(Totals::default()),
                        lost: AtomicU64::new(0),
                    }),
                )
            }),
            role,
            boundary,
            completed: false,
        };
        trace.mark("entry");
        trace
    }

    /// Emits a fixed phase marker without inspecting repository state.
    pub(in super::super) fn mark(&self, phase: &'static str) {
        let Some((started, _)) = &self.active else {
            return;
        };
        let at = crate::diagnostic_clock::tick();
        let _ = writeln!(
            std::io::stderr().lock(),
            "native-cost role={} boundary={:?} phase={phase} process_at={at:?} elapsed={:?}",
            self.role,
            self.boundary,
            at.saturating_sub(*started),
        );
    }

    /// Copies source pairs, preimages, retirement records and scoped directories.
    ///
    /// Ownership workers leave the inapplicable source/retirement counts zero.
    pub(in super::super) fn inventory(
        &self,
        sources: usize,
        preimages: usize,
        records: usize,
        directories: usize,
    ) {
        if let Some((_, state)) = &self.active {
            state.update(|totals| {
                totals.sources = sources;
                totals.preimages = preimages;
                totals.records = records;
                totals.directories = directories;
            });
        }
    }

    /// Starts one aggregate span; byte volume counts actual hash/decode inputs.
    pub(in super::super) fn span(&self, group: Group, bytes: usize) -> Option<Span> {
        let (_, state) = self.active.as_ref()?;
        state.update(|totals| {
            let total = &mut totals.groups[group as usize];
            total.attempts = total.attempts.saturating_add(1);
            total.bytes = total.bytes.saturating_add(bytes as u64);
        });
        Some(Span {
            state: Arc::clone(state),
            group,
            started: crate::diagnostic_clock::tick(),
            outcome: None,
        })
    }

    /// Marks only the actual successful endpoint of the owning operation.
    pub(in super::super) fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        let Some((started, state)) = &self.active else {
            return;
        };
        let at = crate::diagnostic_clock::tick();
        // Even a poisoned observer must release its lock before output.
        let snapshot = state.totals.try_lock().ok().map(|totals| {
            (
                totals.groups,
                (
                    totals.sources,
                    totals.preimages,
                    totals.records,
                    totals.directories,
                ),
            )
        });
        let Some((groups, inventory)) = snapshot else {
            let _ = writeln!(
                std::io::stderr().lock(),
                "native-cost role={} boundary={:?} phase=summary unavailable=true completed={} process_at={at:?}",
                self.role,
                self.boundary,
                self.completed,
            );
            return;
        };
        // Copy only fixed numeric state before writing. No observer lock is
        // held during output, and loss makes incomplete counts explicit.
        let rows = groups.map(|row| {
            (
                row.attempts,
                row.completed,
                row.refused,
                row.unclassified,
                row.bytes,
                row.elapsed,
            )
        });
        let _ = writeln!(
            std::io::stderr().lock(),
            "native-cost role={} boundary={:?} phase=summary completed={} exited_unclassified={} process_at={at:?} elapsed={:?} inventory_s_p_r_u={inventory:?} inclusive_overlapping_association_lineage_hash_decode={rows:?} fields=attempts,completed,refused,exited_unclassified,input_bytes,elapsed lost={}",
            self.role,
            self.boundary,
            self.completed,
            !self.completed,
            at.saturating_sub(*started),
            state.lost.load(Ordering::Relaxed),
        );
    }
}

/// Transfers only one numeric span's duration and actual endpoint outcome.
pub(in super::super) struct Span {
    state: Arc<State>,
    group: Group,
    started: crate::diagnostic_clock::Tick,
    outcome: Option<bool>,
}

impl Span {
    /// Records an actual returned result, never inferring early-exit errors.
    pub(in super::super) fn finish_result<T, E>(&mut self, result: &Result<T, E>) {
        self.outcome = Some(result.is_ok());
    }

    /// Marks a computation which actually reached its successful endpoint.
    pub(in super::super) fn complete(&mut self) {
        self.outcome = Some(true);
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = crate::diagnostic_clock::elapsed(self.started);
        self.state.update(|totals| {
            let total = &mut totals.groups[self.group as usize];
            total.elapsed = total.elapsed.saturating_add(elapsed);
            let count = match self.outcome {
                Some(true) => &mut total.completed,
                Some(false) => &mut total.refused,
                None => &mut total.unclassified,
            };
            *count = count.saturating_add(1);
        });
    }
}
