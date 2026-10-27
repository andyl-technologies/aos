//! Observes genuine canonical read phases without changing their callbacks.
//!
//! This test-only state describes the current thread's existing checked edge.
//! It grants no operation, creates no native handle and never injects a poll.

use std::cell::Cell;

use super::SqliteBlobBackend;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    DiagnosticAdmitted,
    MetadataRowOpen,
}

std::thread_local! {
    static PHASE: Cell<Option<Phase>> = const { Cell::new(None) };
}

/// Restores the prior observation before native cleanup or an unwind escapes.
pub(super) struct Scope {
    previous: Option<Phase>,
}

impl Scope {
    // The caller already transferred the diagnostic loan into retain_failure.
    // This scope covers only its pre-native staging-gate boundary checks.
    pub(super) fn diagnostic_admitted() -> Self {
        Self::enter(Phase::DiagnosticAdmitted)
    }

    // Requiring the real fetched Row ties this observation to the live native
    // metadata cursor. The guard closes before that cursor's explicit cleanup.
    pub(super) fn metadata_row(_row: &rusqlite::Row<'_>) -> Self {
        Self::enter(Phase::MetadataRowOpen)
    }

    fn enter(phase: Phase) -> Self {
        Self {
            previous: PHASE.replace(Some(phase)),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        PHASE.set(self.previous);
    }
}

impl SqliteBlobBackend {
    /// Observes a paid diagnostic before the single-record native scope starts.
    pub(crate) fn canonical_read_diagnostic_admitted_for_test() -> bool {
        PHASE.get() == Some(Phase::DiagnosticAdmitted)
    }

    /// Observes the existing checked edge with an actual metadata row open.
    pub(crate) fn canonical_read_metadata_row_open_for_test() -> bool {
        PHASE.get() == Some(Phase::MetadataRowOpen)
    }
}
