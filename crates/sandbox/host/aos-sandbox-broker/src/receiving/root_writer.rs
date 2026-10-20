//! Drives fixed Root native writers under the same permanent enrollment.
//!
//! Initial alone creates these trusted-coordinator ports after the real paired
//! startup handoff. No path, account, native tuple, parser result or success
//! scalar can construct one. Upper Root retains its exact semantic and complete
//! cumulative byte admissions around these mechanical stages; this native port
//! never pays an upper model or concludes a policy purpose.

mod coordinator;
mod compaction;
mod opening;
pub(in crate::receiving) mod recipe;
mod replay;

pub use compaction::{RootPreparedReplacementV1, RootReplacementFailureOriginalV1};
pub use coordinator::{RootAppendFailureOriginalV1, RootCoordinatorWriterV1, RootPreparedAppendV1, RootWriterPostOriginalV1};
pub use opening::RootWriterOpeningOriginalV1;
pub use replay::RootWriterReplayV1;

/// Preserves actual fixed Root native or invocation-stage refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootWriterErrorV1 {
    /// Preserves the same permanent invocation's refusal.
    #[error(transparent)]
    Invocation(#[from] super::RootObservationErrorV1),
    /// Preserves the mechanical stopping result beside its retained capture.
    #[error(transparent)]
    Native(#[from] crate::canonical_journal::NativeJournalDataErrorV1),
    /// Preserves the shared index-stage stopping result and original cause.
    #[error(transparent)]
    Indexed(#[from] crate::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1),
    /// Preserves the actual shared physical replacement stopping result.
    #[error(transparent)]
    Replacement(#[from] crate::canonical_journal::coordinator::replacement::CanonicalReplacementErrorV1),
    /// Rejects repeated, incomplete or foreign fixed-stage entry.
    #[error("fixed Root writer stage is closed")]
    Closed,
}

/// Returns the existing fixed authority-journal limits as comparison DATA.
///
/// This bound grants neither Root provenance nor permission to open a writer.
#[must_use]
pub fn root_authority_journal_limits_data_v1()
    -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits
{
    recipe::authority_limits()
}
