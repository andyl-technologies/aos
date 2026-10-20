//! Owns the Source provider's actual original writer and challenge custody.
//!
//! The held provider writer and separately held challenge file stay distinct.
//! Canonical codecs, floor unions, and saved-state comparisons remain in their
//! existing LedgerReplay engines; these wrappers preserve native currentness.

use std::collections::BTreeMap;

use aos_sandbox_core::RecordNamespace;

use super::{JournalError, JournalLimits};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

use aos_sandbox_ledger_replay::replay::source_original::union;
pub(super) mod challenge;
pub(super) mod replay;
pub(super) mod writer;

pub use challenge::{SourceOriginalChallengeCheckpointV5, SourceOriginalChallengeHistoryViewV5};
pub use replay::SourceOriginalPhysicalCutV5;
pub use writer::{
    OriginalSourceProtectedReadbackV5, PreparedOriginalSourceAppendV5,
    SourceOriginalAppendSubjectV5, SourceOriginalNativeJournalAuthorityV5,
    SourceOriginalReplayViewV5,
};
pub use aos_sandbox_ledger_replay::replay::source_original::union::{
    SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1, SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1,
    SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1, SourceCapacityStateV5,
    SourceOriginalAdmissionInputV5, SourceOriginalAdmissionDataV5,
    SourceCapacityUnionComparisonDataV5, compare_source_original_admission_data_v5,
    compare_source_capacity_union_data_v5, source_native_ordinary_capacity_request_v1,
    source_native_release_status_capacity_request_v1,
};

fn owner_views(state: &State) -> impl Iterator<Item = (&[u8], &[u8])> {
    aos_sandbox_ledger_replay::replay::source_original::owner_views(state)
}

fn bounded_snapshot_bytes(state: &State, limits: JournalLimits) -> Result<usize, JournalError> {
    aos_sandbox_ledger_replay::replay::source_original::bounded_snapshot_bytes(state, limits)
        .map_err(JournalError::from)
}

fn invalid(reason: &'static str) -> JournalError {
    aos_sandbox_ledger_replay::replay::source_original::invalid(reason).into()
}

#[cfg(test)]
pub(super) use aos_sandbox_ledger_replay::replay::source_original::tests;
