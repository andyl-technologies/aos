//! Conservative semantic representation geometry for initial Native replay.
//!
//! The parser keeps its existing domains and validation order. This prices
//! those domains from the genuinely held prefix, without multiplying an absent
//! advertised tail. It is DATA; only the original role receiver can admit the
//! same staged opening before its argument-free semantic continuation.

use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::framing::HEADER_BYTES;
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    StoredRecordV2, InventoryCorrelationV2, ProjectionEntryV2, ProviderAttemptStateV2,
    native_held_completion::{RootNativeHeldSidecarV1, RootNativeHeldSidecarV2,
                            RootNativeReconstructedCutV1},
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1,
    frame::{NativeHeldSectionV1, SignedNativeHeldControlV1},
};

use super::{JournalError, ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_ledger_replay::replay::phase_records::{
    RootFirstSourceSuccessorIntentV2, RootFirstSourceSuccessorFloorV2, SourceFirstSuccessorReceiptV2, SourceFirstSuccessorPendingV2, SourceFirstSuccessorAckV2,
};
use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1,
};

// The maximum applies per possible Native record, never per encoded byte.
// The actual enum retains its largest permitted variant already; none of these
// widths assumes an allocator layout or uses an unrelated Session schema.
pub(crate) fn native_semantic_row_widths_v1() -> Result<[usize; 8], JournalError> {
    aos_sandbox_ledger_replay::geometry::semantic_rows::native_semantic_row_widths_v1().map_err(JournalError::from)
}



// The SAME representation recipe can price generic append validators that
// inspect a healthy original materialized map rather than replaying history.
// Actual callers supply their retained map's encoded extent and reached cells;
// this pure function authenticates neither map nor payer and performs no IO.
pub(crate) fn semantic_representation_demand_v1(
    encoded: usize,
    rows: usize,
) -> Result<ResourceVector, JournalError> {
    let semantic = aos_sandbox_ledger_replay::geometry::semantic_rows::
        semantic_representation_demand_v1(encoded, rows).map_err(JournalError::from)?;
    semantic.checked_add(super::original_currentness::native_audit_fixed_receiving_demand_v1()?)
        .map_err(|_| JournalError::LimitExceeded("native history observer representation"))
}
