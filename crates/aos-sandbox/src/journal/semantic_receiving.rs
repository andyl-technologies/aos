//! Conservative semantic representation geometry for initial Native replay.
//!
//! The parser keeps its existing domains and validation order. This prices
//! those domains from the genuinely held prefix, without multiplying an absent
//! advertised tail. It is DATA; only the original role receiver can admit the
//! same staged opening before its argument-free semantic continuation.

use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
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
use crate::policy_compiler::{
    RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1,
};

// The maximum applies per possible Native record, never per encoded byte.
// The actual enum retains its largest permitted variant already; none of these
// widths assumes an allocator layout or uses an unrelated Session schema.
pub(crate) fn native_semantic_row_widths_v1() -> Result<[usize; 8], JournalError> {
    aos_sandbox_ledger_replay::geometry::semantic_rows::native_semantic_row_widths_v1().map_err(JournalError::from)
}

impl ProtectedJournalPreopenReplayExtentV1 {
    /// Prices initial replay's canonical models, graph copies and encoded work.
    ///
    /// A completed semantic record needs a complete native header. The actual
    /// held prefix therefore bounds possible rows even for malformed history;
    /// a BEGIN or partial payload receives no semantic expansion until a full
    /// frame exists. The shared Native demand separately prices those complete
    /// advertised negative reservations, including at an empty prefix.
    ///
    /// Thirty-two simultaneous row slots conservatively cover the live and
    /// prospective maps, capacity-family vectors, Root canonical and legacy
    /// graphs, optional v1 diagnostics, the two reconstructed cuts, response
    /// projection, rederived transition maps and their comparison/key sets.
    /// The largest relevant row includes the fixed twelve-control, three-section
    /// nested archive geometry. Source initial replay has no external challenge
    /// history and does not enter its separate physical-history cache path.
    ///
    /// The 128 encoded copies cover owned byte/string collections, geometric
    /// spare capacity, JSON/hex reencoding, nested canonical archives and the
    /// simultaneous graph/prospective/transition copies. Binary catalog and
    /// inventory decoders check complete count-derived byte lengths before
    /// allocation; native suffix counts and sections have fixed 12/3 limits.
    /// Strict decoder limits and the genuine service cgroup cover residual
    /// parser, allocator metadata, page faults and kernel residency (RFC-0006).
    ///
    /// This intentionally refuses some large native histories under a smaller
    /// whole-service envelope. It never selects a cheaper parser or drops an
    /// existing namespace, validator, recovery rule or first cause.
    ///
    /// # Errors
    /// Rejects inconsistent bounds or checked representation overflow.
    pub fn dominant_semantic_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("native semantic receiving demand");
        if self.native_bytes > self.limits.maximum_journal_bytes {
            return Err(invalid());
        }
        let physical = usize::try_from(self.native_bytes).map_err(|_| invalid())?;
        let rows = physical.checked_div(HEADER_BYTES).ok_or_else(invalid)?;
        semantic_representation_demand_v1(physical, rows)
    }
}

// The SAME representation recipe can price generic append validators that
// inspect a healthy original materialized map rather than replaying history.
// Actual callers supply their retained map's encoded extent and reached cells;
// this pure function authenticates neither map nor payer and performs no IO.
pub(super) fn semantic_representation_demand_v1(
    encoded: usize,
    rows: usize,
) -> Result<ResourceVector, JournalError> {
    let semantic = aos_sandbox_ledger_replay::geometry::semantic_rows::
        semantic_representation_demand_v1(encoded, rows).map_err(JournalError::from)?;
    semantic.checked_add(super::original_currentness::native_audit_fixed_receiving_demand_v1()?)
        .map_err(|_| JournalError::LimitExceeded("native history observer representation"))
}
