//! Supplies actual original-publication layouts without moving native owners.
//!
//! Only nonfallible compiled facts join the immutable report. The capture-owner
//! query stays at the completed-owner element and the final fixed-counter query
//! stays at the original result initializer; neither is hoisted into project.

use super::*;
use crucible_node_format::{ContentRef, Id};
use crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report::ReportCacheTreeLayoutData;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_layout::OriginalReportFixedLayoutData;

pub(super) fn project() -> OriginalReportFixedLayoutData {
    OriginalReportFixedLayoutData {
        produced_receipt_bytes: size_of::<crate::reference_packet::control::ProducedOriginalObserveReceipt>(),
        observe_result_bytes: size_of::<crate::bodies::ObserveResult>(),
        observation_batch_bytes: size_of::<crucible_node_format::ObservationBatch>(),
        capture_report_bytes: size_of::<crate::reference_packet::service::capture_allocation::PacketNativeCaptureAllocationReport>(),
        content_ref_bytes: size_of::<ContentRef>(),
        content_entry_bytes: size_of::<(ContentRef, Vec<u8>)>(),
        hasher_bytes: size_of::<blake3::Hasher>(),
    }
}

pub(super) fn capture_owner_bytes_data() -> usize {
    crate::reference_packet::endpoint::original_capture_report_owner_layout_data()
}

pub(super) fn counter_output_data() -> usize {
    original_report_startup_counter_scratch_data()
}

// New initialized/returned and caller-retained DATA plus the two actual
// forwarding return headers. The defining counter prices its own array growth.
pub(super) const fn counter_scratch_data() -> usize {
    size_of::<OriginalReportFixedLayoutData>()
        + size_of::<OriginalReportFixedLayoutData>()
        + size_of::<usize>()
        + size_of::<usize>()
}

#[cfg(test)]
#[path = "layout/original.rs"]
mod original;

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;

/// Reads the genuine private cache key/value layouts at the original tree slot.
pub(super) fn cache_tree_layout_data() -> ReportCacheTreeLayoutData {
    use std::mem::align_of;

    type CacheValue = (
        crucible_node_format::HashRef,
        crate::reference_packet::control::PacketControlReply,
    );

    ReportCacheTreeLayoutData {
        key_bytes: size_of::<Id>(),
        value_bytes: size_of::<CacheValue>(),
        key_alignment: align_of::<Id>(),
        value_alignment: align_of::<CacheValue>(),
    }
}
