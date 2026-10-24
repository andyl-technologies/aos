//! Projects the original generic issuer's genuine upper compiled layouts.
//!
//! The owning Control/model query retains all private types and sizeof/alignof
//! operations. Only the same three immutable layout facts cross into lower DATA;
//! no population ceiling, native grant or requested-storage row is substituted.

use crucible_source_birth_data::profile::reference_packet::service::native_startup::issuer_layout::IssuerDecodeLayoutData;
use std::mem::size_of;

pub(super) fn project() -> IssuerDecodeLayoutData {
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    IssuerDecodeLayoutData {
        maximum_typed_slot_bytes: layouts.maximum_typed_slot_bytes,
        maximum_tree_key_value_bytes: layouts.maximum_tree_key_value_bytes,
        maximum_tree_entry_alignment: layouts.maximum_tree_entry_alignment,
    }
}

// The original full Control layout record stays named by the inherited counter.
// These are the new supplier's initialized/returned DATA and caller-retained DATA.
pub(super) const fn counter_scratch_data() -> usize {
    size_of::<IssuerDecodeLayoutData>() + size_of::<IssuerDecodeLayoutData>()
}

#[cfg(test)]
#[path = "issuer_layout/tests.rs"]
mod tests;
