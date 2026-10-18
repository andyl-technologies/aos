//! Names concrete heap layouts reached by historical native17 authentication.
//!
//! The caller independently bounds lexical occurrences before parsing. This
//! roster supplies the actual element and tree-node layouts for those counts;
//! it does not treat an inline root header as an array element or grant storage.
//! Root/Box payloads, overlapping parse/clone phases and canonical work remain
//! separate terms in the defining construction quote.

use std::alloc::Layout;
use std::mem::{align_of, size_of};

use crucible_node_contract::{
    ArtifactIdentity, ContentRef, Event, FacetSelection, HashRef, Id, NodeBinding,
    ObservationBatch, SchemaRef, U64,
};
use serde_json::Value;

use crate::ProviderError;
use crate::reference_packet::connected::{
    PacketConnectedPublication, PacketDeliveredInput, PacketPendingPublication, PacketReaction,
};
use crate::reference_packet::{PacketEvent, PacketPublication};
use crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data;

// Internally tagged ResponseShape and PacketNative5CaptureProfile deserialize
// through this real pinned serde buffer, including its sequence/map Vec banks.
// Naming the versioned export intentionally makes a serde upgrade recheck it.
type SerdeContent = serde::__private228::de::Content<'static>;

// IdSet is Vec<Id>. Bytes and every String use u8 backing. Nested binding and
// observation DTOs are inline in these concrete Vec slots, while arbitrary
// body/extension values retain their own recursive Value banks.
static ARRAY_ELEMENTS: [Layout; 19] = [
    Layout::new::<u8>(),
    Layout::new::<Value>(),
    Layout::new::<Id>(),
    Layout::new::<NodeBinding>(),
    Layout::new::<HashRef>(),
    Layout::new::<ContentRef>(),
    Layout::new::<ObservationBatch>(),
    Layout::new::<Event>(),
    Layout::new::<FacetSelection>(),
    Layout::new::<ArtifactIdentity>(),
    Layout::new::<SchemaRef>(),
    Layout::new::<PacketEvent>(),
    Layout::new::<PacketPublication>(),
    Layout::new::<PacketReaction>(),
    Layout::new::<PacketDeliveredInput>(),
    Layout::new::<PacketPendingPublication>(),
    Layout::new::<PacketConnectedPublication>(),
    Layout::new::<SerdeContent>(),
    Layout::new::<(SerdeContent, SerdeContent)>(),
];

/// Reports independent maxima for the closed typed allocation roster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoricalAuth17TypedLayouts {
    /// Bounds one concrete array slot, excluding its nested backing.
    pub(super) maximum_array_element_bytes: usize,
    /// Retains the greatest alignment required by an actual array element.
    pub(super) maximum_array_element_alignment: usize,
    /// Bounds one pinned BTree node across the actual key/value roster.
    pub(super) maximum_tree_node_bytes: usize,
    /// Retains the greatest alignment of those keys, values and node headers.
    pub(super) maximum_tree_node_alignment: usize,
}

/// Computes layouts without parsing source data or constructing a DTO.
///
/// Array slots cover all seven Begin argument/result alternatives because
/// decode_request validates that choice before historical transfer checks its
/// expected kind. The temporary observation uniqueness tree contains borrowed
/// producer IDs and their actual U64 sequence, rather than owned Id keys.
///
/// # Errors
/// Refuses overflow or an unsupported pinned BTree node-layout calculation.
pub(super) fn typed_layouts_data() -> Result<HistoricalAuth17TypedLayouts, ProviderError> {
    let mut maximum_array_element_bytes = 0;
    let mut maximum_array_element_alignment = 1;
    for element in &ARRAY_ELEMENTS {
        maximum_array_element_bytes = maximum_array_element_bytes.max(element.size());
        maximum_array_element_alignment = maximum_array_element_alignment.max(element.align());
    }

    // Map<String, Value> and Extensions both use the pinned BTreeMap backing.
    // ObservationBatch::validate uses BTreeSet<(&Id, U64)> with unit values.
    let value_tree = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
    let sequence_tree = original_serialization_tree_node_requested_bytes_data::<(&Id, U64), ()>()?;
    let maximum_tree_node_alignment = align_of::<String>()
        .max(align_of::<Value>())
        .max(align_of::<(&Id, U64)>())
        .max(align_of::<usize>());

    Ok(HistoricalAuth17TypedLayouts {
        maximum_array_element_bytes,
        maximum_array_element_alignment,
        maximum_tree_node_bytes: value_tree.max(sequence_tree),
        maximum_tree_node_alignment,
    })
}

/// Names only the concrete layout counter's explicit inline work views.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<HistoricalAuth17TypedLayouts>()
        + size_of::<Result<HistoricalAuth17TypedLayouts, ProviderError>>()
        + 6 * size_of::<usize>()
        + size_of::<std::slice::Iter<'static, Layout>>()
        + crate::retained_metadata::serialization_storage::
            original_serialization_tree_node_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_vector_requests_fit_the_independent_element_and_alignment_axes() -> TestResult {
        let maxima = typed_layouts_data()?;
        for repeated in [
            Layout::array::<NodeBinding>(3)?,
            Layout::array::<ObservationBatch>(3)?,
            Layout::array::<PacketConnectedPublication>(3)?,
            Layout::array::<(SerdeContent, SerdeContent)>(3)?,
        ] {
            assert!(repeated.size() <= 3 * maxima.maximum_array_element_bytes);
            assert!(repeated.align() <= maxima.maximum_array_element_alignment);
            assert_eq!(repeated.size() % repeated.align(), 0);
        }
        Ok(())
    }

    #[test]
    fn borrowed_sequence_keys_use_the_pinned_tree_layout_and_alignment() -> TestResult {
        let maxima = typed_layouts_data()?;
        let value_tree = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
        let sequence_tree =
            original_serialization_tree_node_requested_bytes_data::<(&Id, U64), ()>()?;
        assert!(maxima.maximum_tree_node_bytes >= value_tree);
        assert!(maxima.maximum_tree_node_bytes >= sequence_tree);
        assert!(maxima.maximum_tree_node_alignment >= align_of::<(&Id, U64)>());
        assert!(maxima.maximum_tree_node_alignment >= align_of::<usize>());
        assert!(maxima.maximum_tree_node_alignment.is_power_of_two());
        Ok(())
    }
}
