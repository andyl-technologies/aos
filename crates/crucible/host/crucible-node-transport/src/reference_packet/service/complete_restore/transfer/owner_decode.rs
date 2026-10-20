//! Counts the selected owner projector's requested storage before owned decoding.
//!
//! The scanner follows the audited selected archive preflight, with a fixed
//! 64-level stack and actual native DTO/map layouts. Its conservative banks are
//! named per simultaneous phase; this is neither a physical peak certificate nor
//! a source, ticket, upload or restoration permission.

use super::*;
use std::mem::{align_of, size_of};

#[path = "owner_decode/issuer_layout.rs"]
mod issuer_layout;

#[path = "owner_decode/selected_construction.rs"]
mod selected_construction;
pub use selected_construction::{
    PacketCompleteRestoreSelectedOwnerInputs,
    complete_restore_invocation_owner_construction_storage_data,
    complete_restore_selected_owner_construction_counter_scratch_data,
    complete_restore_selected_owner_construction_storage_data,
};

#[path = "owner_decode/observation_population.rs"]
mod observation_population;
pub use observation_population::{
    PacketCompleteRestoreModelOutputPopulationData,
    complete_restore_selected_model_output_population_counter_scratch_data,
    complete_restore_selected_model_output_population_data,
};

/// Reports named requested-layout terms for the complete owner-state projector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketCompleteRestoreOwnerValidationStorage {
    /// Covers the full native snapshot's DOM, typed and roundtrip projections.
    pub snapshot_bytes: usize,
    /// Covers the complete journal's DOM, typed and roundtrip projections.
    pub journal_bytes: usize,
    /// Covers the pending Control and complete model validation phases.
    pub control_bytes: usize,
    /// Covers all original spare vector capacities allocated by model adoption.
    pub model_vector_backing_bytes: usize,
    /// Covers the independently parsed anchor and its canonical comparison.
    pub anchor_bytes: usize,
    /// Covers the compiled bounded Capture request/terminal comparison banks.
    pub capture_comparison_bytes: usize,
    /// Covers declared scanner and original-byte framing scratch.
    pub declared_scanner_bytes: usize,
    /// Sums every named requested-layout term without including input banks.
    pub total_bytes: usize,
}

use crucible_source_birth_data::selected_decode::{
    Credit, Phases, exhausted, growth, map_node, mul, scan, sum,
};
pub(crate) use crucible_source_birth_data::selected_decode::{
    selected_native_dto_decode_storage_data, selected_value_decode_storage_data,
};

/// Counts complete selected input occurrences without building a JSON value.
///
/// Raw six-object input banks, sealed protocol owners, the retained Commit and
/// actual displaced model owners remain separate allocation terms. Three full
/// snapshot/journal DOM views cover the original DOM, typed Value children and
/// strict roundtrip comparison. Control uses its owning decoder's compiled phase
/// roster. Every duplicate key and empty container is counted before the strict
/// parser independently rejects malformed or noncanonical input.
///
/// # Errors
/// Refuses oversized selected inputs, excessive nesting, malformed framing,
/// arithmetic overflow or a total exceeding the signed model/Control budget.
pub fn complete_restore_owner_validation_storage_data(
    data: &PacketCompleteRestoreOwnerStateData<'_>,
) -> Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError> {
    data.request.validate_data()?;
    let allocation = &data.request.prepare.allocation;
    let maximum = usize::try_from(allocation.maximum_model_bytes.get()).map_err(|_| exhausted())?;
    let input_maximum =
        usize::try_from(allocation.maximum_input_bytes.get()).map_err(|_| exhausted())?;
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let typed_slot = layouts
        .maximum_typed_slot_bytes
        .max(size_of::<NativeSnapshotData>())
        // This is the actual edition12 DTO, including its independent full
        // registry reference. The raw scan below counts every added key/value
        // occurrence in all three DOM and both canonical comparison phases.
        .max(size_of::<SettledJournalData>())
        .max(size_of::<PacketCompleteRestoreOwnerProjection>());
    let typed_node = map_node(
        layouts.maximum_tree_key_value_bytes,
        layouts.maximum_tree_entry_alignment,
    )?;
    let roundtrip = Phases {
        dom: 3,
        typed: 1,
        canonical: 2,
    };
    let snapshot_bytes = scan(
        data.owner_state_bytes,
        input_maximum,
        typed_slot,
        typed_node,
    )?
    .requested(&roundtrip)?;
    let journal_bytes =
        scan(data.journal_bytes, input_maximum, typed_slot, typed_node)?.requested(&roundtrip)?;
    let control_bytes = scan(
        data.control_bytes,
        layouts.maximum_control_bytes.min(input_maximum),
        typed_slot,
        typed_node,
    )?
    .requested(&Phases {
        dom: layouts.maximum_simultaneous_control_dom_views,
        typed: layouts.maximum_simultaneous_typed_model_views,
        canonical: layouts.maximum_simultaneous_control_encoded_banks,
    })?;
    let model_vector_backing_bytes = model_capacity_backing(data.control_bytes, typed_slot)?;
    let anchor_bytes = scan(
        data.anchor_bytes,
        layouts.maximum_anchor_bytes.min(input_maximum),
        typed_slot,
        typed_node,
    )?
    .requested(&roundtrip)?;

    // These are the owning validator's compiled finite Capture-frame banks,
    // not a protocol P-derived allowance. Two canonical comparisons coexist;
    // strict typed/body parsing is already dominated by the Control phase.
    let capture_comparison_bytes = mul(growth(layouts.maximum_capture_request_bytes, 8)?, 2)?;
    let framing = crate::reference_packet::service::native_snapshot::packet_native_owned11_snapshot_validation_layouts();
    let declared_scanner_bytes = sum(&[
        size_of::<[u8; 64]>(),
        size_of::<Credit>(),
        size_of::<PacketCompleteRestoreOwnerValidationStorage>(),
        framing.plan_header_bytes,
        mul(
            framing.field_cursor_bytes,
            framing.maximum_simultaneous_field_cursors,
        )?,
        framing.field_scan_declared_array_bytes,
        framing.raw_chunk_array_bytes,
        framing.streaming_hash_header_bytes,
        framing.streaming_hash_output_bytes,
        framing.compact_plan_header_bytes,
    ])?;
    let total_bytes = sum(&[
        snapshot_bytes,
        journal_bytes,
        control_bytes,
        model_vector_backing_bytes,
        anchor_bytes,
        capture_comparison_bytes,
        declared_scanner_bytes,
    ])?;
    if total_bytes > maximum {
        return Err(exhausted());
    }
    Ok(PacketCompleteRestoreOwnerValidationStorage {
        snapshot_bytes,
        journal_bytes,
        control_bytes,
        model_vector_backing_bytes,
        anchor_bytes,
        capture_comparison_bytes,
        declared_scanner_bytes,
        total_bytes,
    })
}

// Recorded spare capacities affect future restoration allocations even when
// their vectors are currently empty. Syntax-node counts alone cannot cover them.
fn model_capacity_backing(
    control: &[u8],
    maximum_slot_bytes: usize,
) -> Result<usize, ProviderError> {
    use crate::protocol_snapshot::owned11::{
        OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
        original_owned11_unsigned as unsigned,
    };
    fn field<'a>(input: &'a [u8], wanted: &str) -> Result<&'a [u8], ProviderError> {
        let mut fields = Fields::object(input)?;
        let mut found = None;
        while let Some((key, value)) = fields.pair()? {
            if plain_string(key)? == wanted && found.replace(value).is_some() {
                return Err(exhausted());
            }
        }
        fields.finish()?;
        found.ok_or_else(exhausted)
    }
    let model = field(control, "model")?;
    let capacities = field(model, "capacities")?;
    let mut fields = Fields::object(capacities)?;
    let mut seen = [false; 6];
    let mut total = 0usize;
    while let Some((key, value)) = fields.pair()? {
        let index = match plain_string(key)? {
            "events" => 0,
            "reactions" => 1,
            "delivered_inputs" => 2,
            "publications" => 3,
            "outputs" => 4,
            "stages" => 5,
            _ => return Err(exhausted()),
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(exhausted());
        }
        let count = usize::try_from(unsigned(value)?).map_err(|_| exhausted())?;
        total = sum(&[total, mul(count, maximum_slot_bytes)?])?;
    }
    fields.finish()?;
    if seen.iter().any(|seen| !seen) {
        return Err(exhausted());
    }
    Ok(total)
}

/// Reports explicit fixed scanner, layout, result and nested sum headers.
///
/// This is the counter precredit for the actual helper below. It excludes
/// compiler/recursive frames, allocator metadata and all future decoded owners.
pub(crate) const fn selected_issuer_decode_counter_scratch_data() -> usize {
    size_of::<[u8; 64]>()
        + size_of::<Credit>()
        + size_of::<Phases>()
        + size_of::<crate::reference_packet::control::PacketControlSnapshotValidationLayouts>()
        + issuer_layout::counter_scratch_data()
        // Includes the new helpers' named DOM root-node width.
        + 13 * size_of::<usize>()
        + 3 * size_of::<std::alloc::Layout>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + 2 * size_of::<&[usize]>()
        + 2 * size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[u8]>()
}

/// Counts one closed native issuer decode using its actual selected type layouts.
///
/// This crate-private requested-storage component grants no allocation authority.
/// The true issuer conjoins it with the other simultaneous model-domain terms.
pub(crate) fn selected_issuer_decode_storage_data(
    bytes: &[u8],
    typed_slot: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let layouts = issuer_layout::project();
    scan(
        bytes,
        maximum,
        typed_slot.max(layouts.maximum_typed_slot_bytes),
        map_node(
            layouts.maximum_tree_key_value_bytes,
            layouts.maximum_tree_entry_alignment,
        )?,
    )?
    .requested(&Phases {
        dom: 1,
        typed: 1,
        canonical: 1,
    })
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed requested-storage data controls intentionally panic on failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn model_capacity_quote_counts_spare_empty_vectors_and_refuses_missing_roster() {
        let original = br#"{"model":{"capacities":{"events":3,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":4,"stages":0}}}"#;
        let slot = crate::reference_packet::control::packet_control_snapshot_validation_layouts()
            .maximum_typed_slot_bytes;
        assert_eq!(model_capacity_backing(original, slot).unwrap(), 7 * slot);
        assert!(model_capacity_backing(br#"{"model":{"capacities":{"events":0}}}"#, slot).is_err());
        assert!(model_capacity_backing(br#"{"model":{"capacities":{"events":0,"events":0,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":0,"stages":0}}}"#, slot).is_err());
    }

    #[test]
    fn model_capacity_quote_refuses_overflow_before_any_model_reservation() {
        let original = br#"{"model":{"capacities":{"events":18446744073709551615,"reactions":0,"delivered_inputs":0,"publications":0,"outputs":0,"stages":0}}}"#;
        assert!(model_capacity_backing(original, 2).is_err());
        assert!(model_capacity_backing(br#"{"model":{"capacities":{"events":-1}}}"#, 2).is_err());
    }

    #[test]
    fn actual_value_quote_covers_two_empty_scalar_container_and_escape_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
        for raw in [
            b"{}".as_slice(),
            b"[]",
            b"null",
            b"0",
            br#""""#,
            br#"{"a":[0,1,2],"b":{"quoted":"\u0000\n\"\\\uD834\uDD1E"}}"#,
        ] {
            let original = canonical::parse_json(raw, raw.len())?;
            let independent = original.clone();
            let mut a = MetadataObserver::new();
            a.observe(&original)?;
            let mut b = MetadataObserver::new();
            b.observe(&independent)?;
            let bank = canonical::canonical_json(&independent)?;
            let actual = sum(&[
                requested_metadata_backing_storage_data(&a.finish())?,
                requested_metadata_backing_storage_data(&b.finish())?,
                bank.capacity(),
                2 * size_of::<Value>(),
            ])?;
            let quoted = selected_value_decode_storage_data(raw, usize::MAX)?;
            assert!(quoted >= actual);
            assert!(quoted >= 2 * size_of::<Value>());
        }
        Ok(())
    }

    #[test]
    fn value_quote_exact_one_short_raw_cap_and_depth_limits_refuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = br#"{"schema":"a","values":["one","two",{},[]]}"#;
        let quote = selected_value_decode_storage_data(input, usize::MAX)?;
        assert_eq!(selected_value_decode_storage_data(input, quote)?, quote);
        assert!(selected_value_decode_storage_data(input, quote - 1).is_err());
        assert!(selected_value_decode_storage_data(input, input.len() - 1).is_err());
        let deep = format!("{}null{}", "[".repeat(65), "]".repeat(65));
        assert!(selected_value_decode_storage_data(deep.as_bytes(), usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn value_and_native_dto_quotes_cover_independent_nested_empty_maps()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
        let value_node = map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>(),
        )?;
        for raw in [
            b"{}".as_slice(),
            b"[]",
            br#"{"a":{}}"#,
            br#"{"a":[{},{}],"b":{}}"#,
            br#"[{}, {"a":{}}, []]"#,
        ] {
            let original = canonical::parse_json(raw, raw.len())?;
            let independent = original.clone();
            let mut original_walk = MetadataObserver::new();
            original_walk.observe(&original)?;
            let original_facts = original_walk.finish();
            let mut independent_walk = MetadataObserver::new();
            independent_walk.observe(&independent)?;
            let independent_facts = independent_walk.finish();
            let bank = canonical::canonical_json(&independent)?;
            let actual = sum(&[
                requested_metadata_backing_storage_data(&original_facts)?,
                requested_metadata_backing_storage_data(&independent_facts)?,
                bank.capacity(),
                2 * size_of::<Value>(),
            ])?;
            let credit = scan(raw, usize::MAX, size_of::<Value>(), value_node)?;
            assert_eq!(credit.object_roots, original_facts.tree_containers);
            assert_eq!(credit.object_roots, independent_facts.tree_containers);
            assert!(selected_value_decode_storage_data(raw, usize::MAX)? >= actual);
            assert!(
                selected_native_dto_decode_storage_data(raw, size_of::<Value>(), usize::MAX)?
                    >= actual
            );
        }
        Ok(())
    }

    #[test]
    fn native_dto_object_root_quote_preserves_exact_and_one_short_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw = br#"{"a":[{},{}],"b":{"c":{}}}"#;
        let quoted = selected_native_dto_decode_storage_data(raw, size_of::<Value>(), usize::MAX)?;
        assert_eq!(
            selected_native_dto_decode_storage_data(raw, size_of::<Value>(), quoted)?,
            quoted
        );
        assert!(
            selected_native_dto_decode_storage_data(raw, size_of::<Value>(), quoted - 1).is_err()
        );
        Ok(())
    }
}
