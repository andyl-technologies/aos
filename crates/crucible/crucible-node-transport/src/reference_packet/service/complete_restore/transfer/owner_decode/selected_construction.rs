//! Quotes selected outer13 model work before a Prepare or Commit DTO exists.
//!
//! The raw-before protocol and endpoint leaves remain original bytes. Their
//! independent full inner14 reconstruction is a separate native plan term; this
//! projection never parses or canonicalizes them as a generic JSON snapshot.

use super::*;
use crate::reference_packet::service::native_snapshot::{
    PacketNativeOwned13SnapshotPlan, PacketNativeOwned14SnapshotPlan,
    packet_native_owned13_snapshot_validation_layouts,
    packet_native_owned14_snapshot_validation_layouts,
};

/// Borrows actual signed selected owner bodies for prospective DATA counting.
///
/// These byte views and limits cannot create a source, ticket, native lease or
/// allocation grant. The installed Core action authenticates the same archive
/// owner and conjoins every other simultaneous original before construction.
pub struct PacketCompleteRestoreSelectedOwnerInputs<'a> {
    /// Borrows the exact signed outer13 owner snapshot, retaining raw before bytes.
    pub owner_state: &'a [u8],
    /// Borrows its same source settlement journal including the full registry role.
    pub journal: &'a [u8],
    /// Borrows the exact separately transferred pending Control/model body.
    pub control: &'a [u8],
    /// Borrows the exact unchanged-cut anchor body.
    pub anchor: &'a [u8],
    /// Bounds actual raw traversal under the independently admitted archive policy.
    pub maximum_input_bytes: usize,
    /// Bounds the raw-before bank under that actual selected profile.
    pub maximum_before_bytes: usize,
    /// Bounds this complete future model/Control construction DATA row.
    pub maximum_requested_bytes: usize,
}

/// Names explicit fixed selected-plan, scanner and row views before observation.
///
/// Recursive/compiler frames and allocator physical overhead remain separate.
pub fn complete_restore_selected_owner_construction_counter_scratch_data() -> usize {
    let old = packet_native_owned13_snapshot_validation_layouts();
    let selected = packet_native_owned14_snapshot_validation_layouts();
    // Both real parsers use the same closed Fields/compact families. Their
    // separately declared arrays may differ; select each larger real term.
    let mut framing = old;
    framing.plan_header_bytes = old.plan_header_bytes.max(selected.plan_header_bytes);
    framing.field_cursor_bytes = old.field_cursor_bytes.max(selected.field_cursor_bytes);
    framing.maximum_simultaneous_field_cursors = old
        .maximum_simultaneous_field_cursors
        .max(selected.maximum_simultaneous_field_cursors);
    framing.field_scan_declared_array_bytes = old
        .field_scan_declared_array_bytes
        .max(selected.field_scan_declared_array_bytes);
    framing.raw_chunk_array_bytes = old
        .raw_chunk_array_bytes
        .max(selected.raw_chunk_array_bytes);
    framing.streaming_hash_header_bytes = old
        .streaming_hash_header_bytes
        .max(selected.streaming_hash_header_bytes);
    framing.streaming_hash_output_bytes = old
        .streaming_hash_output_bytes
        .max(selected.streaming_hash_output_bytes);
    framing.compact_plan_header_bytes = old
        .compact_plan_header_bytes
        .max(selected.compact_plan_header_bytes);
    super::super::selected_owner_counter_scratch_data()
        + size_of::<PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + size_of::<&[u8]>()
        + size_of::<&Phases>()
        + size_of::<[usize; 3]>()
        + size_of::<PacketNativeOwned13SnapshotPlan<'static>>()
        + size_of::<PacketNativeOwned14SnapshotPlan<'static>>()
        + size_of::<[&[u8]; 3]>()
        + 3 * size_of::<crate::reference_packet::service::native_snapshot::PacketNativeOwned11SnapshotValidationLayouts>()
        + size_of::<PacketCompleteRestoreOwnerValidationStorage>()
        + 2 * size_of::<Credit>()
        + 2 * size_of::<Phases>()
        + size_of::<[u8; 64]>()
        + size_of::<[usize; 7]>()
        + size_of::<std::array::IntoIter<usize, 7>>()
        + size_of::<[&[u8]; 3]>()
        + size_of::<std::array::IntoIter<&[u8], 3>>()
        + framing.plan_header_bytes
        + framing.field_cursor_bytes * framing.maximum_simultaneous_field_cursors
        + framing.field_scan_declared_array_bytes
        + framing.raw_chunk_array_bytes
        + framing.streaming_hash_header_bytes
        + framing.streaming_hash_output_bytes
        + framing.compact_plan_header_bytes
}

/// Counts actual selected owner occurrences and model spare capacities as DATA.
///
/// The old complete11 estimator and decoder remain unchanged. This selected
/// projection traverses only the JSON fields that its new owning decoder must
/// construct: Capture arguments/request/reference, journal, Control/model and
/// anchor. Raw protocol/endpoint/report originals are not replaced with a DOM;
/// full protocol/report reconstruction and authentication remain separate rows.
/// No JSON value, DTO, frame, digest bank or allocation permission is created.
///
/// # Errors
/// Refuses malformed outer13 framing, changed embedded Control, unsupported
/// bounds, malformed bounded JSON/model capacities, overflow or excess demand.
pub fn complete_restore_selected_owner_construction_storage_data(
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
) -> Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError> {
    if inputs.maximum_input_bytes == 0
        || inputs.maximum_before_bytes == 0
        || inputs.maximum_requested_bytes == 0
    {
        return Err(exhausted());
    }
    let plan = PacketNativeOwned13SnapshotPlan::validate(
        inputs.owner_state,
        inputs.maximum_input_bytes,
        inputs.maximum_before_bytes,
    )?;
    selected_owner_storage(
        inputs,
        plan.control_bytes(),
        [
            plan.capture_arguments_bytes(),
            plan.capture_request_bytes(),
            plan.control_reference_bytes(),
        ],
    )
}

/// Counts the explicit outer14/full inner15 original-invocation owner as DATA.
///
/// The complete borrowed outer14 plan validates the actual class framing and
/// original Report dependency. Raw native-before/report/endpoint bytes are not
/// parsed as a generic snapshot DTO. Their genuine inner15 cold reconstruction
/// remains a separately admitted row. No target or restoration right is issued.
///
/// # Errors
/// Refuses invalid outer14 framing, a changed embedded Control, unavailable
/// finite bounds, unsupported model capacities, overflow or excess demand.
pub fn complete_restore_invocation_owner_construction_storage_data(
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
) -> Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError> {
    if inputs.maximum_input_bytes == 0
        || inputs.maximum_before_bytes == 0
        || inputs.maximum_requested_bytes == 0
    {
        return Err(exhausted());
    }
    let plan = PacketNativeOwned14SnapshotPlan::validate(
        inputs.owner_state,
        inputs.maximum_input_bytes,
        inputs.maximum_before_bytes,
    )?;
    selected_owner_storage(
        inputs,
        plan.control_bytes(),
        [
            plan.capture_arguments_bytes(),
            plan.capture_request_bytes(),
            plan.control_reference_bytes(),
        ],
    )
}

fn selected_owner_storage(
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
    control: &[u8],
    capture_parts: [&[u8]; 3],
) -> Result<PacketCompleteRestoreOwnerValidationStorage, ProviderError> {
    if control != inputs.control {
        return Err(exhausted());
    }
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let typed_slot = layouts
        .maximum_typed_slot_bytes
        .max(size_of::<Envelope>())
        .max(size_of::<CaptureArguments>())
        .max(size_of::<crate::bodies::BeginRequest>())
        .max(size_of::<crate::bodies::BeginArguments>())
        .max(size_of::<ContentRef>())
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
    let mut snapshot_bytes = 0usize;
    for bytes in capture_parts {
        snapshot_bytes = sum(&[
            snapshot_bytes,
            phase_storage(
                bytes,
                inputs.maximum_input_bytes,
                typed_slot,
                typed_node,
                &roundtrip,
            )?,
        ])?;
    }
    // The selected owning decoder additionally calls decode_request(Begin)
    // and BeginRequest::decoded_arguments. These are independent from the
    // roundtrip decoders above: object() clones its map twice, retains canonical
    // bytes, and owns a typed DTO; Begin validation also decodes Capture. The
    // additional typed copies name the sorted-ID validator's real clone keys.
    snapshot_bytes = sum(&[
        snapshot_bytes,
        selected_begin_decoder_storage(
            capture_parts,
            inputs.maximum_input_bytes,
            typed_slot,
            typed_node,
        )?,
    ])?;
    let journal_bytes = phase_storage(
        inputs.journal,
        inputs.maximum_input_bytes,
        typed_slot,
        typed_node,
        &roundtrip,
    )?;
    let control_bytes = phase_storage(
        inputs.control,
        layouts
            .maximum_control_bytes
            .min(inputs.maximum_input_bytes),
        typed_slot,
        typed_node,
        &Phases {
            dom: layouts.maximum_simultaneous_control_dom_views,
            typed: layouts.maximum_simultaneous_typed_model_views,
            canonical: layouts.maximum_simultaneous_control_encoded_banks,
        },
    )?;
    let model_vector_backing_bytes = model_capacity_backing(inputs.control, typed_slot)?;
    let anchor_bytes = anchor_storage(
        inputs.anchor,
        layouts.maximum_anchor_bytes.min(inputs.maximum_input_bytes),
        typed_slot,
        typed_node,
        &roundtrip,
    )?;
    let capture_comparison_bytes = mul(growth(layouts.maximum_capture_request_bytes, 8)?, 2)?;
    let declared_scanner_bytes =
        complete_restore_selected_owner_construction_counter_scratch_data();
    let total_bytes = sum(&[
        snapshot_bytes,
        journal_bytes,
        control_bytes,
        model_vector_backing_bytes,
        anchor_bytes,
        capture_comparison_bytes,
        declared_scanner_bytes,
    ])?;
    if total_bytes > inputs.maximum_requested_bytes {
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

// Counts the two actual public body decoder families before their first clone.
// The full request is a conservative superset of the actual Begin body map;
// raw protocol/endpoint bytes are never included in this JSON decoder phase.
fn selected_begin_decoder_storage(
    parts: [&[u8]; 3],
    maximum: usize,
    typed_slot: usize,
    typed_node: usize,
) -> Result<usize, ProviderError> {
    sum(&[
        phase_storage(
            parts[1],
            maximum,
            typed_slot,
            typed_node,
            &Phases {
                dom: 2,
                typed: 1,
                canonical: 1,
            },
        )?,
        phase_storage(
            parts[0],
            maximum,
            typed_slot,
            typed_node,
            &Phases {
                dom: 4,
                typed: 4,
                canonical: 2,
            },
        )?,
        size_of::<crate::bodies::RequestBody>(),
        size_of::<crate::bodies::BeginRequest>(),
        size_of::<crate::bodies::BeginArguments>(),
        size_of::<Result<crate::bodies::RequestBody, ProviderError>>(),
        size_of::<Result<crate::bodies::BeginArguments, crucible_node_format::ContractError>>(),
    ])
}

// The anchor follows the same independent decode/typed/roundtrip phases as
// the other selected bodies. Empty nested objects still retain their roots.
fn anchor_storage(
    bytes: &[u8],
    maximum: usize,
    typed_slot: usize,
    typed_node: usize,
    phases: &Phases,
) -> Result<usize, ProviderError> {
    phase_storage(bytes, maximum, typed_slot, typed_node, phases)
}

// Explicit roots close the empty-object case independently of property entries.
// Every object may be retained in a Value or rebuilt inside a typed model; no
// unrelated DTO slot, nonempty map population or model-capacity slack funds it.
fn phase_storage(
    bytes: &[u8],
    maximum: usize,
    typed_slot: usize,
    typed_node: usize,
    phases: &Phases,
) -> Result<usize, ProviderError> {
    let credit = scan(bytes, maximum, typed_slot, typed_node)?;
    let value_node = map_node(
        size_of::<String>() + size_of::<Value>(),
        align_of::<Value>(),
    )?;
    sum(&[
        credit.requested(phases)?,
        mul(phases.dom, mul(credit.object_roots, value_node)?)?,
        mul(phases.typed, mul(credit.object_roots, typed_node)?)?,
        mul(phases.dom, size_of::<Value>())?,
    ])
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Data controls fail loudly on a false bound.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn selected_model_phase_funds_nested_empty_object_roots_and_all_dom_views() {
        use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
        let phases = Phases {
            dom: 3,
            typed: 1,
            canonical: 2,
        };
        let node = map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>(),
        )
        .unwrap();
        for bytes in [b"{}".as_slice(), br#"{"a":{},"b":[{},{}]}"#] {
            let actual: Value = serde_json::from_slice(bytes).unwrap();
            let mut observer = MetadataObserver::new();
            observer.observe(&actual).unwrap();
            let backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
            let selected = phase_storage(bytes, 4096, size_of::<Value>(), node, &phases).unwrap();
            let roots = scan(bytes, 4096, size_of::<Value>(), node)
                .unwrap()
                .object_roots;

            assert!(roots > 0);
            assert!(selected >= backing.checked_mul(phases.dom).unwrap());
            assert!(
                selected
                    >= roots
                        .checked_mul(node)
                        .unwrap()
                        .checked_mul(phases.dom + phases.typed)
                        .unwrap()
            );
        }
    }

    #[test]
    fn anchor_roundtrip_keeps_each_actual_nested_empty_object_root() {
        fn object_roots(value: &Value) -> usize {
            match value {
                Value::Object(fields) => 1 + fields.values().map(object_roots).sum::<usize>(),
                Value::Array(values) => values.iter().map(object_roots).sum(),
                _ => 0,
            }
        }

        let phases = Phases {
            dom: 3,
            typed: 1,
            canonical: 2,
        };
        let bytes = br#"[{},[{}],{"edge":{}}]"#;
        let actual: Value = serde_json::from_slice(bytes).unwrap();
        let roots = object_roots(&actual);
        assert_eq!(roots, 4);
        let value_node = map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>(),
        )
        .unwrap();
        let typed_node = map_node(size_of::<ContentRef>(), align_of::<ContentRef>()).unwrap();
        let generic = scan(bytes, 4096, size_of::<ContentRef>(), typed_node)
            .unwrap()
            .requested(&phases)
            .unwrap();

        let selected =
            anchor_storage(bytes, 4096, size_of::<ContentRef>(), typed_node, &phases).unwrap();

        let independent_roots = roots * (3 * value_node + typed_node);
        let independent_dom_headers = 3 * size_of::<Value>();
        assert_eq!(
            selected - generic,
            independent_roots + independent_dom_headers
        );
        assert!(selected > generic);
    }
}
