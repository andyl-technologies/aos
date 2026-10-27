//! Prices the early Control constructor's distinct raw and downstream owners.
//!
//! This companion preserves the old scalar quote and decoder. It adds the
//! complete defining DTO layouts, generated fields, tagged Content buffers and
//! RawValue-expanded populations before the actual early retained constructor.
//! Every axis is demand DATA; archive, Source, native and future phase grants
//! remain independently authenticated by the real caller.

use super::*;
use crucible_node_transport::{
    protocol_snapshot::{raw_value_reparse, serde_decode_layout},
    reference_packet::control::PacketDecodedCaptureFutureControlData as Decoded,
    retained_metadata::serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};

type Axes = (usize, usize, usize, usize);

use crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;

impl PacketCompleteSemanticSource {
    /// Declares the new quotation's bounded failure String before any walk.
    pub(crate) const fn original_control_snapshot_complete_quote_transient_data() -> usize {
        OriginalInitialLifecycleDiagnostics::requested_bytes()
    }

    /// Names complete allocation-free quote controls before the first raw walk.
    pub(crate) fn original_control_snapshot_complete_quote_counter_scratch_data() -> usize {
        Self::original_control_snapshot_construction_counter_scratch_data()
            + OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
            + raw_value_reparse::raw_scanner_counter_scratch_data()
            + original_json_value_storage_extent_counter_scratch_data()
            + NodeRuntime::capture_expanded_selected_json_decode_counter_scratch_data()
            + Decoded::decoder_counter_scratch_data()
            + Decoded::decoder_validation_schema_quote_counter_scratch_data()
            + Decoded::validation_error_counter_scratch_data()
            + size_of::<QuoteControls>()
            + size_of::<Axes>()
            + size_of::<Result<Axes, OperationFailure>>()
    }

    /// Quotes independent retained, transient, fixed and encoded-limit axes.
    ///
    /// The genuine caller first admits the complete static quote controls. The
    /// raw body length supplies an actual lexical upper from the defining JSON
    /// extent supplier; it is not an encoded policy cap. Additional hidden JSON
    /// supplies its own separate parser, typed, canonical and traversal work.
    /// Prior archive/Control/alias owners remain independently live throughout.
    ///
    /// # Errors
    /// Refuses the actual selected Control bound, unsupported layouts or raw
    /// framing, checked overflow, or a whole constructor above the restriction.
    pub(crate) fn original_control_snapshot_complete_construction_data(
        bytes: &[u8],
        selected_control_bytes: U64,
        maximum: usize,
    ) -> Result<Axes, OperationFailure> {
        // The separately declared failure window bounds this new helper's
        // actual refusal String, including errors from the unchanged baseline.
        // The guard restores the caller's original diagnostic mode on all exits.
        let _diagnostics = OriginalInitialLifecycleDiagnostics::begin();
        let (baseline, encoded_limit) = Self::original_control_snapshot_construction_data(
            bytes,
            selected_control_bytes,
            maximum,
        )?;
        let (schema_transient, schema_scratch) =
            Decoded::decoder_validation_schema_construction_data(maximum).map_err(provider)?;
        let writer_failure = Decoded::validation_writer_failure_storage_data();
        let raw = original_json_value_storage_extent_data(bytes.len()).map_err(provider)?;
        let extra = raw_value_reparse::quote_raw_json_data(bytes, maximum).map_err(provider)?;
        let (extra_r, extra_t, extra_s) = extra.requested_storage_data();
        let expanded = extra.expanded_json_extents_data();
        let values = add(raw.maximum_value_nodes, expanded.0)?;
        let members = add(raw.maximum_object_members, expanded.1)?;
        let text = add(raw.maximum_decoded_string_bytes, expanded.2)?;
        let layouts = packet_control_snapshot_validation_layouts();
        let (slot, slot_alignment, map_pair, map_alignment) =
            Decoded::decoder_typed_layout_geometry_data();
        if slot == 0
            || slot_alignment == 0
            || !slot_alignment.is_power_of_two()
            || map_pair == 0
            || map_alignment == 0
            || !map_alignment.is_power_of_two()
        {
            return Err(refused("complete Control defining layout is invalid"));
        }
        let map_node =
            NodeRuntime::capture_protocol_tree_storage(1, 0, map_pair, map_alignment, maximum)
                .map_err(unknown)?;
        let (typed, value, canonical_work, canonical_output, _) =
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(
                values, members, text, slot, map_node, maximum,
            )
            .map_err(unknown)?;

        // Typed defaults can emit fields absent from malformed supplied objects
        // before the actual equality check refuses them. The defining roster
        // names the maximum reachable keys per real DTO node, independently of
        // the raw/expanded strings already counted above.
        let (fields, key_bytes) = Decoded::decoder_emitted_field_geometry_data();
        let generated_members = mul(values, fields)?;
        let generated_values = mul(2, generated_members)?;
        let generated_text = mul(values, key_bytes)?;
        let generated = NodeRuntime::capture_expanded_selected_json_decode_axes_data(
            generated_values,
            generated_members,
            generated_text,
            slot,
            map_node,
            maximum,
        )
        .map_err(unknown)?;
        let typed_owners = layouts.maximum_simultaneous_typed_model_views;
        let value_owners = layouts.maximum_simultaneous_control_dom_views;
        let output_owners = layouts.maximum_simultaneous_control_encoded_banks;
        let retained = sum(&[
            baseline,
            extra_r,
            mul(typed, typed_owners)?,
            mul(value, value_owners)?,
            mul(canonical_output, output_owners)?,
            mul(generated.1, value_owners)?,
            mul(generated.3, output_owners)?,
        ])?;

        let levels = Decoded::decoder_buffered_content_levels_data();
        let content_arrays = mul(
            mul(8, values)?,
            serde_decode_layout::content_slot_bytes_data(),
        )?;
        let content_maps = mul(
            mul(8, members)?,
            serde_decode_layout::content_pair_bytes_data(),
        )?;
        let content_strings = add(mul(4, text)?, mul(16, values)?)?;
        let content = mul(
            levels,
            sum(&[content_arrays, content_maps, content_strings])?,
        )?;
        // Each possible text owner independently covers a decoded Bytes bank
        // and its later base64 formatter while its source String stays alive.
        let byte_formatters = add(mul(8, text)?, mul(32, values)?)?;
        let diagnostics = diagnostic_window(text)?;
        let transient = sum(&[
            baseline,
            extra_t,
            content,
            byte_formatters,
            mul(canonical_work, value_owners)?,
            mul(generated.2, value_owners)?,
            mul(generated.3, output_owners)?,
            diagnostics,
            schema_transient,
            writer_failure.1,
        ])?;
        let depth = add(65, mul(128, extra.maximum_parser_layers_data())?)?;
        let scratch = sum(&[
            Self::original_control_snapshot_complete_quote_counter_scratch_data(),
            extra_s,
            mul(
                depth,
                sum(&[
                    Decoded::decoder_expanded_value_frame_counter_scratch_data(),
                    NodeRuntime::capture_json_value_equality_frame_counter_scratch_data(),
                    crucible_node_format::Bytes::serialization_counter_scratch_data(),
                    crucible_node_format::Bytes::deserialization_counter_scratch_data(),
                    crucible_node_format::values::scalar_deserialization_counter_scratch_bytes_data(
                    ),
                ])?,
            )?,
            crucible_node_format::canonical::json_parse_counter_scratch_bytes_data(),
            crucible_node_format::canonical::canonical_json_counter_scratch_bytes_data(),
            schema_scratch,
            writer_failure.2,
            Decoded::validation_error_counter_scratch_data(),
        ])?;
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(refused(
                "complete Control constructor exceeds independent bound",
            ));
        }
        Ok((retained, transient, scratch, encoded_limit))
    }
}

fn diagnostic_window(text: usize) -> Result<usize, OperationFailure> {
    // The defining successor supplies the actual closed names and serde error
    // allocation layout. Dynamic input escaping/location and two live message
    // stages are independent of that static pool and of decoder field partials.
    let static_text = Decoded::decoder_diagnostic_static_text_bytes_data();
    let error_box = Decoded::decoder_error_impl_allocation_upper_bytes_data();
    let syntax = PARSER_DIAGNOSTIC_STATIC_TEXT_BYTES;
    let parser_reason = add(syntax, 20)?;
    let parser_reason_growth = add(mul(4, parser_reason)?, 16)?;
    let owned_reason = add(
        Decoded::validation_error_owned_reason_bytes_data(),
        parser_reason_growth,
    )?;
    let validation_static = Decoded::validation_error_static_text_bytes_data();
    let message = sum(&[
        mul(10, text)?,
        static_text,
        owned_reason,
        validation_static,
        syntax,
    ])?;
    // JsonUnexpected uses the pinned zmij24 finite-number buffer, including
    // ContentDeserializer errors instantiated with serde_json::Error.
    let message = add(message, size_of::<[u8; 24]>() + 2 * 20)?;
    let growing_message = add(mul(4, message)?, 16)?;
    add(
        owned_reason,
        mul(2, sum(&[growing_message, message, error_box])?)?,
    )
}

// These are the actual canonical::Parser error reasons and serde_json1.0.150
// ErrorCode::Display syntax labels. Message/Io variants are independently
// supplied by the typed/validation/writer facts. Location/cursor digits and
// String growth are separate terms above; no serializer/parser is executed.
const PARSER_DIAGNOSTIC_STATIC_TEXT_BYTES: usize = parser_diagnostic_static_text_bytes();

const fn parser_diagnostic_static_text_bytes() -> usize {
    let reasons = [
        "require a nesting limit between 1 and 64",
        "frame exceeds admitted byte limit",
        "trailing JSON content",
        "expected JSON value",
        "invalid JSON literal",
        "expected JSON string",
        "unterminated JSON string",
        "JSON nesting limit exceeded",
        "array exceeds 65536 elements",
        "expected array comma or close",
        "duplicate object key",
        "expected object colon",
        "expected object comma or close",
        "invalid integer part",
        "missing fractional digits",
        "missing exponent digits",
        "invalid number encoding",
        "invalid finite number",
        "nonfinite number",
        "EOF while parsing a list",
        "EOF while parsing an object",
        "EOF while parsing a string",
        "EOF while parsing a value",
        "expected `:`",
        "expected `,` or `]`",
        "expected `,` or `}`",
        "expected ident",
        "expected value",
        "expected `\"`",
        "invalid escape",
        "invalid number",
        "number out of range",
        "invalid unicode code point",
        "control character (\\u0000-\\u001F) found while parsing a string",
        "key must be a string",
        "invalid value: expected key to be a number in quotes",
        "float key must be finite (got NaN or +/-inf)",
        "lone leading surrogate in hex escape",
        "trailing comma",
        "trailing characters",
        "unexpected end of hex escape",
        "recursion limit exceeded",
    ];
    let mut maximum = 0;
    let mut index = 0;
    while index < reasons.len() {
        if reasons[index].len() > maximum {
            maximum = reasons[index].len();
        }
        index += 1;
    }
    maximum + " at byte ".len() + " at line ".len() + " column ".len()
}

#[allow(dead_code)]
struct QuoteControls {
    raw: OriginalJsonValueStorageExtentData,
    extra: raw_value_reparse::JsonValueReparseConstructionData,
    scalar_arguments: [usize; 2],
    baseline: [usize; 2],
    extra_axes: [usize; 3],
    expanded_facts: [usize; 3],
    layouts:
        crucible_node_transport::reference_packet::control::PacketControlSnapshotValidationLayouts,
    typed_layouts: [usize; 4],
    downstream_axes: [usize; 5],
    generated_axes: [usize; 5],
    values: usize,
    members: usize,
    text: usize,
    map_node: usize,
    generated_members: usize,
    generated_values: usize,
    generated_text: usize,
    emitted_fields: usize,
    emitted_key_bytes: usize,
    typed_owners: usize,
    value_owners: usize,
    output_owners: usize,
    retained: usize,
    levels: usize,
    content_arrays: usize,
    content_maps: usize,
    content_strings: usize,
    content: usize,
    byte_formatters: usize,
    diagnostics: usize,
    schema_transient: usize,
    schema_scratch: usize,
    writer_failure: [usize; 3],
    transient: usize,
    depth: usize,
    scratch: usize,
    diagnostic_static_text: usize,
    validation_owned_reason: usize,
    validation_static_text: usize,
    parser_static_text: usize,
    parser_reason: usize,
    parser_reason_growth: usize,
    error_box: usize,
    message: usize,
    location_message: usize,
    growing_message: usize,
    diagnostic_terms: [usize; 5],
    retained_terms: [usize; 7],
    transient_terms: [usize; 10],
    scratch_terms: [usize; 8],
    recursive_controls: [usize; 5],
    sum_values: &'static [usize],
    sum_value: &'static usize,
    sum_cursor: std::slice::Iter<'static, usize>,
    sum_result: Result<usize, OperationFailure>,
    checked_option: Option<usize>,
}

fn provider(_: crucible_node_transport::ProviderError) -> OperationFailure {
    refused("complete Control defining geometry refused")
}
fn add(a: usize, b: usize) -> Result<usize, OperationFailure> {
    a.checked_add(b)
        .ok_or_else(|| refused("complete Control geometry overflow"))
}
fn mul(a: usize, b: usize) -> Result<usize, OperationFailure> {
    a.checked_mul(b)
        .ok_or_else(|| refused("complete Control geometry overflow"))
}
fn sum(values: &[usize]) -> Result<usize, OperationFailure> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_parser_failures_have_their_own_syntax_and_location_window() {
        for raw in [b"{?".as_slice(), b"\"\\x\"".as_slice()] {
            let error = crucible_node_format::canonical::parse_json(raw, raw.len()).unwrap_err();
            let display = error.to_string();
            let upper = PARSER_DIAGNOSTIC_STATIC_TEXT_BYTES
                + 2 * 20
                + Decoded::validation_error_static_text_bytes_data();

            assert!(display.len() <= upper);
            assert!(diagnostic_window(0).unwrap() > display.len());
        }
    }

    #[test]
    fn actual_complete_row_enforces_the_combined_independent_bound() {
        let selected = U64::new(1_048_576);
        let row =
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                b"{}",
                selected,
                usize::MAX,
            )
            .unwrap();
        let exact = row.0 + row.1 + row.2;

        assert!(row.0 > 0 && row.1 > 0 && row.2 > 0);
        assert_eq!(
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                b"{}", selected, exact,
            )
            .unwrap(),
            row
        );
        assert!(
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                b"{}",
                selected,
                exact - 1,
            )
            .is_err()
        );
        assert!(
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                b"{}",
                U64::new(1),
                usize::MAX,
            )
            .is_err()
        );
    }

    #[test]
    fn equal_length_reserved_string_adds_real_downstream_axes_before_decode() {
        let reserved = "$serde_json::private::RawValue";
        let ordinary = "x".repeat(reserved.len());
        let payload = format!("{}null{}", "[".repeat(70), "]".repeat(70));
        let make = |key: &str| {
            let mut fields = serde_json::Map::new();
            fields.insert(key.into(), serde_json::Value::String(payload.clone()));
            crucible_node_format::canonical::canonical_json(&serde_json::Value::Object(fields))
                .unwrap()
        };
        let raw = make(reserved);
        let inert = make(&ordinary);
        assert_eq!(raw.len(), inert.len());
        let selected = U64::new(1_048_576);
        let extra =
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                &raw,
                selected,
                usize::MAX,
            )
            .unwrap();
        let baseline =
            PacketCompleteSemanticSource::original_control_snapshot_complete_construction_data(
                &inert,
                selected,
                usize::MAX,
            )
            .unwrap();

        assert!(extra.0 > baseline.0);
        assert!(extra.1 > baseline.1);
        assert!(extra.2 > baseline.2);
        assert_eq!(extra.3, baseline.3);
    }
}
