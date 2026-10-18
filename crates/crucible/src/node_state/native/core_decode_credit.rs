//! Preflights closed Host2 and complete-archive JSON without constructing a DOM.
//!
//! This credit describes requested decoder storage only. Canonical grammar,
//! source validation, signed closure and fresh-target authority stay separate.
//! The fixed stack bounds traversal; malformed JSON is still rejected by the
//! original strict parser after the finite allocation check.

use crate::node_contract::{NodeRuntime, RuntimeError};
use std::mem::size_of;

#[derive(Debug)]
pub(super) struct DecodeCredit {
    pub parser_strings: usize,
    pub value_containers: usize,
    pub typed_containers: usize,
    pub canonical_temporaries: usize,
}

impl DecodeCredit {
    pub(super) fn total(&self) -> Result<usize, RuntimeError> {
        self.parser_strings
            .checked_add(self.value_containers)
            .and_then(|bytes| bytes.checked_add(self.typed_containers))
            .and_then(|bytes| bytes.checked_add(self.canonical_temporaries))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

fn add(value: &mut usize, bytes: usize) -> Result<(), RuntimeError> {
    *value = value
        .checked_add(bytes)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

fn multiply(a: usize, b: usize) -> Result<usize, RuntimeError> {
    a.checked_mul(b).ok_or(RuntimeError::ResourceLimit)
}

fn growing_bank(length: usize, minimum: usize) -> Result<usize, RuntimeError> {
    multiply(length, 4)?
        .checked_add(minimum)
        .ok_or(RuntimeError::ResourceLimit)
}

#[derive(Clone, Copy)]
enum Context {
    Opaque,
    Host,
    Scheduling,
    PayloadArray,
    Payload,
    Bytes,
}

#[derive(Clone, Copy)]
struct Container {
    delimiter: u8,
    context: Context,
    typed_slot: usize,
}

/// Names the fixed nonallocating scanner stack separately from DOM/typed banks.
pub(super) fn scanner_storage() -> usize {
    size_of::<[Container; 64]>() + size_of::<DecodeCredit>()
}

/// Counts occurrences before parse, including duplicate keys that the original
/// parser will reject. No duplicate collapse is assumed to release storage.
pub(super) fn preflight(bytes: &[u8], maximum: usize) -> Result<DecodeCredit, RuntimeError> {
    preflight_shape(
        bytes,
        maximum,
        NodeRuntime::capture_closed_inline_storage(),
        true,
        None,
    )
}

/// Counts only the direct complete-index/manifest/journal closed archive types.
/// The archive reader never uses untagged legacy index retries in this route.
pub(super) fn preflight_archive(
    bytes: &[u8],
    maximum: usize,
) -> Result<DecodeCredit, RuntimeError> {
    use super::storage::{Index, NativeArtifactState, NativeOwnerState, Object};
    let typed_slot = NodeRuntime::capture_closed_inline_storage()
        .max(size_of::<Index>())
        .max(size_of::<NativeArtifactState>())
        .max(size_of::<NativeOwnerState>())
        .max(size_of::<Object>())
        .max(size_of::<super::lineage_source::OriginalLineageCoordinator>())
        .max(size_of::<
            super::collecting_scope::CollectingCompleteCaptureProvenance,
        >());
    preflight_shape(bytes, maximum, typed_slot, false, None)
}

/// Counts a selected closed DTO with its actual largest inline and map layouts.
/// This reserves each container independently, including empty nested arrays or
/// objects. Layout facts grant no decoding, source or restoration authority.
pub(super) fn preflight_selected(
    bytes: &[u8],
    typed_slot: usize,
    typed_map_node: usize,
    maximum: usize,
) -> Result<DecodeCredit, RuntimeError> {
    if typed_slot == 0 || typed_map_node == 0 {
        return Err(RuntimeError::ResourceLimit);
    }
    preflight_shape(bytes, maximum, typed_slot, false, Some(typed_map_node))
}

fn preflight_shape(
    bytes: &[u8],
    maximum: usize,
    typed_slot: usize,
    host_shape: bool,
    selected_map_node: Option<usize>,
) -> Result<DecodeCredit, RuntimeError> {
    let value_node = NodeRuntime::capture_map_node_storage::<String, serde_json::Value>();
    let ordered_node =
        NodeRuntime::capture_map_node_storage::<Vec<u16>, (&str, &serde_json::Value)>();
    let mut credit = DecodeCredit {
        parser_strings: 0,
        value_containers: 0,
        typed_containers: 0,
        canonical_temporaries: growing_bank(bytes.len(), 8)?,
    };
    let mut depth = 0usize;
    let mut stack = [Container {
        delimiter: 0,
        context: Context::Opaque,
        typed_slot,
    }; 64];
    let mut pending = Context::Opaque;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b' ' | b'\n' | b'\r' | b'\t' | b':' | b',' => cursor += 1,
            b'{' | b'[' => {
                if depth == stack.len() {
                    return Err(RuntimeError::ResourceLimit);
                }
                let context = if host_shape && depth == 0 && bytes[cursor] == b'{' {
                    Context::Host
                } else if matches!(pending, Context::Opaque)
                    && depth > 0
                    && matches!(stack[depth - 1].context, Context::PayloadArray)
                    && bytes[cursor] == b'{'
                {
                    Context::Payload
                } else {
                    pending
                };
                let element_slot = if matches!(context, Context::Bytes) {
                    size_of::<u8>()
                } else {
                    typed_slot
                };
                stack[depth] = Container {
                    delimiter: bytes[cursor],
                    context,
                    typed_slot: element_slot,
                };
                pending = Context::Opaque;
                depth += 1;
                if selected_map_node.is_some() {
                    add(&mut credit.typed_containers, multiply(4, typed_slot)?)?;
                }
                if bytes[cursor] == b'[' {
                    // Empty arrays request no bank, but the four-slot minimum
                    // is reserved before any later element can trigger growth.
                    add(
                        &mut credit.value_containers,
                        4 * size_of::<serde_json::Value>(),
                    )?;
                    add(
                        &mut credit.typed_containers,
                        if element_slot == 1 {
                            8
                        } else {
                            4 * element_slot
                        },
                    )?;
                }
                cursor += 1;
            }
            b'}' | b']' => {
                if depth == 0
                    || stack[depth - 1].delimiter != if bytes[cursor] == b'}' { b'{' } else { b'[' }
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
                depth -= 1;
                cursor += 1;
            }
            b'"' => {
                cursor += 1;
                let start = cursor;
                let mut closed = false;
                while cursor < bytes.len() {
                    let byte = bytes[cursor];
                    cursor += 1;
                    if byte == b'\\' {
                        if cursor == bytes.len() {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                        cursor += 1;
                    } else if byte == b'"' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let encoded = cursor - start - 1;
                // Strict Parser::string starts an independent serde decoder for
                // each token. Charge its escaped-string scratch growth and the
                // owned DOM String, with an independent typed String copy.
                add(&mut credit.parser_strings, growing_bank(encoded, 8)?)?;
                add(&mut credit.parser_strings, encoded)?;
                add(&mut credit.typed_containers, encoded)?;
                let escaped = multiply(encoded, 6)?
                    .checked_add(2)
                    .ok_or(RuntimeError::ResourceLimit)?;
                add(
                    &mut credit.canonical_temporaries,
                    growing_bank(escaped, 256)?,
                )?;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    let key = &bytes[start..cursor - 1];
                    pending = match (depth.checked_sub(1).map(|level| stack[level].context), key) {
                        (Some(Context::Host), b"objects") => Context::PayloadArray,
                        (Some(Context::Host), b"scheduling") => Context::Scheduling,
                        (Some(Context::Scheduling), b"payload_objects") => Context::PayloadArray,
                        (Some(Context::Payload), b"bytes") => Context::Bytes,
                        _ => Context::Opaque,
                    };
                    add(&mut credit.value_containers, value_node)?;
                    // Selected source DTOs can retain maps of concrete records,
                    // whose node layout exceeds a dynamic JSON Value node.
                    add(
                        &mut credit.typed_containers,
                        selected_map_node.unwrap_or(value_node),
                    )?;
                    add(&mut credit.canonical_temporaries, ordered_node)?;
                    add(
                        &mut credit.canonical_temporaries,
                        multiply(encoded, 8)?
                            .checked_add(16)
                            .ok_or(RuntimeError::ResourceLimit)?,
                    )?;
                }
                add(
                    &mut credit.value_containers,
                    4 * size_of::<serde_json::Value>(),
                )?;
                let slot = depth
                    .checked_sub(1)
                    .map_or(typed_slot, |level| stack[level].typed_slot);
                add(&mut credit.typed_containers, multiply(4, slot)?)?;
            }
            _ => {
                // Primitive tokens need no owning string. Their array slot is
                // nevertheless charged; strict number/literal grammar remains
                // the original parser's responsibility.
                while cursor < bytes.len() && !b" \n\r\t,:]}".contains(&bytes[cursor]) {
                    cursor += 1;
                }
                add(
                    &mut credit.value_containers,
                    4 * size_of::<serde_json::Value>(),
                )?;
                let slot = depth
                    .checked_sub(1)
                    .map_or(typed_slot, |level| stack[level].typed_slot);
                add(&mut credit.typed_containers, multiply(4, slot)?)?;
                pending = Context::Opaque;
            }
        }
        if credit.total()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
    }
    if depth != 0 {
        return Err(RuntimeError::InvalidReceipt);
    }
    // The boxed Runtime7 record is a distinct owning allocation. Native/source
    // validators and their reference sets are charged separately below.
    add(&mut credit.typed_containers, typed_slot)?;
    if credit.total()? > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(credit)
}

/// Rejects the older runtime variant before any closed typed record allocation.
/// Fixed canonical field names are compared as borrowed source slices; escaped
/// aliases are noncanonical and remain refused by this complete-only route.
pub(super) fn require_original_lineage(bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut cursor = 0usize;
    let mut depth = 0usize;
    let mut runtime = false;
    let mut found = false;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' | b'[' => {
                depth = depth.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(RuntimeError::InvalidReceipt)?;
                if depth < 2 {
                    runtime = false;
                }
                cursor += 1;
            }
            b'"' => {
                let start = cursor + 1;
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor] != b'"' {
                    if bytes[cursor] == b'\\' {
                        cursor += 1;
                    }
                    cursor += 1;
                }
                if cursor >= bytes.len() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let token = &bytes[start..cursor];
                cursor += 1;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    next += 1;
                    while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    if depth == 1 && token == b"runtime" {
                        if bytes.get(next) != Some(&b'{') {
                            return Err(RuntimeError::UnsupportedFacet);
                        }
                        runtime = true;
                    } else if depth == 2 && runtime && token == b"kind" {
                        if !bytes[next..].starts_with(b"\"original-lineage\"") {
                            return Err(RuntimeError::UnsupportedFacet);
                        }
                        found = true;
                    }
                }
            }
            _ => cursor += 1,
        }
    }
    if !found {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(())
}

/// Reserves the actual Runtime7 validation algorithms independently of parse:
/// direct/transitive row indices, bitmaps, completion vectors, borrowed required
/// references, sorted source-key clones and owner participant clones.
pub(super) fn validation_storage(
    credit: &DecodeCredit,
    limits: crate::node_contract::HostSchedulingContinuationLimits,
) -> Result<usize, RuntimeError> {
    use crate::node_contract::{OriginalInputLineageLimits, RuntimeError};
    use crucible_node_contract::{ContentRef, Id};
    let OriginalInputLineageLimits {
        maximum_objects: objects,
        maximum_edges: edges,
        ..
    } = limits.lineage;
    let queue = multiply(
        edges
            .checked_add(multiply(
                objects.checked_add(1).ok_or(RuntimeError::ResourceLimit)?,
                4,
            )?)
            .ok_or(RuntimeError::ResourceLimit)?,
        size_of::<usize>(),
    )?;
    let completed = multiply(objects, size_of::<Option<Vec<usize>>>())?;
    let bitmaps = multiply(objects, 2 * size_of::<bool>())?;
    let transitive = multiply(edges, size_of::<usize>())?;
    let required = multiply(
        objects,
        NodeRuntime::capture_map_node_storage::<&ContentRef, ()>(),
    )?;
    // Domains are admitted at seven connections, plus the coordinator domain.
    let domains = multiply(
        15,
        NodeRuntime::capture_map_node_storage::<Id, ()>()
            .checked_add(128)
            .ok_or(RuntimeError::ResourceLimit)?,
    )?;
    // Sorted validators clone each adjacent key at most twice. Parser string
    // credit also conservatively covers Runtime7's decimal formatter temporary.
    let sorted_keys = multiply(credit.parser_strings, 2)?;
    // OwnerBinding's separately collected participant roster cannot exceed
    // the already bounded complete closed typed-container bank.
    let participants = credit.typed_containers;
    [
        queue,
        completed,
        bitmaps,
        transitive,
        required,
        domains,
        sorted_keys,
        participants,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
    })
}

#[cfg(test)]
mod tests {
    // Invalid finite fixture setup must fail these data-only controls.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn selected_layout_counts_concrete_maps_and_every_empty_container() {
        let maximum = 64 * 1024 * 1024;
        let bytes = br#"{"operations":[{},{},{},{},{},{}]}"#;
        let ordinary = preflight(bytes, maximum).expect("finite ordinary shape");
        let selected =
            preflight_selected(bytes, 8192, 16384, maximum).expect("finite selected shape");
        let total = selected.total().expect("finite selected sum");

        assert!(selected.typed_containers > ordinary.typed_containers);
        assert!(selected.typed_containers >= 6 * 4 * 8192);
        assert!(matches!(
            preflight_selected(bytes, 8192, 16384, total - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(matches!(
            preflight_selected(bytes, 0, 16384, maximum),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(matches!(
            preflight_selected(bytes, usize::MAX, 16384, maximum),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn borrowed_decode_shape_refuses_complete_total_before_dom() {
        let bytes = br#"{"objects":[{"bytes":[1,2,3],"label":"a\\b"}],"nested":{"value":[]}}"#;
        let credit = preflight(bytes, 512 * 1024 * 1024).expect("finite inert JSON shape");
        let total = credit.total().expect("finite sum");
        assert!(
            credit.parser_strings > 0 && credit.value_containers > 0 && credit.typed_containers > 0
        );
        assert!(matches!(
            preflight(bytes, total - 1),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn complete_decode_layout_covers_original_nonempty_readonly_data() {
        // This is historical source-one readonly producer data. Parsing its
        // edition-two shape does not retag it as Host2 or issue capture/restore.
        let bytes =
            include_bytes!("core_decode_credit/fixtures/nonempty-readonly-continuation2.json");
        let maximum = 512 * 1024 * 1024;
        let credit = preflight(bytes, maximum).expect("finite nonempty JSON shape");
        require_original_lineage(bytes).expect("original Runtime7 variant");
        let limits = crate::node_contract::HostSchedulingContinuationLimits {
            maximum_record_bytes: 8 * 1024 * 1024,
            lineage: crate::node_contract::OriginalInputLineageLimits::default(),
        };
        let record = crate::node_contract::HostSchedulingContinuationRecord::decode(bytes, limits)
            .expect("historical inert readonly record");
        let actual =
            NodeRuntime::capture_host_record_storage(&record).expect("actual decoded banks");
        assert!(credit.typed_containers >= actual);
        assert!(validation_storage(&credit, limits).expect("validator banks") > 0);
    }

    #[test]
    fn payload_byte_slots_do_not_relabel_dynamic_extension_arrays() {
        let payload = preflight(
            br#"{"objects":[{"reference":{},"bytes":[0,1,2,3]}]}"#,
            512 * 1024 * 1024,
        )
        .expect("closed payload shape");
        let extension = preflight(
            br#"{"source":{"extensions":{"objects":[{"reference":{},"bytes":[0,1,2,3]}]}}}"#,
            512 * 1024 * 1024,
        )
        .expect("dynamic extension shape");
        assert!(extension.typed_containers > payload.typed_containers);
        assert!(payload.value_containers > 0);
    }

    #[test]
    fn complete_decoder_does_not_admit_a_legacy_or_nested_variant() {
        assert!(
            require_original_lineage(br#"{"runtime":{"kind":"original-lineage","record":{}}}"#)
                .is_ok()
        );
        assert!(matches!(
            require_original_lineage(br#"{"runtime":{"kind":"legacy","record":{}}}"#),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert!(matches!(require_original_lineage(br#"{"source":{"runtime":{"kind":"original-lineage"}},"runtime":{"kind":"legacy"}}"#), Err(RuntimeError::UnsupportedFacet)));
    }

    #[test]
    fn duplicate_keys_keep_all_preparse_allocation_occurrences() {
        let single = preflight(br#"{"value":"payload"}"#, 512 * 1024 * 1024).expect("finite shape");
        let duplicate = preflight(
            br#"{"value":"payload","value":"payload"}"#,
            512 * 1024 * 1024,
        )
        .expect("finite shape");
        assert!(duplicate.total().expect("sum") > single.total().expect("sum"));
        assert!(
            crucible_node_contract::canonical::parse_json(
                br#"{"value":"payload","value":"payload"}"#,
                128
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_or_excessively_nested_input_has_no_dom() {
        assert!(matches!(
            preflight(br#"{"value":"unterminated}"#, usize::MAX),
            Err(RuntimeError::InvalidReceipt)
        ));
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(matches!(
            preflight(deep.as_bytes(), usize::MAX),
            Err(RuntimeError::ResourceLimit)
        ));
    }
}

/// Counts the distinct Host17 root plus the unchanged current Runtime7 and
/// scheduler child families. Byte-array roles retain their defining u8 geometry.
pub(super) fn preflight_restored_host17(
    bytes: &[u8],
    maximum: usize,
) -> Result<DecodeCredit, RuntimeError> {
    use crate::node_contract::{
        HostSchedulingRestoredContinuationRecord17, RestoredHostAdmissionPolicy17,
        RestoredHostAncestry17, RestoredHostSemanticAncestor,
    };
    let typed_slot = NodeRuntime::capture_closed_inline_storage()
        .max(size_of::<HostSchedulingRestoredContinuationRecord17>())
        .max(size_of::<RestoredHostAncestry17>())
        .max(size_of::<RestoredHostSemanticAncestor>())
        .max(size_of::<RestoredHostAdmissionPolicy17>());
    preflight_shape(bytes, maximum, typed_slot, true, None)
}
