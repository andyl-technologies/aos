//! Applies genuine expanded JSON event facts to selected typed and JCS layouts.
//!
//! This arithmetic constructs no JSON or decoder owner. It prices each later
//! consumer independently of the RawValue parser that produced the facts. DTO
//! defaults/field text and custom formatters not represented by those facts
//! remain explicit caller terms; no source permission or admission is issued.

use crate::node_contract::{NodeRuntime, RuntimeError};
use serde_json::Value;
use std::mem::size_of;

type Axes = (usize, usize, usize, usize, usize);

impl NodeRuntime {
    /// Prices selected typed backing, a Value copy, JCS work/output and encoding.
    ///
    /// `values` includes value and independently owned key occurrences;
    /// `members` counts object entries and `decoded_text` bounds their actual
    /// decoded text. These are additional facts from the actual raw reparse
    /// supplier, not a caller's encoded cap. Typed slots/map nodes must come
    /// from the complete actual defining DTO roster. Returned terms are
    /// independent construction windows, never a credit against an earlier row.
    ///
    /// # Errors
    /// Refuses zero defining layouts, impossible empty facts, unsupported pinned
    /// sort geometry, arithmetic overflow or the independent requested ceiling.
    pub(crate) fn capture_expanded_selected_json_decode_axes_data(
        values: usize,
        members: usize,
        decoded_text: usize,
        typed_slot: usize,
        typed_map_node: usize,
        maximum: usize,
    ) -> Result<Axes, RuntimeError> {
        if typed_slot == 0 || typed_map_node == 0 {
            return Err(RuntimeError::InvalidReceipt);
        }
        if values == 0 {
            return if members == 0 && decoded_text == 0 {
                Ok((0, 0, 0, 0, 0))
            } else {
                Err(RuntimeError::InvalidReceipt)
            };
        }
        let (typed, value) =
            backing_data(values, members, decoded_text, typed_slot, typed_map_node)?;
        let ordered_map = Self::capture_map_node_storage::<Vec<u16>, (&str, &Value)>();
        let sort_entry = size_of::<(Vec<u16>, (&str, &Value))>();
        if size_of::<usize>() != 8 || mul(5, sort_entry)? > ordered_map {
            return Err(RuntimeError::ResourceLimit);
        }

        // JCS quotes at most six bytes per text byte. Its String bank, UTF16
        // key Vecs and ordered-map/input-Vec/stable-sort allocations are
        // independent. Five sort entries fit each pinned node;
        // two nodes per member therefore cover both final tree and Vec/scratch.
        // serde_json::to_string uses its own128-byte initial Vec. Summed
        // geometric requests fit4*encoded+256; encoded<=6*text+2 per String
        // gives24*text+(256+8) per possible string occurrence.
        let quoted = add(mul(24, decoded_text)?, mul(264, values)?)?;
        let utf16 = add(mul(8, decoded_text)?, mul(16, members)?)?;
        let sorting = mul(mul(2, members)?, ordered_map)?;
        let mut failure_reason = 0_usize;
        for reason in [
            "nesting exceeds 64 containers",
            "exceeds 65536 elements",
            "not a finite JCS number",
        ] {
            failure_reason = failure_reason.max(reason.len());
        }
        let canonical_work = sum(&[quoted, utf16, sorting, failure_reason])?;
        // Finite binary64 spelling fits32 bytes, integral spelling20; four
        // further bytes per event cover all JSON delimiters/punctuation. Typed
        // generated field/default text absent from the facts is caller-owned.
        let encoded = add(mul(6, decoded_text)?, mul(36, values)?)?;
        // This is only the independently growing canonical output Vec. Its
        // actual u8 minimum8 needs at most16 remainder in the cumulative growth
        // proof;256 is a looser bound for that SAME bank, not another workspace.
        let canonical_output = add(mul(4, encoded)?, 256)?;
        let requested = sum(&[
            typed,
            value,
            canonical_work,
            canonical_output,
            Self::capture_expanded_selected_json_decode_counter_scratch_data(),
        ])?;
        if requested > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((typed, value, canonical_work, canonical_output, encoded))
    }

    /// Prices only selected typed backing and an independent Value copy.
    ///
    /// This shares the full helper's defining event arithmetic. A consumer that
    /// does not perform JCS on its expanded result must not invent that pass or
    /// fail because an unused canonical axis exceeds its actual ceiling.
    ///
    /// # Errors
    /// Refuses invalid facts/layouts, overflow or the independent ceiling.
    pub(crate) fn capture_expanded_selected_json_decode_backing_data(
        values: usize,
        members: usize,
        decoded_text: usize,
        typed_slot: usize,
        typed_map_node: usize,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let result = backing_data(values, members, decoded_text, typed_slot, typed_map_node)?;
        if result == (0, 0) {
            return Ok(result);
        }
        if add(
            add(result.0, result.1)?,
            Self::capture_expanded_selected_json_decode_counter_scratch_data(),
        )? > maximum
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(result)
    }

    /// Names this arithmetic/layout walk before its independently admitted call.
    /// Canonical execution/parser/formatter fixed controls remain caller terms.
    pub(crate) const fn capture_expanded_selected_json_decode_counter_scratch_data() -> usize {
        size_of::<Axes>()
            + size_of::<Result<Axes, RuntimeError>>()
            + size_of::<QuoteScalarControls>()
            + size_of::<BackingScalarControls>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<[usize; 5]>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<[&'static str; 3]>()
            + size_of::<std::array::IntoIter<&'static str, 3>>()
    }
}

// Layout-only roster of the six actual quote arguments and its named scalar
// locals. It does not represent a retained owner or a reusable work allowance.
#[allow(dead_code)]
struct QuoteScalarControls {
    arguments: [usize; 6],
    value_map: usize,
    ordered_map: usize,
    sort_entry: usize,
    strings: usize,
    typed: usize,
    value: usize,
    quoted: usize,
    utf16: usize,
    sorting: usize,
    failure_reason: usize,
    canonical_work: usize,
    encoded: usize,
    canonical_output: usize,
    requested: usize,
}

#[allow(dead_code)]
struct BackingScalarControls {
    arguments: [usize; 5],
    value_map: usize,
    strings: usize,
    typed: usize,
    value: usize,
}

fn backing_data(
    values: usize,
    members: usize,
    decoded_text: usize,
    typed_slot: usize,
    typed_map_node: usize,
) -> Result<(usize, usize), RuntimeError> {
    if typed_slot == 0 || typed_map_node == 0 {
        return Err(RuntimeError::InvalidReceipt);
    }
    if values == 0 {
        return if members == 0 && decoded_text == 0 {
            Ok((0, 0))
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    }
    // Same per-container/array-minimum/primitive8-slot arithmetic and actual
    // u8/String minimum/doubling sum as the full selected constructor helper.
    let value_map = NodeRuntime::capture_map_node_storage::<String, Value>();
    let strings = add(mul(4, decoded_text)?, mul(16, values)?)?;
    let typed = sum(&[
        mul(mul(8, values)?, typed_slot)?,
        mul(members, typed_map_node)?,
        strings,
    ])?;
    let value = sum(&[
        mul(mul(8, values)?, size_of::<Value>())?,
        mul(members, value_map)?,
        strings,
    ])?;
    Ok((typed, value))
}

fn add(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right).ok_or(RuntimeError::ResourceLimit)
}

fn mul(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_mul(right).ok_or(RuntimeError::ResourceLimit)
}

fn sum(values: &[usize]) -> Result<usize, RuntimeError> {
    values
        .iter()
        .try_fold(0_usize, |total, value| add(total, *value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_extra_events_create_no_phantom_constructor() {
        assert_eq!(
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(0, 0, 0, 32, 64, 0)
                .unwrap(),
            (0, 0, 0, 0, 0)
        );
        assert!(
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(
                0,
                1,
                0,
                32,
                64,
                usize::MAX
            )
            .is_err()
        );
    }

    #[test]
    fn selected_layouts_and_exact_ceiling_are_independent_axes() {
        let first = NodeRuntime::capture_expanded_selected_json_decode_axes_data(
            7,
            2,
            31,
            32,
            64,
            usize::MAX,
        )
        .unwrap();
        let larger = NodeRuntime::capture_expanded_selected_json_decode_axes_data(
            7,
            2,
            31,
            64,
            128,
            usize::MAX,
        )
        .unwrap();
        assert!(larger.0 > first.0);
        assert_eq!(
            (larger.1, larger.2, larger.3, larger.4),
            (first.1, first.2, first.3, first.4)
        );
        let total = first.0
            + first.1
            + first.2
            + first.3
            + NodeRuntime::capture_expanded_selected_json_decode_counter_scratch_data();
        assert!(
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(7, 2, 31, 32, 64, total)
                .is_ok()
        );
        assert!(
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(
                7,
                2,
                31,
                32,
                64,
                total - 1
            )
            .is_err()
        );
        assert!(
            NodeRuntime::capture_expanded_selected_json_decode_axes_data(
                usize::MAX,
                2,
                31,
                32,
                64,
                usize::MAX
            )
            .is_err()
        );
    }
}
