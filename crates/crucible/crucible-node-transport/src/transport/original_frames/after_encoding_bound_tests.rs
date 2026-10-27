//! Measures actual emitted bank tuples against conservative Source89 growth bounds.
//!
//! These tests populate the real bank through its lifetime operations. A bounded
//! streaming counter measures the original serializer's fields without creating
//! a second giant JSON owner. Literal progress and IDs remain data; neither an
//! encoding bound nor an I/O-complete descriptor issues source authority.

#![expect(
    clippy::unwrap_used,
    reason = "Actual bank/serializer controls use panic as their assertion signal"
)]

use super::*;
use crucible_node_format::Id;
use std::io::{self, Write};

/// Tracks the eight top-level tuple fields across arbitrary writer boundaries.
/// Nested tuple/string bytes count toward their enclosing field unchanged.
#[derive(Default)]
struct TupleWidths {
    fields: [usize; 8],
    field: usize,
    depth: usize,
    string: bool,
    escaped: bool,
    finished: bool,
}

impl Write for TupleWidths {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for &byte in bytes {
            if self.depth == 0 {
                if byte != b'[' || self.finished {
                    return Err(io::Error::other("expected one original tuple"));
                }
                self.depth = 1;
                continue;
            }
            if !self.string && self.depth == 1 {
                if byte == b',' {
                    self.field += 1;
                    if self.field >= self.fields.len() {
                        return Err(io::Error::other("original tuple has extra field"));
                    }
                    continue;
                }
                if byte == b']' {
                    self.depth = 0;
                    self.finished = true;
                    continue;
                }
            }

            self.fields[self.field] += 1;
            if self.string {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.string = false;
                }
            } else {
                match byte {
                    b'"' => self.string = true,
                    b'[' | b'{' => self.depth += 1,
                    b']' | b'}' => self.depth -= 1,
                    _ => {}
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn emitted_widths(bank: &OriginalFrameReservation, compact: bool) -> [usize; 8] {
    let mut measured = TupleWidths::default();
    serde_json::to_writer(&mut measured, &bank.protocol_view_with_encoding(compact)).unwrap();
    assert!(measured.finished);
    assert_eq!(measured.depth, 0);
    assert_eq!(measured.field, 7);
    assert!(!measured.string);
    measured.fields
}

fn assert_bounded(bank: &OriginalFrameReservation, label: &str) {
    for compact in [false, true] {
        let observed = emitted_widths(bank, compact);
        let (literal_bound, descriptor_bound) = bank.maximum_encoding_growth(compact).unwrap();
        assert!(
            observed[6] <= literal_bound,
            "{label}: compact={compact} literal {} exceeds {literal_bound}",
            observed[6]
        );
        assert!(
            observed[7] <= descriptor_bound,
            "{label}: compact={compact} descriptors {} exceed {descriptor_bound}",
            observed[7]
        );
        println!(
            "bank={label} compact={compact} retained={} incoming={} outgoing={} emitted_literal={} literal_bound={literal_bound} emitted_descriptors={} descriptor_bound={descriptor_bound}",
            bank.bytes.len(),
            bank.incoming,
            bank.outgoing,
            observed[6],
            observed[7]
        );
    }
}

fn request_id(index: usize) -> Id {
    // All accepted bytes have three-digit JSON numeric-array tokens. Distinct
    // indices preserve the actual same-direction no-reuse rule at full count.
    if index == 0 {
        return Id::new("z".repeat(128)).unwrap();
    }
    let mut chars = [b'z'; 128];
    let mut index = index;
    for byte in &mut chars[..3] {
        *byte = b'd' + (index % 23) as u8;
        index /= 23;
    }
    Id::new(String::from_utf8(chars.to_vec()).unwrap()).unwrap()
}

fn append_actual(
    bank: &mut OriginalFrameReservation,
    direction: FrameDirection,
    length: usize,
    id: usize,
    complete: bool,
) {
    let slot = bank.begin(direction, length).unwrap();
    bank.retain_request(slot, &request_id(id)).unwrap();
    let chunk = [255_u8; 8192];
    let mut remaining = length;
    while remaining != 0 {
        let extent = remaining.min(chunk.len());
        bank.append(slot, &chunk[..extent]).unwrap();
        remaining -= extent;
    }
    if direction == FrameDirection::Outgoing {
        // Distinct advances prove proposed length and actual publication are
        // serialized independently, including a still-partial descriptor.
        let first = length / 2;
        bank.advance(slot, first).unwrap();
        if complete {
            bank.advance(slot, length - first).unwrap();
        }
    }
    if complete {
        bank.finish(slot).unwrap();
    }
}

#[test]
fn streamed_measurement_matches_actual_serialized_tuple_fields() {
    let mut bank = OriginalFrameReservation::reserve(64, 2).unwrap();
    append_actual(&mut bank, FrameDirection::Incoming, 9, 0, true);
    append_actual(&mut bank, FrameDirection::Outgoing, 11, 0, false);

    for compact in [false, true] {
        let original = serde_json::to_vec(&bank.protocol_view_with_encoding(compact)).unwrap();
        let tuple: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let fields = tuple.as_array().unwrap();
        assert_eq!(serde_json::to_vec(&tuple).unwrap(), original);
        let observed = emitted_widths(&bank, compact);
        for (index, field) in fields.iter().enumerate() {
            assert_eq!(observed[index], serde_json::to_vec(field).unwrap().len());
        }
        assert_eq!(fields[7][0][0], "incoming");
        assert_eq!(fields[7][1][0], "outgoing");
        assert_eq!(fields[7][0][4], true);
        assert_eq!(fields[7][1][4], false);
        assert_eq!(fields[7][1][3], 5);
        assert_eq!(fields[7][0][5].as_array().unwrap().len(), 128);
        assert!(
            fields[7][0][5]
                .as_array()
                .unwrap()
                .iter()
                .all(|byte| byte.as_u64().unwrap() >= 100)
        );
    }
    assert_bounded(&bank, "measured-partial-bank");
}

#[test]
fn reserved_empty_and_zero_length_slots_fit_without_losing_spare_capacity() {
    let mut bank = OriginalFrameReservation::reserve(8192, 8).unwrap();
    let pointer = bank.bytes.as_ptr();
    let capacity = bank.bytes.capacity();
    let descriptor_capacity = bank.slots.capacity();
    assert_bounded(&bank, "empty-spare-bank");

    for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
        let slot = bank.begin(direction, 0).unwrap();
        bank.append(slot, &[]).unwrap();
        bank.retain_request(slot, &request_id(0)).unwrap();
        if direction == FrameDirection::Outgoing {
            bank.advance(slot, 0).unwrap();
        }
        assert!(bank.finish(slot).is_err());
    }
    assert_bounded(&bank, "zero-length-unfinished-slots");
    assert!(bank.bytes.is_empty());
    assert_eq!(bank.bytes.as_ptr(), pointer);
    assert_eq!(bank.bytes.capacity(), capacity);
    assert_eq!(bank.slots.capacity(), descriptor_capacity);
    assert_eq!(bank.frames().count(), 2);
    assert!(
        bank.frames()
            .all(|frame| frame.bytes.is_empty() && frame.transferred == 0 && !frame.complete)
    );
}

#[test]
fn populated_literal_banks_cover_compact_chunk_and_padding_boundaries() {
    for length in [4, 3071, 3072, 3073, 6143, 6144, 6145] {
        for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
            let mut bank = OriginalFrameReservation::reserve(length, 1).unwrap();
            let pointer = bank.bytes.as_ptr();
            append_actual(&mut bank, direction, length, 0, true);
            assert_eq!(bank.bytes.len(), bank.maximum_bytes);
            assert_eq!(bank.bytes.as_ptr(), pointer);
            assert!(bank.complete());
            assert!(bank.begin(direction, 0).is_err());
            assert_bounded(&bank, &format!("full-boundary-{length}-{direction:?}"));

            let compact = serde_json::to_vec(&bank.protocol_view_with_encoding(true)).unwrap();
            let tuple: serde_json::Value = serde_json::from_slice(&compact).unwrap();
            let leaf = serde_json::to_vec(&tuple[6]).unwrap();
            let plan = crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes::validate(
                &leaf,
                leaf.len(),
                length,
            )
            .unwrap();
            let mut decoded = Vec::with_capacity(length);
            plan.fill_preowned(&mut decoded).unwrap();
            assert_eq!(decoded, bank.bytes);
        }
    }
}

#[test]
fn maximum_direction_counts_and_accepted_id_expansion_fit_descriptors() {
    let count = MAX_ORIGINAL_FRAMES_PER_DIRECTION;
    let mut bank = OriginalFrameReservation::reserve(8 * count, count).unwrap();
    let pointer = bank.bytes.as_ptr();
    let descriptors = bank.slots.as_ptr();
    for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
        for index in 0..count {
            append_actual(&mut bank, direction, 4, index, true);
        }
        assert!(bank.begin(direction, 0).is_err());
    }

    assert_eq!(bank.incoming, count);
    assert_eq!(bank.outgoing, count);
    assert_eq!(bank.bytes.len(), bank.maximum_bytes);
    assert_eq!(bank.slots.len(), 2 * count);
    assert_eq!(bank.bytes.as_ptr(), pointer);
    assert_eq!(bank.slots.as_ptr(), descriptors);
    assert!(bank.complete());
    assert!(Id::new("z".repeat(129)).is_err());
    let widest = request_id(0);
    assert_eq!(widest.as_str().len(), 128);
    assert_eq!(
        serde_json::to_vec(widest.as_str().as_bytes())
            .unwrap()
            .len(),
        serde_json::to_vec([255_u8; 128].as_slice()).unwrap().len()
    );
    assert_bounded(&bank, "maximum-4096-both-directions");
}

#[test]
fn maximum_literal_byte_ceiling_fits_both_actual_streaming_encodings() {
    let mut bank = OriginalFrameReservation::reserve(MAX_ORIGINAL_FRAME_BYTES, 1).unwrap();
    let pointer = bank.bytes.as_ptr();
    let half = MAX_ORIGINAL_FRAME_BYTES / 2;
    append_actual(&mut bank, FrameDirection::Incoming, half, 0, true);
    append_actual(
        &mut bank,
        FrameDirection::Outgoing,
        MAX_ORIGINAL_FRAME_BYTES - half,
        0,
        true,
    );

    assert_eq!(bank.bytes.len(), MAX_ORIGINAL_FRAME_BYTES);
    assert_eq!(bank.bytes.as_ptr(), pointer);
    assert_eq!(bank.incoming, 1);
    assert_eq!(bank.outgoing, 1);
    assert!(bank.complete());
    assert_bounded(&bank, "maximum-512MiB-literal-bank");
}
