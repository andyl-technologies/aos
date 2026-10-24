//! Checks exact decimal-string parity at every unsigned digit boundary.

// crucible-lint: allow panic-shortcut -- These wire-parity tests deliberately panic on encoding mismatches.

use super::{I64, U64};
use std::io::Cursor;

fn assert_original_wire_and_round_trip(value: u64) {
    let mut output = Cursor::new([0u8; 22]);
    serde_json::to_writer(&mut output, &U64::new(value)).unwrap();
    let length = usize::try_from(output.position()).unwrap();
    let encoded = &output.get_ref()[..length];

    // This is the previous implementation's actual formatter and serializer,
    // independently of the replacement's division/buffer/index arithmetic.
    let previous = serde_json::to_vec(&value.to_string()).unwrap();
    assert_eq!(encoded, previous, "wire mismatch for {value}");
    let decoded: U64 = serde_json::from_slice(encoded).unwrap();
    assert_eq!(decoded.get(), value);
    assert_eq!(length, value.to_string().len() + 2);
}

#[test]
fn all_decimal_digit_boundaries_keep_the_original_string_encoding() {
    assert_original_wire_and_round_trip(0);
    assert_original_wire_and_round_trip(u64::MAX);
    let mut power = 1u64;
    loop {
        for value in [power - 1, power, power + 1] {
            assert_original_wire_and_round_trip(value);
        }
        let Some(next) = power.checked_mul(10) else {
            break;
        };
        power = next;
    }
}

#[test]
fn binary_boundaries_and_small_values_preserve_exact_decimal_bytes() {
    for value in 0..=1024 {
        assert_original_wire_and_round_trip(value);
    }
    for bit in 0..64 {
        let value = 1u64 << bit;
        for candidate in [value - 1, value, value + 1] {
            assert_original_wire_and_round_trip(candidate);
        }
    }
}

#[test]
fn full_width_string_fits_exactly_and_propagates_a_short_writer_refusal() {
    let mut exact = Cursor::new([0u8; 22]);
    serde_json::to_writer(&mut exact, &U64::new(u64::MAX)).unwrap();
    assert_eq!(exact.position(), 22);
    assert_eq!(exact.get_ref(), b"\"18446744073709551615\"");

    let mut short = Cursor::new([0u8; 21]);
    assert!(serde_json::to_writer(&mut short, &U64::new(u64::MAX)).is_err());
}

#[test]
fn signed_decimal_branch_keeps_its_existing_formatter() {
    for value in [i64::MIN, -10, -1, 0, 1, 10, i64::MAX] {
        let encoded = serde_json::to_vec(&I64::new(value)).unwrap();
        assert_eq!(encoded, serde_json::to_vec(&value.to_string()).unwrap());
        let decoded: I64 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.get(), value);
    }
}

#[path = "u64_serialize_bench.rs"]
mod benchmark;
