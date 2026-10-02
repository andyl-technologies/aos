//! Reads normative golden witnesses for independently constructed format tests.
//!
//! The reference file is a test input. No fixture is produced by decoding and
//! re-encoding its own bytes; callers construct the described models separately.

use alloc::{format, vec::Vec};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

/// Returns the exact bytes of one uniquely named positive reference witness.
///
/// # Panics
/// Panics when the reference lacks the named section or its unique hex block,
/// or when its published hex is malformed.
#[allow(
    clippy::unwrap_used,
    reason = "Malformed normative test input must fail the test."
)]
pub(super) fn bytes(name: &str) -> Vec<u8> {
    let heading = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&heading).count(), 1);
    let section = REFERENCE.split_once(&heading).unwrap().1;
    let section = section.split("\n##").next().unwrap();
    assert_eq!(section.matches("```hex\n").count(), 1);
    let hex = section.split_once("```hex\n").unwrap().1;
    let hex = hex.split_once("\n```").unwrap().0;
    let digits: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(digits.len() % 2, 0);

    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            assert!(
                pair.iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            );
            let pair = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
