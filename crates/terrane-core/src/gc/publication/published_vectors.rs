//! Reads normative golden witnesses for independently constructed format tests.
//!
//! The reference file is a test input. No fixture is produced by decoding and
//! re-encoding its own bytes; callers construct the described models separately.

use crate::refs::{Locality, RefRecord};
use alloc::{format, vec::Vec};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

/// Returns the exact bytes of one uniquely named reference witness.
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

/// Constructs the earlier published whole head without decoding its wire bytes.
pub(super) fn legacy_ref() -> RefRecord {
    RefRecord {
        commit: [
            0xc8, 0xef, 0xdd, 0x18, 0x0d, 0xe6, 0xc5, 0xb1, 0xe0, 0x4a, 0xbe, 0x44, 0x35, 0x23,
            0x8e, 0x89, 0x69, 0x77, 0x64, 0x97, 0x75, 0x96, 0x82, 0xc6, 0x09, 0x4a, 0x4c, 0xed,
            0xe9, 0xc5, 0x79, 0xd6,
        ],
        seq: 1,
        writer_epoch: 1,
        home: Locality {
            region: Some("eu-west-1".into()),
            zone: None,
            host: None,
        },
        policy: None,
        candidate_id: None,
    }
}
