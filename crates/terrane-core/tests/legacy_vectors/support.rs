//! Extracts reviewed published bytes without using any format encoder.

use super::core_model::identity::Digest;
use alloc::{format, string::String, vec::Vec};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

pub(super) fn hexadecimal(text: &str) -> Vec<u8> {
    let digits: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

pub(super) fn fixed<const N: usize>(text: &str) -> [u8; N] {
    hexadecimal(text).try_into().unwrap()
}

pub(super) fn digest(text: &str) -> Digest {
    fixed(text)
}

/// Selects a unique complete heading and the numbered hex block below it.
pub(super) fn wire(heading: &str, index: usize) -> Vec<u8> {
    let marker = format!("{heading}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1, "{heading}");
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n##")
        .next()
        .unwrap();
    let encoded = section.split("```hex\n").nth(index + 1).unwrap();

    hexadecimal(encoded.split_once("```").unwrap().0)
}
