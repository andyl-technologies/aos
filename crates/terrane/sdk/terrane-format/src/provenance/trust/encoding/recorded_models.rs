//! Independently assembles raw context models without the owning codecs.

use alloc::{vec, vec::Vec};

/// Frozen original behavioral names, independently written from the registry.
pub(crate) const LEGACY: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

/// Returns the independently enumerated revision vocabulary.
pub(crate) fn vocabulary(revision: u64) -> Vec<&'static str> {
    let mut names = LEGACY.to_vec();
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision >= 3 {
        names.push("index-gaps");
    }
    names.sort_unstable();
    names
}

/// Writes an unsigned primitive with a chosen major type.
pub(crate) fn head(major: u8, value: u64) -> Vec<u8> {
    let mut bytes = vec![major << 5];
    match value {
        0..=23 => bytes[0] |= value as u8,
        24..=255 => {
            bytes[0] |= 24;
            bytes.push(value as u8);
        }
        256..=65535 => {
            bytes[0] |= 25;
            bytes.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            bytes[0] |= 26;
            bytes.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            bytes[0] |= 27;
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    bytes
}

/// Encodes an independent unsigned integer.
pub(crate) fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

/// Encodes an independent byte string.
pub(crate) fn bytes(value: &[u8]) -> Vec<u8> {
    let mut result = head(2, value.len() as u64);
    result.extend_from_slice(value);
    result
}

/// Encodes an independent text string.
pub(crate) fn text(value: &str) -> Vec<u8> {
    let mut result = head(3, value.len() as u64);
    result.extend_from_slice(value.as_bytes());
    result
}

/// Joins independently encoded array elements.
pub(crate) fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut result = head(4, values.len() as u64);
    for value in values {
        result.extend_from_slice(value);
    }
    result
}

/// Builds a complete raw v3 tuple, including deliberately invalid claim arrays.
pub(crate) fn context(
    revision: u64,
    behavioral: &[&str],
    later: &[&str],
    selected: Option<&[u8]>,
) -> Vec<u8> {
    array(&[
        uint(3),
        bytes(&[1; 32]),
        text("private:test"),
        bytes(&array(&[text("preset"), text("any")])),
        text(""),
        uint(262144),
        selected.map(bytes).unwrap_or_else(|| vec![0xf6]),
        array(&[
            bytes(&[2; 32]),
            uint(revision),
            array(&behavioral.iter().map(|n| text(n)).collect::<Vec<_>>()),
            array(&later.iter().map(|n| text(n)).collect::<Vec<_>>()),
        ]),
    ])
}

/// Builds complete selected evidence with independently supplied relationships.
pub(crate) fn evidence(view: u8, domain: &str, row_name: &str, side_name: &str) -> Vec<u8> {
    let location = array(&[bytes(&[view; 32]), bytes(&[2; 32]), bytes(b"file")]);
    let side = array(&[
        bytes(&[3; 32]),
        bytes(&[4; 32]),
        text(side_name),
        text("hash"),
        text("v1"),
        bytes(&uint(24)),
        bytes(&[5; 32]),
        location.clone(),
        array(&[text("private:producer"), bytes(b"file")]),
    ]);
    array(&[array(&[
        location,
        text(row_name),
        text(domain),
        bytes(b"file"),
        side,
    ])])
}
