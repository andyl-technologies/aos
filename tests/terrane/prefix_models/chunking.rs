//! Reads all published gear, mask and stream rows through private profile fields.
//!
//! The independent oracle uses raw BLAKE3-XOF and the specified scan arithmetic.
//! Its fields are ordinary parameters and do not admit content to any backend.
//!
//! ```text
//! gear[i] = u64le(BLAKE3-XOF("terrane-gear-v1" || 0x00 || seed)[8*i..8*i+8])
//! fp = (2 * fp + gear[input[i]]) mod 2^64
//! ```

#![allow(
    clippy::unwrap_used,
    reason = "every published parameter and offset must match"
)]

#[allow(
    clippy::duplicate_mod,
    reason = "isolated private consumers share the primitive reference reader"
)]
#[path = "support.rs"]
mod support;

use super::ChunkProfile;
use alloc::{format, string::ToString, vec, vec::Vec};
use support::{
    REFERENCE, blocks, changed, decimal, hexadecimal, literal_after, section, table, unquote, word,
};

fn mask(bits: u64) -> u64 {
    (0..bits).fold(0, |value, index| {
        value | (1 << (16 + 31 * index / (bits - 1)))
    })
}

fn independent_profile() -> ChunkProfile {
    let seed = [0; 32];
    let mut bytes = [0; 2048];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-gear-v1");
    hasher.update(&[0]);
    hasher.update(&seed);
    hasher.finalize_xof().fill(&mut bytes);
    let gear = core::array::from_fn(|index| {
        u64::from_le_bytes(bytes[8 * index..8 * index + 8].try_into().unwrap())
    });
    ChunkProfile {
        minimum: 262_144,
        target: 1_048_576,
        maximum: 4_194_304,
        window: 48,
        normalization: 2,
        seed,
        gear,
        strict_mask: mask(22),
        eager_mask: mask(18),
    }
}

/// Scans from independent fields without invoking a profile boundary method.
fn independent_ends(profile: &ChunkProfile, input: &[u8]) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut start = 0;
    while start < input.len() {
        let remaining = &input[start..];
        let mut length = remaining.len().min(profile.maximum);
        let mut fingerprint = 0u64;
        for (index, byte) in remaining
            .iter()
            .enumerate()
            .take(length)
            .skip(profile.minimum)
        {
            fingerprint = fingerprint
                .wrapping_mul(2)
                .wrapping_add(profile.gear[usize::from(*byte)]);
            let mask = if index < profile.target {
                profile.strict_mask
            } else {
                profile.eager_mask
            };
            if fingerprint & mask == 0 {
                length = index + 1;
                break;
            }
        }
        start += length;
        ends.push(start);
    }
    ends
}

fn expected_ends(body: &str) -> Result<Vec<usize>, alloc::string::String> {
    let paragraphs = blocks(body, "text", 2)?;
    paragraphs[1]
        .split_ascii_whitespace()
        .map(|value| {
            usize::try_from(decimal(value)?).map_err(|error| format!("stream offset: {error}"))
        })
        .collect()
}

#[test]
fn published_gear_masks_and_cdc_offsets_match_profile() {
    let body = section(REFERENCE, "Gear table").unwrap();
    assert!(body.contains("all-zero 32-byte seed"));
    let rows = table(body, "| i | `gear[i]` |", 2).unwrap();
    assert_eq!(rows.len(), 8);
    let independent = independent_profile();
    let owning = ChunkProfile::cdc_1m([0; 32]);
    assert_eq!(
        owning, independent,
        "every parameter and all 256 gear words"
    );
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(decimal(row[0]).unwrap(), index as u64);
        assert_eq!(word(unquote(row[1]).unwrap()).unwrap(), owning.gear[index]);
        let altered = changed(
            body,
            row[1],
            &format!("`0x{:016x}`", owning.gear[index] ^ 1),
        );
        let observed = table(&altered, "| i | `gear[i]` |", 2).unwrap();
        assert_ne!(
            word(unquote(observed[index][1]).unwrap()).unwrap(),
            owning.gear[index]
        );
    }
    let bytes: Vec<_> = independent
        .gear
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let digest = literal_after(body, "BLAKE3 of the full 2 048-byte table: `").unwrap();
    assert_eq!(
        hexadecimal(digest).unwrap(),
        blake3::hash(&bytes).as_bytes()
    );
    let altered = changed(
        body,
        digest,
        &format!(
            "{}{}",
            if digest.starts_with('0') { "1" } else { "0" },
            &digest[1..]
        ),
    );
    assert_ne!(
        hexadecimal(literal_after(&altered, "BLAKE3 of the full 2 048-byte table: `").unwrap())
            .unwrap(),
        blake3::hash(&bytes).as_bytes()
    );

    for (marker, actual) in [
        (
            "two level-2 masks derived by CDC-1 are\n`",
            owning.strict_mask,
        ),
        ("and\n`", owning.eager_mask),
    ] {
        let published = literal_after(body, marker).unwrap();
        assert_eq!(word(published).unwrap(), actual);
        let altered = changed(body, published, &format!("0x{:016x}", actual ^ 1));
        assert_ne!(
            word(literal_after(&altered, marker).unwrap()).unwrap(),
            actual
        );
    }

    let mut input = vec![0; 16_777_216];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"terrane-cdc-boundaries-v1");
    hasher.update(&[0]);
    hasher.finalize_xof().fill(&mut input);
    let primitive = independent_ends(&independent, &input);
    let published = expected_ends(body).unwrap();
    let actual: Vec<_> = owning.ranges(&input).map(|range| range.end).collect();
    assert_eq!(published.len(), 15);
    assert_eq!(primitive, published);
    assert_eq!(actual, published);
    for (index, offset) in published.iter().enumerate() {
        let offsets = blocks(body, "text", 2).unwrap()[1];
        let original = offsets.split_ascii_whitespace().nth(index).unwrap();
        let altered_offsets = changed(offsets, original, &(offset + 1).to_string());
        let altered = changed(body, offsets, &altered_offsets);
        assert_ne!(expected_ends(&altered).unwrap(), actual);
    }
    assert_eq!(actual.last(), Some(&input.len()));
    assert_eq!(owning.boundaries(&[]), vec![0..0]);
    assert!(expected_ends(body.split_once("The cumulative end offsets").unwrap().0).is_err());
}
