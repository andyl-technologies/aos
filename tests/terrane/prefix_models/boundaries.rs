//! Compares every published node threshold and full-key item hash without I/O.
//!
//! ```text
//! B(S) = floor(2^20 + (S - 4096) * (2^24 - 2^20) / 28672)
//! T(S, L) = min(2^32, floor(B(S) * L / 8))
//! ```

#![allow(
    clippy::unwrap_used,
    reason = "published rows must match their independent arithmetic"
)]

use super::{
    content::item_fields,
    support::{REFERENCE, changed, decimal, section, table, unquote},
};
use terrane_format::boundary::{self, BoundaryDecision};

fn base(size: u64) -> u64 {
    if size < 4096 {
        return 0;
    }
    if size >= 32768 {
        return 1 << 24;
    }
    ((1u128 << 20) + u128::from(size - 4096) * ((1u128 << 24) - (1u128 << 20)) / 28672) as u64
}

fn rows_match(body: &str) -> Result<bool, String> {
    let bases = table(body, "| S (bytes) | base probability | B(S) |", 3)?;
    let comparisons = table(body, "| S (bytes) | L (bytes) | comparison threshold |", 3)?;
    if bases.len() != 10 || comparisons.len() != 5 {
        return Ok(false);
    }
    for row in bases {
        let size = decimal(row[0])?;
        let independent = base(size);
        // The display column uses the continuous profile before the integer floor.
        let (numerator, denominator) = if size >= 32768 {
            (1u128 << 24, 1u128 << 32)
        } else {
            let position = size.checked_sub(4096).ok_or("base row below minimum")?;
            (
                (1u128 << 20) * 28672 + u128::from(position) * ((1u128 << 24) - (1u128 << 20)),
                28672 * (1u128 << 32),
            )
        };
        let rounded = (numerator * 1_000_000_000 + denominator / 2) / denominator;
        let probability = format!("0.{rounded:09}");
        if row[1] != probability
            || decimal(row[2])? != independent
            || u64::from(boundary::base_threshold(size)) != independent
        {
            return Ok(false);
        }
    }
    for row in comparisons {
        let size = decimal(row[0])?;
        let length = decimal(row[1])?;
        let independent = (u128::from(base(size)) * u128::from(length) / 8).min(1 << 32) as u64;
        if decimal(row[2])? != independent || boundary::threshold(size, length) != independent {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Executes all fifteen rows, the item hash, and changes to each expected field.
///
/// # Panics
/// Panics if a row is malformed or disagrees with the primitive or owning function.
pub(super) fn check_boundaries() {
    let body = section(REFERENCE, "Node boundaries").unwrap();
    assert!(rows_match(body).unwrap());
    for (header, columns) in [
        ("| S (bytes) | base probability | B(S) |", 3),
        ("| S (bytes) | L (bytes) | comparison threshold |", 3),
    ] {
        for row in table(body, header, columns).unwrap() {
            let original = format!("| {} | {} | {} |", row[0], row[1], row[2]);
            let replacement = format!(
                "| {} | {} | {} |",
                row[0],
                row[1],
                decimal(row[2]).unwrap() + 1
            );
            assert!(!rows_match(&changed(body, &original, &replacement)).unwrap());
        }
    }
    assert!(
        !rows_match(body.split_once("Per-item comparison vectors").unwrap().0).unwrap_or(false)
    );

    let leaf = section(REFERENCE, "Leaf node with one inline file").unwrap();
    let quantities = table(leaf, "| Quantity | Value |", 2).unwrap();
    assert_eq!(quantities.len(), 2);
    assert_eq!(
        quantities[1][0],
        "rolling hash of the item (TREE-21, low 32 bits of BLAKE3 over the encoded item, little-endian)"
    );
    let published_hash = decimal(unquote(quantities[1][1]).unwrap()).unwrap();
    let item = item_fields().encode();
    let raw = blake3::hash(&item);
    let independent = u32::from_le_bytes(raw.as_bytes()[..4].try_into().unwrap());
    assert_eq!(u64::from(independent), published_hash);
    assert_eq!(boundary::item_hash(&item), independent);
    let altered = changed(leaf, quantities[1][1], &format!("`{}`", published_hash + 1));
    let observed = table(&altered, "| Quantity | Value |", 2).unwrap();
    assert_ne!(
        decimal(unquote(observed[1][1]).unwrap()).unwrap(),
        u64::from(boundary::item_hash(&item))
    );

    assert_eq!(
        boundary::decide(0, item.len() as u64, &item).unwrap(),
        BoundaryDecision::Continue
    );
    assert_eq!(
        boundary::decide(65536 - item.len() as u64, item.len() as u64, &item).unwrap(),
        BoundaryDecision::CloseAfter
    );
    assert_eq!(
        boundary::decide(65537 - item.len() as u64, item.len() as u64, &item).unwrap(),
        BoundaryDecision::SplitBefore
    );
    assert_eq!(boundary::threshold(u64::MAX, u64::MAX), 1 << 32);
}
