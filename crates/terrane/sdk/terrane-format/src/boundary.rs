//! Computes the draft Terrane node boundary decisions without I/O.
//!
//! TREE-21 hashes canonical items independently of leaf prefix compression.
//! TREE-22 compares that hash with an integer threshold based on accumulated
//! encoded item bytes, including the item just appended. Node framing is
//! excluded. A checked decision splits before an item would exceed the cap;
//! the caller then re-encodes that item with reset prefix compression.

use core::fmt;

/// Specifies the minimum accumulated item bytes before a probabilistic cut.
pub const MIN_NODE: u64 = 4_096;

/// Specifies the maximum accumulated item bytes allowed in one node.
pub const MAX_NODE: u64 = 65_536;

/// Returns the exact TREE-22 base threshold before scaling by item length.
///
/// Sizes below [`MIN_NODE`] return zero. At 32 KiB and above, the threshold
/// remains `2^24`; the mandatory maximum cut is handled by [`decide`].
/// Integer arithmetic reproduces the normative golden-vector table exactly.
pub const fn base_threshold(encoded_item_bytes: u64) -> u32 {
    if encoded_item_bytes < MIN_NODE {
        return 0;
    }

    if encoded_item_bytes >= 32_768 {
        return 1 << 24;
    }

    let scaled = (1 << 20) + (encoded_item_bytes - MIN_NODE) * ((1 << 24) - (1 << 20)) / 28_672;
    scaled as u32
}

/// Returns the TREE-22 byte-normalized per-item comparison threshold.
///
/// `encoded_item_bytes` includes the current item's stored encoding, and
/// `stored_item_bytes` is that item's actual prefix-compressed length. The
/// threshold saturates at `2^32`, which requires a wider type than the hash.
/// Wide intermediate arithmetic prevents overflow even for unvalidated sizes.
pub const fn threshold(encoded_item_bytes: u64, stored_item_bytes: u64) -> u64 {
    let scaled = base_threshold(encoded_item_bytes) as u128 * stored_item_bytes as u128 / 8;

    if scaled >= 1 << 32 {
        1 << 32
    } else {
        scaled as u64
    }
}

/// Returns the TREE-21 low 32 bits of an item's BLAKE3 digest.
///
/// The first four digest bytes are interpreted in little-endian order, as
/// fixed by the leaf-item golden vector. A leaf caller supplies the canonical
/// item with its full key and `shared = 0`; an internal caller supplies the
/// canonical child reference. No identity-domain prefix participates.
pub fn item_hash(canonical_item: &[u8]) -> u32 {
    let digest = blake3::hash(canonical_item);
    let bytes = digest.as_bytes();

    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Describes whether a canonical item stays in the current node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryDecision {
    /// Appends the item and continues accumulating the node.
    Continue,
    /// Appends the item and closes the node after it.
    CloseAfter,
    /// Closes the current node before appending the item.
    ///
    /// The caller re-encodes the item as the new node's first item and calls
    /// [`decide`] again with zero accumulated bytes.
    SplitBefore,
}

/// Describes input sizes that cannot form a valid capped node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryError {
    /// Indicates an item that cannot fit alone in a node.
    ItemTooLarge {
        /// Carries the oversized encoding's byte length.
        bytes: u64,
    },
    /// Indicates a current node that already exceeds the cap.
    NodeTooLarge {
        /// Carries the current node's accumulated item bytes.
        bytes: u64,
    },
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ItemTooLarge { bytes } => write!(
                formatter,
                "encoded item of {bytes} bytes exceeds {MAX_NODE}"
            ),
            Self::NodeTooLarge { bytes } => write!(
                formatter,
                "node item size of {bytes} bytes exceeds {MAX_NODE}"
            ),
        }
    }
}

impl core::error::Error for BoundaryError {}

/// Returns the checked TREE-22 split decision for one canonical item.
///
/// `node_item_bytes` excludes the current item; `stored_item_bytes` includes
/// prefix compression applied for a leaf. `canonical_item` is the full-key
/// encoding specified by [`item_hash`], also the item's standalone encoding.
/// A final nonempty node closes at the end of the stream regardless of this
/// decision. The caller validates canonical encoding independently.
///
/// # Errors
/// Returns [`BoundaryError::ItemTooLarge`] if the stored or standalone item
/// encoding exceeds [`MAX_NODE`], or [`BoundaryError::NodeTooLarge`] if the
/// accumulated node already exceeds that bound.
pub fn decide(
    node_item_bytes: u64,
    stored_item_bytes: u64,
    canonical_item: &[u8],
) -> Result<BoundaryDecision, BoundaryError> {
    let standalone_bytes = canonical_item.len() as u64;
    let largest_encoding = standalone_bytes.max(stored_item_bytes);
    if largest_encoding > MAX_NODE {
        return Err(BoundaryError::ItemTooLarge {
            bytes: largest_encoding,
        });
    }

    if node_item_bytes > MAX_NODE {
        return Err(BoundaryError::NodeTooLarge {
            bytes: node_item_bytes,
        });
    }

    // Both terms are capped at 64 KiB, so their sum cannot overflow.
    let encoded_item_bytes = node_item_bytes + stored_item_bytes;
    if encoded_item_bytes > MAX_NODE {
        return Ok(BoundaryDecision::SplitBefore);
    }

    if encoded_item_bytes == MAX_NODE
        || (encoded_item_bytes >= MIN_NODE
            && u64::from(item_hash(canonical_item))
                < threshold(encoded_item_bytes, stored_item_bytes))
    {
        return Ok(BoundaryDecision::CloseAfter);
    }

    Ok(BoundaryDecision::Continue)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundaryDecision, BoundaryError, MAX_NODE, MIN_NODE, base_threshold, decide, item_hash,
        threshold,
    };

    #[test]
    fn thresholds_match_every_normative_table_row() {
        let rows = [
            (4_096, 1_048_576),
            (8_192, 3_295_524),
            (12_288, 5_542_473),
            (16_384, 7_789_421),
            (20_480, 10_036_370),
            (24_576, 12_283_318),
            (28_672, 14_530_267),
            (32_768, 16_777_216),
            (49_152, 16_777_216),
            (65_536, 16_777_216),
        ];

        for (size, expected) in rows {
            assert_eq!(base_threshold(size), expected, "size {size}");
        }
        assert_eq!(base_threshold(MIN_NODE - 1), 0);
        assert_eq!(base_threshold(u64::MAX), 16_777_216);
    }

    #[test]
    fn item_hash_matches_the_normative_full_key_leaf() {
        let item = [
            0x83, 0x49, b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', 0x00, 0xa4, 0x01,
            0x01, 0x02, 0x19, 0x01, 0xa4, 0x03, 0x0f, 0x04, 0x82, 0x00, 0x58, 0x20, 0x94, 0x79,
            0xe1, 0xe5, 0x74, 0x91, 0x07, 0x8e, 0xb0, 0x9f, 0x9d, 0xec, 0xc2, 0xc5, 0x6c, 0x63,
            0x11, 0x0c, 0x37, 0x2d, 0xe0, 0x15, 0x57, 0xd7, 0x35, 0x60, 0xdb, 0xc2, 0xba, 0x9f,
            0x3b, 0xa0,
        ];

        assert_eq!(item_hash(&item), 1_677_076_257);
        assert_eq!(
            decide(0, item.len() as u64, &item),
            Ok(BoundaryDecision::Continue)
        );
    }

    #[test]
    fn comparison_vectors_scale_by_stored_length_and_saturate() {
        for (size, length, expected) in [
            (4_096, 8, 1_048_576),
            (8_192, 48, 19_773_144),
            (16_384, 64, 62_315_368),
            (32_768, 128, 268_435_456),
            (65_536, 65_536, 4_294_967_296),
        ] {
            assert_eq!(threshold(size, length), expected);
        }
        assert_eq!(threshold(u64::MAX, u64::MAX), 1 << 32);
        assert_eq!(threshold(MIN_NODE - 1, u64::MAX), 0);
    }

    #[test]
    fn strict_cap_splits_before_overflow_and_closes_at_exact_fit() {
        let item = [0x83, 0x40, 0x00, 0xa1, 0x01, 0x05];

        assert_eq!(
            decide(MAX_NODE - 6, 6, &item),
            Ok(BoundaryDecision::CloseAfter)
        );
        assert_eq!(
            decide(MAX_NODE - 5, 6, &item),
            Ok(BoundaryDecision::SplitBefore)
        );
        assert_eq!(
            decide(0, MAX_NODE + 1, &item),
            Err(BoundaryError::ItemTooLarge {
                bytes: MAX_NODE + 1
            })
        );
        assert_eq!(
            decide(MAX_NODE + 1, 6, &item),
            Err(BoundaryError::NodeTooLarge {
                bytes: MAX_NODE + 1
            })
        );
    }
}
