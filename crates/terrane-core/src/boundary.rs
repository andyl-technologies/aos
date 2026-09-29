//! Computes the draft Terrane node boundary decisions without I/O.
//!
//! TREE-21 hashes canonical items independently of leaf prefix compression.
//! TREE-22 compares that hash with an integer threshold based on accumulated
//! encoded item bytes, including the item just appended. Node framing is
//! excluded. These functions implement the draft rule; they do not validate
//! canonical encoding or enforce the decoder's node-size limit.

/// Specifies the minimum accumulated item bytes before a probabilistic cut.
pub const MIN_NODE: u64 = 4_096;

/// Specifies the accumulated item bytes that force a cut after an item.
pub const MAX_NODE: u64 = 65_536;

/// Returns the exact TREE-22 probability threshold scaled by `2^32`.
///
/// Sizes below [`MIN_NODE`] return zero. At 32 KiB and above, the threshold
/// remains `2^24`; the mandatory maximum cut is handled by [`closes_node`].
/// Integer arithmetic reproduces the normative golden-vector table exactly.
pub const fn threshold(encoded_item_bytes: u64) -> u32 {
    if encoded_item_bytes < MIN_NODE {
        return 0;
    }

    if encoded_item_bytes >= 32_768 {
        return 1 << 24;
    }

    let scaled = (1 << 20) + (encoded_item_bytes - MIN_NODE) * ((1 << 24) - (1 << 20)) / 28_672;
    scaled as u32
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

/// Reports whether the draft procedure closes a node after the current item.
///
/// `encoded_item_bytes` includes the current item's stored encoding, with
/// prefix compression applied for a leaf. `canonical_item` uses the full-key
/// encoding specified by [`item_hash`]. A final node always closes at the end
/// of the stream even when this function returns false.
///
/// A forced cut occurs after reaching [`MAX_NODE`]. Consequently, this draft
/// rule can overshoot the decoder limit by the size of the last item; callers
/// must not mistake a boundary decision for validation of node size.
pub fn closes_node(encoded_item_bytes: u64, canonical_item: &[u8]) -> bool {
    encoded_item_bytes >= MAX_NODE
        || (encoded_item_bytes >= MIN_NODE
            && item_hash(canonical_item) < threshold(encoded_item_bytes))
}

#[cfg(test)]
mod tests {
    use super::{MAX_NODE, MIN_NODE, closes_node, item_hash, threshold};

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
            assert_eq!(threshold(size), expected, "size {size}");
        }
        assert_eq!(threshold(MIN_NODE - 1), 0);
        assert_eq!(threshold(u64::MAX), 16_777_216);
    }

    #[test]
    fn item_hash_matches_the_normative_full_key_leaf() {
        let item = [
            0x83, 0x49, b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', 0x00, 0xa4, 0x01,
            0x01, 0x02, 0x19, 0x01, 0xa4, 0x03, 0x0f, 0x04, 0x82, 0x00, 0x58, 0x20, 0x94,
            0x79, 0xe1, 0xe5, 0x74, 0x91, 0x07, 0x8e, 0xb0, 0x9f, 0x9d, 0xec, 0xc2, 0xc5,
            0x6c, 0x63, 0x11, 0x0c, 0x37, 0x2d, 0xe0, 0x15, 0x57, 0xd7, 0x35, 0x60, 0xdb,
            0xc2, 0xba, 0x9f, 0x3b, 0xa0,
        ];

        assert_eq!(item_hash(&item), 1_677_076_257);
        assert!(!closes_node(MIN_NODE - 1, &item));
        assert!(closes_node(MAX_NODE, &item));
        assert!(closes_node(u64::MAX, &item));
    }
}
