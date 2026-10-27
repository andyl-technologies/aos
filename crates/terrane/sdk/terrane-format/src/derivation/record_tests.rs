//! Checks independently assembled memo frames and recipe/record hash preimages.

#![allow(clippy::unwrap_used)]

use super::{Memo, MemoError};
use alloc::vec;
use alloc::vec::Vec;

fn frame(recipe: &[u8], root: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa2, 0x01, 0x58, recipe.len() as u8];
    bytes.extend_from_slice(recipe);
    bytes.extend_from_slice(&[0x02, 0x58, root.len() as u8]);
    bytes.extend_from_slice(root);
    bytes
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut preimage = b"terrane-memo-v1\0".to_vec();
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}

#[test]
fn memo_record_matches_independent_wire_and_identity() {
    let recipe = core::array::from_fn(|index| index as u8);
    let root = core::array::from_fn(|index| 0x80 + index as u8);
    let expected = frame(&recipe, &root);
    assert_eq!(expected.len(), 71);

    let memo = Memo::new(recipe, root);
    assert_eq!(memo.encode(), expected);
    assert_eq!(Memo::decode(&expected).unwrap(), memo);
    assert_eq!(memo.recipe_hash(), recipe);
    assert_eq!(memo.result_root(), root);
    assert_eq!(memo.identity().unwrap(), hash(&expected));
}

#[test]
fn memo_record_refuses_every_truncation_and_noncanonical_schema() {
    let valid = frame(&[0x11; 32], &[0x22; 32]);
    for length in 0..valid.len() {
        assert!(Memo::decode(&valid[..length]).is_err(), "prefix {length}");
    }

    let cases = [
        ("missing field", 0, 0xa1),
        ("extra field", 0, 0xa3),
        ("array instead of map", 0, 0x82),
        ("wrong first key", 1, 0x02),
        ("duplicate field", 36, 0x01),
        ("unknown field", 36, 0x03),
        ("text instead of digest", 2, 0x78),
    ];
    for (name, offset, byte) in cases {
        let mut bytes = valid.clone();
        bytes[offset] = byte;
        assert!(Memo::decode(&bytes).is_err(), "{name}");
    }
    for bytes in [
        frame(&[0x11; 31], &[0x22; 32]),
        frame(&[0x11; 32], &[0x22; 31]),
    ] {
        assert_eq!(Memo::decode(&bytes), Err(MemoError::Schema));
    }

    let mut reordered = valid.clone();
    reordered[1] = 2;
    reordered[36] = 1;
    assert_eq!(Memo::decode(&reordered), Err(MemoError::Schema));
    for (offset, header, argument) in [(0, 0xb8, 2), (1, 0x18, 1), (2, 0x59, 0), (37, 0x59, 0)] {
        let mut bytes = valid.clone();
        bytes[offset] = header;
        bytes.insert(offset + 1, argument);
        bytes.pop();
        // Keep the input within the size bound so the CBOR parser, rather
        // than the outer allocation limit, must refuse each nonminimal header.
        assert_eq!(
            Memo::decode(&bytes),
            Err(MemoError::Encoding(crate::cbor::Error::NonCanonical)),
            "nonminimal header {offset}"
        );
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(Memo::decode(&trailing), Err(MemoError::Limit));
    assert_eq!(Memo::decode(&vec![0; 4096]), Err(MemoError::Limit));
}

#[test]
fn memo_identity_separates_recipe_lookup_and_record_fields() {
    // Canonical retained overlay recipe {1:"overlay", 2:[]} is assembled
    // without using the owning Recipe codec or identity-profile helper.
    let recipe = b"\xa2\x01\x67overlay\x02\x80";
    let lookup = hash(recipe);
    let root = [0x33; 32];
    let memo = Memo::new(lookup, root);
    let identity = memo.identity().unwrap();
    assert_eq!(identity, hash(&frame(&lookup, &root)));
    assert_ne!(identity, lookup);

    let mut other_lookup = lookup;
    other_lookup[0] ^= 1;
    assert_ne!(Memo::new(other_lookup, root).identity().unwrap(), identity);
    let mut other_root = root;
    other_root[0] ^= 1;
    assert_ne!(Memo::new(lookup, other_root).identity().unwrap(), identity);
    assert_eq!(memo.recipe_hash(), lookup);
}
