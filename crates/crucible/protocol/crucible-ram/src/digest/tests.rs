//! Checks logical-page and tree digest domains against literal preimages.

use super::*;

#[test]
fn page_hash_matches_literal_full_and_partial_page_preimages() {
    for valid in [1, 7, 4095, 4096] {
        let bytes: Vec<_> = (0..valid).map(|index| (index % 251) as u8).collect();
        let mut preimage = b"crucible.ram.page.v1\0".to_vec();
        preimage.extend_from_slice(&(valid as u32).to_be_bytes());
        preimage.extend_from_slice(&bytes);

        assert_eq!(
            PageDigest::hash(&bytes).unwrap().as_bytes(),
            blake3::hash(&preimage).as_bytes()
        );
    }
    assert!(PageDigest::hash(&[]).is_err());
    assert!(PageDigest::hash(&[0; 4097]).is_err());
}

#[test]
fn shared_tag_initializer_preserves_leaf_empty_and_ordered_node_domains() {
    let page = PageDigest::from_bytes([0x17; 32]);
    let mut leaf = b"crucible.ram.leaf.v1\0".to_vec();
    leaf.extend_from_slice(page.as_bytes());
    assert_eq!(leaf_digest(page).as_bytes(), blake3::hash(&leaf).as_bytes());
    assert_eq!(
        empty_leaf_digest().as_bytes(),
        blake3::hash(b"crucible.ram.empty.v1\0").as_bytes()
    );

    let left = NodeDigest::from_bytes([0x23; 32]);
    let right = NodeDigest::from_bytes([0x42; 32]);
    for height in [1_u32, 52] {
        let mut node = b"crucible.ram.node.v1\0".to_vec();
        node.extend_from_slice(&height.to_be_bytes());
        node.extend_from_slice(left.as_bytes());
        node.extend_from_slice(right.as_bytes());
        assert_eq!(
            inner_digest(height, left, right).unwrap().as_bytes(),
            blake3::hash(&node).as_bytes()
        );
    }
}
