//! Checks deterministic identities, canonical link counts and irreversible capacity.

#![allow(clippy::unwrap_used)]

use super::*;

fn identity(path: &[u8]) -> NodeIdentity {
    NodeIdentity::new([7; 32], path).unwrap()
}

#[test]
fn internal_identity_is_independent_of_first_lookup_order() {
    let first = identity(b"a");
    let second = identity(b"b");
    let mut forward = InodeTable::new(2).unwrap();
    let mut reverse = InodeTable::new(2).unwrap();

    let a = forward.touch(first, 1).unwrap();
    let b = forward.touch(second, 1).unwrap();
    let reverse_b = reverse.touch(second, 1).unwrap();
    let reverse_a = reverse.touch(first, 1).unwrap();

    assert_eq!(a.number(), 16);
    assert_eq!(b.number(), 17);
    assert_eq!(reverse_b.number(), 16);
    assert_eq!(reverse_a.number(), 17);
    assert_eq!(first, identity(b"a"));
    assert_eq!(second, identity(b"b"));
    assert_ne!(first.node_id(), second.node_id());
    assert_ne!(first, NodeIdentity::new([8; 32], b"a").unwrap());
    assert_ne!(identity(b"graft-a/file"), identity(b"graft-b/file"));
}

#[test]
fn full_table_preserves_old_numbers_and_canonical_link_counts() {
    let mut table = InodeTable::new(2).unwrap();
    assert!(table.is_empty());
    let canonical = identity(b"first-link");

    let original = table.touch(canonical, 3).unwrap();
    let other = table.touch(identity(b"other"), 1).unwrap();
    assert_eq!(table.touch(identity(b"third"), 1), Err(Error::Capacity));
    // Every resolved alias supplies the same validated canonical first path.
    assert_eq!(table.touch(canonical, 3), Ok(original));
    assert_eq!(table.touch(identity(b"other"), 1), Ok(other));

    assert_eq!(original.links(), 3);
    assert_eq!(table.len(), 2);
    assert!(!table.is_empty());
    assert_ne!(original.number(), other.number());
}

#[test]
fn metadata_refusal_consumes_no_number_or_existing_identity() {
    let mut table = InodeTable::new(2).unwrap();
    let first = identity(b"first");
    assert_eq!(table.touch(first, 0), Err(Error::Links));
    assert!(table.is_empty());
    let original = table.touch(first, 2).unwrap();

    assert_eq!(table.touch(first, 1), Err(Error::Links));
    assert_eq!(table.touch(first, 2), Ok(original));
    assert_eq!(table.touch(identity(b"next"), 1).unwrap().number(), 17);
}

#[test]
fn truncated_collision_cannot_alias_or_replace_a_retained_entry() {
    let first = identity(b"first");
    let mut collision = identity(b"second");
    collision.node_id = first.node_id;
    let mut table = InodeTable::new(2).unwrap();
    let original = table.touch(first, 1).unwrap();

    assert_eq!(table.touch(collision, 1), Err(Error::Collision));
    assert_eq!(table.touch(first, 1), Ok(original));
    assert_eq!(table.len(), 1);
    assert_eq!(table.touch(identity(b"next"), 1).unwrap().number(), 17);
}

#[test]
fn invalid_bounds_and_paths_fail_before_table_growth() {
    assert!(matches!(InodeTable::new(0), Err(Error::Configuration)));
    assert!(matches!(
        InodeTable::new(u32::MAX),
        Err(Error::Configuration)
    ));
    assert!(InodeTable::new(LAST_INODE - FIRST_INODE + 1).is_ok());
    assert!(NodeIdentity::new([7; 32], b"").is_ok());
    for path in [b"/absolute".as_slice(), b"a/../b", b"a//b", b"a\0b"] {
        assert_eq!(NodeIdentity::new([7; 32], path), Err(Error::Path));
    }
}
