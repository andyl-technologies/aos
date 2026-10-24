//! Checks deterministic identities, canonical link counts and irreversible capacity.

#![allow(clippy::unwrap_used)]

use super::*;

mod allocation;

#[test]
fn directory_pages_and_refusals_do_not_allocate_even_on_first_inode_touch() {
    use crate::structural_index::{Index, compile_tree};
    use terrane_format::{
        tree_builder::Tree,
        tree_format::{Entry, EntryKind, ExtendedAttribute, LeafItem, TreeUse},
    };

    let tree = Tree::build(
        vec![LeafItem {
            key: b"link".to_vec(),
            entry: Entry {
                kind: EntryKind::Symlink {
                    target: b"exact target",
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: vec![ExtendedAttribute {
                    name: b"user.raw",
                    value: b"value\0\xff",
                }],
                xattrs_present: true,
                provenance: None,
            },
        }],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    let bytes = compile_tree(&tree, &std::collections::BTreeMap::new(), 2, 4096).unwrap();
    let index = Index::open(&bytes).unwrap();
    let namespace = crate::fuse_namespace::Namespace::new(index, 2, 4096).unwrap();
    let mut table = InodeTable::with_reserved_capacity(2, 4096).unwrap();
    let mut limited = InodeTable::with_reserved_capacity(1, 4096).unwrap();
    let mut metadata_table = InodeTable::with_reserved_capacity(2, 4096).unwrap();
    let mut output = [0; 512];

    let ((), allocations) = allocation::measure(|| {
        for _ in 0..3 {
            let entry = namespace.lookup(1, b"link").unwrap().unwrap();
            assert_eq!(namespace.entry(1).unwrap().path(), b"");
            assert!(namespace.lookup(1, b"absent").unwrap().is_none());
            let presentation = crate::fuse_metadata::Presentation::default();
            let cache = crate::fuse_metadata::CachePolicy::Pinned;
            assert_eq!(
                crate::fuse_metadata::lookup(
                    entry,
                    presentation,
                    cache,
                    &mut metadata_table,
                    &mut output
                )
                .unwrap()
                .len(),
                128
            );
            assert_eq!(
                crate::fuse_metadata::getattr(
                    entry,
                    presentation,
                    cache,
                    &mut metadata_table,
                    &mut output
                )
                .unwrap()
                .len(),
                104
            );
            assert_eq!(
                crate::fuse_metadata::readlink(entry).unwrap(),
                b"exact target"
            );
            let policy = crate::fuse_xattr::Policy::Recorded;
            assert_eq!(
                crate::fuse_xattr::get(entry, policy, b"user.raw", 0, &mut output)
                    .unwrap()
                    .len(),
                8
            );
            assert_eq!(
                crate::fuse_xattr::get(entry, policy, b"user.raw", 32, &mut output).unwrap(),
                b"value\0\xff"
            );
            assert_eq!(
                crate::fuse_xattr::list(entry, policy, 32, &mut output).unwrap(),
                b"user.raw\0"
            );
            assert_eq!(
                crate::fuse_xattr::get(entry, policy, b"user.raw", 1, &mut output),
                Err(crate::fuse_xattr::Error::Range)
            );
            assert_eq!(
                crate::fuse_metadata::negative_lookup(cache, &mut output)
                    .unwrap()
                    .len(),
                128
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"", 0, &mut table, &mut output),
                Ok(96)
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"", 2, &mut table, &mut output),
                Ok(32)
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"", 3, &mut table, &mut []),
                Ok(0)
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"", 0, &mut table, &mut []),
                Err(crate::fuse_directory::Error::BufferTooSmall)
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"link", 0, &mut table, &mut output),
                Err(crate::fuse_directory::Error::NotDirectory)
            );
            assert_eq!(
                crate::fuse_directory::read(index, b"", 0, &mut limited, &mut output),
                Err(crate::fuse_directory::Error::Inode(Error::Capacity))
            );
        }
    });

    assert_eq!(allocations, 0);
    assert_eq!(table.len(), 2);
    assert_eq!(limited.len(), 1);
    assert_eq!(metadata_table.len(), 1);
}

type Constructor = fn(u32) -> Result<InodeTable, Error>;

fn constructors() -> [Constructor; 2] {
    [InodeTable::new, |limit| {
        InodeTable::with_reserved_capacity(limit, 4096)
    }]
}

fn identity(path: &[u8]) -> NodeIdentity {
    NodeIdentity::new([7; 32], path).unwrap()
}

#[test]
fn internal_identity_is_independent_of_first_lookup_order() {
    for new_table in constructors() {
        let first = identity(b"a");
        let second = identity(b"b");
        let mut forward = new_table(2).unwrap();
        let mut reverse = new_table(2).unwrap();

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
}

#[test]
fn full_table_preserves_old_numbers_and_canonical_link_counts() {
    for new_table in constructors() {
        let mut table = new_table(2).unwrap();
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
}

#[test]
fn metadata_refusal_consumes_no_number_or_existing_identity() {
    for new_table in constructors() {
        let mut table = new_table(2).unwrap();
        let first = identity(b"first");
        assert_eq!(table.touch(first, 0), Err(Error::Links));
        assert!(table.is_empty());
        let original = table.touch(first, 2).unwrap();

        assert_eq!(table.touch(first, 1), Err(Error::Links));
        assert_eq!(table.touch(first, 2), Ok(original));
        assert_eq!(table.touch(identity(b"next"), 1).unwrap().number(), 17);
    }
}

#[test]
fn truncated_collision_cannot_alias_or_replace_a_retained_entry() {
    for new_table in constructors() {
        let first = identity(b"first");
        let mut collision = identity(b"second");
        collision.node_id = first.node_id;
        let mut table = new_table(2).unwrap();
        let original = table.touch(first, 1).unwrap();

        assert_eq!(table.touch(collision, 1), Err(Error::Collision));
        assert_eq!(table.touch(first, 1), Ok(original));
        assert_eq!(table.len(), 1);
        assert_eq!(table.touch(identity(b"next"), 1).unwrap().number(), 17);
    }
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

#[test]
fn reserved_budget_refuses_before_allocation_and_keeps_number_assignment_lazy() {
    let ((), allocations) = allocation::measure(|| {
        assert!(matches!(
            InodeTable::with_reserved_capacity(0, 4096),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            InodeTable::with_reserved_capacity(u32::MAX, 4096),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            InodeTable::with_reserved_capacity(1, 0),
            Err(Error::MemoryBudget)
        ));
        assert!(matches!(
            InodeTable::with_reserved_capacity(LAST_INODE - FIRST_INODE + 1, 4096),
            Err(Error::MemoryBudget)
        ));
    });
    assert_eq!(allocations, 0);

    let mut table = InodeTable::with_reserved_capacity(16, 4096).unwrap();
    assert!(table.is_empty());
    assert_eq!(table.touch(identity(b"first"), 1).unwrap().number(), 16);
}

#[test]
fn reserved_probe_chains_keep_collisions_and_full_table_refusals_distinct() {
    let mut table = InodeTable::with_reserved_capacity(16, 4096).unwrap();
    let identities: [_; 16] = std::array::from_fn(|index| {
        let mut identity = NodeIdentity::new([index as u8; 32], b"same-probe-start").unwrap();
        // Every row starts at the last slot, forcing a wrapped probe chain.
        identity.node_id = 31 + (index as u64) * 64;
        identity
    });
    for (index, identity) in identities.iter().copied().enumerate() {
        assert_eq!(
            table.touch(identity, 1).unwrap().number(),
            16 + index as u32
        );
    }
    for (index, identity) in identities.iter().copied().enumerate().rev() {
        assert_eq!(
            table.touch(identity, 1).unwrap().number(),
            16 + index as u32
        );
    }

    let mut collision = identity(b"collision");
    collision.node_id = identities[15].node_id;
    assert_eq!(table.touch(collision, 1), Err(Error::Collision));
    assert_eq!(table.touch(identities[15], 2), Err(Error::Links));
    assert_eq!(table.touch(identity(b"new"), 1), Err(Error::Capacity));
    assert_eq!(table.len(), 16);
}

#[test]
fn reserved_first_touch_and_checked_metadata_operations_allocate_nothing() {
    use crate::structural_index::{Index, Kind, Record, compile};
    use terrane_format::tree_format::ContentRef;

    // Confirm that the instrument catches real allocations before relying on
    // its zero count. Construction and structural validation precede serving.
    let (control, allocations) = allocation::measure(|| std::hint::black_box(vec![9u8; 128]));
    assert!(!control.is_empty());
    assert!(allocations > 0);
    let bytes = compile(
        [7; 32],
        &[
            Record {
                path: b"dir",
                kind: Kind::Directory {
                    governing_root: None,
                },
            },
            Record {
                path: b"dir/file",
                kind: Kind::File {
                    content: ContentRef::Inline([3; 32]),
                    size: 12,
                },
            },
            Record {
                path: b"link",
                kind: Kind::Symlink(b"dir/../dir/file"),
            },
        ],
        4,
        4096,
    )
    .unwrap();
    let index = Index::open(&bytes).unwrap();
    let mut table = InodeTable::with_reserved_capacity(3, 4096).unwrap();

    let ((), allocations) = allocation::measure(|| {
        for _ in 0..3 {
            let root = index.lookup(b"").unwrap();
            for entry in root.children().unwrap() {
                table.touch_entry(entry).unwrap();
                let metadata = entry.metadata().unwrap();
                assert!(metadata.attributes.get(b"absent").is_none());
                assert_eq!(metadata.xattrs.iter().count(), 0);
            }
            let file = index.lookup(b"dir/file").unwrap();
            let original = table.touch_entry(file).unwrap();
            assert_eq!(table.touch_entry(file).unwrap(), original);
            assert_eq!(
                index.lookup(b"link").unwrap().kind(),
                Kind::Symlink(b"dir/../dir/file")
            );
            assert!(index.lookup(b"missing").is_none());
            assert_eq!(table.touch_entry(root), Err(Error::Capacity));
        }
    });

    assert_eq!(allocations, 0);
    assert_eq!(table.len(), 3);
}
