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
    let mut dispatch = crate::fuse_dispatch::Metadata::new(
        index,
        crate::fuse_dispatch::Limits {
            namespace_entries: 2,
            namespace_bytes: 4096,
            inodes: 2,
            inode_bytes: 4096,
        },
        crate::fuse_metadata::CachePolicy::Pinned,
        crate::fuse_xattr::Policy::Recorded,
    )
    .unwrap();
    let mut lookup = [0; 45];
    lookup[..4].copy_from_slice(&45u32.to_ne_bytes());
    lookup[4..8].copy_from_slice(&1u32.to_ne_bytes());
    lookup[8..16].copy_from_slice(&1u64.to_ne_bytes());
    lookup[16..24].copy_from_slice(&1u64.to_ne_bytes());
    lookup[40..].copy_from_slice(b"link\0");
    let lookup = crate::fuse_protocol::Request::parse(&lookup, 4096).unwrap();
    let link = index.lookup(b"link").unwrap();
    let link_node = NodeIdentity::new(link.governing_root().unwrap(), link.path())
        .unwrap()
        .node_id();
    let record = |opcode: u32, node: u64, body: &[u8]| {
        let mut bytes = vec![0; 40];
        bytes.extend_from_slice(body);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..8].copy_from_slice(&opcode.to_ne_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&node.to_ne_bytes());
        bytes
    };
    let mut directory_read = [0; 40];
    directory_read[..8].copy_from_slice(&1u64.to_ne_bytes());
    directory_read[16..20].copy_from_slice(&512u32.to_ne_bytes());
    let requests = [
        (record(3, link_node, &[0; 16]), 104),
        (record(5, link_node, &[]), 12),
        (record(28, 1, &directory_read), 96),
        (record(22, link_node, b"\0\0\0\0\0\0\0\0user.raw\0"), 8),
        (record(23, link_node, &[0; 8]), 8),
    ];
    let mut kernel_read = [0; 40];
    kernel_read[..8].copy_from_slice(&1u64.to_ne_bytes());
    kernel_read[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
    kernel_read[16..20].copy_from_slice(&512u32.to_ne_bytes());
    let kernel_read = record(15, link_node, &kernel_read);
    let kernel_read = crate::fuse_protocol::Request::parse(&kernel_read, 4096).unwrap();
    let original_node = std::num::NonZeroU64::new(link_node).unwrap();
    let original_handle = std::num::NonZeroU64::new(1).unwrap();
    let forget_bytes = record(2, link_node, &1u64.to_ne_bytes());
    let forget = crate::fuse_protocol::Request::parse(&forget_bytes, 4096).unwrap();
    let mut lifetime = crate::fuse_lifetime::Table::new(crate::fuse_lifetime::Limits {
        nodes: 1,
        handles: 1,
        bytes: 4096,
    })
    .unwrap();
    let mut pending_opens = crate::fuse_open::Queue::new(crate::fuse_open::Limits {
        nodes: 1,
        waiters: 1,
        bytes: 4096,
    })
    .unwrap();
    #[allow(
        clippy::disallowed_methods,
        reason = "This fixed test origin anchors pure queue operations without reading a clock during allocation measurement or changing repository state."
    )]
    let open_now = std::time::Instant::now();
    let open_timeout = std::time::Duration::from_secs(60);
    let mut backings = crate::fuse_backing::Table::<u64>::new(crate::fuse_backing::Limits {
        nodes: 1,
        bytes: 4096,
    })
    .unwrap();
    let mut output = [0; 512];

    let ((), allocations) = allocation::measure(|| {
        for _ in 0..3 {
            lifetime.lookup(original_node).unwrap();
            lifetime.pin(original_node).unwrap();
            let handle = lifetime
                .open(original_node, crate::fuse_lifetime::Kind::File)
                .unwrap();
            lifetime.forget(forget, 1).unwrap();
            lifetime
                .check(handle, original_node, crate::fuse_lifetime::Kind::File)
                .unwrap();
            lifetime
                .close(handle, original_node, crate::fuse_lifetime::Kind::File)
                .unwrap();
            assert_eq!(lifetime.next_unreferenced(), None);
            lifetime.unpin(original_node).unwrap();
            assert_eq!(lifetime.next_unreferenced(), Some(original_node));
            let crate::fuse_open::Enqueued::Start(ticket) = pending_opens
                .enqueue(original_node, original_handle, open_now, open_timeout)
                .unwrap()
            else {
                panic!("fresh original open did not start its handoff");
            };
            backings.reserve(ticket).unwrap();
            backings.install(ticket, 42).unwrap();
            assert_eq!(backings.get(original_node), Some(&42));
            let rejected = backings.install(ticket, 99).unwrap_err();
            assert_eq!(rejected.error, crate::fuse_backing::Error::Stale);
            assert_eq!(backings.retire(original_node), Ok(Some(42)));
            pending_opens
                .complete(ticket, crate::fuse_open::Outcome::Ready)
                .unwrap();
            assert_eq!(
                pending_opens.next_reply(open_now).unwrap().outcome,
                crate::fuse_open::Outcome::Ready
            );
            assert_eq!((pending_opens.pending(), pending_opens.waiting()), (0, 0));
            let read =
                crate::fuse_read::Read::parse(kernel_read, original_node, original_handle).unwrap();
            assert_eq!(read.offset(), u64::MAX);
            assert_eq!(read.length(), 512);
            assert!(
                matches!(dispatch.dispatch(lookup, |_| crate::fuse_metadata::Presentation::default(), &mut output).unwrap(), crate::fuse_dispatch::Response::Payload(bytes) if bytes.len() == 128)
            );
            for (bytes, length) in &requests {
                let request = crate::fuse_protocol::Request::parse(bytes, 4096).unwrap();
                assert!(
                    matches!(dispatch.dispatch(request, |_| crate::fuse_metadata::Presentation::default(), &mut output).unwrap(), crate::fuse_dispatch::Response::Payload(bytes) if bytes.len() == *length)
                );
            }
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
                crate::fuse_read::open(std::num::NonZeroU64::new(1).unwrap(), &mut output)
                    .unwrap()
                    .len(),
                16
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
