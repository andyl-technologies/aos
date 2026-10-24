//! Checks native payload layouts, schema overrides and unchanged refused outputs.

#![allow(
    clippy::unwrap_used,
    reason = "Codec fixtures panic when a checked payload or expected field cannot be constructed."
)]

use super::*;
use crate::structural_index::{self, Index};
use std::collections::BTreeMap;
use terrane_format::{
    tree_builder::Tree,
    tree_format::{Attribute, ContentRef, Entry as TreeEntry, EntryKind, LeafItem, TreeUse},
};

fn bytes(uid: &'static [u8]) -> Vec<u8> {
    let file = |path: &[u8]| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o640,
                size: 3,
                content: ContentRef::Inline([2; 32]),
                link_id: Some(b"a"),
            },
            attrs: vec![Attribute {
                name: "uid",
                value: uid,
            }],
            attrs_present: true,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let mut directory = file(b"directory");
    directory.entry.kind = EntryKind::Directory { mode: 0o750 };
    let mut link = file(b"link");
    link.entry.kind = EntryKind::Symlink {
        target: b".././raw\xff",
    };
    let tree = Tree::build(
        vec![file(b"a"), file(b"b"), directory, link],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    structural_index::compile_tree(&tree, &BTreeMap::new(), 16, 65536).unwrap()
}

fn table() -> InodeTable {
    InodeTable::with_reserved_capacity(16, 65536).unwrap()
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn field(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn lookup_and_getattr_preserve_recorded_fields_and_hardlink_identity() {
    let bytes = bytes(b"\x18\x2a");
    let index = Index::open(&bytes).unwrap();
    let mut table = table();
    let mut output = [0xaa; 144];
    let entry = index.lookup(b"b").unwrap();
    let lookup = lookup(
        entry,
        Presentation::default(),
        CachePolicy::Pinned,
        &mut table,
        &mut output,
    )
    .unwrap();
    assert_eq!(lookup.len(), 128);
    let node = word(lookup, 0);
    let inode = word(lookup, 40);
    assert!(node > 1);
    assert_eq!(inode, 16);
    assert_eq!(word(lookup, 8), 1);
    assert_eq!(word(lookup, 16), u64::MAX);
    assert_eq!(word(lookup, 24), u64::MAX);
    assert_eq!(word(lookup, 48), 3);
    assert_eq!(word(lookup, 56), 0);
    assert_eq!(field(lookup, 100), libc::S_IFREG | 0o640);
    assert_eq!(field(lookup, 104), 2);
    assert_eq!(field(lookup, 108), 42);
    assert_eq!(field(lookup, 112), 0);
    assert_eq!(field(lookup, 120), 4096);
    assert_eq!(output[128..], [0xaa; 16]);

    let alias = index.lookup(b"a").unwrap();
    let encoded = getattr(
        alias,
        Presentation::default(),
        CachePolicy::Revalidate,
        &mut table,
        &mut output,
    )
    .unwrap();
    assert_eq!(encoded.len(), 104);
    assert_eq!(word(encoded, 0), 0);
    assert_eq!(word(encoded, 16), inode);
    assert_eq!(word(encoded, 24), 3);
    for offset in [40, 48, 56] {
        assert_eq!(word(encoded, offset), 1);
    }
    assert_eq!(table.len(), 1);
}

#[test]
fn root_and_symlink_replies_keep_kernel_root_separate_and_target_bytes_exact() {
    let bytes = bytes(b"\x00");
    let index = Index::open(&bytes).unwrap();
    let mut table = table();
    let mut output = [0xaa; 128];
    let root = index.lookup(b"").unwrap();
    let encoded = lookup(
        root,
        Presentation::default(),
        CachePolicy::Revalidate,
        &mut table,
        &mut output,
    )
    .unwrap();
    assert_eq!(word(encoded, 0), 1);
    assert_eq!(word(encoded, 40), 16);
    assert_eq!(field(encoded, 100), libc::S_IFDIR | 0o555);
    assert_eq!(field(encoded, 104), 3);
    assert_eq!(word(encoded, 16), 0);
    assert_eq!(word(encoded, 24), 0);

    let link = index.lookup(b"link").unwrap();
    let target = readlink(link).unwrap();
    assert_eq!(target, b".././raw\xff");
    assert!(target.as_ptr() >= bytes.as_ptr() && target.as_ptr() < bytes.as_ptr_range().end);
    assert_eq!(readlink(root), Err(Error::NotSymlink));
    let encoded = getattr(
        link,
        Presentation::default(),
        CachePolicy::Pinned,
        &mut table,
        &mut output,
    )
    .unwrap();
    assert_eq!(word(encoded, 24), target.len() as u64);
    assert_eq!(field(encoded, 76), libc::S_IFLNK | 0o777);
    assert_eq!(field(encoded, 80), 1);
}

#[test]
fn canonical_overrides_ignore_recorded_ownership_and_keep_explicit_timestamps() {
    let bytes = bytes(b"\xf5");
    let index = Index::open(&bytes).unwrap();
    let entry = index.lookup(b"a").unwrap();
    let mut table = table();
    let mut output = [0xaa; 128];
    assert_eq!(
        getattr(
            entry,
            Presentation::default(),
            CachePolicy::Pinned,
            &mut table,
            &mut output
        ),
        Err(Error::Metadata)
    );
    assert!(table.is_empty());
    assert_eq!(output, [0xaa; 128]);

    let presentation = Presentation {
        mode: Some(0o555),
        uid: Some(7),
        gid: Some(8),
        timestamp: Timestamp::new(-1, 999_999_999).unwrap(),
    };
    let encoded = getattr(
        entry,
        presentation,
        CachePolicy::Pinned,
        &mut table,
        &mut output,
    )
    .unwrap();
    assert_eq!(field(encoded, 76), libc::S_IFREG | 0o555);
    assert_eq!(field(encoded, 84), 7);
    assert_eq!(field(encoded, 88), 8);
    for offset in [40, 48, 56] {
        assert_eq!(word(encoded, offset), u64::MAX);
    }
    for offset in [64, 68, 72] {
        assert_eq!(field(encoded, offset), 999_999_999);
    }
    assert_eq!(Timestamp::new(0, 1_000_000_000), Err(Error::Metadata));
}

#[test]
fn refused_metadata_or_capacity_never_assigns_an_inode_or_changes_output() {
    let bytes = bytes(b"\x00");
    let entry = Index::open(&bytes).unwrap().lookup(b"a").unwrap();
    let mut table = table();
    for length in 0..128 {
        let mut output = [0xaa; 128];
        assert_eq!(
            lookup(
                entry,
                Presentation::default(),
                CachePolicy::Pinned,
                &mut table,
                &mut output[..length]
            ),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(output, [0xaa; 128]);
        assert!(table.is_empty());
    }
    for presentation in [
        Presentation {
            mode: Some(0o100644),
            ..Presentation::default()
        },
        Presentation {
            uid: Some(u32::MAX),
            ..Presentation::default()
        },
        Presentation {
            gid: Some(u32::MAX),
            ..Presentation::default()
        },
    ] {
        let mut output = [0xaa; 128];
        assert_eq!(
            getattr(
                entry,
                presentation,
                CachePolicy::Pinned,
                &mut table,
                &mut output
            ),
            Err(Error::Metadata)
        );
        assert_eq!(output, [0xaa; 128]);
        assert!(table.is_empty());
    }
    let mut limited = InodeTable::with_reserved_capacity(1, 4096).unwrap();
    let root = Index::open(&bytes).unwrap().lookup(b"").unwrap();
    let mut output = [0; 128];
    lookup(
        root,
        Presentation::default(),
        CachePolicy::Pinned,
        &mut limited,
        &mut output,
    )
    .unwrap();
    output.fill(0xaa);
    assert_eq!(
        getattr(
            entry,
            Presentation::default(),
            CachePolicy::Pinned,
            &mut limited,
            &mut output
        ),
        Err(Error::Inode(inode_policy::Error::Capacity))
    );
    assert_eq!(output, [0xaa; 128]);
    assert_eq!(limited.len(), 1);

    let mut lazy = InodeTable::new(16).unwrap();
    let mut output = [0xaa; 128];
    assert_eq!(
        getattr(
            entry,
            Presentation::default(),
            CachePolicy::Pinned,
            &mut lazy,
            &mut output
        ),
        Err(Error::UnreservedInodes)
    );
    assert_eq!(output, [0xaa; 128]);
}

#[test]
fn negative_lookup_caches_absence_only_for_pinned_views_and_clears_payload() {
    for (cache, expected) in [
        (CachePolicy::Pinned, u64::MAX),
        (CachePolicy::Revalidate, 0),
    ] {
        let mut output = [0xaa; 144];
        let encoded = negative_lookup(cache, &mut output).unwrap();
        assert_eq!(encoded.len(), 128);
        assert_eq!(word(encoded, 0), 0);
        assert_eq!(word(encoded, 16), expected);
        assert!(
            encoded[..16]
                .iter()
                .chain(encoded[24..].iter())
                .all(|byte| *byte == 0)
        );
        assert_eq!(output[128..], [0xaa; 16]);
    }
}
