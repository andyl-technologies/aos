//! Checks wire pages, resume positions, namespace boundaries and inode refusals.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::structural_index::{Record, compile, compile_tree};
use std::collections::BTreeMap;
use terrane_format::{
    tree_builder::Tree,
    tree_format::{ContentRef, Entry as TreeEntry, EntryKind, LeafItem, TreeUse},
};

#[derive(Debug, Eq, PartialEq)]
struct Decoded<'a> {
    inode: u64,
    cookie: u64,
    kind: u32,
    name: &'a [u8],
}

fn decode(mut bytes: &[u8]) -> Vec<Decoded<'_>> {
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        let name_length = u32::from_ne_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let end = 24 + name_length;
        let aligned = (end + 7) & !7;
        assert!(bytes[end..aligned].iter().all(|byte| *byte == 0));
        entries.push(Decoded {
            inode: u64::from_ne_bytes(bytes[..8].try_into().unwrap()),
            cookie: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            kind: u32::from_ne_bytes(bytes[20..24].try_into().unwrap()),
            name: &bytes[24..end],
        });
        bytes = &bytes[aligned..];
    }
    entries
}

fn fixture() -> Vec<u8> {
    compile(
        [7; 32],
        &[
            Record {
                path: b"a",
                kind: Kind::Directory {
                    governing_root: None,
                },
            },
            Record {
                path: b"a/deep",
                kind: Kind::Directory {
                    governing_root: None,
                },
            },
            Record {
                path: b"a/deep/file",
                kind: Kind::File {
                    content: ContentRef::Inline([3; 32]),
                    size: 4,
                },
            },
            Record {
                path: b"a/link",
                kind: Kind::Symlink(b"../raw/./target"),
            },
            Record {
                path: b"z",
                kind: Kind::File {
                    content: ContentRef::Inline([3; 32]),
                    size: 4,
                },
            },
        ],
        16,
        65536,
    )
    .unwrap()
}

fn table() -> InodeTable {
    InodeTable::with_reserved_capacity(16, 8192).unwrap()
}

#[test]
fn encodes_only_direct_children_with_exact_names_types_padding_and_parent() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();
    let mut inodes = table();
    let mut output = [0xa5; 512];

    let length = read(index, b"a", 0, &mut inodes, &mut output).unwrap();
    let entries = decode(&output[..length]);

    assert_eq!(
        entries.iter().map(|row| row.name).collect::<Vec<_>>(),
        [b".".as_slice(), b"..", b"deep", b"link"]
    );
    assert_eq!(
        entries.iter().map(|row| row.cookie).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(
        entries.iter().map(|row| row.kind).collect::<Vec<_>>(),
        [
            u32::from(libc::DT_DIR),
            u32::from(libc::DT_DIR),
            u32::from(libc::DT_DIR),
            u32::from(libc::DT_LNK)
        ]
    );
    assert_eq!(
        entries[0].inode,
        u64::from(
            inodes
                .touch_entry(index.lookup(b"a").unwrap())
                .unwrap()
                .1
                .number()
        )
    );
    assert_eq!(
        entries[1].inode,
        u64::from(
            inodes
                .touch_entry(index.lookup(b"").unwrap())
                .unwrap()
                .1
                .number()
        )
    );
    assert!(output[length..].iter().all(|byte| *byte == 0xa5));
}

#[test]
fn resumes_one_complete_record_at_a_time_and_rewind_preserves_original_numbers() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();
    let mut inodes = table();
    let mut full = [0; 512];
    let length = read(index, b"", 0, &mut inodes, &mut full).unwrap();
    let expected = decode(&full[..length]);
    let mut cookie = 0;

    for original in &expected {
        let mut page = [0x5a; 33];
        let length = read(index, b"", cookie, &mut inodes, &mut page).unwrap();
        assert_eq!(length, 32);
        let actual = decode(&page[..length]);
        assert_eq!(actual, [Decoded { ..*original }]);
        cookie = actual[0].cookie;
        assert_eq!(page[32], 0x5a);
    }

    assert_eq!(read(index, b"", cookie, &mut inodes, &mut []).unwrap(), 0);
    assert_eq!(read(index, b"", u64::MAX, &mut inodes, &mut []).unwrap(), 0);
    let mut rewind = [0; 512];
    assert_eq!(
        read(index, b"", 0, &mut inodes, &mut rewind).unwrap(),
        length
    );
    assert_eq!(rewind[..length], full[..length]);
    assert_eq!(inodes.len(), 3);
    assert_eq!(expected[0].inode, expected[1].inode);
}

#[test]
fn raw_maximum_component_needs_one_complete_aligned_record_before_inode_assignment() {
    let mut name = [b'x'; 255];
    name[0] = 0xff;
    let bytes = compile(
        [1; 32],
        &[Record {
            path: &name,
            kind: Kind::Symlink(b"unaltered target"),
        }],
        2,
        65536,
    )
    .unwrap();
    let index = Index::open(&bytes).unwrap();
    let mut inodes = table();
    let mut short = [0xa5; 279];

    assert_eq!(
        read(index, b"", 2, &mut inodes, &mut short),
        Err(Error::BufferTooSmall)
    );
    assert!(inodes.is_empty());
    assert_eq!(short, [0xa5; 279]);
    let mut exact = [0xa5; 280];
    assert_eq!(
        read(index, b"", 2, &mut inodes, &mut exact).unwrap(),
        exact.len()
    );
    let entries = decode(&exact);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, name);
    assert_eq!(entries[0].cookie, 3);
    assert_eq!(entries[0].kind, u32::from(libc::DT_LNK));
    assert_eq!(inodes.len(), 1);
}

#[test]
fn rejects_lazy_storage_absent_paths_and_non_directories_without_effects() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();
    let mut output = [0xa5; 512];
    let mut lazy = InodeTable::new(16).unwrap();
    assert_eq!(
        read(index, b"", 0, &mut lazy, &mut output),
        Err(Error::UnreservedInodes)
    );
    assert!(lazy.is_empty());
    let mut inodes = table();

    for (path, error) in [
        (b"absent".as_slice(), Error::NotFound),
        (b"z", Error::NotDirectory),
        (b"a/link", Error::NotDirectory),
    ] {
        assert_eq!(read(index, path, 0, &mut inodes, &mut output), Err(error));
        assert!(inodes.is_empty());
        assert_eq!(output, [0xa5; 512]);
    }
    assert_eq!(
        read(index, b"", 0, &mut inodes, &mut []),
        Err(Error::BufferTooSmall)
    );
    assert!(inodes.is_empty());
}

#[test]
fn inode_exhaustion_never_writes_a_partial_record_or_recycles_a_number() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();
    let mut inodes = InodeTable::with_reserved_capacity(1, 4096).unwrap();
    let mut output = [0xa5; 512];

    assert_eq!(
        read(index, b"", 0, &mut inodes, &mut output),
        Err(Error::Inode(inode_policy::Error::Capacity))
    );
    assert_eq!(inodes.len(), 1);
    assert!(output[64..].iter().all(|byte| *byte == 0xa5));
    let original = decode(&output[..64])[0].inode;

    let mut first = [0; 32];
    assert_eq!(read(index, b"", 0, &mut inodes, &mut first).unwrap(), 32);
    assert_eq!(decode(&first)[0].inode, original);
    assert_eq!(inodes.len(), 1);
}

#[test]
fn hard_link_names_share_one_presented_inode_but_equal_content_keeps_distinct_inodes() {
    let entries = [
        (b"a", Some(b"a".as_slice())),
        (b"b", Some(b"a".as_slice())),
        (b"c", None),
    ]
    .into_iter()
    .map(|(path, link_id)| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o444,
                size: 1,
                content: ContentRef::Inline([2; 32]),
                link_id,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    })
    .collect();
    let tree = Tree::build(entries, None, 4096, TreeUse::Ordinary).unwrap();
    let bytes = compile_tree(&tree, &BTreeMap::new(), 4, 65536).unwrap();
    let index = Index::open(&bytes).unwrap();
    let mut inodes = table();
    let mut output = [0; 512];

    let length = read(index, b"", 2, &mut inodes, &mut output).unwrap();
    let entries = decode(&output[..length]);
    assert_eq!(
        entries.iter().map(|row| row.name).collect::<Vec<_>>(),
        [b"a", b"b", b"c"]
    );
    assert_eq!(entries[0].inode, entries[1].inode);
    assert_ne!(entries[0].inode, entries[2].inode);
    assert!(
        entries
            .iter()
            .all(|row| row.kind == u32::from(libc::DT_REG))
    );
    assert_eq!(inodes.len(), 2);
}
