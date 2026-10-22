//! Exercises nested directory runs, metadata preservation, and hostile bytes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

mod metadata;
mod trees;

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
                    size: 12,
                },
            },
            Record {
                path: b"a/link",
                kind: Kind::Symlink(b"../../outside/./unchanged"),
            },
            Record {
                path: b"b",
                kind: Kind::Directory {
                    governing_root: Some([9; 32]),
                },
            },
            Record {
                path: b"b/file",
                kind: Kind::File {
                    content: ContentRef::Manifest([3; 32]),
                    size: u64::MAX,
                },
            },
            Record {
                path: b"z",
                kind: Kind::File {
                    content: ContentRef::Inline([3; 32]),
                    size: 12,
                },
            },
        ],
        100,
        65536,
    )
    .unwrap()
}

#[test]
fn nested_tree_has_sorted_paths_and_contiguous_direct_child_indices() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();

    assert_eq!(index.len(), 8);
    assert!(!index.is_empty());
    assert_eq!(index.root_hash(), [7; 32]);
    for (path, expected) in [
        (&b""[..], vec![&b"a"[..], &b"b"[..], &b"z"[..]]),
        (&b"a"[..], vec![&b"a/deep"[..], &b"a/link"[..]]),
        (&b"a/deep"[..], vec![&b"a/deep/file"[..]]),
        (&b"b"[..], vec![&b"b/file"[..]]),
    ] {
        let mut children = index.lookup(path).unwrap().children().unwrap();
        assert_eq!(children.len(), expected.len());
        assert_eq!(
            children
                .by_ref()
                .map(|entry| entry.path())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(children.len(), 0);
        assert!(children.next().is_none());
    }
    assert!(index.lookup(b"missing").is_none());
    assert!(index.lookup(b"a/deep/file/child").is_none());
    assert!(index.entry(8).is_none());
}

#[test]
fn content_kind_size_symlink_bytes_and_graft_governance_survive_roundtrip() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();

    assert_eq!(
        index.lookup(b"a/deep/file").unwrap().kind(),
        Kind::File {
            content: ContentRef::Inline([3; 32]),
            size: 12
        }
    );
    assert_eq!(
        index.lookup(b"b/file").unwrap().kind(),
        Kind::File {
            content: ContentRef::Manifest([3; 32]),
            size: u64::MAX
        }
    );
    assert_eq!(
        index.lookup(b"a/link").unwrap().kind(),
        Kind::Symlink(b"../../outside/./unchanged")
    );
    assert_eq!(
        index.lookup(b"a/link").unwrap().governing_root().unwrap(),
        [7; 32]
    );
    assert_eq!(
        index.lookup(b"b").unwrap().governing_root().unwrap(),
        [9; 32]
    );
    assert_eq!(
        index.lookup(b"b/file").unwrap().governing_root().unwrap(),
        [9; 32]
    );
    assert_eq!(
        index
            .lookup(b"a/deep/file")
            .unwrap()
            .children()
            .unwrap_err(),
        Error::Tree
    );
    assert_eq!(
        index.metadata - index.hashes,
        64,
        "content and graft hashes are deduplicated"
    );
}

#[test]
fn empty_tree_and_exact_compiler_bounds_are_supported() {
    let bytes = compile(
        [0; 32],
        &[],
        1,
        HEADER + 32 + ENTRY + super::metadata::MINIMUM,
    )
    .unwrap();
    // Independent v2 wire example, with one empty 36-byte metadata record.
    // Literal offsets keep this independent of the encoder's layout arithmetic.
    let mut golden = [0u8; 228];
    golden[..12].copy_from_slice(b"TRIX\x02\0\0\0\x01\0\0\0");
    for (slot, value) in [
        (12, 84u64),
        (20, 116),
        (28, 116),
        (36, 116),
        (44, 152),
        (52, 228),
        (60, 228),
        (68, 116),
        (76, 228),
    ] {
        golden[slot..slot + 8].copy_from_slice(&value.to_le_bytes());
    }
    golden[164] = 1;
    golden[176..184].fill(0xff);
    golden[192..196].fill(0xff);
    golden[212] = 36;
    golden[216..220].fill(0xff);
    assert_eq!(bytes, golden);

    let index = Index::open(&bytes).unwrap();

    assert_eq!(index.len(), 1);
    assert_eq!(index.lookup(b"").unwrap().children().unwrap().len(), 0);
    assert_eq!(compile([0; 32], &[], 0, usize::MAX), Err(Error::Limit));
    assert_eq!(compile([0; 32], &[], 1, bytes.len() - 1), Err(Error::Limit));
}

#[test]
fn compiler_rejects_missing_nondirectory_duplicate_and_invalid_paths() {
    let file = Kind::File {
        content: ContentRef::Inline([1; 32]),
        size: 0,
    };
    for records in [
        vec![Record {
            path: b"absent/child",
            kind: file,
        }],
        vec![
            Record {
                path: b"a",
                kind: file,
            },
            Record {
                path: b"a/b",
                kind: file,
            },
        ],
        vec![
            Record {
                path: b"a",
                kind: file,
            },
            Record {
                path: b"a",
                kind: file,
            },
        ],
        vec![
            Record {
                path: b"b",
                kind: file,
            },
            Record {
                path: b"a",
                kind: file,
            },
        ],
        vec![Record {
            path: b"../a",
            kind: file,
        }],
        vec![Record {
            path: b"",
            kind: file,
        }],
        vec![Record {
            path: b"a",
            kind: Kind::Symlink(b""),
        }],
        vec![Record {
            path: b"a",
            kind: Kind::Symlink(b"has\0nul"),
        }],
    ] {
        assert_eq!(compile([0; 32], &records, 100, 65536), Err(Error::Tree));
    }
    let bytes = compile(
        [0; 32],
        &[Record {
            path: b"\xff",
            kind: file,
        }],
        2,
        65536,
    )
    .unwrap();
    assert!(Index::open(&bytes).unwrap().lookup(b"\xff").is_some());
}

#[test]
fn every_truncation_and_hostile_header_offset_is_rejected() {
    let bytes = fixture();
    for length in 0..bytes.len() {
        assert!(
            Index::open(&bytes[..length]).is_err(),
            "accepted truncation {length}"
        );
    }
    for slot in [12, 20, 28, 36, 44, 52, 60, 68, 76] {
        let mut malformed = bytes.clone();
        malformed[slot..slot + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            Index::open(&malformed).is_err(),
            "accepted offset at {slot}"
        );
    }
    for slot in [0, 4, 6] {
        let mut malformed = bytes.clone();
        malformed[slot] ^= 0x80;
        assert!(Index::open(&malformed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Index::open(&trailing).is_err());
}

#[test]
fn forged_parent_child_and_arena_relationships_are_rejected() {
    let bytes = fixture();
    let index = Index::open(&bytes).unwrap();
    for (start, value) in [
        (index.entries + 40, 0),                // root cannot have a parent
        (index.entries + ENTRY + 40, 7),        // parent must precede child
        (index.entries + ENTRY + 44, 0),        // overlapping child run
        (index.entries + ENTRY + 48, u32::MAX), // overflowing child run
        (index.entries + 3 * ENTRY + 48, 1),    // file cannot have children
        (index.children, 0),                    // root cannot be a child
        (index.children + 4, 1),                // duplicate child
        (index.children + 4, 6),                // child's encoded parent disagrees
        (index.entries + ENTRY + 8, u32::MAX),  // path exceeds arena
    ] {
        let mut malformed = bytes.clone();
        malformed[start..start + 4].copy_from_slice(&value.to_le_bytes());
        assert!(
            Index::open(&malformed).is_err(),
            "accepted mutation at {start}"
        );
    }
    for (relative, value) in [(12, 255), (13, 2), (14, 1)] {
        let mut malformed = bytes.clone();
        malformed[index.entries + relative] = value;
        assert!(Index::open(&malformed).is_err());
    }
    let mut malformed = bytes.clone();
    malformed[index.hashes + 32..index.hashes + 64].copy_from_slice(&[3; 32]);
    assert!(
        Index::open(&malformed).is_err(),
        "duplicate hash arena member"
    );
}

#[test]
fn arbitrary_short_inputs_and_single_byte_mutations_never_panic() {
    let mut state = 0x531bc729u32;
    for length in 0..512 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let _ = Index::open(&bytes);
    }

    let original = fixture();
    for position in 0..original.len() {
        let mut bytes = original.clone();
        bytes[position] ^= 0xff;
        if let Ok(index) = Index::open(&bytes) {
            for position in 0..index.len() {
                let entry = index.entry(position).unwrap();
                assert!(index.lookup(entry.path()).is_some());
                entry.governing_root().unwrap();
                entry.canonical_inode().unwrap();
                assert!(entry.link_count().unwrap() > 0);
                let metadata = entry.metadata().unwrap();
                for fields in [
                    metadata.attributes,
                    metadata.xattrs,
                    metadata.root_properties,
                    metadata.graft_overrides,
                ] {
                    assert_eq!(fields.iter().count(), fields.len() as usize);
                }
                if let Kind::Directory { .. } = entry.kind() {
                    for child in entry.children().unwrap() {
                        assert!(child.path() > entry.path());
                    }
                }
            }
        }
    }
}
