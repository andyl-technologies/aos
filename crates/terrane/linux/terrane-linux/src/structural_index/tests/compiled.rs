//! Checks producer binding independently of structurally valid reader input.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};

use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry as TreeEntry, EntryKind, LeafItem, TreeUse};

use super::super::*;

fn tree() -> Tree<'static> {
    Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: TreeEntry {
                kind: EntryKind::File {
                    mode: 0o444,
                    size: 1,
                    content: ContentRef::Inline([3; 32]),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap()
}

#[test]
fn canonical_compilation_refuses_a_valid_index_with_an_unchanged_root_tag() {
    let tree = tree();
    let compiled = CompiledIndex::from_tree(&tree, &BTreeMap::new(), 2, 65536).unwrap();
    let nodes = tree
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect();
    let from_nodes =
        CompiledIndex::from_nodes(tree.root_identity(), &nodes, 4096, 2, 65536, 65536).unwrap();
    assert_eq!(compiled.key(), from_nodes.key());
    assert_eq!(compiled.key().root(), tree.root_identity());
    assert_eq!(compiled.key().version(), VERSION);
    assert_eq!(compiled.bytes(), from_nodes.bytes());

    let mut forged = compiled.bytes().to_vec();
    let index = Index::open(&forged).unwrap();
    let mode = index.metadata + offset(&forged, index.entries + ENTRY + 52).unwrap();
    forged[mode] ^= 1;
    let checked = Index::open(&forged).unwrap();
    assert_eq!(checked.root_hash(), compiled.key().root());
    assert_eq!(
        checked.lookup(b"file").unwrap().metadata().unwrap().mode,
        Some(0o445)
    );

    let error = compiled
        .verify_reader(&mut Cursor::new(forged))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    compiled
        .verify_reader(&mut Cursor::new(compiled.bytes()))
        .unwrap();
}

struct ShortReader<'a> {
    bytes: Cursor<&'a [u8]>,
    interrupted: bool,
}

impl Read for ShortReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let length = buffer.len().min(3);
        self.bytes.read(&mut buffer[..length])
    }
}

struct PrefixWriter {
    bytes: Vec<u8>,
    fail_at: usize,
}

impl Write for PrefixWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len() >= self.fail_at {
            return Err(io::Error::other("injected copy failure"));
        }
        let length = buffer.len().min(3).min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn streaming_copy_and_verification_preserve_short_io_failures_and_exact_length() {
    let compiled = CompiledIndex::from_tree(&tree(), &BTreeMap::new(), 2, 65536).unwrap();
    let mut writer = PrefixWriter {
        bytes: Vec::new(),
        fail_at: usize::MAX,
    };
    compiled.write_to(&mut writer).unwrap();
    assert_eq!(writer.bytes, compiled.bytes());
    let mut reader = ShortReader {
        bytes: Cursor::new(&writer.bytes),
        interrupted: true,
    };
    compiled.verify_reader(&mut reader).unwrap();

    let mut partial = PrefixWriter {
        bytes: Vec::new(),
        fail_at: 7,
    };
    assert_eq!(
        compiled.write_to(&mut partial).unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(partial.bytes, compiled.bytes()[..7]);
    assert_eq!(
        compiled
            .verify_reader(&mut Cursor::new(partial.bytes))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut trailing = writer.bytes;
    trailing.push(0);
    assert_eq!(
        compiled
            .verify_reader(&mut Cursor::new(trailing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected read failure",
            ))
        }
    }
    assert_eq!(
        compiled.verify_reader(&mut FailedRead).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}
