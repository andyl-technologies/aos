//! Checks raw xattr replies, policy filtering and unchanged refused outputs.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::structural_index::{self, Index};
use std::collections::BTreeMap;
use terrane_format::{
    tree_builder::Tree,
    tree_format::{
        ContentRef, Entry as TreeEntry, EntryKind, ExtendedAttribute, LeafItem, TreeUse,
    },
};

fn bytes(mut fields: Vec<ExtendedAttribute<'_>>) -> Vec<u8> {
    fields.sort_by(|left, right| {
        left.name
            .len()
            .cmp(&right.name.len())
            .then(left.name.cmp(right.name))
    });
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: TreeEntry {
                kind: EntryKind::File {
                    mode: 0o444,
                    size: 0,
                    content: ContentRef::Inline([2; 32]),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: fields,
                xattrs_present: true,
                provenance: None,
            },
        }],
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap();
    structural_index::compile_tree(&tree, &BTreeMap::new(), 2, 524288).unwrap()
}

#[test]
fn raw_values_and_size_probes_preserve_exact_bytes_and_unused_output() {
    let bytes = bytes(vec![ExtendedAttribute {
        name: b"user.\xff",
        value: b"\0value\xff",
    }]);
    let index = Index::open(&bytes).unwrap();
    let entry = index.lookup(b"file").unwrap();
    let mut output = [0xaa; 24];

    assert_eq!(
        get(entry, Policy::Recorded, b"user.\xff", 0, &mut output).unwrap(),
        [7u32.to_ne_bytes(), [0; 4]].concat()
    );
    assert_eq!(&output[8..], &[0xaa; 16]);
    assert_eq!(
        get(entry, Policy::Recorded, b"user.\xff", 20, &mut output).unwrap(),
        b"\0value\xff"
    );
    assert_eq!(output[7], 0);
    assert_eq!(&output[8..], &[0xaa; 16]);
}

#[test]
fn list_and_get_hide_privileged_names_even_during_size_probes() {
    let bytes = bytes(vec![
        ExtendedAttribute {
            name: b"security.capability",
            value: b"secret",
        },
        ExtendedAttribute {
            name: b"system.posix_acl_access",
            value: b"acl",
        },
        ExtendedAttribute {
            name: b"trusted.overlay",
            value: b"overlay",
        },
        ExtendedAttribute {
            name: b"user.\xff",
            value: b"raw",
        },
        ExtendedAttribute {
            name: b"securityish.value",
            value: b"ordinary",
        },
    ]);
    let index = Index::open(&bytes).unwrap();
    let entry = index.lookup(b"file").unwrap();
    let expected = b"user.\xff\0securityish.value\0";
    let mut output = [0xaa; 64];

    assert_eq!(
        list(entry, Policy::Recorded, 64, &mut output).unwrap(),
        expected
    );
    assert_eq!(
        list(entry, Policy::Recorded, 0, &mut output).unwrap()[..4],
        (expected.len() as u32).to_ne_bytes()
    );
    for name in [
        b"security.capability".as_slice(),
        b"system.posix_acl_access",
        b"trusted.overlay",
        b"absent",
    ] {
        output.fill(0xaa);
        assert_eq!(
            get(entry, Policy::Recorded, name, 0, &mut output),
            Err(Error::NoData)
        );
        assert_eq!(output, [0xaa; 64]);
    }
}

#[test]
fn disabled_empty_and_missing_attributes_have_distinct_kernel_results() {
    let bytes = bytes(vec![ExtendedAttribute {
        name: b"user.empty",
        value: b"",
    }]);
    let index = Index::open(&bytes).unwrap();
    let entry = index.lookup(b"file").unwrap();
    let mut output = [0xaa; 8];

    assert_eq!(
        list(entry, Policy::default(), 0, &mut output),
        Err(Error::Disabled)
    );
    assert_eq!(
        get(entry, Policy::Disabled, b"user.empty", 0, &mut output),
        Err(Error::Disabled)
    );
    assert_eq!(output, [0xaa; 8]);
    assert_eq!(
        get(entry, Policy::Recorded, b"user.empty", 0, &mut output).unwrap(),
        [0; 8]
    );
    assert_eq!(
        get(entry, Policy::Recorded, b"user.empty", 1, &mut []).unwrap(),
        b""
    );
    assert_eq!(
        get(entry, Policy::Recorded, b"missing", 1, &mut output),
        Err(Error::NoData)
    );
    let root = index.lookup(b"").unwrap();
    assert_eq!(
        list(root, Policy::Recorded, 0, &mut output).unwrap(),
        [0; 8]
    );
    assert_eq!(list(root, Policy::Recorded, 1, &mut []).unwrap(), b"");
}

#[test]
fn short_requests_invalid_names_and_worker_capacity_leave_output_unchanged() {
    let bytes = bytes(vec![ExtendedAttribute {
        name: b"user.name",
        value: b"value",
    }]);
    let index = Index::open(&bytes).unwrap();
    let entry = index.lookup(b"file").unwrap();
    let mut output = [0xaa; 16];

    assert_eq!(
        get(entry, Policy::Recorded, b"user.name", 4, &mut output),
        Err(Error::Range)
    );
    assert_eq!(
        list(entry, Policy::Recorded, 9, &mut output),
        Err(Error::Range)
    );
    assert_eq!(
        get(entry, Policy::Recorded, b"user.name", 0, &mut output[..7]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        list(entry, Policy::Recorded, 16, &mut output[..9]),
        Err(Error::BufferTooSmall)
    );
    for name in [b"".as_slice(), b"user.\0bad", &[b'x'; 256]] {
        assert_eq!(
            get(entry, Policy::Recorded, name, 16, &mut output),
            Err(Error::Name)
        );
    }
    assert_eq!(output, [0xaa; 16]);

    let invalid = bytes_with_nul();
    let invalid = Index::open(&invalid).unwrap();
    assert_eq!(
        list(
            invalid.lookup(b"file").unwrap(),
            Policy::Recorded,
            16,
            &mut output
        ),
        Err(Error::Name)
    );
    assert_eq!(output, [0xaa; 16]);
}

fn bytes_with_nul() -> Vec<u8> {
    bytes(vec![ExtendedAttribute {
        name: b"user.\0bad",
        value: b"value",
    }])
}

#[test]
fn linux_payload_limits_preserve_checked_tree_bounds_and_refuse_overflow() {
    let value = vec![7; 60000];
    let value_bytes = bytes(vec![ExtendedAttribute {
        name: b"user.max",
        value: &value,
    }]);
    let index = Index::open(&value_bytes).unwrap();
    let mut output = vec![0; MAX_PAYLOAD];
    assert_eq!(
        get(
            index.lookup(b"file").unwrap(),
            Policy::Recorded,
            b"user.max",
            MAX_PAYLOAD as u32,
            &mut output
        )
        .unwrap(),
        value
    );

    // Tree framing also consumes the format's 64 KiB item budget. Exercise a
    // large valid map, and check the defensive Linux ceiling independently.
    let names: Vec<_> = (0..200)
        .map(|number| {
            let mut name = vec![b'x'; 255];
            name[..4].copy_from_slice(format!("{number:04}").as_bytes());
            name
        })
        .collect();
    let fields = names
        .iter()
        .map(|name| ExtendedAttribute { name, value: b"" })
        .collect();
    let many = bytes(fields);
    let many = Index::open(&many).unwrap();
    let entry = many.lookup(b"file").unwrap();
    assert_eq!(
        list(entry, Policy::Recorded, 0, &mut output).unwrap()[..4],
        51200u32.to_ne_bytes()
    );
    assert_eq!(
        list(entry, Policy::Recorded, 51200, &mut output)
            .unwrap()
            .len(),
        51200
    );
    output.fill(0xaa);
    assert_eq!(
        list(entry, Policy::Recorded, 51199, &mut output),
        Err(Error::Range)
    );
    assert!(output.iter().all(|byte| *byte == 0xaa));
    assert_eq!(
        reply_length(MAX_PAYLOAD, MAX_PAYLOAD as u32),
        Ok(MAX_PAYLOAD)
    );
    assert_eq!(reply_length(MAX_PAYLOAD + 1, 0), Err(Error::TooLarge));
    assert_eq!(
        reply_length(MAX_PAYLOAD + 1, u32::MAX),
        Err(Error::TooLarge)
    );
}
