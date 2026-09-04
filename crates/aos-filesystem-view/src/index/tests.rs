//! Structural-index encoding, validation, compatibility, and limit tests.

use super::builder::*;
use super::validate::*;
use super::view::*;
use super::wire::*;
use super::*;
use aos_sandbox_core::model::FilesystemMetadata;
use aos_sandbox_core::{MediaType, ObjectDescriptor, descriptor_for_bytes};
use std::io::Cursor as IoCursor;

fn descriptor() -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor")
            .unwrap_or_else(|error| panic!("media type failed: {error}")),
        ObjectDigest::from_bytes([7; 32]),
        9,
    )
}

fn directory_descriptor() -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.directory.v1+cbor")
            .unwrap_or_else(|error| panic!("media type failed: {error}")),
        ObjectDigest::from_bytes([8; 32]),
        13,
    )
}

fn index_media_for(bytes: &[u8]) -> MediaType {
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .unwrap_or_else(|_| panic!("index version missing")),
    );
    let media = match version {
        VERSION_V1 => INDEX_MEDIA_TYPE_V1,
        VERSION_V2 => INDEX_MEDIA_TYPE_V2,
        VERSION_V3 => INDEX_MEDIA_TYPE_V3,
        _ => panic!("unexpected index version"),
    };
    MediaType::new(media).unwrap_or_else(|error| panic!("media failed: {error}"))
}

fn root_index() -> (
    Vec<u8>,
    u64,
    IndexSummary,
    ObjectDescriptor,
    ObjectDescriptor,
) {
    let tree = descriptor();
    let root = directory_descriptor();
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    let staged = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"));
    let (writer, summary) = staged.into_parts();
    let position = writer.position();
    (writer.into_inner(), position, summary, tree, root)
}

fn root_index_v3() -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    (writer.into_inner(), tree, root)
}

fn root_index_v1() -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut record = Vec::new();
    encode_record(
        &mut record,
        &IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
    )
    .unwrap_or_else(|error| panic!("record failed: {error}"));
    let payload_digest: [u8; 32] = Sha256::digest(&record).into();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    put_u32(&mut bytes, VERSION_V1);
    put_u32(&mut bytes, HEADER_BYTES_V1 as u32);
    bytes.extend_from_slice(&[3; 32]);
    bytes.extend_from_slice(tree.digest().as_bytes());
    put_u64(&mut bytes, tree.encoded_size());
    bytes.extend_from_slice(root.digest().as_bytes());
    put_u64(&mut bytes, root.encoded_size());
    put_u32(&mut bytes, 0);
    put_u32(&mut bytes, 0);
    put_u64(&mut bytes, 1);
    put_u64(&mut bytes, record.len() as u64);
    bytes.extend_from_slice(&payload_digest);
    bytes.extend_from_slice(&record);
    (bytes, tree, root)
}

#[test]
fn staging_requires_a_fresh_empty_writer_and_finishes_at_exact_eof() {
    let prefilled = IoCursor::new(vec![7]);
    assert!(matches!(
        StructuralIndexBuilder::new(
            IndexStaging::new(prefilled, 4096, 4096),
            [3; 32],
            descriptor(),
            directory_descriptor(),
            0,
        ),
        Err(IndexError::NonEmptyStaging)
    ));

    let mut nonzero = IoCursor::new(Vec::new());
    nonzero.set_position(1);
    assert!(matches!(
        StructuralIndexBuilder::new(
            IndexStaging::new(nonzero, 4096, 4096),
            [3; 32],
            descriptor(),
            directory_descriptor(),
            0,
        ),
        Err(IndexError::NonEmptyStaging)
    ));

    let builder = StructuralIndexBuilder::new(
        IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096),
        [3; 32],
        descriptor(),
        directory_descriptor(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    assert!(matches!(builder.finish(), Err(IndexError::InvalidRecord)));

    let (bytes, position, summary, _, _) = root_index();
    assert_eq!(position, summary.bytes);
    assert_eq!(bytes.len() as u64, summary.bytes);
    assert_eq!(summary.records, 1);
    assert_eq!(summary.bytes, 365);
    let media = index_media_for(&bytes);
    assert_eq!(
        descriptor_for_bytes(media, &bytes).digest().as_bytes(),
        &[
            8, 145, 194, 237, 13, 115, 216, 207, 52, 172, 55, 126, 39, 45, 244, 26, 247, 98, 8, 7,
            204, 223, 126, 153, 72, 150, 234, 51, 248, 250, 155, 123,
        ]
    );
}

#[test]
fn v1_golden_vector_remains_valid_but_has_no_point_lookup() {
    let (bytes, tree, root) = root_index_v1();
    assert_eq!(bytes.len(), 333);
    let media =
        MediaType::new(INDEX_MEDIA_TYPE_V1).unwrap_or_else(|error| panic!("media failed: {error}"));
    assert_eq!(
        descriptor_for_bytes(media.clone(), &bytes)
            .digest()
            .as_bytes(),
        &[
            157, 145, 103, 153, 247, 240, 82, 185, 151, 121, 216, 129, 29, 146, 175, 2, 71, 156,
            251, 40, 219, 210, 163, 199, 76, 130, 171, 169, 23, 104, 214, 50,
        ]
    );
    let index = descriptor_for_bytes(media, &bytes);
    let validated = validate_index(
        &bytes,
        4096,
        1_048_576,
        &IndexExpectation {
            index: &index,
            compiler_abi: [3; 32],
            tree: &tree,
            root: &root,
            tree_features: 0,
        },
    )
    .unwrap_or_else(|error| panic!("V1 validation failed: {error}"));
    let root_view = validated
        .root()
        .unwrap_or_else(|error| panic!("root decode failed: {error}"));
    assert!(!validated.supports_point_lookup());
    assert!(matches!(
        crate::InodeTable::new(
            &validated,
            [0; 32],
            crate::InodeTableLimits::new(1, 4096, 1, 1, 1),
        ),
        Err(crate::InodeError::Index(IndexError::PointLookupUnavailable))
    ));
    let name = PathName::new(b"child".to_vec())
        .unwrap_or_else(|error| panic!("path name failed: {error}"));
    assert!(matches!(
        validated.lookup_child(&root_view, &name),
        Err(IndexError::PointLookupUnavailable)
    ));
}

fn validate_fresh<'a>(
    bytes: &'a [u8],
    tree: &ObjectDescriptor,
    root: &ObjectDescriptor,
) -> Result<ValidatedIndex<'a>, IndexError> {
    let media = index_media_for(bytes);
    let index = descriptor_for_bytes(media, bytes);
    validate_index(
        bytes,
        4096,
        1_048_576,
        &IndexExpectation {
            index: &index,
            compiler_abi: [3; 32],
            tree,
            root,
            tree_features: 0,
        },
    )
}

fn lookup_index() -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 7, 8, 9, 10, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    );
    let layout = ContentLayout::whole(content);
    let mut builder = StructuralIndexBuilder::new(
        IndexStaging::new(IoCursor::new(Vec::new()), 8192, 8192),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"z",
            metadata: &metadata,
            node: IndexNode::File {
                content: &layout,
                hardlink_group: None,
            },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 1,
            name: b"\x80",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    (writer.into_inner(), tree, root)
}

fn iterable_index() -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let tree = descriptor();
    let root = directory_descriptor();
    let directory = ObjectDescriptor::new(
        root.media_type().clone(),
        ObjectDigest::from_bytes([9; 32]),
        17,
    );
    let metadata = FilesystemMetadata::new(0o755, 7, 8, 9, 10, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content_descriptor = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    );
    let content = ContentLayout::whole(content_descriptor);
    let paths = [b"b".as_slice(), b"c".as_slice()]
        .into_iter()
        .map(|name| {
            RelativePath::new(vec![
                PathName::new(name.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}")),
            ])
            .unwrap_or_else(|error| panic!("path failed: {error}"))
        })
        .collect::<Vec<_>>();
    let group = hardlink_group_digest(&paths, &metadata, &content)
        .unwrap_or_else(|error| panic!("hard-link group failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 32 * 1024, 8192),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"a",
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &directory,
            },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 1,
            name: b"b",
            metadata: &metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: Some(group),
            },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 2,
            name: b"c",
            metadata: &metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: Some(group),
            },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 3,
            name: b"d",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        },
        IndexRecord {
            parent: 1,
            depth: 2,
            sibling_ordinal: 0,
            name: b"nested",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    (writer.into_inner(), tree, root)
}

#[test]
fn v3_directory_ranges_and_exact_nlink_are_lazy_and_canonical() {
    let (bytes, tree, root) = iterable_index();
    assert_eq!(
        descriptor_for_bytes(index_media_for(&bytes), &bytes)
            .digest()
            .as_bytes(),
        &[
            118, 109, 109, 56, 7, 22, 111, 231, 229, 148, 152, 44, 86, 236, 184, 171, 14, 134, 234,
            50, 21, 157, 220, 226, 157, 1, 17, 27, 140, 35, 253, 9,
        ]
    );
    let validated = validate_fresh(&bytes, &tree, &root)
        .unwrap_or_else(|error| panic!("validation failed: {error}"));
    assert!(validated.supports_point_lookup());
    assert!(validated.supports_directory_iteration());
    let root = validated
        .root()
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    assert_eq!(
        validated
            .nlink(&root)
            .unwrap_or_else(|error| panic!("root nlink failed: {error}")),
        3
    );
    let mut entries = validated
        .directory_entries(&root)
        .unwrap_or_else(|error| panic!("iteration failed: {error}"));
    assert_eq!(entries.len(), 4);
    let observed = entries
        .by_ref()
        .map(|entry| {
            let entry = entry.unwrap_or_else(|error| panic!("entry failed: {error}"));
            (entry.node().name(), entry.nlink())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        vec![
            (b"a".as_slice(), 2),
            (b"b".as_slice(), 2),
            (b"c".as_slice(), 2),
            (b"d".as_slice(), 1),
        ]
    );
    assert_eq!(entries.len(), 0);
    let a = validated
        .lookup_child(
            &root,
            &PathName::new(b"a".to_vec()).unwrap_or_else(|error| panic!("name failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
        .unwrap_or_else(|| panic!("a missing"));
    assert_eq!(
        validated
            .nlink(&a)
            .unwrap_or_else(|error| panic!("a nlink failed: {error}")),
        2
    );
    let nested = validated
        .directory_entries(&a)
        .unwrap_or_else(|error| panic!("nested iteration failed: {error}"))
        .next()
        .unwrap_or_else(|| panic!("nested entry missing"))
        .unwrap_or_else(|error| panic!("nested entry failed: {error}"));
    assert_eq!(
        (nested.node().name(), nested.nlink()),
        (b"nested".as_slice(), 1)
    );
    assert!(
        bytes
            .as_ptr_range()
            .contains(&nested.node().name().as_ptr())
    );
}

#[test]
fn v3_empty_root_and_foreign_nodes_fail_closed() {
    let (empty_bytes, empty_tree, empty_root_descriptor) = root_index_v3();
    let empty = validate_fresh(&empty_bytes, &empty_tree, &empty_root_descriptor)
        .unwrap_or_else(|error| panic!("empty validation failed: {error}"));
    let empty_root = empty
        .root()
        .unwrap_or_else(|error| panic!("empty root failed: {error}"));
    assert_eq!(
        empty
            .nlink(&empty_root)
            .unwrap_or_else(|error| panic!("empty nlink failed: {error}")),
        2
    );
    let empty_range = empty
        .directory_range(&empty_root)
        .unwrap_or_else(|error| panic!("empty range failed: {error}"));
    assert!(empty_range.is_empty());
    assert_eq!(empty_range.len(), 0);
    assert!(empty_range.iter().next().is_none());

    let (other_bytes, other_tree, other_root) = iterable_index();
    let other = validate_fresh(&other_bytes, &other_tree, &other_root)
        .unwrap_or_else(|error| panic!("other validation failed: {error}"));
    let foreign = other
        .root()
        .unwrap_or_else(|error| panic!("foreign root failed: {error}"));
    assert!(matches!(
        empty.directory_range(&foreign),
        Err(IndexError::ForeignNode)
    ));
    assert!(matches!(
        empty.nlink(&foreign),
        Err(IndexError::ForeignNode)
    ));
}

#[test]
fn v3_hardlink_counts_span_distinct_parent_ranges() {
    let tree = descriptor();
    let root = directory_descriptor();
    let directory_a = ObjectDescriptor::new(
        root.media_type().clone(),
        ObjectDigest::from_bytes([10; 32]),
        10,
    );
    let directory_b = ObjectDescriptor::new(
        root.media_type().clone(),
        ObjectDigest::from_bytes([11; 32]),
        11,
    );
    let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content = ContentLayout::whole(ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    ));
    let paths = [(b"a".as_slice(), b"x".as_slice()), (b"b", b"y")]
        .into_iter()
        .map(|(parent, name)| {
            RelativePath::new(vec![
                PathName::new(parent.to_vec())
                    .unwrap_or_else(|error| panic!("parent failed: {error}")),
                PathName::new(name.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}")),
            ])
            .unwrap_or_else(|error| panic!("path failed: {error}"))
        })
        .collect::<Vec<_>>();
    let group = hardlink_group_digest(&paths, &metadata, &content)
        .unwrap_or_else(|error| panic!("group failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 16 * 1024),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"a",
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &directory_a,
            },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 1,
            name: b"b",
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &directory_b,
            },
        },
        IndexRecord {
            parent: 1,
            depth: 2,
            sibling_ordinal: 0,
            name: b"x",
            metadata: &metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: Some(group),
            },
        },
        IndexRecord {
            parent: 2,
            depth: 2,
            sibling_ordinal: 0,
            name: b"y",
            metadata: &metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: Some(group),
            },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    let bytes = writer.into_inner();
    let validated = validate_fresh(&bytes, &tree, &root)
        .unwrap_or_else(|error| panic!("validation failed: {error}"));
    let root_view = validated
        .root()
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    for ordinal in 0..2 {
        let directory = validated
            .directory_range(&root_view)
            .unwrap_or_else(|error| panic!("root range failed: {error}"))
            .get(ordinal)
            .unwrap_or_else(|error| panic!("directory seek failed: {error}"))
            .unwrap_or_else(|| panic!("directory missing"))
            .into_node();
        let member = validated
            .directory_range(&directory)
            .unwrap_or_else(|error| panic!("member range failed: {error}"))
            .get(0)
            .unwrap_or_else(|error| panic!("member seek failed: {error}"))
            .unwrap_or_else(|| panic!("member missing"));
        assert_eq!(member.nlink(), 2);
        assert_eq!(
            validated
                .nlink(member.node())
                .unwrap_or_else(|error| panic!("member nlink failed: {error}")),
            2
        );
    }
}

#[test]
fn v3_validator_reconstructs_directory_order_offsets_and_link_counts() {
    let (bytes, tree, root) = iterable_index();
    let exact_index = descriptor_for_bytes(index_media_for(&bytes), &bytes);
    assert!(matches!(
        validate_index(
            &bytes,
            bytes.len() as u64 - 1,
            1_048_576,
            &IndexExpectation {
                index: &exact_index,
                compiler_abi: [3; 32],
                tree: &tree,
                root: &root,
                tree_features: 0,
            },
        ),
        Err(IndexError::LimitExceeded)
    ));
    let wrong_media = descriptor_for_bytes(
        MediaType::new(INDEX_MEDIA_TYPE_V2).unwrap_or_else(|error| panic!("media failed: {error}")),
        &bytes,
    );
    assert!(matches!(
        validate_index(
            &bytes,
            bytes.len() as u64,
            1_048_576,
            &IndexExpectation {
                index: &wrong_media,
                compiler_abi: [3; 32],
                tree: &tree,
                root: &root,
                tree_features: 0,
            },
        ),
        Err(IndexError::DescriptorMismatch)
    ));
    let records_bytes = u64::from_le_bytes(
        bytes[HEADER_BYTES_V1..HEADER_BYTES_V1 + 8]
            .try_into()
            .unwrap_or_else(|_| panic!("records length missing")),
    ) as usize;
    let slots = u64::from_le_bytes(
        bytes[HEADER_BYTES_V1 + 8..HEADER_BYTES_V1 + 16]
            .try_into()
            .unwrap_or_else(|_| panic!("slot count missing")),
    ) as usize;
    let table = HEADER_BYTES_V3 + records_bytes + slots * LOOKUP_SLOT_BYTES;

    let mut swapped = bytes.clone();
    let second = table + DIRECTORY_SLOT_BYTES;
    let (prefix, suffix) = swapped.split_at_mut(second);
    prefix[table..second].swap_with_slice(&mut suffix[..DIRECTORY_SLOT_BYTES]);
    resign_payload(&mut swapped);
    assert!(matches!(
        validate_fresh(&swapped, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut forged_nlink = bytes.clone();
    forged_nlink[table + 24..table + 32].copy_from_slice(&99_u64.to_le_bytes());
    resign_payload(&mut forged_nlink);
    assert!(matches!(
        validate_fresh(&forged_nlink, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut forged_offset = bytes.clone();
    forged_offset[table + 8..table + 16]
        .copy_from_slice(&((HEADER_BYTES_V3 + 1) as u64).to_le_bytes());
    resign_payload(&mut forged_offset);
    assert!(matches!(
        validate_fresh(&forged_offset, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut forged_record = bytes.clone();
    forged_record[table + 16..table + 24].copy_from_slice(&u64::MAX.to_le_bytes());
    resign_payload(&mut forged_record);
    assert!(matches!(
        validate_fresh(&forged_record, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut forged_root = bytes;
    forged_root[HEADER_BYTES_V3 - 16..HEADER_BYTES_V3 - 8].copy_from_slice(&4_u64.to_le_bytes());
    assert!(matches!(
        validate_fresh(&forged_root, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut open_extension = iterable_index().0;
    open_extension[HEADER_BYTES_V3 - 1] = 1;
    assert!(matches!(
        validate_fresh(&open_extension, &tree, &root),
        Err(IndexError::InvalidHeader)
    ));

    let mut wrong_count = iterable_index().0;
    wrong_count[HEADER_BYTES_V2..HEADER_BYTES_V2 + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        validate_fresh(&wrong_count, &tree, &root),
        Err(IndexError::InvalidHeader)
    ));
    let mut wrong_width = iterable_index().0;
    wrong_width[HEADER_BYTES_V2 + 8..HEADER_BYTES_V2 + 12].copy_from_slice(&31_u32.to_le_bytes());
    assert!(matches!(
        validate_fresh(&wrong_width, &tree, &root),
        Err(IndexError::InvalidHeader)
    ));
    let mut wrong_version = iterable_index().0;
    wrong_version[8..12].copy_from_slice(&VERSION_V2.to_le_bytes());
    assert!(matches!(
        validate_fresh(&wrong_version, &tree, &root),
        Err(IndexError::InvalidHeader)
    ));
}

#[test]
fn v3_nlink_rejects_a_corrupted_direct_ordinal_position() {
    let (mut bytes, tree, root) = iterable_index();
    let descriptor = descriptor_for_bytes(index_media_for(&bytes), &bytes);
    let records_bytes = u64::from_le_bytes(
        bytes[HEADER_BYTES_V1..HEADER_BYTES_V1 + 8]
            .try_into()
            .unwrap_or_else(|_| panic!("records length missing")),
    );
    let lookup_slots = u64::from_le_bytes(
        bytes[HEADER_BYTES_V1 + 8..HEADER_BYTES_V1 + 16]
            .try_into()
            .unwrap_or_else(|_| panic!("slot count missing")),
    );
    let table_offset = directory_table_offset(records_bytes, lookup_slots)
        .unwrap_or_else(|error| panic!("table offset failed: {error}"));
    let table = usize::try_from(table_offset)
        .unwrap_or_else(|_| panic!("table offset is not representable"));
    let b_slot = read_directory_slot(&bytes, table_offset, 1)
        .unwrap_or_else(|error| panic!("b slot failed: {error}"));
    let second = table + 2 * DIRECTORY_SLOT_BYTES;
    let (prefix, suffix) = bytes.split_at_mut(second);
    prefix[table + DIRECTORY_SLOT_BYTES..second]
        .swap_with_slice(&mut suffix[..DIRECTORY_SLOT_BYTES]);

    // Safe construction never permits bytes to change after validation.
    // This deliberately forged internal wrapper proves the O(1) direct
    // ordinal access still fails closed if that invariant is violated.
    let forged = ValidatedIndex {
        bytes: &bytes,
        descriptor: descriptor.clone(),
        summary: IndexSummary {
            compiler_abi: [3; 32],
            tree_digest: tree.digest(),
            tree_size: tree.encoded_size(),
            root_digest: root.digest(),
            root_size: root.encoded_size(),
            records: 6,
            bytes: bytes.len() as u64,
        },
        crosslinks: IndexCrosslinks {
            compiler_abi: [3; 32],
            tree,
            root,
            tree_features: 0,
            hardlink_groups: 1,
            hardlink_members: 2,
        },
        layout: IndexLayout::IterableV3 {
            records_bytes,
            lookup_slots,
            directory_slots: lookup_slots,
            root_nlink: 3,
        },
    };
    let b = decode_record_view(
        forged.bytes,
        usize::try_from(b_slot.record_offset)
            .unwrap_or_else(|_| panic!("record offset is not representable")),
        b_slot.record_id,
        descriptor.digest(),
    )
    .unwrap_or_else(|error| panic!("b decode failed: {error}"));
    assert!(matches!(forged.nlink(&b), Err(IndexError::InvalidRecord)));
}

#[test]
fn v3_high_fanout_iteration_is_bounded_and_byte_exact() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 2 * 1024 * 1024, 4096),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    for ordinal in 0..1024_u32 {
        let name = format!("entry-{ordinal:04}");
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal,
                name: name.as_bytes(),
                metadata: &metadata,
                node: IndexNode::Symlink { target: b"target" },
            })
            .unwrap_or_else(|error| panic!("child push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    let bytes = writer.into_inner();
    let index = descriptor_for_bytes(index_media_for(&bytes), &bytes);
    let validated = validate_index(
        &bytes,
        2 * 1024 * 1024,
        128 * 1024 * 1024,
        &IndexExpectation {
            index: &index,
            compiler_abi: [3; 32],
            tree: &tree,
            root: &root,
            tree_features: 0,
        },
    )
    .unwrap_or_else(|error| panic!("validation failed: {error}"));
    let root = validated
        .root()
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    let range = validated
        .directory_range(&root)
        .unwrap_or_else(|error| panic!("range failed: {error}"));
    assert_eq!(range.len(), 1024);
    assert!(!range.is_empty());
    for ordinal in [0_u64, 511, 1023] {
        let entry = range
            .get(ordinal)
            .unwrap_or_else(|error| panic!("seek failed: {error}"))
            .unwrap_or_else(|| panic!("entry {ordinal} missing"));
        assert_eq!(
            entry.node().name(),
            format!("entry-{ordinal:04}").as_bytes()
        );
    }
    assert!(
        range
            .get(1024)
            .unwrap_or_else(|error| panic!("end seek failed: {error}"))
            .is_none()
    );
    assert!(
        range
            .get(u64::MAX)
            .unwrap_or_else(|error| panic!("large seek failed: {error}"))
            .is_none()
    );
    let mut entries = range.iter();
    assert_eq!(entries.len(), 1024);
    for ordinal in 0..1024_u32 {
        let entry = entries
            .next()
            .unwrap_or_else(|| panic!("entry {ordinal} missing"))
            .unwrap_or_else(|error| panic!("entry failed: {error}"));
        assert_eq!(entry.node().sibling_ordinal(), ordinal);
        assert_eq!(
            entry.node().name(),
            format!("entry-{ordinal:04}").as_bytes()
        );
        assert_eq!(entry.nlink(), 1);
    }
    assert!(entries.next().is_none());
}

#[test]
fn v3_finish_admits_aggregate_actual_table_capacity() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096),
        [3; 32],
        tree,
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"child",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let exact = builder
        .finish_working_bytes()
        .unwrap_or_else(|error| panic!("working charge failed: {error}"));
    assert!(exact > builder.retained_working_bytes().unwrap_or(0));
    builder.maximum_working_bytes = exact - 1;
    assert!(matches!(builder.finish(), Err(IndexError::LimitExceeded)));
}

#[test]
fn push_actual_retained_capacity_blocks_scratch_allocation_and_write() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 16 * 1024),
        [3; 32],
        tree,
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    builder.entries = Vec::with_capacity(8);
    builder.refuse_record_scratch_allocation = true;
    let child = IndexRecord {
        parent: 0,
        depth: 1,
        sibling_ordinal: 0,
        name: b"child",
        metadata: &metadata,
        node: IndexNode::Symlink { target: b"target" },
    };
    let external = 500_u64;
    let actual_retained = builder
        .retained_working_bytes()
        .unwrap_or_else(|error| panic!("retained charge failed: {error}"));
    let scratch = byte_vector_charge(
        record_encoded_len(&child).unwrap_or_else(|error| panic!("record length failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("scratch charge failed: {error}"));
    let maximum = external + actual_retained + scratch - 1;
    let position = builder
        .writer
        .stream_position()
        .unwrap_or_else(|error| panic!("position failed: {error}"));
    assert!(matches!(
        builder.push_with_external(&child, external, maximum),
        Err(IndexError::LimitExceeded)
    ));
    assert_eq!(builder.records, 1);
    assert!(builder.entries.is_empty());
    assert_eq!(
        builder
            .writer
            .stream_position()
            .unwrap_or_else(|error| panic!("position failed: {error}")),
        position
    );
}

#[test]
fn finish_actual_directory_capacity_blocks_hardlink_allocation() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content = ContentLayout::whole(ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    ));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 16 * 1024),
        [3; 32],
        tree,
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"child",
            metadata: &metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: Some(ObjectDigest::from_bytes([4; 32])),
            },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    builder.directory_capacity_floor = 8;
    builder.refuse_hardlink_allocation = true;
    let external = 500_u64;
    let retained = builder
        .retained_working_bytes()
        .unwrap_or_else(|error| panic!("retained charge failed: {error}"));
    let maximum = external
        + retained
        + directory_vector_charge(8)
            .unwrap_or_else(|error| panic!("directory charge failed: {error}"))
        + hardlink_vector_charge(1)
            .unwrap_or_else(|error| panic!("hardlink charge failed: {error}"))
        - 1;
    assert!(matches!(
        builder.finish_with_external(external, maximum),
        Err(IndexError::LimitExceeded)
    ));
}

#[test]
fn finish_actual_lookup_capacity_obeys_staging_local_limit() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let mut builder = StructuralIndexBuilder::new_v3(
        IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 16 * 1024),
        [3; 32],
        tree,
        root.clone(),
        0,
    )
    .unwrap_or_else(|error| panic!("builder failed: {error}"));
    for record in [
        IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        },
        IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"child",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        },
    ] {
        builder
            .push(&record)
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    builder.lookup_capacity_floor = 8;
    let retained = builder
        .retained_working_bytes()
        .unwrap_or_else(|error| panic!("retained charge failed: {error}"));
    let local_maximum = retained
        + lookup_vector_charge(8).unwrap_or_else(|error| panic!("lookup charge failed: {error}"))
        - 1;
    assert!(
        builder
            .finish_working_bytes()
            .unwrap_or_else(|error| panic!("forecast failed: {error}"))
            < local_maximum
    );
    builder.maximum_working_bytes = local_maximum;
    assert!(matches!(
        builder.finish_with_external(10_000, u64::MAX),
        Err(IndexError::LimitExceeded)
    ));
}

#[test]
fn v2_point_lookup_is_byte_exact_lazy_and_allocation_free() {
    let (bytes, tree, root) = lookup_index();
    let media =
        MediaType::new(INDEX_MEDIA_TYPE_V2).unwrap_or_else(|error| panic!("media failed: {error}"));
    assert_eq!(
        descriptor_for_bytes(media, &bytes).digest().as_bytes(),
        &[
            43, 195, 204, 224, 254, 52, 240, 117, 151, 113, 200, 69, 165, 159, 85, 211, 21, 210,
            243, 62, 195, 151, 144, 66, 130, 38, 172, 185, 62, 229, 192, 188,
        ]
    );
    let validated = validate_fresh(&bytes, &tree, &root)
        .unwrap_or_else(|error| panic!("validation failed: {error}"));
    let root_view = validated
        .root()
        .unwrap_or_else(|error| panic!("root failed: {error}"));
    assert_eq!(root_view.kind(), IndexNodeKind::Directory);
    assert_eq!(root_view.record_id(), 0);
    assert!(!validated.supports_directory_iteration());
    assert!(matches!(
        validated.directory_entries(&root_view),
        Err(IndexError::DirectoryIterationUnavailable)
    ));
    assert!(matches!(
        validated.nlink(&root_view),
        Err(IndexError::DirectoryIterationUnavailable)
    ));

    let z = PathName::new(b"z".to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"));
    let file = validated
        .lookup_child(&root_view, &z)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
        .unwrap_or_else(|| panic!("file missing"));
    assert_eq!(file.record_id(), 1);
    assert_eq!(file.kind(), IndexNodeKind::File);
    assert_eq!(file.name(), b"z");
    assert_eq!((file.uid(), file.gid()), (7, 8));
    assert_eq!(
        file.hardlink_group()
            .unwrap_or_else(|error| panic!("hard-link decode failed: {error}")),
        None
    );
    assert!(matches!(
        validated.lookup_child(&file, &z),
        Err(IndexError::ForeignNode)
    ));

    let non_utf8 = PathName::new(vec![0x80]).unwrap_or_else(|error| panic!("name failed: {error}"));
    let symlink = validated
        .lookup_child(&root_view, &non_utf8)
        .unwrap_or_else(|error| panic!("lookup failed: {error}"))
        .unwrap_or_else(|| panic!("symlink missing"));
    assert_eq!(symlink.kind(), IndexNodeKind::Symlink);
    assert_eq!(symlink.name(), &[0x80]);

    let missing =
        PathName::new(b"missing".to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"));
    assert!(
        validated
            .lookup_child(&root_view, &missing)
            .unwrap_or_else(|error| panic!("lookup failed: {error}"))
            .is_none()
    );
}

#[test]
fn v2_validator_rejects_noncanonical_or_forged_lookup_entries() {
    let (bytes, tree, root) = lookup_index();
    let records_bytes = u64::from_le_bytes(
        bytes[HEADER_BYTES_V1..HEADER_BYTES_V1 + 8]
            .try_into()
            .unwrap_or_else(|_| panic!("records length missing")),
    ) as usize;
    let table = HEADER_BYTES_V2 + records_bytes;

    let mut swapped = bytes.clone();
    let second = table + LOOKUP_SLOT_BYTES;
    let (prefix, suffix) = swapped.split_at_mut(second);
    prefix[table..second].swap_with_slice(&mut suffix[..LOOKUP_SLOT_BYTES]);
    resign_payload(&mut swapped);
    assert!(matches!(
        validate_fresh(&swapped, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut forged_offset = bytes.clone();
    forged_offset[table + 40..table + 48]
        .copy_from_slice(&((HEADER_BYTES_V2 + 1) as u64).to_le_bytes());
    resign_payload(&mut forged_offset);
    assert!(matches!(
        validate_fresh(&forged_offset, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));

    let mut clustered = bytes;
    clustered[table + 8..table + 40].fill(0);
    clustered[second + 8..second + 40].fill(0);
    resign_payload(&mut clustered);
    assert!(matches!(
        validate_fresh(&clustered, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn lookup_build_storage_is_pre_admitted_before_growth_and_finish() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree, root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
    builder.maximum_working_bytes = build_vector_charge(1).unwrap_or(u64::MAX) - 1;
    assert!(matches!(
        builder.push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"child",
            metadata: &metadata,
            node: IndexNode::Symlink { target: b"target" },
        }),
        Err(IndexError::LimitExceeded)
    ));
}

fn resign_payload(bytes: &mut [u8]) {
    let header_bytes = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .unwrap_or_else(|_| panic!("header length missing")),
    ) as usize;
    let digest: [u8; 32] = Sha256::digest(&bytes[header_bytes..]).into();
    bytes[152..HEADER_BYTES_V1].copy_from_slice(&digest);
}

#[test]
fn authenticated_zero_record_index_is_rejected() {
    let (mut bytes, _, _, tree, root) = root_index();
    bytes[136..144].copy_from_slice(&0_u64.to_le_bytes());

    assert!(matches!(
        validate_fresh(&bytes, &tree, &root),
        Err(IndexError::InvalidHeader)
    ));
}

#[test]
fn authenticated_impossible_xattr_and_acl_counts_fail_before_allocation() {
    let (bytes, _, _, tree, root) = root_index();
    // `u32::MAX` is the canonical absent-ACL sentinel, so the largest
    // hostile ACL entry count is one less than the xattr maximum.
    for (count_offset, count) in [
        (HEADER_BYTES_V2 + 52, u32::MAX),
        (HEADER_BYTES_V2 + 56, u32::MAX - 1),
    ] {
        let mut hostile = bytes.clone();
        hostile[count_offset..count_offset + 4].copy_from_slice(&count.to_le_bytes());
        resign_payload(&mut hostile);

        assert!(matches!(
            validate_fresh(&hostile, &tree, &root),
            Err(IndexError::InvalidRecord)
        ));
    }
}

#[test]
fn authenticated_impossible_sparse_extent_count_fails_before_allocation() {
    let tree = descriptor();
    let root = directory_descriptor();
    let root_metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let file_metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let sparse = SparseContent::new(1, Vec::new())
        .unwrap_or_else(|error| panic!("sparse content failed: {error}"));
    let content = ContentLayout::Sparse(sparse);
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &root_metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: 0,
            depth: 1,
            sibling_ordinal: 0,
            name: b"f",
            metadata: &file_metadata,
            node: IndexNode::File {
                content: &content,
                hardlink_group: None,
            },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    let mut bytes = writer.into_inner();
    let root_record_bytes = u32::from_le_bytes(
        bytes[HEADER_BYTES_V2..HEADER_BYTES_V2 + 4]
            .try_into()
            .unwrap_or_else(|_| panic!("root record length missing")),
    ) as usize;
    let file_record = HEADER_BYTES_V2 + root_record_bytes;
    let sparse_count = file_record + 70;
    bytes[sparse_count..sparse_count + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    resign_payload(&mut bytes);

    assert!(matches!(
        validate_fresh(&bytes, &tree, &root),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn authenticated_descriptor_is_required_before_semantic_parsing() {
    let (mut bytes, _, summary, tree, root) = root_index();
    let media = index_media_for(&bytes);
    let index = descriptor_for_bytes(media.clone(), &bytes);
    let expected = IndexExpectation {
        index: &index,
        compiler_abi: [3; 32],
        tree: &tree,
        root: &root,
        tree_features: 0,
    };
    let validated = validate_index(&bytes, 4096, 1_048_576, &expected)
        .unwrap_or_else(|error| panic!("validation failed: {error}"));
    assert_eq!(*validated.summary(), summary);
    assert_eq!(validated.bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(validated.descriptor(), &index);
    assert_eq!(validated.crosslinks().tree, tree);
    assert_eq!(validated.crosslinks().root, root);
    assert_eq!(validated.crosslinks().hardlink_groups, 0);
    assert_eq!(validated.crosslinks().hardlink_members, 0);
    let exact_working = (bytes.len() as u64) * 64 + 4_096;
    validate_index(&bytes, 4096, exact_working, &expected)
        .unwrap_or_else(|error| panic!("exact working ceiling failed: {error}"));
    assert!(matches!(
        validate_index(&bytes, 4096, exact_working - 1, &expected),
        Err(IndexError::LimitExceeded)
    ));

    bytes[HEADER_BYTES_V2 + 17] ^= 1;
    let internal: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES_V2..]).into();
    bytes[152..184].copy_from_slice(&internal);
    assert!(matches!(
        validate_index(&bytes, 4096, 1_048_576, &expected),
        Err(IndexError::DescriptorMismatch)
    ));

    let substituted = descriptor_for_bytes(media, &bytes);
    let substituted_expected = IndexExpectation {
        index: &substituted,
        ..expected
    };
    assert!(matches!(
        validate_index(&bytes, 4096, 1_048_576, &substituted_expected),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn recomputed_checksum_cannot_hide_invalid_reserved_record_bytes() {
    let tree = descriptor();
    let root = directory_descriptor();
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let directory = directory_descriptor();
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &directory,
            },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    let staged = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"));
    let (writer, _) = staged.into_parts();
    let mut bytes = writer.into_inner();
    bytes[HEADER_BYTES_V2 + 17] = 1;
    let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES_V2..]).into();
    bytes[152..184].copy_from_slice(&digest);
    let media = index_media_for(&bytes);
    let index = descriptor_for_bytes(media, &bytes);
    let expected = IndexExpectation {
        index: &index,
        compiler_abi: [3; 32],
        tree: &tree,
        root: &root,
        tree_features: 0,
    };
    assert!(matches!(
        validate_index(&bytes, 4096, 1_048_576, &expected),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn authenticated_but_semantically_wrong_root_and_sibling_order_fail() {
    let tree = descriptor();
    let expected_root = directory_descriptor();
    let wrong_root = ObjectDescriptor::new(
        expected_root.media_type().clone(),
        ObjectDigest::from_bytes([6; 32]),
        expected_root.encoded_size(),
    );
    let metadata = FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder =
        StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), expected_root.clone(), 0)
            .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &wrong_root,
            },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    assert!(matches!(
        validate_fresh(writer.get_ref(), &tree, &expected_root),
        Err(IndexError::InvalidRecord)
    ));

    let content = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    );
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder =
        StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), expected_root.clone(), 0)
            .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory {
                descriptor: &expected_root,
            },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    for (name, ordinal) in [(b"z".as_slice(), 0), (b"a".as_slice(), 1)] {
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal,
                name,
                metadata: &metadata,
                node: IndexNode::File {
                    content: &ContentLayout::whole(content.clone()),
                    hardlink_group: None,
                },
            })
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    assert!(matches!(
        validate_fresh(writer.get_ref(), &tree, &expected_root),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn authenticated_wrong_hardlink_membership_fails_semantic_validation() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content_descriptor = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    );
    let content = ContentLayout::whole(content_descriptor);
    let group = ObjectDigest::from_bytes([4; 32]);
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    for (ordinal, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal as u32,
                name,
                metadata: &metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: Some(group),
                },
            })
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    assert!(matches!(
        validate_fresh(writer.get_ref(), &tree, &root),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn valid_hardlink_path_reconstruction_requires_admission() {
    let tree = descriptor();
    let root = directory_descriptor();
    let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None)
        .unwrap_or_else(|error| panic!("metadata failed: {error}"));
    let content_descriptor = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media failed: {error}")),
        ObjectDigest::from_bytes([5; 32]),
        0,
    );
    let content = ContentLayout::whole(content_descriptor);
    let paths = [b"a".as_slice(), b"b".as_slice()]
        .into_iter()
        .map(|name| {
            RelativePath::new(vec![
                PathName::new(name.to_vec())
                    .unwrap_or_else(|error| panic!("path name failed: {error}")),
            ])
            .unwrap_or_else(|error| panic!("path failed: {error}"))
        })
        .collect::<Vec<_>>();
    let group = hardlink_group_digest(&paths, &metadata, &content)
        .unwrap_or_else(|error| panic!("group failed: {error}"));
    assert_eq!(
        group.as_bytes(),
        &[
            152, 254, 2, 165, 195, 187, 123, 177, 171, 161, 46, 128, 53, 90, 7, 113, 184, 115, 90,
            174, 75, 222, 106, 108, 132, 98, 111, 3, 150, 242, 103, 91,
        ]
    );
    let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
    let mut builder = StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: &[],
            metadata: &metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap_or_else(|error| panic!("push failed: {error}"));
    for (ordinal, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal as u32,
                name,
                metadata: &metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: Some(group),
                },
            })
            .unwrap_or_else(|error| panic!("push failed: {error}"));
    }
    let (writer, _) = builder
        .finish()
        .unwrap_or_else(|error| panic!("finish failed: {error}"))
        .into_parts();
    let bytes = writer.get_ref();
    let media = index_media_for(bytes);
    let index = descriptor_for_bytes(media, bytes);
    let expected = IndexExpectation {
        index: &index,
        compiler_abi: [3; 32],
        tree: &tree,
        root: &root,
        tree_features: 0,
    };
    let base_reservation = (bytes.len() as u64) * 64 + 4_096;
    assert!(matches!(
        validate_index(bytes, 4096, base_reservation, &expected),
        Err(IndexError::LimitExceeded)
    ));
    let validated = validate_index(bytes, 4096, u64::MAX, &expected)
        .unwrap_or_else(|error| panic!("admitted validation failed: {error}"));
    assert_eq!(validated.crosslinks().hardlink_groups, 1);
    assert_eq!(validated.crosslinks().hardlink_members, 2);
    let root_view = validated
        .root()
        .unwrap_or_else(|error| panic!("root decode failed: {error}"));
    for name in [b"a".as_slice(), b"b".as_slice()] {
        let name =
            PathName::new(name.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"));
        let file = validated
            .lookup_child(&root_view, &name)
            .unwrap_or_else(|error| panic!("lookup failed: {error}"))
            .unwrap_or_else(|| panic!("hard-link member missing"));
        assert_eq!(
            file.hardlink_group()
                .unwrap_or_else(|error| panic!("hard-link decode failed: {error}")),
            Some(group)
        );
    }
}
