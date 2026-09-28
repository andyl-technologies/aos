//! Borrowed-validator admission and whole-index corruption regressions.

use super::*;

fn validate_at<'a>(
    bytes: &'a [u8],
    tree: &ObjectDescriptor,
    root: &ObjectDescriptor,
    cap: u64,
) -> Result<ValidatedIndex<'a>, IndexError> {
    let descriptor = descriptor_for_bytes(index_media(), bytes);
    validate_index(
        bytes,
        bytes.len() as u64,
        cap,
        &IndexExpectation {
            index: &descriptor,
            compiler_abi: [3; 32],
            tree,
            root,
            tree_features: 0,
        },
    )
}

fn estimate(bytes: &[u8], tree: &ObjectDescriptor, root: &ObjectDescriptor) -> u64 {
    let descriptor = descriptor_for_bytes(index_media(), bytes);
    index_validation_working_bytes(
        bytes,
        bytes.len() as u64,
        &IndexExpectation {
            index: &descriptor,
            compiler_abi: [3; 32],
            tree,
            root,
            tree_features: 0,
        },
    )
    .unwrap()
}

fn table_offsets(bytes: &[u8]) -> (usize, usize, usize) {
    let records = u64::from_le_bytes(
        bytes[RECORDS_BYTES_OFFSET..RECORDS_BYTES_OFFSET + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let slots = u64::from_le_bytes(
        bytes[LOOKUP_SLOTS_OFFSET..LOOKUP_SLOTS_OFFSET + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let lookup = HEADER_BYTES + records;
    (lookup, lookup + slots * LOOKUP_SLOT_BYTES, slots)
}

fn flat_index(
    children: u32,
    metadata: &FilesystemMetadata,
) -> (Vec<u8>, ObjectDescriptor, ObjectDescriptor) {
    let tree = descriptor();
    let root = directory_descriptor();
    let content = ContentLayout::whole(ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap(),
        ObjectDigest::from_bytes([5; 32]),
        0,
    ));
    let ceiling = 16 * 1_048_576;
    let mut builder = StructuralIndexBuilder::new(
        IndexStaging::new(IoCursor::new(Vec::new()), ceiling, ceiling),
        [3; 32],
        tree.clone(),
        root.clone(),
        0,
    )
    .unwrap();
    builder
        .push(&IndexRecord {
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: b"",
            metadata,
            node: IndexNode::Directory { descriptor: &root },
        })
        .unwrap();
    for ordinal in 0..children {
        let name = format!("{ordinal:08}");
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: ordinal,
                name: name.as_bytes(),
                metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: None,
                },
            })
            .unwrap();
    }
    let (writer, _) = builder.finish().unwrap().into_parts();
    (writer.into_inner(), tree, root)
}

#[test]
fn validation_memory_flat_input_above_four_mib_is_normally_admitted() {
    let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, Vec::new(), None).unwrap();
    let (bytes, tree, root) = flat_index(20_000, &metadata);
    let normal = crate::TreeCompileLimits::default().working_bytes;
    // This crosses the historical input-times-64 rejection threshold without
    // raising the production budget or duplicating the new admission formula.
    assert!(bytes.len() as u64 > normal / 64);
    let admitted = estimate(&bytes, &tree, &root);
    assert!(admitted < normal);
    let validated = validate_at(&bytes, &tree, &root, normal).unwrap();
    assert_eq!(validated.summary().records, 20_001);
    assert_eq!(validated.records().count(), 20_001);
    validate_at(&bytes, &tree, &root, admitted).unwrap();
    assert!(matches!(
        validate_at(&bytes, &tree, &root, admitted - 1),
        Err(IndexError::LimitExceeded)
    ));
}

#[test]
fn validation_memory_each_table_rejects_duplicate_missing_root_and_foreign_ids() {
    let (bytes, tree, root) = iterable_index();
    validate_at(&bytes, &tree, &root, estimate(&bytes, &tree, &root)).unwrap();
    let (lookup, directory, slots) = table_offsets(&bytes);
    for (table, width, id_offset) in [
        (lookup, LOOKUP_SLOT_BYTES, 48),
        (directory, DIRECTORY_SLOT_BYTES, 16),
    ] {
        let mut duplicate = bytes.clone();
        let first = duplicate[table..table + width].to_vec();
        let last = table + (slots - 1) * width;
        duplicate[last..last + width].copy_from_slice(&first);
        resign_payload(&mut duplicate);
        assert!(matches!(
            validate_at(&duplicate, &tree, &root, u64::MAX),
            Err(IndexError::InvalidRecord)
        ));
        for id in [0, slots as u64 + 1, u64::MAX] {
            let mut forged = bytes.clone();
            forged[table + id_offset..table + id_offset + 8].copy_from_slice(&id.to_le_bytes());
            resign_payload(&mut forged);
            assert!(matches!(
                validate_at(&forged, &tree, &root, u64::MAX),
                Err(IndexError::InvalidRecord)
            ));
        }
    }
    let mut missing = bytes.clone();
    missing[LOOKUP_SLOTS_OFFSET..LOOKUP_SLOTS_OFFSET + 8]
        .copy_from_slice(&((slots - 1) as u64).to_le_bytes());
    assert!(matches!(
        validate_at(&missing, &tree, &root, u64::MAX),
        Err(IndexError::InvalidHeader)
    ));
    let mut extra = bytes;
    extra.extend_from_slice(&[0; DIRECTORY_SLOT_BYTES]);
    assert!(matches!(
        validate_at(&extra, &tree, &root, u64::MAX),
        Err(IndexError::InvalidHeader)
    ));
}

#[test]
fn validation_memory_directory_sweep_preserves_sibling_ordinal_checks() {
    let (bytes, tree, root) = lookup_index();
    let (_, directory, _) = table_offsets(&bytes);
    let second = read_directory_slot(&bytes, directory as u64, 1).unwrap();
    for ordinal in [0_u32, 2, u32::MAX] {
        let mut forged = bytes.clone();
        let offset = second.record_offset as usize + 16;
        forged[offset..offset + 4].copy_from_slice(&ordinal.to_le_bytes());
        resign_payload(&mut forged);
        assert!(matches!(
            validate_at(&forged, &tree, &root, u64::MAX),
            Err(IndexError::InvalidRecord)
        ));
    }
}

fn rebind_lookup_to_records(bytes: &mut [u8]) {
    // Only corruption fixtures rebuild a table, to reach the sibling-name
    // check with every lookup commitment already matching changed records.
    let (lookup, _, slots) = table_offsets(bytes);
    let artifact = ObjectDigest::from_bytes([0; 32]);
    let mut expected = Vec::new();
    let mut offset = HEADER_BYTES;
    for id in 0..=slots as u64 {
        let record = decode_record_view(bytes, offset, id, artifact).unwrap();
        if id != 0 {
            expected.push(LookupSlot {
                parent: record.parent,
                name_hash: lookup_hash(record.parent, record.name),
                record_offset: offset as u64,
                record_id: id,
            });
        }
        offset += record.encoded_record.len();
    }
    expected.sort_unstable_by_key(|slot| (slot.parent, slot.name_hash, slot.record_id));
    for (index, slot) in expected.into_iter().enumerate() {
        let offset = lookup + index * LOOKUP_SLOT_BYTES;
        bytes[offset..offset + LOOKUP_SLOT_BYTES].copy_from_slice(&encode_lookup_slot(slot));
    }
    resign_payload(bytes);
}

#[test]
fn validation_memory_directory_sweep_preserves_name_order_and_uniqueness() {
    let (bytes, tree, root) = lookup_index();
    let (_, directory, _) = table_offsets(&bytes);
    let first = read_directory_slot(&bytes, directory as u64, 0).unwrap();
    for name in [0x80, 0x81] {
        let mut forged = bytes.clone();
        forged[first.record_offset as usize + RECORD_FIXED_BYTES + 4] = name;
        rebind_lookup_to_records(&mut forged);
        assert!(matches!(
            validate_at(&forged, &tree, &root, u64::MAX),
            Err(IndexError::InvalidRecord)
        ));
    }
}

#[test]
fn validation_memory_large_record_scratch_is_admitted_before_owned_decode() {
    let metadata = FilesystemMetadata::new(
        0o644,
        0,
        0,
        0,
        0,
        vec![Xattr::new(b"user.large".to_vec(), vec![7; 65_536]).unwrap()],
        None,
    )
    .unwrap();
    let (bytes, tree, root) = flat_index(1, &metadata);
    let admitted = estimate(&bytes, &tree, &root);
    assert!(admitted > 4 * 1_048_576);
    assert!(matches!(
        validate_at(&bytes, &tree, &root, 1_048_576),
        Err(IndexError::LimitExceeded)
    ));
    validate_at(&bytes, &tree, &root, admitted).unwrap();

    let mut truncated = bytes;
    truncated[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    resign_payload(&mut truncated);
    assert!(matches!(
        validate_at(&truncated, &tree, &root, u64::MAX),
        Err(IndexError::InvalidRecord)
    ));
}

#[test]
fn validation_memory_estimate_never_substitutes_for_full_record_validation() {
    let (mut bytes, tree, root) = root_index_bytes();
    let descriptor = descriptor_for_bytes(index_media(), &bytes);
    let authenticated = IndexExpectation {
        index: &descriptor,
        compiler_abi: [3; 32],
        tree: &tree,
        root: &root,
        tree_features: 0,
    };
    bytes[HEADER_BYTES + 28] ^= 1;
    assert!(matches!(
        index_validation_working_bytes(&bytes, bytes.len() as u64, &authenticated),
        Err(IndexError::DescriptorMismatch)
    ));

    // A root directory descriptor's digest is outside the borrowed frame's
    // header/name checks. Reauthenticated bytes can be estimated, but cannot
    // become a ValidatedIndex with the wrong independently known root.
    let (mut bytes, tree, root) = root_index_bytes();
    let root_digest_offset =
        HEADER_BYTES + RECORD_FIXED_BYTES + 4 + 4 + 4 + 4 + root.media_type().as_str().len();
    bytes[root_digest_offset] ^= 1;
    resign_payload(&mut bytes);
    let _non_authorizing = estimate(&bytes, &tree, &root);
    assert!(matches!(
        validate_at(&bytes, &tree, &root, u64::MAX),
        Err(IndexError::InvalidRecord)
    ));
}
