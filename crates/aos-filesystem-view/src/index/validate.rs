//! Structural-index authentication, reconstruction, and corruption validation.

use super::view::*;
use super::wire::*;
use super::*;

/// Records authenticated source links and validated hard-link membership.
#[derive(Debug, Eq, PartialEq)]
pub struct IndexCrosslinks {
    /// Exact compiler semantic ABI authenticated for the index.
    pub compiler_abi: [u8; 32],
    /// Exact portable tree descriptor authenticated for the index.
    pub tree: ObjectDescriptor,
    /// Exact root-directory descriptor authenticated for the index.
    pub root: ObjectDescriptor,
    /// Closed tree-role feature bit set authenticated for the index.
    pub tree_features: u32,
    /// Number of validated hard-link groups.
    pub hardlink_groups: u64,
    /// Number of validated hard-link members.
    pub hardlink_members: u64,
}

/// Reports structural-index staging or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// A byte-slice lookup name is outside the portable component profile.
    #[error("invalid structural-index lookup name: {0}")]
    InvalidPathName(#[from] InvalidPathName),
    /// Staging I/O failed.
    #[error("structural-index I/O failed: {0}")]
    Io(#[source] std::io::Error),
    /// A size, count, or conversion exceeded its hard ceiling.
    #[error("structural index exceeds a configured or representable limit")]
    LimitExceeded,
    /// An admitted index allocation was refused by the allocator.
    #[error("structural-index allocation was refused")]
    AllocationRefused,
    /// The supplied staging writer already contains bytes.
    #[error("structural-index staging writer is not fresh and empty")]
    NonEmptyStaging,
    /// The finalized staging writer contains an unexpected tail or hole.
    #[error("structural-index staging writer has an unexpected final length")]
    UnexpectedStagingLength,
    /// Header magic, version, length, or a required scalar is invalid.
    #[error("invalid structural-index header")]
    InvalidHeader,
    /// Payload checksum differs from the committed header.
    #[error("structural-index payload checksum mismatch")]
    ChecksumMismatch,
    /// A record is truncated or has invalid tags, reserved bytes, or lengths.
    #[error("invalid structural-index record")]
    InvalidRecord,
    /// The candidate bytes do not match the authenticated publication descriptor.
    #[error("structural index does not match its authenticated descriptor")]
    DescriptorMismatch,
    /// Point lookup was requested from a validation-only V1 artifact.
    #[error("point lookup is unavailable for structural-index V1")]
    PointLookupUnavailable,
    /// Directory iteration or exact link counts were requested from V1/V2.
    #[error("directory iteration is unavailable before structural-index V3")]
    DirectoryIterationUnavailable,
    /// A lookup parent came from another artifact or was not a directory.
    #[error("lookup parent does not belong to this index or is not a directory")]
    ForeignNode,
}

pub(super) struct ParsedRecord {
    pub(super) parent: u64,
    pub(super) depth: u32,
    pub(super) sibling_ordinal: u32,
    pub(super) name: Vec<u8>,
    pub(super) directory: Option<ObjectDescriptor>,
    pub(super) metadata: FilesystemMetadata,
    pub(super) content: Option<ContentLayout>,
    pub(super) hardlink_group: Option<ObjectDigest>,
    pub(super) symlink_target: Option<Vec<u8>>,
}

pub(super) struct IndexNodeRecord {
    pub(super) parent: u64,
    pub(super) depth: u32,
    pub(super) sibling_ordinal: u32,
    pub(super) directory: bool,
    pub(super) name: Vec<u8>,
    pub(super) record_offset: u64,
}

pub(super) struct IndexHardlinkMember {
    pub(super) node: u64,
    pub(super) metadata: FilesystemMetadata,
    pub(super) content: ContentLayout,
}

/// Authenticated commitments required to validate a candidate index.
///
/// The index descriptor and the tree commitments must come from an
/// authenticated sealed publication. They must never be derived from the
/// untrusted candidate bytes or copied out of its header.
pub struct IndexExpectation<'a> {
    /// Exact descriptor of the structural-index artifact.
    pub index: &'a ObjectDescriptor,
    /// Exact compiler semantic ABI.
    pub compiler_abi: [u8; 32],
    /// Exact portable tree descriptor.
    pub tree: &'a ObjectDescriptor,
    /// Exact root-directory descriptor committed by the tree publisher.
    pub root: &'a ObjectDescriptor,
    /// Closed tree-role feature bit set committed by the publisher.
    pub tree_features: u32,
}

/// Validates a complete index before a worker maps or serves it.
///
/// Validation uses a conservative input-scaled model for its heterogeneous
/// maps and decoded records; it does not claim allocator-exact accounting for
/// those containers. The runtime cgroup memory ceiling remains the final
/// allocator/OOM backstop. Builder table and scratch peaks are accounted from
/// observed `Vec` capacities separately.
///
/// # Errors
///
/// Returns [`IndexError`] when the candidate exceeds either byte ceiling,
/// differs from the authenticated descriptor, or is malformed, truncated,
/// corrupt, semantically inconsistent, or has trailing bytes.
pub fn validate_index<'a>(
    bytes: &'a [u8],
    maximum_bytes: u64,
    maximum_working_bytes: u64,
    expected: &IndexExpectation<'_>,
) -> Result<ValidatedIndex<'a>, IndexError> {
    if bytes.len() < HEADER_BYTES_V1 || bytes.len() as u64 > maximum_bytes {
        return Err(IndexError::LimitExceeded);
    }
    let validation_reservation = (bytes.len() as u64)
        .checked_mul(64)
        .and_then(|value| value.checked_add(4_096))
        .ok_or(IndexError::LimitExceeded)?;
    if validation_reservation > maximum_working_bytes {
        return Err(IndexError::LimitExceeded);
    }
    if expected.tree_features & !KNOWN_FEATURES != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != MAGIC {
        return Err(IndexError::InvalidHeader);
    }
    let version = cursor.u32()?;
    let header_bytes = cursor.u32()? as usize;
    let (index_media_type, expected_header_bytes) = match version {
        VERSION_V1 => (INDEX_MEDIA_TYPE_V1, HEADER_BYTES_V1),
        VERSION_V2 => (INDEX_MEDIA_TYPE_V2, HEADER_BYTES_V2),
        VERSION_V3 => (INDEX_MEDIA_TYPE_V3, HEADER_BYTES_V3),
        _ => return Err(IndexError::InvalidHeader),
    };
    if header_bytes != expected_header_bytes || bytes.len() < header_bytes {
        return Err(IndexError::InvalidHeader);
    }
    let index_media = MediaType::new(index_media_type).map_err(|_| IndexError::InvalidHeader)?;
    if expected.index.media_type() != &index_media
        || descriptor_for_bytes(index_media, bytes) != *expected.index
    {
        return Err(IndexError::DescriptorMismatch);
    }
    let compiler_abi = cursor.array::<32>()?;
    let tree_digest = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let tree_size = cursor.u64()?;
    let root_digest = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let root_size = cursor.u64()?;
    let tree_features = cursor.u32()?;
    if cursor.u32()? != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let records = cursor.u64()?;
    if records == 0 {
        return Err(IndexError::InvalidHeader);
    }
    let payload_bytes = cursor.u64()?;
    let expected_hash = cursor.array::<32>()?;
    let (records_bytes, lookup_slots, directory_slots, root_nlink, layout) =
        if version >= VERSION_V2 {
            let records_bytes = cursor.u64()?;
            let lookup_slots = cursor.u64()?;
            if cursor.u32()? as usize != LOOKUP_SLOT_BYTES
                || cursor.u32()? != LOOKUP_HASH_SHA256
                || cursor.u64()? != 0
            {
                return Err(IndexError::InvalidHeader);
            }
            if version == VERSION_V3 {
                let directory_slots = cursor.u64()?;
                if cursor.u32()? as usize != DIRECTORY_SLOT_BYTES || cursor.u32()? != 0 {
                    return Err(IndexError::InvalidHeader);
                }
                let root_nlink = cursor.u64()?;
                if root_nlink < 2 || cursor.u64()? != 0 {
                    return Err(IndexError::InvalidHeader);
                }
                (
                    records_bytes,
                    lookup_slots,
                    directory_slots,
                    root_nlink,
                    IndexLayout::IterableV3 {
                        records_bytes,
                        lookup_slots,
                        directory_slots,
                        root_nlink,
                    },
                )
            } else {
                (
                    records_bytes,
                    lookup_slots,
                    0,
                    0,
                    IndexLayout::PointLookupV2 {
                        records_bytes,
                        lookup_slots,
                    },
                )
            }
        } else {
            (payload_bytes, 0, 0, 0, IndexLayout::SequentialV1)
        };
    if compiler_abi != expected.compiler_abi
        || tree_digest != expected.tree.digest()
        || tree_size != expected.tree.encoded_size()
        || root_digest != expected.root.digest()
        || root_size != expected.root.encoded_size()
        || tree_features != expected.tree_features
        || validate_descriptor_role(DescriptorRole::ImmutableViewSource, expected.tree).is_err()
        || validate_descriptor_role(DescriptorRole::DirectoryChild, expected.root).is_err()
    {
        return Err(IndexError::InvalidHeader);
    }
    let payload_len = usize::try_from(payload_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if cursor.remaining() != payload_len {
        return Err(IndexError::InvalidHeader);
    }
    let payload = cursor.take(payload_len)?;
    let actual_hash: [u8; 32] = Sha256::digest(payload).into();
    if actual_hash != expected_hash {
        return Err(IndexError::ChecksumMismatch);
    }
    let records_len = usize::try_from(records_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if records_len > payload.len() {
        return Err(IndexError::InvalidHeader);
    }
    let table_slots = lookup_slot_count(records)?;
    let lookup_bytes = if version >= VERSION_V2 {
        lookup_allocation_bytes(table_slots)?
    } else {
        0
    };
    let lookup_len = usize::try_from(lookup_bytes).map_err(|_| IndexError::LimitExceeded)?;
    if records_len
        .checked_add(lookup_len)
        .ok_or(IndexError::LimitExceeded)?
        > payload.len()
    {
        return Err(IndexError::InvalidHeader);
    }
    let records_payload = &payload[..records_len];
    let lookup_payload = &payload[records_len..records_len + lookup_len];
    let directory_payload = &payload[records_len + lookup_len..];
    if version >= VERSION_V2 {
        let canonical_slots = lookup_slot_count(records)?;
        let table_bytes = lookup_allocation_bytes(canonical_slots)?;
        let canonical_slots_u64 =
            u64::try_from(canonical_slots).map_err(|_| IndexError::LimitExceeded)?;
        if lookup_slots != canonical_slots_u64 || table_bytes != lookup_payload.len() as u64 {
            return Err(IndexError::InvalidHeader);
        }
        let directory_bytes = if version == VERSION_V3 {
            let bytes = directory_allocation_bytes(canonical_slots)?;
            if directory_slots != canonical_slots_u64 || bytes != directory_payload.len() as u64 {
                return Err(IndexError::InvalidHeader);
            }
            bytes
        } else {
            if !directory_payload.is_empty() {
                return Err(IndexError::InvalidHeader);
            }
            0
        };
        if records_bytes
            .checked_add(table_bytes)
            .and_then(|bytes| bytes.checked_add(directory_bytes))
            .ok_or(IndexError::LimitExceeded)?
            != payload_bytes
        {
            return Err(IndexError::InvalidHeader);
        }
    } else if !lookup_payload.is_empty() || !directory_payload.is_empty() {
        return Err(IndexError::InvalidHeader);
    }
    let mut records_cursor = Cursor::new(records_payload);
    let record_capacity = usize::try_from(records).map_err(|_| IndexError::LimitExceeded)?;
    if record_capacity > records_payload.len() / RECORD_FIXED_BYTES {
        return Err(IndexError::InvalidHeader);
    }
    let mut nodes: Vec<IndexNodeRecord> = Vec::new();
    nodes
        .try_reserve_exact(record_capacity)
        .map_err(|_| IndexError::AllocationRefused)?;
    let mut siblings: std::collections::BTreeMap<u64, std::collections::BTreeMap<u32, Vec<u8>>> =
        std::collections::BTreeMap::new();
    let mut hardlinks: std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>> =
        std::collections::BTreeMap::new();
    let mut observed_features = 0_u32;
    for expected_id in 0..records {
        let record_offset = header_bytes
            .checked_add(records_cursor.position())
            .ok_or(IndexError::LimitExceeded)?;
        let record = validate_record(&mut records_cursor, expected_id)?;
        let parent = record.parent;
        let depth = record.depth;
        let directory = record.directory.is_some();
        if expected_id != 0 {
            let parent_index = usize::try_from(parent).map_err(|_| IndexError::InvalidRecord)?;
            let parent_record = nodes.get(parent_index).ok_or(IndexError::InvalidRecord)?;
            if !parent_record.directory || parent_record.depth.checked_add(1) != Some(depth) {
                return Err(IndexError::InvalidRecord);
            }
        } else if record.directory.as_ref() != Some(expected.root) {
            return Err(IndexError::InvalidRecord);
        }
        if expected_id == 0 && record.sibling_ordinal != 0 {
            return Err(IndexError::InvalidRecord);
        }

        if expected_id != 0
            && siblings
                .entry(parent)
                .or_default()
                .insert(record.sibling_ordinal, record.name.clone())
                .is_some()
        {
            return Err(IndexError::InvalidRecord);
        }
        if record.metadata.acl().is_some() {
            observed_features |= FEATURE_ACL;
        }
        if let Some(target) = &record.symlink_target {
            if target.first() == Some(&b'/') {
                observed_features |= FEATURE_ABSOLUTE_SYMLINK;
            } else if symlink_escapes_parent(target, depth.saturating_sub(1) as usize) {
                observed_features |= FEATURE_PARENT_SYMLINK;
            }
        }
        if let (Some(group), Some(content)) = (record.hardlink_group, record.content.clone()) {
            hardlinks
                .entry(group)
                .or_default()
                .push(IndexHardlinkMember {
                    node: expected_id,
                    metadata: record.metadata.clone(),
                    content,
                });
        }
        nodes.push(IndexNodeRecord {
            parent,
            depth,
            sibling_ordinal: record.sibling_ordinal,
            directory,
            name: record.name,
            record_offset: record_offset as u64,
        });
    }
    if records_cursor.remaining() != 0 {
        return Err(IndexError::InvalidRecord);
    }
    if observed_features & !tree_features != 0 {
        return Err(IndexError::InvalidRecord);
    }
    validate_siblings(&siblings)?;
    let hardlink_path_reservation = hardlink_path_reservation(&hardlinks, &nodes)?;
    let total_validation_reservation = validation_reservation
        .checked_add(hardlink_path_reservation)
        .ok_or(IndexError::LimitExceeded)?;
    if total_validation_reservation > maximum_working_bytes {
        return Err(IndexError::LimitExceeded);
    }
    validate_index_hardlinks(&hardlinks, &nodes)?;
    if version >= VERSION_V2 {
        validate_lookup_table(lookup_payload, &nodes)?;
    }
    if version == VERSION_V3 {
        validate_directory_table(directory_payload, root_nlink, &nodes, &hardlinks)?;
    }
    let hardlink_groups = u64::try_from(hardlinks.len()).map_err(|_| IndexError::LimitExceeded)?;
    let hardlink_members = hardlinks.values().try_fold(0_u64, |total, members| {
        let members = u64::try_from(members.len()).map_err(|_| IndexError::LimitExceeded)?;
        total.checked_add(members).ok_or(IndexError::LimitExceeded)
    })?;
    Ok(ValidatedIndex {
        bytes,
        descriptor: expected.index.clone(),
        summary: IndexSummary {
            compiler_abi,
            tree_digest,
            tree_size,
            root_digest,
            root_size,
            records,
            bytes: bytes.len() as u64,
        },
        crosslinks: IndexCrosslinks {
            compiler_abi,
            tree: expected.tree.clone(),
            root: expected.root.clone(),
            tree_features,
            hardlink_groups,
            hardlink_members,
        },
        layout,
    })
}

pub(super) fn preflight_collection(
    count: u32,
    remaining_record_bytes: usize,
    minimum_encoded_item_bytes: usize,
    decoded_item_bytes: usize,
) -> Result<usize, IndexError> {
    let count = usize::try_from(count).map_err(|_| IndexError::InvalidRecord)?;
    let minimum_encoded = count
        .checked_mul(minimum_encoded_item_bytes)
        .ok_or(IndexError::InvalidRecord)?;
    if minimum_encoded > remaining_record_bytes {
        return Err(IndexError::InvalidRecord);
    }
    let decoded = count
        .checked_mul(decoded_item_bytes)
        .ok_or(IndexError::InvalidRecord)?;
    let admitted = remaining_record_bytes
        .checked_mul(64)
        .and_then(|value| value.checked_add(4_096))
        .ok_or(IndexError::LimitExceeded)?;
    if decoded > admitted {
        return Err(IndexError::InvalidRecord);
    }
    Ok(count)
}

pub(super) fn symlink_escapes_parent(target: &[u8], mut depth: usize) -> bool {
    for component in target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." if depth == 0 => return true,
            b".." => depth -= 1,
            _ => depth = depth.saturating_add(1),
        }
    }
    false
}

pub(super) fn validate_siblings(
    siblings: &std::collections::BTreeMap<u64, std::collections::BTreeMap<u32, Vec<u8>>>,
) -> Result<(), IndexError> {
    for entries in siblings.values() {
        let mut previous: Option<&[u8]> = None;
        for (expected, (ordinal, name)) in entries.iter().enumerate() {
            let expected = u32::try_from(expected).map_err(|_| IndexError::InvalidRecord)?;
            if *ordinal != expected || previous.is_some_and(|value| value >= name.as_slice()) {
                return Err(IndexError::InvalidRecord);
            }
            previous = Some(name);
        }
    }
    Ok(())
}

pub(super) fn validate_lookup_table(
    bytes: &[u8],
    nodes: &[IndexNodeRecord],
) -> Result<(), IndexError> {
    let slots = bytes.len() / LOOKUP_SLOT_BYTES;
    if !bytes.len().is_multiple_of(LOOKUP_SLOT_BYTES) {
        return Err(IndexError::InvalidHeader);
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(slots)
        .map_err(|_| IndexError::AllocationRefused)?;
    for (record_id, node) in nodes.iter().enumerate().skip(1) {
        let record_id = u64::try_from(record_id).map_err(|_| IndexError::LimitExceeded)?;
        expected.push(LookupSlot {
            parent: node.parent,
            name_hash: lookup_hash(node.parent, &node.name),
            record_offset: node.record_offset,
            record_id,
        });
    }
    expected.sort_unstable_by_key(|entry| (entry.parent, entry.name_hash, entry.record_id));
    for (encoded, expected) in bytes.chunks_exact(LOOKUP_SLOT_BYTES).zip(expected) {
        if encoded != encode_lookup_slot(expected) {
            return Err(IndexError::InvalidRecord);
        }
    }
    Ok(())
}

pub(super) fn validate_directory_table(
    bytes: &[u8],
    root_nlink: u64,
    nodes: &[IndexNodeRecord],
    hardlinks: &std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>>,
) -> Result<(), IndexError> {
    if !bytes.len().is_multiple_of(DIRECTORY_SLOT_BYTES) {
        return Err(IndexError::InvalidHeader);
    }
    let mut nlinks = Vec::new();
    nlinks
        .try_reserve_exact(nodes.len())
        .map_err(|_| IndexError::AllocationRefused)?;
    nlinks.extend(
        nodes
            .iter()
            .map(|node| if node.directory { 2_u64 } else { 1_u64 }),
    );
    for node in nodes.iter().skip(1).filter(|node| node.directory) {
        let parent = usize::try_from(node.parent).map_err(|_| IndexError::InvalidRecord)?;
        let value = nlinks.get_mut(parent).ok_or(IndexError::InvalidRecord)?;
        *value = value.checked_add(1).ok_or(IndexError::LimitExceeded)?;
    }
    for members in hardlinks.values() {
        let count = u64::try_from(members.len()).map_err(|_| IndexError::LimitExceeded)?;
        for member in members {
            let index = usize::try_from(member.node).map_err(|_| IndexError::InvalidRecord)?;
            *nlinks.get_mut(index).ok_or(IndexError::InvalidRecord)? = count;
        }
    }
    if nlinks.first().copied() != Some(root_nlink) {
        return Err(IndexError::InvalidRecord);
    }

    let mut expected = Vec::new();
    expected
        .try_reserve_exact(nodes.len().saturating_sub(1))
        .map_err(|_| IndexError::AllocationRefused)?;
    for (record_id, node) in nodes.iter().enumerate().skip(1) {
        let record_id = u64::try_from(record_id).map_err(|_| IndexError::LimitExceeded)?;
        let nlink = nlinks
            .get(usize::try_from(record_id).map_err(|_| IndexError::LimitExceeded)?)
            .copied()
            .ok_or(IndexError::InvalidRecord)?;
        expected.push((
            node.parent,
            node.sibling_ordinal,
            DirectorySlot {
                parent: node.parent,
                record_offset: node.record_offset,
                record_id,
                nlink,
            },
        ));
    }
    expected.sort_unstable_by_key(|(parent, ordinal, slot)| (*parent, *ordinal, slot.record_id));
    for (encoded, (_, _, expected)) in bytes.chunks_exact(DIRECTORY_SLOT_BYTES).zip(expected) {
        if encoded != encode_directory_slot(expected) {
            return Err(IndexError::InvalidRecord);
        }
    }
    Ok(())
}

pub(super) fn validate_index_hardlinks(
    groups: &std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>>,
    nodes: &[IndexNodeRecord],
) -> Result<(), IndexError> {
    for (claimed, members) in groups {
        let first = members.first().ok_or(IndexError::InvalidRecord)?;
        if members.len() < 2
            || members
                .iter()
                .any(|member| member.metadata != first.metadata || member.content != first.content)
        {
            return Err(IndexError::InvalidRecord);
        }
        let mut member_nodes = Vec::new();
        member_nodes
            .try_reserve_exact(members.len())
            .map_err(|_| IndexError::AllocationRefused)?;
        member_nodes.extend(members.iter().map(|member| member.node));
        member_nodes.sort_by(|left, right| compare_node_paths(*left, *right, nodes));
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(member_nodes.len())
            .map_err(|_| IndexError::AllocationRefused)?;
        for node in member_nodes {
            paths.push(reconstruct_path(node, nodes)?);
        }
        if paths.windows(2).any(|pair| pair[0] == pair[1])
            || hardlink_group_digest(&paths, &first.metadata, &first.content)
                .map_err(|_| IndexError::InvalidRecord)?
                != *claimed
        {
            return Err(IndexError::InvalidRecord);
        }
    }
    Ok(())
}

pub(super) fn hardlink_path_reservation(
    groups: &std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>>,
    nodes: &[IndexNodeRecord],
) -> Result<u64, IndexError> {
    groups.values().flatten().try_fold(0_u64, |total, member| {
        let mut node = member.node;
        let mut path = 256_u64;
        while node != 0 {
            let record = nodes.get(node as usize).ok_or(IndexError::InvalidRecord)?;
            let name = record.name.len() as u64;
            path = path
                .checked_add(128)
                .and_then(|value| value.checked_add(name.saturating_mul(4)))
                .ok_or(IndexError::LimitExceeded)?;
            node = record.parent;
        }
        total.checked_add(path).ok_or(IndexError::LimitExceeded)
    })
}

pub(super) fn compare_node_paths(
    left: u64,
    right: u64,
    nodes: &[IndexNodeRecord],
) -> std::cmp::Ordering {
    let mut left = left;
    let mut right = right;
    let mut left_depth = nodes.get(left as usize).map_or(0, |record| record.depth);
    let mut right_depth = nodes.get(right as usize).map_or(0, |record| record.depth);
    while left_depth > right_depth {
        left = nodes
            .get(left as usize)
            .map_or(u64::MAX, |record| record.parent);
        left_depth -= 1;
    }
    while right_depth > left_depth {
        right = nodes
            .get(right as usize)
            .map_or(u64::MAX, |record| record.parent);
        right_depth -= 1;
    }
    while left != right {
        let Some(left_record) = nodes.get(left as usize) else {
            return left.cmp(&right);
        };
        let Some(right_record) = nodes.get(right as usize) else {
            return left.cmp(&right);
        };
        if left_record.parent == right_record.parent {
            return left_record.name.cmp(&right_record.name);
        }
        left = left_record.parent;
        right = right_record.parent;
    }
    std::cmp::Ordering::Equal
}

pub(super) fn reconstruct_path(
    node: u64,
    nodes: &[IndexNodeRecord],
) -> Result<RelativePath, IndexError> {
    let depth = nodes
        .get(node as usize)
        .ok_or(IndexError::InvalidRecord)?
        .depth as usize;
    let mut components = Vec::new();
    components
        .try_reserve_exact(depth)
        .map_err(|_| IndexError::AllocationRefused)?;
    let mut current = node;
    while current != 0 {
        let record = nodes
            .get(current as usize)
            .ok_or(IndexError::InvalidRecord)?;
        let mut name = Vec::new();
        name.try_reserve_exact(record.name.len())
            .map_err(|_| IndexError::AllocationRefused)?;
        name.extend_from_slice(&record.name);
        components.push(PathName::new(name).map_err(|_| IndexError::InvalidRecord)?);
        current = record.parent;
    }
    components.reverse();
    RelativePath::new(components).map_err(|_| IndexError::InvalidRecord)
}
