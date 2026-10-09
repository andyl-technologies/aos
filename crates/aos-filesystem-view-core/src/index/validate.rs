//! Structural-index authentication, reconstruction, and corruption validation.

use super::view::*;
use super::wire::*;
use super::*;

mod budget;
mod input;
mod tables;

use budget::ValidationBudget;
use input::authenticate_input;

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

pub(super) struct IndexNodeRecord<'a> {
    pub(super) parent: u64,
    pub(super) depth: u32,
    pub(super) sibling_ordinal: u32,
    pub(super) directory: bool,
    pub(super) name: &'a [u8],
    pub(super) record_offset: u64,
}

pub(super) struct IndexHardlinkMember {
    pub(super) node: u64,
    pub(super) metadata: FilesystemMetadata,
    pub(super) content: ContentLayout,
}

/// Authenticated commitments required to validate a candidate index.
///
/// For an externally supplied index, the descriptor and tree commitments must
/// come from an authenticated sealed publication. A freshly compiled private
/// index may instead use the compiler-owned [`super::CompiledIndexBinding`]
/// and a descriptor computed from that compiler's output. Neither path may
/// copy commitments out of untrusted candidate bytes or their header.
pub struct IndexExpectation<'a> {
    /// Exact descriptor of the structural-index artifact.
    pub index: &'a ObjectDescriptor,
    /// Exact compiler semantic ABI.
    pub compiler_abi: [u8; 32],
    /// Exact portable tree descriptor.
    pub tree: &'a ObjectDescriptor,
    /// Exact root-directory descriptor committed by the source tree.
    pub root: &'a ObjectDescriptor,
    /// Closed tree-role feature bit set observed during compilation or publication.
    pub tree_features: u32,
}

/// Estimates conservative validation working bytes without granting validation authority.
///
/// The authenticated envelope and bounded borrowed frames determine vector,
/// peak decoded-record, retained hard-link and path charges. This does not
/// validate all record or table semantics and never returns a validated index.
/// The estimate is not allocator-exact; observed vector capacity and the cgroup
/// backstop still apply when validation runs.
///
/// # Errors
///
/// Returns an error for an unauthenticated envelope, malformed bounded frame,
/// byte ceiling violation, or unrepresentable charge. Full semantic corruption
/// can remain undetected until [`validate_index`] runs.
pub fn index_validation_working_bytes(
    bytes: &[u8],
    maximum_bytes: u64,
    expected: &IndexExpectation<'_>,
) -> Result<u64, IndexError> {
    let input = authenticate_input(bytes, maximum_bytes, expected)?;
    let model = ValidationBudget::estimate(&input, expected.index.digest())?;
    model.total(model.requested_vector_bytes()?)
}

/// Validates a complete index before a worker maps or serves it.
///
/// Validation borrows retained names and checks the on-disk tables directly.
/// Admission charges scalable vector capacities, the largest decoded record,
/// and conservative retained hard-link records and reconstructed paths. The
/// heterogeneous scratch/hard-link model is not allocator-exact; the runtime
/// cgroup memory ceiling remains the final allocator/OOM backstop.
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
    let input = authenticate_input(bytes, maximum_bytes, expected)?;
    let model = ValidationBudget::estimate(&input, expected.index.digest())?;
    model.require(model.requested_vector_bytes()?, maximum_working_bytes)?;

    // All scalable vectors are admitted before allocation. Charge observed
    // capacities as well: try_reserve_exact need not return an exact capacity.
    let mut nodes = Vec::new();
    let mut seen = Vec::new();
    let mut nlinks = Vec::new();
    model.reserve_vectors(&mut nodes, &mut seen, &mut nlinks, maximum_working_bytes)?;

    let mut records_cursor = Cursor::new(input.records);
    let mut hardlinks: std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>> =
        std::collections::BTreeMap::new();
    let mut observed_features = 0_u32;
    for expected_id in 0..input.summary.records {
        let record_offset = records_cursor.position();
        let record = validate_record(&mut records_cursor, expected_id)?;
        // The complete owned decoder above remains authoritative for metadata,
        // content, feature and descriptor semantics. Only the retained name is
        // borrowed, from the identical immutable frame at its validated offset.
        let view = decode_record_view(
            input.records,
            record_offset,
            expected_id,
            expected.index.digest(),
        )?;
        if view.name != record.name.as_slice() {
            return Err(IndexError::InvalidRecord);
        }
        let parent = record.parent;
        let depth = record.depth;
        let directory = record.directory.is_some();
        if expected_id != 0 {
            let parent_index = usize::try_from(parent).map_err(|_| IndexError::InvalidRecord)?;
            let parent_record: &IndexNodeRecord<'_> =
                nodes.get(parent_index).ok_or(IndexError::InvalidRecord)?;
            if !parent_record.directory || parent_record.depth.checked_add(1) != Some(depth) {
                return Err(IndexError::InvalidRecord);
            }
        } else if record.directory.as_ref() != Some(expected.root) {
            return Err(IndexError::InvalidRecord);
        }
        if expected_id == 0 && record.sibling_ordinal != 0 {
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
        if let (Some(group), Some(content)) = (record.hardlink_group, record.content) {
            // The preflight reserves all encoded hard-link records under the
            // conservative heterogeneous-container model before any map growth.
            hardlinks
                .entry(group)
                .or_default()
                .push(IndexHardlinkMember {
                    node: expected_id,
                    metadata: record.metadata,
                    content,
                });
        }
        nodes.push(IndexNodeRecord {
            parent,
            depth,
            sibling_ordinal: record.sibling_ordinal,
            directory,
            name: view.name,
            record_offset: u64::try_from(
                HEADER_BYTES
                    .checked_add(record_offset)
                    .ok_or(IndexError::LimitExceeded)?,
            )
            .map_err(|_| IndexError::LimitExceeded)?,
        });
    }
    if records_cursor.remaining() != 0 || observed_features & !expected.tree_features != 0 {
        return Err(IndexError::InvalidRecord);
    }
    tables::validate_lookup_table(input.lookup, &nodes, &mut seen)?;
    tables::validate_directory_table(
        input.directory,
        input.layout.root_nlink,
        &nodes,
        &hardlinks,
        &mut seen,
        &mut nlinks,
    )?;
    // Directory canonicality includes the old sibling-order check; reject it
    // before the potentially depth-scaled hard-link path reconstruction.
    // The depth/component preflight bounds these exact reconstructed paths;
    // retain the original path-accounting and semantic checks as a crosscheck.
    if hardlink_path_reservation(&hardlinks, &nodes)? > model.hardlink_paths {
        return Err(IndexError::LimitExceeded);
    }
    validate_index_hardlinks(&hardlinks, &nodes)?;
    let hardlink_groups = u64::try_from(hardlinks.len()).map_err(|_| IndexError::LimitExceeded)?;
    let hardlink_members = hardlinks.values().try_fold(0_u64, |total, members| {
        let members = u64::try_from(members.len()).map_err(|_| IndexError::LimitExceeded)?;
        total.checked_add(members).ok_or(IndexError::LimitExceeded)
    })?;
    Ok(ValidatedIndex {
        bytes,
        descriptor: expected.index.clone(),
        summary: input.summary,
        crosslinks: IndexCrosslinks {
            compiler_abi: expected.compiler_abi,
            tree: expected.tree.clone(),
            root: expected.root.clone(),
            tree_features: expected.tree_features,
            hardlink_groups,
            hardlink_members,
        },
        layout: input.layout,
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

pub(super) fn validate_index_hardlinks(
    groups: &std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>>,
    nodes: &[IndexNodeRecord<'_>],
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
    nodes: &[IndexNodeRecord<'_>],
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
    nodes: &[IndexNodeRecord<'_>],
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
            return left_record.name.cmp(right_record.name);
        }
        left = left_record.parent;
        right = right_record.parent;
    }
    std::cmp::Ordering::Equal
}

pub(super) fn reconstruct_path(
    node: u64,
    nodes: &[IndexNodeRecord<'_>],
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
        name.extend_from_slice(record.name);
        components.push(PathName::new(name).map_err(|_| IndexError::InvalidRecord)?);
        current = record.parent;
    }
    components.reverse();
    RelativePath::new(components).map_err(|_| IndexError::InvalidRecord)
}
