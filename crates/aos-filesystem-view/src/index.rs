//! Architecture-neutral structural-index staging and validation.
//!
//! Format v1 is a little-endian derived cache:
//!
//! ```text
//! header = magic[8], version:u32, header-bytes:u32, compiler-abi[32],
//!          tree-digest[32], tree-size:u64, root-digest[32], root-size:u64,
//!          tree-features:u32, reserved:u32, record-count:u64,
//!          payload-bytes:u64, payload-sha256[32]
//! payload = record*
//! record = record-bytes:u32, parent:u64, depth:u32, sibling-ordinal:u32,
//!          kind:u8, reserved[3],
//!          mode:u16, reserved:u16, uid:u32, gid:u32, mtime-sec:i64,
//!          mtime-nsec:u32, body...
//! ```
//!
//! All variable fields are length-prefixed and the validator rejects unknown
//! tags, nonzero reserved bytes, overflow, truncation, and trailing data.

use std::io::{Seek, SeekFrom, Write};

use aos_sandbox_core::model::{
    Acl, AclEntry, ContentLayout, Extent, FilesystemMetadata, SparseContent, Xattr,
};
use aos_sandbox_core::{
    DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, PathName, RelativePath,
    descriptor_for_bytes, hardlink_group_digest, validate_descriptor_role,
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"AOSVIDX\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 184;
const RECORD_FIXED_BYTES: usize = 44;

/// Media type of the node-local structural-index format.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.aos.filesystem-view.index.v1";

pub(crate) const FEATURE_ACL: u32 = 1 << 0;
pub(crate) const FEATURE_ABSOLUTE_SYMLINK: u32 = 1 << 1;
pub(crate) const FEATURE_PARENT_SYMLINK: u32 = 1 << 2;
const KNOWN_FEATURES: u32 = FEATURE_ACL | FEATURE_ABSOLUTE_SYMLINK | FEATURE_PARENT_SYMLINK;

/// Describes one expanded path written to the structural index.
#[derive(Clone, Debug)]
pub struct IndexRecord<'a> {
    /// Expanded parent record, or `u64::MAX` for the root.
    pub parent: u64,
    /// Expanded path depth, with root at zero.
    pub depth: u32,
    /// Zero-based position in the source directory's canonical entry order.
    pub sibling_ordinal: u32,
    /// Empty for root; otherwise the byte-exact final path component.
    pub name: &'a [u8],
    /// Portable metadata, retained independently of presentation maps.
    pub metadata: &'a FilesystemMetadata,
    /// Portable node semantics.
    pub node: IndexNode<'a>,
}

/// Borrows one portable node for index encoding.
#[derive(Clone, Copy, Debug)]
pub enum IndexNode<'a> {
    /// Stores a regular file.
    File {
        /// Exact portable content layout.
        content: &'a ContentLayout,
        /// Optional tree-scoped hard-link group.
        hardlink_group: Option<ObjectDigest>,
    },
    /// Stores a directory and its exact portable descriptor.
    Directory {
        /// Exact descriptor for the directory object.
        descriptor: &'a ObjectDescriptor,
    },
    /// Stores byte-exact symbolic-link target bytes.
    Symlink {
        /// Uninterpreted target bytes.
        target: &'a [u8],
    },
}

/// Owns a fresh private writer until compilation succeeds or destroys it.
pub struct IndexStaging<W> {
    writer: W,
    maximum_bytes: u64,
    maximum_record_bytes: u64,
}

impl<W> IndexStaging<W> {
    /// Creates an unused staging capability.
    #[must_use]
    pub const fn new(writer: W, maximum_bytes: u64, maximum_record_bytes: u64) -> Self {
        Self {
            writer,
            maximum_bytes,
            maximum_record_bytes,
        }
    }

    pub(crate) fn narrow(mut self, maximum_bytes: u64, maximum_record_bytes: u64) -> Self {
        self.maximum_bytes = self.maximum_bytes.min(maximum_bytes);
        self.maximum_record_bytes = self.maximum_record_bytes.min(maximum_record_bytes);
        self
    }
}

/// Contains an index writer returned only after complete graph validation.
pub struct StagedIndex<W> {
    writer: W,
    summary: IndexSummary,
}

impl<W> StagedIndex<W> {
    /// Returns the finalized private writer and structural summary.
    #[must_use]
    pub fn into_parts(self) -> (W, IndexSummary) {
        (self.writer, self.summary)
    }
}

/// Writes a private structural-index artifact behind the consuming compiler.
pub(crate) struct StructuralIndexBuilder<W> {
    writer: W,
    compiler_abi: [u8; 32],
    tree: ObjectDescriptor,
    root: ObjectDescriptor,
    tree_features: u32,
    maximum_bytes: u64,
    maximum_record_bytes: u64,
    records: u64,
    payload_bytes: u64,
    payload_hash: Sha256,
}

impl<W: Write + Seek> StructuralIndexBuilder<W> {
    pub(crate) fn new(
        staging: IndexStaging<W>,
        compiler_abi: [u8; 32],
        tree: ObjectDescriptor,
        root: ObjectDescriptor,
        tree_features: u32,
    ) -> Result<Self, IndexError> {
        let IndexStaging {
            mut writer,
            maximum_bytes,
            maximum_record_bytes,
        } = staging;
        if maximum_bytes < HEADER_BYTES as u64 || maximum_record_bytes == 0 {
            return Err(IndexError::LimitExceeded);
        }
        validate_descriptor_role(DescriptorRole::ImmutableViewSource, &tree)
            .map_err(|_| IndexError::InvalidHeader)?;
        if writer.stream_position().map_err(IndexError::Io)? != 0
            || writer.seek(SeekFrom::End(0)).map_err(IndexError::Io)? != 0
        {
            return Err(IndexError::NonEmptyStaging);
        }
        writer.seek(SeekFrom::Start(0)).map_err(IndexError::Io)?;
        writer
            .write_all(&[0; HEADER_BYTES])
            .map_err(IndexError::Io)?;
        Ok(Self {
            writer,
            compiler_abi,
            tree,
            root,
            tree_features,
            maximum_bytes,
            maximum_record_bytes,
            records: 0,
            payload_bytes: 0,
            payload_hash: Sha256::new(),
        })
    }

    /// Appends one expanded node after reserving its exact encoded size.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] for arithmetic/format limits or staging I/O.
    pub(crate) fn push(&mut self, record: &IndexRecord<'_>) -> Result<u64, IndexError> {
        let encoded_len = record_encoded_len(record)?;
        let record_bytes = u64::try_from(encoded_len).map_err(|_| IndexError::LimitExceeded)?;
        if record_bytes > self.maximum_record_bytes {
            return Err(IndexError::LimitExceeded);
        }
        let next_payload = self
            .payload_bytes
            .checked_add(record_bytes)
            .ok_or(IndexError::LimitExceeded)?;
        let total = (HEADER_BYTES as u64)
            .checked_add(next_payload)
            .ok_or(IndexError::LimitExceeded)?;
        if total > self.maximum_bytes {
            return Err(IndexError::LimitExceeded);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_len)
            .map_err(|_| IndexError::AllocationRefused)?;
        encode_record(&mut bytes, record)?;
        if bytes.len() != encoded_len {
            return Err(IndexError::InvalidRecord);
        }
        let id = self.records;
        self.writer.write_all(&bytes).map_err(IndexError::Io)?;
        self.payload_hash.update(&bytes);
        self.payload_bytes = next_payload;
        self.records = self
            .records
            .checked_add(1)
            .ok_or(IndexError::LimitExceeded)?;
        Ok(id)
    }

    /// Finalizes the header and returns the writer and index summary.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Io`] when seeking, writing, or flushing fails.
    pub(crate) fn finish(mut self) -> Result<StagedIndex<W>, IndexError> {
        if self.records == 0 {
            return Err(IndexError::InvalidRecord);
        }
        let payload_digest: [u8; 32] = self.payload_hash.finalize().into();
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        put_u32(&mut header, VERSION);
        put_u32(&mut header, HEADER_BYTES as u32);
        header.extend_from_slice(&self.compiler_abi);
        header.extend_from_slice(self.tree.digest().as_bytes());
        put_u64(&mut header, self.tree.encoded_size());
        header.extend_from_slice(self.root.digest().as_bytes());
        put_u64(&mut header, self.root.encoded_size());
        put_u32(&mut header, self.tree_features);
        put_u32(&mut header, 0);
        put_u64(&mut header, self.records);
        put_u64(&mut header, self.payload_bytes);
        header.extend_from_slice(&payload_digest);
        if header.len() != HEADER_BYTES {
            return Err(IndexError::InvalidHeader);
        }
        self.writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.writer.write_all(&header))
            .and_then(|_| self.writer.flush())
            .map_err(IndexError::Io)?;
        let expected_end = HEADER_BYTES as u64 + self.payload_bytes;
        let actual_end = self.writer.seek(SeekFrom::End(0)).map_err(IndexError::Io)?;
        if actual_end != expected_end {
            return Err(IndexError::UnexpectedStagingLength);
        }
        Ok(StagedIndex {
            writer: self.writer,
            summary: IndexSummary {
                compiler_abi: self.compiler_abi,
                tree_digest: self.tree.digest(),
                tree_size: self.tree.encoded_size(),
                root_digest: self.root.digest(),
                root_size: self.root.encoded_size(),
                records: self.records,
                bytes: HEADER_BYTES as u64 + self.payload_bytes,
            },
        })
    }
}

pub(crate) fn record_encoded_len(record: &IndexRecord<'_>) -> Result<usize, IndexError> {
    let mut length = 48_usize;
    add_bytes_len(&mut length, record.name)?;
    length = checked_len_add(length, 4)?;
    for xattr in record.metadata.xattrs() {
        add_bytes_len(&mut length, xattr.name())?;
        add_bytes_len(&mut length, xattr.value())?;
    }
    length = checked_len_add(length, 4)?;
    if let Some(acl) = record.metadata.acl() {
        length = checked_len_add(
            length,
            acl.entries()
                .len()
                .checked_mul(6)
                .ok_or(IndexError::LimitExceeded)?,
        )?;
    }
    match record.node {
        IndexNode::File {
            content,
            hardlink_group,
        } => {
            length = checked_len_add(length, content_encoded_len(content)?)?;
            length = checked_len_add(length, 1 + usize::from(hardlink_group.is_some()) * 32)?;
        }
        IndexNode::Directory { descriptor } => {
            length = checked_len_add(length, descriptor_encoded_len(descriptor)?)?;
        }
        IndexNode::Symlink { target } => add_bytes_len(&mut length, target)?,
    }
    u32::try_from(length).map_err(|_| IndexError::LimitExceeded)?;
    Ok(length)
}

fn content_encoded_len(content: &ContentLayout) -> Result<usize, IndexError> {
    match content {
        ContentLayout::Whole { content } => checked_len_add(1, descriptor_encoded_len(content)?),
        ContentLayout::Sparse(sparse) => {
            let mut length = 13_usize;
            for extent in sparse.extents() {
                length = checked_len_add(length, 16)?;
                length = checked_len_add(length, descriptor_encoded_len(extent.content())?)?;
            }
            Ok(length)
        }
    }
}

fn descriptor_encoded_len(descriptor: &ObjectDescriptor) -> Result<usize, IndexError> {
    checked_len_add(44, descriptor.media_type().as_str().len())
}

fn add_bytes_len(length: &mut usize, bytes: &[u8]) -> Result<(), IndexError> {
    u32::try_from(bytes.len()).map_err(|_| IndexError::LimitExceeded)?;
    *length = checked_len_add(*length, 4)?;
    *length = checked_len_add(*length, bytes.len())?;
    Ok(())
}

fn checked_len_add(left: usize, right: usize) -> Result<usize, IndexError> {
    left.checked_add(right).ok_or(IndexError::LimitExceeded)
}

/// Summarizes an index completed by successful whole-graph compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexSummary {
    /// Compiler ABI identity.
    pub compiler_abi: [u8; 32],
    /// Source tree digest.
    pub tree_digest: ObjectDigest,
    /// Source tree encoded size.
    pub tree_size: u64,
    /// Root-directory digest.
    pub root_digest: ObjectDigest,
    /// Root-directory encoded size.
    pub root_size: u64,
    /// Number of expanded node records.
    pub records: u64,
    /// Exact index bytes.
    pub bytes: u64,
}

/// Binds validated structure and cross-links to exact immutable index bytes.
///
/// The value deliberately does not implement [`Copy`] or [`Clone`]. Consumers
/// that need validation authority retain this wrapper rather than replaying a
/// detached [`IndexSummary`] against different bytes.
///
/// ```compile_fail
/// use aos_filesystem_view::ValidatedIndex;
///
/// fn duplicate(index: ValidatedIndex<'_>) {
///     let _copy = index.clone();
/// }
/// ```
pub struct ValidatedIndex<'a> {
    bytes: &'a [u8],
    descriptor: ObjectDescriptor,
    summary: IndexSummary,
    crosslinks: IndexCrosslinks,
}

impl ValidatedIndex<'_> {
    /// Returns the exact immutable bytes covered by validation.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the authenticated descriptor covering [`Self::bytes`].
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Returns the structural summary for diagnostics and resource reporting.
    ///
    /// This detached summary is not validation authority. Authority remains
    /// attached to this wrapper and [`Self::bytes`].
    #[must_use]
    pub const fn summary(&self) -> &IndexSummary {
        &self.summary
    }

    /// Returns the authenticated source and hard-link cross-link summary.
    #[must_use]
    pub const fn crosslinks(&self) -> &IndexCrosslinks {
        &self.crosslinks
    }
}

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
}

struct ParsedRecord {
    parent: u64,
    depth: u32,
    sibling_ordinal: u32,
    name: Vec<u8>,
    directory: Option<ObjectDescriptor>,
    metadata: FilesystemMetadata,
    content: Option<ContentLayout>,
    hardlink_group: Option<ObjectDigest>,
    symlink_target: Option<Vec<u8>>,
}

struct IndexNodeRecord {
    parent: u64,
    depth: u32,
    directory: bool,
    name: Vec<u8>,
}

struct IndexHardlinkMember {
    node: u64,
    metadata: FilesystemMetadata,
    content: ContentLayout,
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
    if bytes.len() < HEADER_BYTES || bytes.len() as u64 > maximum_bytes {
        return Err(IndexError::LimitExceeded);
    }
    let validation_reservation = (bytes.len() as u64)
        .checked_mul(64)
        .and_then(|value| value.checked_add(4_096))
        .ok_or(IndexError::LimitExceeded)?;
    if validation_reservation > maximum_working_bytes {
        return Err(IndexError::LimitExceeded);
    }
    let index_media = MediaType::new(INDEX_MEDIA_TYPE).map_err(|_| IndexError::InvalidHeader)?;
    if expected.index.media_type() != &index_media
        || descriptor_for_bytes(index_media, bytes) != *expected.index
    {
        return Err(IndexError::DescriptorMismatch);
    }
    if expected.tree_features & !KNOWN_FEATURES != 0 {
        return Err(IndexError::InvalidHeader);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != MAGIC
        || cursor.u32()? != VERSION
        || cursor.u32()? as usize != HEADER_BYTES
    {
        return Err(IndexError::InvalidHeader);
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
    let mut records_cursor = Cursor::new(payload);
    let record_capacity = usize::try_from(records).map_err(|_| IndexError::LimitExceeded)?;
    if record_capacity > payload.len() / RECORD_FIXED_BYTES {
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
            directory,
            name: record.name,
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
    })
}

fn encode_record(output: &mut Vec<u8>, record: &IndexRecord<'_>) -> Result<(), IndexError> {
    put_u32(output, 0);
    put_u64(output, record.parent);
    put_u32(output, record.depth);
    put_u32(output, record.sibling_ordinal);
    let kind = match record.node {
        IndexNode::File { .. } => 0,
        IndexNode::Directory { .. } => 1,
        IndexNode::Symlink { .. } => 2,
    };
    output.push(kind);
    output.extend_from_slice(&[0; 3]);
    put_u16(output, record.metadata.mode());
    put_u16(output, 0);
    put_u32(output, record.metadata.uid());
    put_u32(output, record.metadata.gid());
    put_i64(output, record.metadata.mtime_seconds());
    put_u32(output, record.metadata.mtime_nanos());
    put_bytes(output, record.name)?;
    put_u32_len(output, record.metadata.xattrs().len())?;
    for xattr in record.metadata.xattrs() {
        put_bytes(output, xattr.name())?;
        put_bytes(output, xattr.value())?;
    }
    match record.metadata.acl() {
        None => put_u32(output, u32::MAX),
        Some(acl) => {
            put_u32_len(output, acl.entries().len())?;
            for entry in acl.entries() {
                encode_acl(output, *entry);
            }
        }
    }
    match record.node {
        IndexNode::File {
            content,
            hardlink_group,
        } => {
            encode_content(output, content)?;
            match hardlink_group {
                None => output.push(0),
                Some(digest) => {
                    output.push(1);
                    output.extend_from_slice(digest.as_bytes());
                }
            }
        }
        IndexNode::Directory { descriptor } => encode_descriptor(output, descriptor)?,
        IndexNode::Symlink { target } => put_bytes(output, target)?,
    }
    let length = u32::try_from(output.len()).map_err(|_| IndexError::LimitExceeded)?;
    output[0..4].copy_from_slice(&length.to_le_bytes());
    Ok(())
}

fn validate_record(cursor: &mut Cursor<'_>, expected_id: u64) -> Result<ParsedRecord, IndexError> {
    let length = cursor.u32()? as usize;
    if length < RECORD_FIXED_BYTES || length - 4 > cursor.remaining() {
        return Err(IndexError::InvalidRecord);
    }
    let record = cursor.take(length - 4)?;
    let mut value = Cursor::new(record);
    let parent = value.u64()?;
    let depth = value.u32()?;
    let sibling_ordinal = value.u32()?;
    let kind = value.byte()?;
    let reserved = value.take(3)?;
    let mode = value.u16()?;
    if reserved != [0; 3] || mode > 0o7777 || value.u16()? != 0 {
        return Err(IndexError::InvalidRecord);
    }
    let uid = value.u32()?;
    let gid = value.u32()?;
    let mtime_seconds = value.i64()?;
    let mtime_nanos = value.u32()?;
    if mtime_nanos >= 1_000_000_000 {
        return Err(IndexError::InvalidRecord);
    }
    let name = value.length_bytes()?;
    if (expected_id == 0 && (parent != u64::MAX || depth != 0 || !name.is_empty()))
        || (expected_id != 0 && (parent >= expected_id || depth == 0 || name.is_empty()))
    {
        return Err(IndexError::InvalidRecord);
    }
    if expected_id != 0 && PathName::new(name.to_vec()).is_err() {
        return Err(IndexError::InvalidRecord);
    }
    let xattrs = value.u32()?;
    let xattr_count =
        preflight_collection(xattrs, value.remaining(), 9, std::mem::size_of::<Xattr>())?;
    let mut parsed_xattrs = Vec::new();
    parsed_xattrs
        .try_reserve_exact(xattr_count)
        .map_err(|_| IndexError::AllocationRefused)?;
    let mut previous_xattr: Option<&[u8]> = None;
    for _ in 0..xattrs {
        let name = value.length_bytes()?;
        let xattr_value = value.length_bytes()?;
        if name.is_empty()
            || name.len() > 255
            || name.contains(&0)
            || xattr_value.len() > 1_048_576
            || previous_xattr.is_some_and(|previous| previous >= name)
        {
            return Err(IndexError::InvalidRecord);
        }
        parsed_xattrs.push(
            Xattr::new(name.to_vec(), xattr_value.to_vec())
                .map_err(|_| IndexError::InvalidRecord)?,
        );
        previous_xattr = Some(name);
    }
    let acl = value.u32()?;
    let mut parsed_acl = None;
    if acl != u32::MAX {
        let acl_count =
            preflight_collection(acl, value.remaining(), 6, std::mem::size_of::<AclEntry>())?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(acl_count)
            .map_err(|_| IndexError::AllocationRefused)?;
        let mut previous = None;
        let mut user = None;
        let mut group = None;
        let mut mask = None;
        let mut other = None;
        let mut named = false;
        for _ in 0..acl {
            let tag = value.byte()?;
            let qualifier = value.u32()?;
            let permissions = value.byte()?;
            if tag > 5 || permissions > 7 {
                return Err(IndexError::InvalidRecord);
            }
            let identity = (tag, qualifier);
            if previous.is_some_and(|prior| prior >= identity)
                || (matches!(tag, 0 | 2 | 4 | 5) && qualifier != u32::MAX)
                || (matches!(tag, 1 | 3) && qualifier == u32::MAX)
            {
                return Err(IndexError::InvalidRecord);
            }
            match tag {
                0 => {
                    user = Some(permissions);
                    entries.push(AclEntry::UserObject(permissions));
                }
                1 => {
                    named = true;
                    entries.push(AclEntry::NamedUser {
                        uid: qualifier,
                        permissions,
                    });
                }
                2 => {
                    group = Some(permissions);
                    entries.push(AclEntry::GroupObject(permissions));
                }
                3 => {
                    named = true;
                    entries.push(AclEntry::NamedGroup {
                        gid: qualifier,
                        permissions,
                    });
                }
                4 => {
                    mask = Some(permissions);
                    entries.push(AclEntry::Mask(permissions));
                }
                5 => {
                    other = Some(permissions);
                    entries.push(AclEntry::Other(permissions));
                }
                _ => return Err(IndexError::InvalidRecord),
            }
            previous = Some(identity);
        }
        if user != Some(((mode >> 6) & 7) as u8)
            || other != Some((mode & 7) as u8)
            || group.is_none()
            || (named && mask.is_none())
            || mask.or(group) != Some(((mode >> 3) & 7) as u8)
        {
            return Err(IndexError::InvalidRecord);
        }
        parsed_acl = Some(Acl::new(entries).map_err(|_| IndexError::InvalidRecord)?);
    }
    let metadata = FilesystemMetadata::new(
        mode,
        uid,
        gid,
        mtime_seconds,
        mtime_nanos,
        parsed_xattrs,
        parsed_acl,
    )
    .map_err(|_| IndexError::InvalidRecord)?;
    let mut content = None;
    let mut hardlink_group = None;
    let mut symlink_target = None;
    let descriptor = match kind {
        0 => {
            content = Some(validate_content(&mut value)?);
            hardlink_group = match value.byte()? {
                0 => None,
                1 => Some(ObjectDigest::from_bytes(value.array::<32>()?)),
                _ => return Err(IndexError::InvalidRecord),
            };
            None
        }
        1 => Some(validate_descriptor(
            &mut value,
            DescriptorRole::DirectoryChild,
        )?),
        2 => {
            let target = value.length_bytes()?;
            if target.len() > 4_096 || target.contains(&0) {
                return Err(IndexError::InvalidRecord);
            }
            symlink_target = Some(target.to_vec());
            None
        }
        _ => return Err(IndexError::InvalidRecord),
    };
    if value.remaining() != 0 {
        return Err(IndexError::InvalidRecord);
    }
    Ok(ParsedRecord {
        parent,
        depth,
        sibling_ordinal,
        name: name.to_vec(),
        directory: descriptor,
        metadata,
        content,
        hardlink_group,
        symlink_target,
    })
}

fn encode_content(output: &mut Vec<u8>, content: &ContentLayout) -> Result<(), IndexError> {
    match content {
        ContentLayout::Whole { content } => {
            output.push(0);
            encode_descriptor(output, content)?;
        }
        ContentLayout::Sparse(sparse) => {
            output.push(1);
            put_u64(output, sparse.logical_size());
            put_u32_len(output, sparse.extents().len())?;
            for extent in sparse.extents() {
                put_u64(output, extent.offset());
                put_u64(output, extent.length());
                encode_descriptor(output, extent.content())?;
            }
        }
    }
    Ok(())
}

fn validate_content(cursor: &mut Cursor<'_>) -> Result<ContentLayout, IndexError> {
    match cursor.byte()? {
        0 => validate_descriptor(cursor, DescriptorRole::FileContent).map(ContentLayout::whole),
        1 => {
            let logical_size = cursor.u64()?;
            let count = cursor.u32()?;
            let extent_count =
                preflight_collection(count, cursor.remaining(), 61, std::mem::size_of::<Extent>())?;
            let mut prior_end = None;
            let mut first_offset = None;
            let mut extents = Vec::new();
            extents
                .try_reserve_exact(extent_count)
                .map_err(|_| IndexError::AllocationRefused)?;
            for _ in 0..count {
                let offset = cursor.u64()?;
                let length = cursor.u64()?;
                let descriptor = validate_descriptor(cursor, DescriptorRole::FileContent)?;
                let end = offset
                    .checked_add(length)
                    .ok_or(IndexError::InvalidRecord)?;
                if length == 0
                    || end > logical_size
                    || prior_end.is_some_and(|prior| prior >= offset)
                    || descriptor.encoded_size() != length
                {
                    return Err(IndexError::InvalidRecord);
                }
                first_offset.get_or_insert(offset);
                prior_end = Some(end);
                extents.push(
                    Extent::new(offset, length, descriptor)
                        .map_err(|_| IndexError::InvalidRecord)?,
                );
            }
            if logical_size > 0
                && count == 1
                && first_offset == Some(0)
                && prior_end == Some(logical_size)
            {
                return Err(IndexError::InvalidRecord);
            }
            let sparse =
                SparseContent::new(logical_size, extents).map_err(|_| IndexError::InvalidRecord)?;
            Ok(ContentLayout::Sparse(sparse))
        }
        _ => Err(IndexError::InvalidRecord),
    }
}

fn preflight_collection(
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

fn symlink_escapes_parent(target: &[u8], mut depth: usize) -> bool {
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

fn validate_siblings(
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

fn validate_index_hardlinks(
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

fn hardlink_path_reservation(
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

fn compare_node_paths(left: u64, right: u64, nodes: &[IndexNodeRecord]) -> std::cmp::Ordering {
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

fn reconstruct_path(node: u64, nodes: &[IndexNodeRecord]) -> Result<RelativePath, IndexError> {
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

fn encode_descriptor(output: &mut Vec<u8>, value: &ObjectDescriptor) -> Result<(), IndexError> {
    put_bytes(output, value.media_type().as_str().as_bytes())?;
    output.extend_from_slice(value.digest().as_bytes());
    put_u64(output, value.encoded_size());
    Ok(())
}

fn validate_descriptor(
    cursor: &mut Cursor<'_>,
    role: DescriptorRole,
) -> Result<ObjectDescriptor, IndexError> {
    let media_type = cursor.length_bytes()?;
    let media_type = std::str::from_utf8(media_type).map_err(|_| IndexError::InvalidRecord)?;
    let media_type =
        MediaType::new(media_type.to_owned()).map_err(|_| IndexError::InvalidRecord)?;
    let digest = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let size = cursor.u64()?;
    let descriptor = ObjectDescriptor::new(media_type, digest, size);
    validate_descriptor_role(role, &descriptor).map_err(|_| IndexError::InvalidRecord)?;
    Ok(descriptor)
}

fn encode_acl(output: &mut Vec<u8>, entry: AclEntry) {
    let (tag, qualifier, permissions) = match entry {
        AclEntry::UserObject(value) => (0, u32::MAX, value),
        AclEntry::NamedUser { uid, permissions } => (1, uid, permissions),
        AclEntry::GroupObject(value) => (2, u32::MAX, value),
        AclEntry::NamedGroup { gid, permissions } => (3, gid, permissions),
        AclEntry::Mask(value) => (4, u32::MAX, value),
        AclEntry::Other(value) => (5, u32::MAX, value),
    };
    output.push(tag);
    put_u32(output, qualifier);
    output.push(permissions);
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IndexError> {
    put_u32_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_u32_len(output: &mut Vec<u8>, length: usize) -> Result<(), IndexError> {
    put_u32(
        output,
        u32::try_from(length).map_err(|_| IndexError::LimitExceeded)?,
    );
    Ok(())
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}
fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}
fn put_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_le_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], IndexError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(IndexError::InvalidRecord)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(IndexError::InvalidRecord)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexError> {
        self.take(N)?
            .try_into()
            .map_err(|_| IndexError::InvalidRecord)
    }
    fn byte(&mut self) -> Result<u8, IndexError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, IndexError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, IndexError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn i64(&mut self) -> Result<i64, IndexError> {
        Ok(i64::from_le_bytes(self.array()?))
    }
    fn length_bytes(&mut self) -> Result<&'a [u8], IndexError> {
        let length = self.u32()? as usize;
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
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
        let mut builder =
            StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
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
        assert_eq!(summary.bytes, 333);
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
        assert_eq!(
            descriptor_for_bytes(media, &bytes).digest().as_bytes(),
            &[
                157, 145, 103, 153, 247, 240, 82, 185, 151, 121, 216, 129, 29, 146, 175, 2, 71,
                156, 251, 40, 219, 210, 163, 199, 76, 130, 171, 169, 23, 104, 214, 50,
            ]
        );
    }

    fn validate_fresh<'a>(
        bytes: &'a [u8],
        tree: &ObjectDescriptor,
        root: &ObjectDescriptor,
    ) -> Result<ValidatedIndex<'a>, IndexError> {
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
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

    fn resign_payload(bytes: &mut [u8]) {
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES..]).into();
        bytes[152..HEADER_BYTES].copy_from_slice(&digest);
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
            (HEADER_BYTES + 52, u32::MAX),
            (HEADER_BYTES + 56, u32::MAX - 1),
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
        let mut builder =
            StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
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
            bytes[HEADER_BYTES..HEADER_BYTES + 4]
                .try_into()
                .unwrap_or_else(|_| panic!("root record length missing")),
        ) as usize;
        let file_record = HEADER_BYTES + root_record_bytes;
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
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
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

        bytes[HEADER_BYTES + 17] ^= 1;
        let internal: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES..]).into();
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
        let mut builder =
            StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
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
        bytes[HEADER_BYTES + 17] = 1;
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES..]).into();
        bytes[152..184].copy_from_slice(&digest);
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
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
        let mut builder =
            StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
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
                152, 254, 2, 165, 195, 187, 123, 177, 171, 161, 46, 128, 53, 90, 7, 113, 184, 115,
                90, 174, 75, 222, 106, 108, 132, 98, 111, 3, 150, 242, 103, 91,
            ]
        );
        let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096);
        let mut builder =
            StructuralIndexBuilder::new(staging, [3; 32], tree.clone(), root.clone(), 0)
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
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
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
    }
}
