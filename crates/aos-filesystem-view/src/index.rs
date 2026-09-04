//! Architecture-neutral structural-index staging and validation.
//!
//! Formats v1 and v2 are little-endian derived caches. V2 leaves the v1
//! record encoding unchanged and appends a fixed-width point-lookup table:
//!
//! ```text
//! header = magic[8], version:u32, header-bytes:u32, compiler-abi[32],
//!          tree-digest[32], tree-size:u64, root-digest[32], root-size:u64,
//!          tree-features:u32, reserved:u32, record-count:u64,
//!          payload-bytes:u64, payload-sha256[32]
//! v1-payload = record*
//! v2-header-tail = records-bytes:u64, lookup-slots:u64, lookup-slot-bytes:u32,
//!                  lookup-hash:u32, reserved:u64
//! v2-payload = record*, lookup-entry*
//! lookup-entry = parent:u64, name-sha256[32], record-offset:u64, record-id:u64
//! record = record-bytes:u32, parent:u64, depth:u32, sibling-ordinal:u32,
//!          kind:u8, reserved[3],
//!          mode:u16, reserved:u16, uid:u32, gid:u32, mtime-sec:i64,
//!          mtime-nsec:u32, body...
//! ```
//!
//! Lookup entries are sorted canonically by parent, full domain-separated name
//! digest, and record ID. All variable fields are length-prefixed and the
//! validator rejects unknown tags, nonzero reserved bytes, non-canonical
//! tables, overflow, truncation, and trailing data.

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
const VERSION_V1: u32 = 1;
const VERSION_V2: u32 = 2;
const HEADER_BYTES_V1: usize = 184;
const HEADER_BYTES_V2: usize = 216;
const RECORD_FIXED_BYTES: usize = 48;
const LOOKUP_SLOT_BYTES: usize = 56;
const LOOKUP_HASH_SHA256: u32 = 1;

/// Media type emitted for new node-local structural indexes.
pub const INDEX_MEDIA_TYPE: &str = INDEX_MEDIA_TYPE_V2;
/// Media type of the validation-only sequential structural-index format.
pub const INDEX_MEDIA_TYPE_V1: &str = "application/vnd.aos.filesystem-view.index.v1";
/// Media type of the point-lookup structural-index format.
pub const INDEX_MEDIA_TYPE_V2: &str = "application/vnd.aos.filesystem-view.index.v2";

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
    maximum_working_bytes: u64,
}

impl<W> IndexStaging<W> {
    /// Creates an unused staging capability.
    #[must_use]
    pub const fn new(writer: W, maximum_bytes: u64, maximum_record_bytes: u64) -> Self {
        Self {
            writer,
            maximum_bytes,
            maximum_record_bytes,
            maximum_working_bytes: maximum_bytes,
        }
    }

    pub(crate) fn narrow(
        mut self,
        maximum_bytes: u64,
        maximum_record_bytes: u64,
        maximum_working_bytes: u64,
    ) -> Self {
        self.maximum_bytes = self.maximum_bytes.min(maximum_bytes);
        self.maximum_record_bytes = self.maximum_record_bytes.min(maximum_record_bytes);
        self.maximum_working_bytes = self.maximum_working_bytes.min(maximum_working_bytes);
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
    maximum_working_bytes: u64,
    records: u64,
    payload_bytes: u64,
    payload_hash: Sha256,
    lookup_entries: Vec<LookupSlot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LookupSlot {
    parent: u64,
    name_hash: [u8; 32],
    record_offset: u64,
    record_id: u64,
}

impl<W: Write + Seek> StructuralIndexBuilder<W> {
    pub(crate) fn retained_working_bytes(&self) -> Result<u64, IndexError> {
        lookup_vector_charge(self.lookup_entries.len())
    }

    pub(crate) fn retained_working_bytes_after_push(&self) -> Result<u64, IndexError> {
        if self.records == 0 {
            return self.retained_working_bytes();
        }
        let entries = self
            .lookup_entries
            .len()
            .checked_add(1)
            .ok_or(IndexError::LimitExceeded)?;
        lookup_vector_charge(entries)
    }

    pub(crate) fn finish_working_bytes(&self) -> Result<u64, IndexError> {
        let slots = lookup_slot_count(self.records)?;
        self.retained_working_bytes()?
            .checked_add(lookup_vector_charge(slots)?)
            .ok_or(IndexError::LimitExceeded)
    }

    pub(crate) fn finish_temporary_working_bytes(&self) -> Result<u64, IndexError> {
        lookup_vector_charge(lookup_slot_count(self.records)?)
    }

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
            maximum_working_bytes,
        } = staging;
        if maximum_bytes < HEADER_BYTES_V2 as u64 || maximum_record_bytes == 0 {
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
            .write_all(&[0; HEADER_BYTES_V2])
            .map_err(IndexError::Io)?;
        Ok(Self {
            writer,
            compiler_abi,
            tree,
            root,
            tree_features,
            maximum_bytes,
            maximum_record_bytes,
            maximum_working_bytes,
            records: 0,
            payload_bytes: 0,
            payload_hash: Sha256::new(),
            lookup_entries: Vec::new(),
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
        let total = (HEADER_BYTES_V2 as u64)
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
        if id != 0 {
            let next_entries = self
                .lookup_entries
                .len()
                .checked_add(1)
                .ok_or(IndexError::LimitExceeded)?;
            let retained_bytes = lookup_vector_charge(next_entries)?;
            if retained_bytes > self.maximum_working_bytes {
                return Err(IndexError::LimitExceeded);
            }
            self.lookup_entries
                .try_reserve_exact(1)
                .map_err(|_| IndexError::AllocationRefused)?;
        }
        let record_offset = (HEADER_BYTES_V2 as u64)
            .checked_add(self.payload_bytes)
            .ok_or(IndexError::LimitExceeded)?;
        self.writer.write_all(&bytes).map_err(IndexError::Io)?;
        self.payload_hash.update(&bytes);
        self.payload_bytes = next_payload;
        self.records = self
            .records
            .checked_add(1)
            .ok_or(IndexError::LimitExceeded)?;
        if id != 0 {
            self.lookup_entries.push(LookupSlot {
                parent: record.parent,
                name_hash: lookup_hash(record.parent, record.name),
                record_offset,
                record_id: id,
            });
        }
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
        let records_bytes = self.payload_bytes;
        let lookup_slots = lookup_slot_count(self.records)?;
        let lookup_bytes = lookup_allocation_bytes(lookup_slots)?;
        let peak_lookup_working = self.finish_working_bytes()?;
        if peak_lookup_working > self.maximum_working_bytes {
            return Err(IndexError::LimitExceeded);
        }
        let next_payload = records_bytes
            .checked_add(lookup_bytes)
            .ok_or(IndexError::LimitExceeded)?;
        let total_bytes = (HEADER_BYTES_V2 as u64)
            .checked_add(next_payload)
            .ok_or(IndexError::LimitExceeded)?;
        if total_bytes > self.maximum_bytes {
            return Err(IndexError::LimitExceeded);
        }

        let mut table = Vec::new();
        table
            .try_reserve_exact(lookup_slots)
            .map_err(|_| IndexError::AllocationRefused)?;
        table.extend_from_slice(&self.lookup_entries);
        table.sort_unstable_by_key(|entry| (entry.parent, entry.name_hash, entry.record_id));
        for slot in table {
            let encoded = encode_lookup_slot(slot);
            self.writer.write_all(&encoded).map_err(IndexError::Io)?;
            self.payload_hash.update(encoded);
        }
        self.payload_bytes = next_payload;

        let payload_digest: [u8; 32] = self.payload_hash.finalize().into();
        let mut header = Vec::with_capacity(HEADER_BYTES_V2);
        header.extend_from_slice(MAGIC);
        put_u32(&mut header, VERSION_V2);
        put_u32(&mut header, HEADER_BYTES_V2 as u32);
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
        put_u64(&mut header, records_bytes);
        put_u64(&mut header, lookup_slots as u64);
        put_u32(&mut header, LOOKUP_SLOT_BYTES as u32);
        put_u32(&mut header, LOOKUP_HASH_SHA256);
        put_u64(&mut header, 0);
        if header.len() != HEADER_BYTES_V2 {
            return Err(IndexError::InvalidHeader);
        }
        self.writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.writer.write_all(&header))
            .and_then(|_| self.writer.flush())
            .map_err(IndexError::Io)?;
        let expected_end = HEADER_BYTES_V2 as u64 + self.payload_bytes;
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
                bytes: HEADER_BYTES_V2 as u64 + self.payload_bytes,
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

fn lookup_slot_count(records: u64) -> Result<usize, IndexError> {
    let children = records.checked_sub(1).ok_or(IndexError::InvalidRecord)?;
    usize::try_from(children).map_err(|_| IndexError::LimitExceeded)
}

fn lookup_allocation_bytes(slots: usize) -> Result<u64, IndexError> {
    let bytes = slots
        .checked_mul(LOOKUP_SLOT_BYTES)
        .ok_or(IndexError::LimitExceeded)?;
    u64::try_from(bytes).map_err(|_| IndexError::LimitExceeded)
}

fn lookup_vector_charge(slots: usize) -> Result<u64, IndexError> {
    let payload = slots
        .checked_mul(std::mem::size_of::<LookupSlot>())
        .ok_or(IndexError::LimitExceeded)?;
    payload
        .checked_add(std::mem::size_of::<Vec<LookupSlot>>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(IndexError::LimitExceeded)
}

fn lookup_hash(parent: u64, name: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AOS filesystem-view lookup v2\0");
    digest.update(parent.to_le_bytes());
    digest.update((name.len() as u64).to_le_bytes());
    digest.update(name);
    digest.finalize().into()
}

fn encode_lookup_slot(slot: LookupSlot) -> [u8; LOOKUP_SLOT_BYTES] {
    let mut bytes = [0_u8; LOOKUP_SLOT_BYTES];
    bytes[0..8].copy_from_slice(&slot.parent.to_le_bytes());
    bytes[8..40].copy_from_slice(&slot.name_hash);
    bytes[40..48].copy_from_slice(&slot.record_offset.to_le_bytes());
    bytes[48..56].copy_from_slice(&slot.record_id.to_le_bytes());
    bytes
}

fn read_lookup_slot(bytes: &[u8], table_offset: u64, slot: u64) -> Result<LookupSlot, IndexError> {
    let offset = slot
        .checked_mul(LOOKUP_SLOT_BYTES as u64)
        .and_then(|value| table_offset.checked_add(value))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(IndexError::InvalidRecord)?;
    let end = offset
        .checked_add(LOOKUP_SLOT_BYTES)
        .ok_or(IndexError::InvalidRecord)?;
    let encoded = bytes.get(offset..end).ok_or(IndexError::InvalidRecord)?;
    let mut cursor = Cursor::new(encoded);
    Ok(LookupSlot {
        parent: cursor.u64()?,
        name_hash: cursor.array::<32>()?,
        record_offset: cursor.u64()?,
        record_id: cursor.u64()?,
    })
}

fn decode_record_view<'a>(
    bytes: &'a [u8],
    offset: usize,
    id: u64,
    artifact: ObjectDigest,
) -> Result<IndexNodeView<'a>, IndexError> {
    let encoded = bytes.get(offset..).ok_or(IndexError::InvalidRecord)?;
    let mut cursor = Cursor::new(encoded);
    let length = cursor.u32()? as usize;
    if length < RECORD_FIXED_BYTES || length - 4 > cursor.remaining() {
        return Err(IndexError::InvalidRecord);
    }
    let encoded_record = encoded.get(..length).ok_or(IndexError::InvalidRecord)?;
    let mut record = Cursor::new(cursor.take(length - 4)?);
    let parent = record.u64()?;
    let depth = record.u32()?;
    let sibling_ordinal = record.u32()?;
    let kind = match record.byte()? {
        0 => IndexNodeKind::File,
        1 => IndexNodeKind::Directory,
        2 => IndexNodeKind::Symlink,
        _ => return Err(IndexError::InvalidRecord),
    };
    if record.take(3)? != [0; 3] {
        return Err(IndexError::InvalidRecord);
    }
    let mode = record.u16()?;
    if mode > 0o7777 || record.u16()? != 0 {
        return Err(IndexError::InvalidRecord);
    }
    let uid = record.u32()?;
    let gid = record.u32()?;
    let mtime_seconds = record.i64()?;
    let mtime_nanos = record.u32()?;
    let name = record.length_bytes()?;
    if mtime_nanos >= 1_000_000_000
        || (id == 0 && (parent != u64::MAX || depth != 0 || !name.is_empty()))
        || (id != 0
            && (parent >= id
                || depth == 0
                || name.is_empty()
                || name.len() > 255
                || name.contains(&0)
                || name.contains(&b'/')
                || name == b"."
                || name == b".."))
    {
        return Err(IndexError::InvalidRecord);
    }
    Ok(IndexNodeView {
        artifact,
        id,
        parent,
        depth,
        sibling_ordinal,
        kind,
        mode,
        uid,
        gid,
        mtime_seconds,
        mtime_nanos,
        name,
        encoded_record,
    })
}

fn record_hardlink_group(
    encoded: &[u8],
    kind: IndexNodeKind,
) -> Result<Option<ObjectDigest>, IndexError> {
    if kind != IndexNodeKind::File {
        return Ok(None);
    }
    let mut record = Cursor::new(encoded);
    let length = record.u32()? as usize;
    if length != encoded.len() {
        return Err(IndexError::InvalidRecord);
    }
    record.take(RECORD_FIXED_BYTES - 4)?;
    record.length_bytes()?;
    let xattrs = record.u32()?;
    for _ in 0..xattrs {
        record.length_bytes()?;
        record.length_bytes()?;
    }
    let acl = record.u32()?;
    if acl != u32::MAX {
        let acl_bytes = usize::try_from(acl)
            .ok()
            .and_then(|count| count.checked_mul(6))
            .ok_or(IndexError::InvalidRecord)?;
        record.take(acl_bytes)?;
    }
    match record.byte()? {
        0 => skip_descriptor(&mut record)?,
        1 => {
            record.u64()?;
            let extents = record.u32()?;
            for _ in 0..extents {
                record.u64()?;
                record.u64()?;
                skip_descriptor(&mut record)?;
            }
        }
        _ => return Err(IndexError::InvalidRecord),
    }
    match record.byte()? {
        0 => Ok(None),
        1 => Ok(Some(ObjectDigest::from_bytes(record.array::<32>()?))),
        _ => Err(IndexError::InvalidRecord),
    }
}

fn skip_descriptor(cursor: &mut Cursor<'_>) -> Result<(), IndexError> {
    cursor.length_bytes()?;
    cursor.take(32)?;
    cursor.u64()?;
    Ok(())
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
    layout: IndexLayout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexLayout {
    SequentialV1,
    PointLookupV2 {
        records_bytes: u64,
        lookup_slots: u64,
    },
}

impl<'bytes> ValidatedIndex<'bytes> {
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

    /// Decodes the root record without retaining a per-node heap object.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::InvalidRecord`] if the validated byte slice was
    /// replaced internally, which safe callers cannot do.
    pub fn root(&self) -> Result<IndexNodeView<'_>, IndexError> {
        self.retained_root()
    }

    /// Decodes a root whose byte lifetime is retained by an internal owner.
    pub(crate) fn retained_root(&self) -> Result<IndexNodeView<'bytes>, IndexError> {
        let offset = match self.layout {
            IndexLayout::SequentialV1 => HEADER_BYTES_V1,
            IndexLayout::PointLookupV2 { .. } => HEADER_BYTES_V2,
        };
        decode_record_view(self.bytes, offset, 0, self.descriptor.digest())
    }

    /// Finds one byte-exact child by parent and portable path component.
    ///
    /// The lookup performs binary search over the authenticated fixed-width
    /// table and then compares the candidate record's component bytes. It
    /// allocates no memory and decodes only candidate records. Node handles
    /// are scoped to the exact validated artifact that produced them.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::PointLookupUnavailable`] for a V1 artifact,
    /// [`IndexError::ForeignNode`] for a parent from another artifact, or
    /// [`IndexError::InvalidRecord`] if an internal validated offset is invalid.
    pub fn lookup_child<'index>(
        &'index self,
        parent: &IndexNodeView<'_>,
        name: &PathName,
    ) -> Result<Option<IndexNodeView<'index>>, IndexError> {
        self.retained_lookup_child(parent, name)
    }

    /// Looks up a child whose byte lifetime is retained by an internal owner.
    pub(crate) fn retained_lookup_child(
        &self,
        parent: &IndexNodeView<'_>,
        name: &PathName,
    ) -> Result<Option<IndexNodeView<'bytes>>, IndexError> {
        let IndexLayout::PointLookupV2 {
            records_bytes,
            lookup_slots,
        } = self.layout
        else {
            return Err(IndexError::PointLookupUnavailable);
        };
        if parent.artifact != self.descriptor.digest() || parent.kind != IndexNodeKind::Directory {
            return Err(IndexError::ForeignNode);
        }

        let target_hash = lookup_hash(parent.id, name.as_bytes());
        let table_offset = (HEADER_BYTES_V2 as u64)
            .checked_add(records_bytes)
            .ok_or(IndexError::InvalidRecord)?;
        let mut left = 0_u64;
        let mut right = lookup_slots;
        while left < right {
            let middle = left + (right - left) / 2;
            let slot = read_lookup_slot(self.bytes, table_offset, middle)?;
            if (slot.parent, slot.name_hash) < (parent.id, target_hash) {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        while left < lookup_slots {
            let slot = read_lookup_slot(self.bytes, table_offset, left)?;
            if (slot.parent, slot.name_hash) != (parent.id, target_hash) {
                break;
            }
            let offset =
                usize::try_from(slot.record_offset).map_err(|_| IndexError::InvalidRecord)?;
            let candidate =
                decode_record_view(self.bytes, offset, slot.record_id, self.descriptor.digest())?;
            if candidate.parent == parent.id && candidate.name == name.as_bytes() {
                return Ok(Some(candidate));
            }
            left += 1;
        }
        Ok(None)
    }

    /// Reports whether this artifact supports immutable point lookup.
    #[must_use]
    pub const fn supports_point_lookup(&self) -> bool {
        matches!(self.layout, IndexLayout::PointLookupV2 { .. })
    }
}

/// Identifies the portable node kind in a lazily decoded index record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexNodeKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

/// Borrows the fixed metadata and component name of one validated record.
///
/// The record ID is stable only within this exact derived artifact and compiler
/// ABI. It is not a portable inode number and must not be persisted across
/// recompilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexNodeView<'a> {
    artifact: ObjectDigest,
    id: u64,
    parent: u64,
    depth: u32,
    sibling_ordinal: u32,
    kind: IndexNodeKind,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime_seconds: i64,
    mtime_nanos: u32,
    name: &'a [u8],
    encoded_record: &'a [u8],
}

impl IndexNodeView<'_> {
    /// Returns the artifact-scoped record identifier.
    #[must_use]
    pub const fn record_id(&self) -> u64 {
        self.id
    }

    /// Returns the record's parent identifier, or `u64::MAX` for the root.
    #[must_use]
    pub const fn parent_record_id(&self) -> u64 {
        self.parent
    }

    /// Returns the expanded depth, with the root at zero.
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns the canonical ordinal within the source directory.
    #[must_use]
    pub const fn sibling_ordinal(&self) -> u32 {
        self.sibling_ordinal
    }

    /// Returns the portable node kind.
    #[must_use]
    pub const fn kind(&self) -> IndexNodeKind {
        self.kind
    }

    /// Returns the portable permission and executable bits.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }

    /// Returns the portable owner UID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the portable owner GID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the normalized modification-time seconds.
    #[must_use]
    pub const fn mtime_seconds(&self) -> i64 {
        self.mtime_seconds
    }

    /// Returns the normalized modification-time nanoseconds.
    #[must_use]
    pub const fn mtime_nanos(&self) -> u32 {
        self.mtime_nanos
    }

    /// Returns the byte-exact final path component, empty only for the root.
    #[must_use]
    pub const fn name(&self) -> &[u8] {
        self.name
    }

    /// Returns the portable hard-link group identity for a file, when present.
    ///
    /// This digest is source-model identity, not a portable or
    /// per-connection inode number.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::InvalidRecord`] if the validated byte slice was
    /// replaced internally, which safe callers cannot do.
    pub fn hardlink_group(&self) -> Result<Option<ObjectDigest>, IndexError> {
        record_hardlink_group(self.encoded_record, self.kind)
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
    /// Point lookup was requested from a validation-only V1 artifact.
    #[error("point lookup is unavailable for structural-index V1")]
    PointLookupUnavailable,
    /// A lookup parent came from another artifact or was not a directory.
    #[error("lookup parent does not belong to this index or is not a directory")]
    ForeignNode,
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
    record_offset: u64,
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
    let (records_bytes, lookup_slots, layout) = if version == VERSION_V2 {
        let records_bytes = cursor.u64()?;
        let lookup_slots = cursor.u64()?;
        if cursor.u32()? as usize != LOOKUP_SLOT_BYTES
            || cursor.u32()? != LOOKUP_HASH_SHA256
            || cursor.u64()? != 0
        {
            return Err(IndexError::InvalidHeader);
        }
        (
            records_bytes,
            lookup_slots,
            IndexLayout::PointLookupV2 {
                records_bytes,
                lookup_slots,
            },
        )
    } else {
        (payload_bytes, 0, IndexLayout::SequentialV1)
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
    let (records_payload, lookup_payload) = payload.split_at(records_len);
    if version == VERSION_V2 {
        let canonical_slots = lookup_slot_count(records)?;
        let table_bytes = lookup_allocation_bytes(canonical_slots)?;
        if lookup_slots != canonical_slots as u64
            || table_bytes != lookup_payload.len() as u64
            || records_bytes
                .checked_add(table_bytes)
                .ok_or(IndexError::LimitExceeded)?
                != payload_bytes
        {
            return Err(IndexError::InvalidHeader);
        }
    } else if !lookup_payload.is_empty() {
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
    if version == VERSION_V2 {
        validate_lookup_table(lookup_payload, &nodes)?;
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

fn validate_lookup_table(bytes: &[u8], nodes: &[IndexNodeRecord]) -> Result<(), IndexError> {
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

    const fn position(&self) -> usize {
        self.position
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
        let media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
        assert_eq!(
            descriptor_for_bytes(media, &bytes).digest().as_bytes(),
            &[
                8, 145, 194, 237, 13, 115, 216, 207, 52, 172, 55, 126, 39, 45, 244, 26, 247, 98, 8,
                7, 204, 223, 126, 153, 72, 150, 234, 51, 248, 250, 155, 123,
            ]
        );
    }

    #[test]
    fn v1_golden_vector_remains_valid_but_has_no_point_lookup() {
        let (bytes, tree, root) = root_index_v1();
        assert_eq!(bytes.len(), 333);
        let media = MediaType::new(INDEX_MEDIA_TYPE_V1)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
        assert_eq!(
            descriptor_for_bytes(media.clone(), &bytes)
                .digest()
                .as_bytes(),
            &[
                157, 145, 103, 153, 247, 240, 82, 185, 151, 121, 216, 129, 29, 146, 175, 2, 71,
                156, 251, 40, 219, 210, 163, 199, 76, 130, 171, 169, 23, 104, 214, 50,
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

    #[test]
    fn v2_point_lookup_is_byte_exact_lazy_and_allocation_free() {
        let (bytes, tree, root) = lookup_index();
        let media = MediaType::new(INDEX_MEDIA_TYPE_V2)
            .unwrap_or_else(|error| panic!("media failed: {error}"));
        assert_eq!(
            descriptor_for_bytes(media, &bytes).digest().as_bytes(),
            &[
                43, 195, 204, 224, 254, 52, 240, 117, 151, 113, 200, 69, 165, 159, 85, 211, 21,
                210, 243, 62, 195, 151, 144, 66, 130, 38, 172, 185, 62, 229, 192, 188,
            ]
        );
        let validated = validate_fresh(&bytes, &tree, &root)
            .unwrap_or_else(|error| panic!("validation failed: {error}"));
        let root_view = validated
            .root()
            .unwrap_or_else(|error| panic!("root failed: {error}"));
        assert_eq!(root_view.kind(), IndexNodeKind::Directory);
        assert_eq!(root_view.record_id(), 0);

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

        let non_utf8 =
            PathName::new(vec![0x80]).unwrap_or_else(|error| panic!("name failed: {error}"));
        let symlink = validated
            .lookup_child(&root_view, &non_utf8)
            .unwrap_or_else(|error| panic!("lookup failed: {error}"))
            .unwrap_or_else(|| panic!("symlink missing"));
        assert_eq!(symlink.kind(), IndexNodeKind::Symlink);
        assert_eq!(symlink.name(), &[0x80]);

        let missing = PathName::new(b"missing".to_vec())
            .unwrap_or_else(|error| panic!("name failed: {error}"));
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
        let staging = IndexStaging::new(IoCursor::new(Vec::new()), 4096, 4096).narrow(
            4096,
            4096,
            lookup_vector_charge(1).unwrap_or(u64::MAX) - 1,
        );
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
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES_V2..]).into();
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
        bytes[HEADER_BYTES_V2 + 17] = 1;
        let digest: [u8; 32] = Sha256::digest(&bytes[HEADER_BYTES_V2..]).into();
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
}
