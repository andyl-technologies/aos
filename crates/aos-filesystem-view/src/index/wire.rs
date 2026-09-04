//! Structural-index wire constants, codecs, and bounded byte readers.

use super::builder::*;
use super::validate::*;
use super::view::*;
use super::*;

pub(super) const MAGIC: &[u8; 8] = b"AOSVIDX\0";
pub(super) const VERSION_V1: u32 = 1;
pub(super) const VERSION_V2: u32 = 2;
pub(super) const VERSION_V3: u32 = 3;
pub(super) const HEADER_BYTES_V1: usize = 184;
pub(super) const HEADER_BYTES_V2: usize = 216;
pub(super) const HEADER_BYTES_V3: usize = 248;
pub(super) const RECORD_FIXED_BYTES: usize = 48;
pub(super) const LOOKUP_SLOT_BYTES: usize = 56;
pub(super) const LOOKUP_HASH_SHA256: u32 = 1;
pub(super) const DIRECTORY_SLOT_BYTES: usize = 32;

/// Media type emitted for new node-local structural indexes.
pub const INDEX_MEDIA_TYPE: &str = INDEX_MEDIA_TYPE_V3;
/// Media type of the validation-only sequential structural-index format.
pub const INDEX_MEDIA_TYPE_V1: &str = "application/vnd.aos.filesystem-view.index.v1";
/// Media type of the point-lookup structural-index format.
pub const INDEX_MEDIA_TYPE_V2: &str = "application/vnd.aos.filesystem-view.index.v2";
/// Media type of the iterable structural-index format.
pub const INDEX_MEDIA_TYPE_V3: &str = "application/vnd.aos.filesystem-view.index.v3";

pub(crate) const FEATURE_ACL: u32 = 1 << 0;
pub(crate) const FEATURE_ABSOLUTE_SYMLINK: u32 = 1 << 1;
pub(crate) const FEATURE_PARENT_SYMLINK: u32 = 1 << 2;
pub(super) const KNOWN_FEATURES: u32 =
    FEATURE_ACL | FEATURE_ABSOLUTE_SYMLINK | FEATURE_PARENT_SYMLINK;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LookupSlot {
    pub(super) parent: u64,
    pub(super) name_hash: [u8; 32],
    pub(super) record_offset: u64,
    pub(super) record_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectorySlot {
    pub(super) parent: u64,
    pub(super) record_offset: u64,
    pub(super) record_id: u64,
    pub(super) nlink: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectoryBuildSlot {
    pub(super) slot: DirectorySlot,
    pub(super) sibling_ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct HardlinkSlot {
    pub(super) group: ObjectDigest,
    pub(super) record_id: u64,
}

pub(super) struct HeaderEncoder {
    pub(super) bytes: [u8; HEADER_BYTES_V3],
    pub(super) position: usize,
}

impl HeaderEncoder {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; HEADER_BYTES_V3],
            position: 0,
        }
    }

    pub(super) fn put(&mut self, value: &[u8]) -> Result<(), IndexError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(IndexError::InvalidHeader)?;
        let destination = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(IndexError::InvalidHeader)?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    pub(super) fn u32(&mut self, value: u32) -> Result<(), IndexError> {
        self.put(&value.to_le_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), IndexError> {
        self.put(&value.to_le_bytes())
    }

    pub(super) fn finish(&self, expected: usize) -> Result<&[u8], IndexError> {
        if self.position != expected {
            return Err(IndexError::InvalidHeader);
        }
        self.bytes.get(..expected).ok_or(IndexError::InvalidHeader)
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

pub(super) fn content_encoded_len(content: &ContentLayout) -> Result<usize, IndexError> {
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

pub(super) fn descriptor_encoded_len(descriptor: &ObjectDescriptor) -> Result<usize, IndexError> {
    checked_len_add(44, descriptor.media_type().as_str().len())
}

pub(super) fn add_bytes_len(length: &mut usize, bytes: &[u8]) -> Result<(), IndexError> {
    u32::try_from(bytes.len()).map_err(|_| IndexError::LimitExceeded)?;
    *length = checked_len_add(*length, 4)?;
    *length = checked_len_add(*length, bytes.len())?;
    Ok(())
}

pub(super) fn checked_len_add(left: usize, right: usize) -> Result<usize, IndexError> {
    left.checked_add(right).ok_or(IndexError::LimitExceeded)
}

pub(super) fn lookup_slot_count(records: u64) -> Result<usize, IndexError> {
    let children = records.checked_sub(1).ok_or(IndexError::InvalidRecord)?;
    usize::try_from(children).map_err(|_| IndexError::LimitExceeded)
}

pub(super) fn lookup_allocation_bytes(slots: usize) -> Result<u64, IndexError> {
    let bytes = slots
        .checked_mul(LOOKUP_SLOT_BYTES)
        .ok_or(IndexError::LimitExceeded)?;
    u64::try_from(bytes).map_err(|_| IndexError::LimitExceeded)
}

pub(super) fn lookup_vector_charge(slots: usize) -> Result<u64, IndexError> {
    vector_charge::<LookupSlot>(slots)
}

pub(super) fn build_vector_charge(slots: usize) -> Result<u64, IndexError> {
    vector_charge::<BuildEntry>(slots)
}

pub(super) fn directory_vector_charge(slots: usize) -> Result<u64, IndexError> {
    vector_charge::<DirectoryBuildSlot>(slots)
}

pub(super) fn hardlink_vector_charge(slots: usize) -> Result<u64, IndexError> {
    vector_charge::<HardlinkSlot>(slots)
}

pub(crate) fn byte_vector_charge(bytes: usize) -> Result<u64, IndexError> {
    vector_charge::<u8>(bytes)
}

pub(super) fn vector_charge<T>(slots: usize) -> Result<u64, IndexError> {
    let payload = slots
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(IndexError::LimitExceeded)?;
    payload
        .checked_add(std::mem::size_of::<Vec<T>>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(IndexError::LimitExceeded)
}

pub(super) fn directory_allocation_bytes(slots: usize) -> Result<u64, IndexError> {
    let bytes = slots
        .checked_mul(DIRECTORY_SLOT_BYTES)
        .ok_or(IndexError::LimitExceeded)?;
    u64::try_from(bytes).map_err(|_| IndexError::LimitExceeded)
}

pub(super) fn lookup_hash(parent: u64, name: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AOS filesystem-view lookup v2\0");
    digest.update(parent.to_le_bytes());
    digest.update((name.len() as u64).to_le_bytes());
    digest.update(name);
    digest.finalize().into()
}

pub(super) fn encode_lookup_slot(slot: LookupSlot) -> [u8; LOOKUP_SLOT_BYTES] {
    let mut bytes = [0_u8; LOOKUP_SLOT_BYTES];
    bytes[0..8].copy_from_slice(&slot.parent.to_le_bytes());
    bytes[8..40].copy_from_slice(&slot.name_hash);
    bytes[40..48].copy_from_slice(&slot.record_offset.to_le_bytes());
    bytes[48..56].copy_from_slice(&slot.record_id.to_le_bytes());
    bytes
}

pub(super) fn read_lookup_slot(
    bytes: &[u8],
    table_offset: u64,
    slot: u64,
) -> Result<LookupSlot, IndexError> {
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

pub(super) fn encode_directory_slot(slot: DirectorySlot) -> [u8; DIRECTORY_SLOT_BYTES] {
    let mut bytes = [0_u8; DIRECTORY_SLOT_BYTES];
    bytes[0..8].copy_from_slice(&slot.parent.to_le_bytes());
    bytes[8..16].copy_from_slice(&slot.record_offset.to_le_bytes());
    bytes[16..24].copy_from_slice(&slot.record_id.to_le_bytes());
    bytes[24..32].copy_from_slice(&slot.nlink.to_le_bytes());
    bytes
}

pub(super) fn read_directory_slot(
    bytes: &[u8],
    table_offset: u64,
    slot: u64,
) -> Result<DirectorySlot, IndexError> {
    let offset = slot
        .checked_mul(DIRECTORY_SLOT_BYTES as u64)
        .and_then(|value| table_offset.checked_add(value))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(IndexError::InvalidRecord)?;
    let end = offset
        .checked_add(DIRECTORY_SLOT_BYTES)
        .ok_or(IndexError::InvalidRecord)?;
    let mut cursor = Cursor::new(bytes.get(offset..end).ok_or(IndexError::InvalidRecord)?);
    Ok(DirectorySlot {
        parent: cursor.u64()?,
        record_offset: cursor.u64()?,
        record_id: cursor.u64()?,
        nlink: cursor.u64()?,
    })
}

pub(super) fn decode_record_view<'a>(
    bytes: &'a [u8],
    offset: usize,
    id: u64,
    artifact: ObjectDigest,
) -> Result<IndexNodeView<'a>, IndexError> {
    let encoded = bytes.get(offset..).ok_or(IndexError::InvalidRecord)?;
    let mut cursor = Cursor::new(encoded);
    let length = usize::try_from(cursor.u32()?).map_err(|_| IndexError::InvalidRecord)?;
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
        record_offset: u64::try_from(offset).map_err(|_| IndexError::InvalidRecord)?,
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

pub(super) fn record_hardlink_group(
    encoded: &[u8],
    kind: IndexNodeKind,
) -> Result<Option<ObjectDigest>, IndexError> {
    if kind != IndexNodeKind::File {
        return Ok(None);
    }
    let mut record = Cursor::new(encoded);
    let length = usize::try_from(record.u32()?).map_err(|_| IndexError::InvalidRecord)?;
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

pub(super) fn skip_descriptor(cursor: &mut Cursor<'_>) -> Result<(), IndexError> {
    cursor.length_bytes()?;
    cursor.take(32)?;
    cursor.u64()?;
    Ok(())
}

pub(super) fn encode_record(
    output: &mut Vec<u8>,
    record: &IndexRecord<'_>,
) -> Result<(), IndexError> {
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

pub(super) fn validate_record(
    cursor: &mut Cursor<'_>,
    expected_id: u64,
) -> Result<ParsedRecord, IndexError> {
    let length = usize::try_from(cursor.u32()?).map_err(|_| IndexError::InvalidRecord)?;
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

pub(super) fn encode_content(
    output: &mut Vec<u8>,
    content: &ContentLayout,
) -> Result<(), IndexError> {
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

pub(super) fn validate_content(cursor: &mut Cursor<'_>) -> Result<ContentLayout, IndexError> {
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

pub(super) fn encode_descriptor(
    output: &mut Vec<u8>,
    value: &ObjectDescriptor,
) -> Result<(), IndexError> {
    put_bytes(output, value.media_type().as_str().as_bytes())?;
    output.extend_from_slice(value.digest().as_bytes());
    put_u64(output, value.encoded_size());
    Ok(())
}

pub(super) fn validate_descriptor(
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

pub(super) fn encode_acl(output: &mut Vec<u8>, entry: AclEntry) {
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

pub(super) fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IndexError> {
    put_u32_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn put_u32_len(output: &mut Vec<u8>, length: usize) -> Result<(), IndexError> {
    put_u32(
        output,
        u32::try_from(length).map_err(|_| IndexError::LimitExceeded)?,
    );
    Ok(())
}

pub(super) fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}
pub(super) fn put_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub(super) struct Cursor<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) position: usize,
}

impl<'a> Cursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) const fn position(&self) -> usize {
        self.position
    }
    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], IndexError> {
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
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexError> {
        self.take(N)?
            .try_into()
            .map_err(|_| IndexError::InvalidRecord)
    }
    pub(super) fn byte(&mut self) -> Result<u8, IndexError> {
        Ok(self.take(1)?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, IndexError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, IndexError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(super) fn i64(&mut self) -> Result<i64, IndexError> {
        Ok(i64::from_le_bytes(self.array()?))
    }
    pub(super) fn length_bytes(&mut self) -> Result<&'a [u8], IndexError> {
        let length = usize::try_from(self.u32()?).map_err(|_| IndexError::InvalidRecord)?;
        self.take(length)
    }
}
