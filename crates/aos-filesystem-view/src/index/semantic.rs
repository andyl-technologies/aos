//! Allocation-free semantic views over authenticated structural-index records.
//!
//! The structural-index validator authenticates and validates complete records
//! before constructing a [`ValidatedIndex`]. This module reparses those
//! immutable bytes into borrowed ranges; it never materializes the owned tree
//! model and never allocates.

use std::iter::FusedIterator;

use super::view::*;
use super::wire::*;
use super::*;

/// Borrows the variable metadata and kind-specific body of one index record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexNodeSemantics<'a> {
    xattrs: IndexXattrRange<'a>,
    acl: Option<IndexAclRange<'a>>,
    body: IndexNodeBodyView<'a>,
}

impl<'a> IndexNodeSemantics<'a> {
    /// Returns the canonical extended attributes.
    #[must_use]
    pub const fn xattrs(&self) -> IndexXattrRange<'a> {
        self.xattrs
    }

    /// Returns the optional canonical POSIX ACL.
    #[must_use]
    pub const fn acl(&self) -> Option<IndexAclRange<'a>> {
        self.acl
    }

    /// Returns the kind-specific record body.
    #[must_use]
    pub const fn body(&self) -> IndexNodeBodyView<'a> {
        self.body
    }

    /// Returns a regular file's exact logical size, including sparse holes.
    #[must_use]
    pub const fn logical_size(&self) -> Option<u64> {
        match self.body {
            IndexNodeBodyView::File(file) => Some(file.logical_size()),
            IndexNodeBodyView::Directory { .. } | IndexNodeBodyView::Symlink { .. } => None,
        }
    }
}

/// Borrows the kind-specific body of one index record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexNodeBodyView<'a> {
    /// Describes immutable regular-file content and hard-link identity.
    File(IndexFileView<'a>),
    /// Identifies the portable child-directory object.
    Directory {
        /// Authenticated directory descriptor.
        descriptor: IndexObjectDescriptorView<'a>,
    },
    /// Borrows the byte-exact symbolic-link target.
    Symlink {
        /// Target bytes, which need not be UTF-8.
        target: &'a [u8],
    },
}

/// Borrows a regular file's content layout and optional hard-link identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexFileView<'a> {
    content: IndexContentView<'a>,
    hardlink_group: Option<ObjectDigest>,
}

impl<'a> IndexFileView<'a> {
    /// Returns the immutable content layout.
    #[must_use]
    pub const fn content(&self) -> IndexContentView<'a> {
        self.content
    }

    /// Returns the optional tree-scoped hard-link group digest.
    #[must_use]
    pub const fn hardlink_group(&self) -> Option<ObjectDigest> {
        self.hardlink_group
    }

    /// Returns the exact logical file size, including sparse holes.
    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        match self.content {
            IndexContentView::Whole { content } => content.encoded_size(),
            IndexContentView::Sparse(sparse) => sparse.logical_size(),
        }
    }
}

/// Borrows an immutable whole-file or normalized sparse content layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexContentView<'a> {
    /// Stores every logical byte in one content object.
    Whole {
        /// Authenticated raw-content descriptor.
        content: IndexObjectDescriptorView<'a>,
    },
    /// Stores maximal non-hole extents and leaves holes implicit.
    Sparse(IndexSparseContentView<'a>),
}

/// Borrows a normalized sparse content layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexSparseContentView<'a> {
    logical_size: u64,
    extents: IndexExtentRange<'a>,
}

impl<'a> IndexSparseContentView<'a> {
    /// Returns the logical file size including holes.
    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Returns the canonical maximal non-hole extents.
    #[must_use]
    pub const fn extents(&self) -> IndexExtentRange<'a> {
        self.extents
    }
}

/// Borrows one authenticated object descriptor without allocating its media type.
///
/// Whole-index validation has already checked the media-type syntax and its
/// descriptor role. Borrowed decoding therefore needs only a UTF-8 and bounds
/// check; it does not reconstruct the owned `MediaType(String)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexObjectDescriptorView<'a> {
    media_type: &'a str,
    digest: ObjectDigest,
    encoded_size: u64,
}

impl<'a> IndexObjectDescriptorView<'a> {
    /// Returns the syntactically validated media type.
    #[must_use]
    pub const fn media_type(&self) -> &'a str {
        self.media_type
    }

    /// Returns the exact SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact stored object size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
}

/// Borrows a canonical sequence of extended attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexXattrRange<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> IndexXattrRange<'a> {
    /// Returns the exact attribute count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Reports whether no extended attributes are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates attributes in canonical byte-name order.
    #[must_use]
    pub const fn iter(self) -> IndexXattrs<'a> {
        IndexXattrs {
            cursor: Cursor::new(self.bytes),
            remaining: self.count,
        }
    }
}

impl<'a> IntoIterator for IndexXattrRange<'a> {
    type Item = Result<IndexXattrView<'a>, IndexError>;
    type IntoIter = IndexXattrs<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterates canonical borrowed extended attributes without allocating.
pub struct IndexXattrs<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl<'a> Iterator for IndexXattrs<'a> {
    type Item = Result<IndexXattrView<'a>, IndexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let item = self.cursor.length_bytes().and_then(|name| {
            self.cursor
                .length_bytes()
                .map(|value| IndexXattrView { name, value })
        });
        match item {
            Ok(item) => {
                self.remaining -= 1;
                Some(Ok(item))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for IndexXattrs<'_> {}
impl FusedIterator for IndexXattrs<'_> {}

/// Borrows one byte-exact extended attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexXattrView<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> IndexXattrView<'a> {
    /// Returns the uninterpreted attribute name bytes.
    #[must_use]
    pub const fn name(&self) -> &'a [u8] {
        self.name
    }

    /// Returns the uninterpreted attribute value bytes.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Borrows one present canonical POSIX ACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexAclRange<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> IndexAclRange<'a> {
    /// Returns the exact ACL entry count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Reports whether the present ACL has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates entries in canonical typed order.
    #[must_use]
    pub const fn iter(self) -> IndexAclEntries<'a> {
        IndexAclEntries {
            cursor: Cursor::new(self.bytes),
            remaining: self.count,
        }
    }
}

impl<'a> IntoIterator for IndexAclRange<'a> {
    type Item = Result<AclEntry, IndexError>;
    type IntoIter = IndexAclEntries<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterates canonical POSIX ACL entries without allocating.
pub struct IndexAclEntries<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl Iterator for IndexAclEntries<'_> {
    type Item = Result<AclEntry, IndexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match decode_acl_entry(&mut self.cursor) {
            Ok(entry) => {
                self.remaining -= 1;
                Some(Ok(entry))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for IndexAclEntries<'_> {}
impl FusedIterator for IndexAclEntries<'_> {}

/// Borrows a canonical sequence of sparse extents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexExtentRange<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> IndexExtentRange<'a> {
    /// Returns the exact extent count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Reports whether the sparse file contains no stored extents.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates extents in increasing logical-offset order.
    #[must_use]
    pub const fn iter(self) -> IndexExtents<'a> {
        IndexExtents {
            cursor: Cursor::new(self.bytes),
            remaining: self.count,
        }
    }
}

impl<'a> IntoIterator for IndexExtentRange<'a> {
    type Item = Result<IndexExtentView<'a>, IndexError>;
    type IntoIter = IndexExtents<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterates canonical sparse extents without allocating.
pub struct IndexExtents<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}

impl<'a> Iterator for IndexExtents<'a> {
    type Item = Result<IndexExtentView<'a>, IndexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let item = decode_extent_view(&mut self.cursor);
        match item {
            Ok(item) => {
                self.remaining -= 1;
                Some(Ok(item))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for IndexExtents<'_> {}
impl FusedIterator for IndexExtents<'_> {}

/// Borrows one maximal non-hole extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexExtentView<'a> {
    offset: u64,
    length: u64,
    content: IndexObjectDescriptorView<'a>,
}

impl<'a> IndexExtentView<'a> {
    /// Returns the logical start offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the positive logical extent length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the exclusive logical end.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// Returns the exact raw-content descriptor.
    #[must_use]
    pub const fn content(&self) -> IndexObjectDescriptorView<'a> {
        self.content
    }
}

impl<'bytes> ValidatedIndex<'bytes> {
    /// Borrows a node's authenticated variable metadata and semantic body.
    ///
    /// Locator authentication is constant-time for a root, otherwise it uses a
    /// V2 point-lookup binary search or a V3 parent-range binary search and
    /// direct ordinal access. A V2 cryptographic hash-collision run is scanned
    /// to find the exact ID and offset. The subsequent exact identity check and
    /// semantic parsing are linear in the encoded record length. The complete
    /// operation uses constant working memory and performs no allocation.
    /// Retain the returned small view when several fields from the same record
    /// are needed.
    ///
    /// ```compile_fail
    /// use aos_filesystem_view::{IndexError, IndexNodeSemantics, IndexNodeView, ValidatedIndex};
    ///
    /// fn escape(
    ///     index: &ValidatedIndex<'_>,
    ///     node: &IndexNodeView<'_>,
    /// ) -> Result<IndexNodeSemantics<'static>, IndexError> {
    ///     index.record_semantics(node)
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::ForeignNode`] when `node` belongs to another
    /// artifact. Returns [`IndexError::InvalidRecord`] if its private identity
    /// does not resolve to the same authenticated record or an internal byte
    /// invariant no longer holds, which safe callers cannot cause.
    pub fn record_semantics<'index>(
        &'index self,
        node: &IndexNodeView<'_>,
    ) -> Result<IndexNodeSemantics<'index>, IndexError> {
        let decoded = self.authenticate_node(node)?;
        decode_record_semantics(decoded.encoded_record, decoded.kind, decoded.mode)
    }
}

pub(super) fn decode_record_semantics(
    encoded: &[u8],
    kind: IndexNodeKind,
    mode: u16,
) -> Result<IndexNodeSemantics<'_>, IndexError> {
    let mut record = Cursor::new(encoded);
    let length = usize::try_from(record.u32()?).map_err(|_| IndexError::InvalidRecord)?;
    if length != encoded.len() || length < RECORD_FIXED_BYTES {
        return Err(IndexError::InvalidRecord);
    }
    record.take(RECORD_FIXED_BYTES - 4)?;
    record.length_bytes()?;

    let xattr_count = usize::try_from(record.u32()?).map_err(|_| IndexError::InvalidRecord)?;
    if xattr_count > record.remaining() / 9 {
        return Err(IndexError::InvalidRecord);
    }
    let xattr_start = record.position();
    let mut previous_xattr = None;
    for _ in 0..xattr_count {
        let name = record.length_bytes()?;
        let value = record.length_bytes()?;
        if name.is_empty()
            || name.len() > 255
            || name.contains(&0)
            || value.len() > 1_048_576
            || previous_xattr.is_some_and(|previous| previous >= name)
        {
            return Err(IndexError::InvalidRecord);
        }
        previous_xattr = Some(name);
    }
    let xattr_end = record.position();
    let xattrs = IndexXattrRange {
        bytes: cursor_range(&record, xattr_start, xattr_end)?,
        count: xattr_count,
    };

    let acl_count = record.u32()?;
    let acl = if acl_count == u32::MAX {
        None
    } else {
        let count = usize::try_from(acl_count).map_err(|_| IndexError::InvalidRecord)?;
        let bytes = count.checked_mul(6).ok_or(IndexError::InvalidRecord)?;
        let start = record.position();
        let encoded_acl = record.take(bytes)?;
        let mut acl_cursor = Cursor::new(encoded_acl);
        let mut previous = None;
        let mut user = None;
        let mut group = None;
        let mut mask = None;
        let mut other = None;
        let mut named = false;
        for _ in 0..count {
            let entry = decode_acl_entry(&mut acl_cursor)?;
            let identity = acl_identity(entry);
            if previous.is_some_and(|prior| prior >= identity) {
                return Err(IndexError::InvalidRecord);
            }
            match entry {
                AclEntry::UserObject(permissions) => user = Some(permissions),
                AclEntry::NamedUser { .. } | AclEntry::NamedGroup { .. } => named = true,
                AclEntry::GroupObject(permissions) => group = Some(permissions),
                AclEntry::Mask(permissions) => mask = Some(permissions),
                AclEntry::Other(permissions) => other = Some(permissions),
            }
            previous = Some(identity);
        }
        if acl_cursor.remaining() != 0
            || user != Some(((mode >> 6) & 7) as u8)
            || other != Some((mode & 7) as u8)
            || group.is_none()
            || (named && mask.is_none())
            || mask.or(group) != Some(((mode >> 3) & 7) as u8)
        {
            return Err(IndexError::InvalidRecord);
        }
        let end = record.position();
        Some(IndexAclRange {
            bytes: cursor_range(&record, start, end)?,
            count,
        })
    };

    let body = match kind {
        IndexNodeKind::File => {
            let content = decode_content_view(&mut record)?;
            let hardlink_group = match record.byte()? {
                0 => None,
                1 => Some(ObjectDigest::from_bytes(record.array::<32>()?)),
                _ => return Err(IndexError::InvalidRecord),
            };
            IndexNodeBodyView::File(IndexFileView {
                content,
                hardlink_group,
            })
        }
        IndexNodeKind::Directory => IndexNodeBodyView::Directory {
            descriptor: decode_descriptor_view(&mut record)?,
        },
        IndexNodeKind::Symlink => {
            let target = record.length_bytes()?;
            if target.len() > 4_096 || target.contains(&0) {
                return Err(IndexError::InvalidRecord);
            }
            IndexNodeBodyView::Symlink { target }
        }
    };
    if record.remaining() != 0 {
        return Err(IndexError::InvalidRecord);
    }
    Ok(IndexNodeSemantics { xattrs, acl, body })
}

fn decode_content_view<'a>(cursor: &mut Cursor<'a>) -> Result<IndexContentView<'a>, IndexError> {
    match cursor.byte()? {
        0 => Ok(IndexContentView::Whole {
            content: decode_descriptor_view(cursor)?,
        }),
        1 => {
            let logical_size = cursor.u64()?;
            let count = usize::try_from(cursor.u32()?).map_err(|_| IndexError::InvalidRecord)?;
            if count > cursor.remaining() / 61 {
                return Err(IndexError::InvalidRecord);
            }
            let start = cursor.position();
            let mut prior_end = None;
            let mut first_offset = None;
            for _ in 0..count {
                let extent = decode_extent_view(cursor)?;
                let end = extent
                    .offset
                    .checked_add(extent.length)
                    .ok_or(IndexError::InvalidRecord)?;
                if extent.length == 0
                    || end > logical_size
                    || prior_end.is_some_and(|prior| prior >= extent.offset)
                    || extent.content.encoded_size != extent.length
                {
                    return Err(IndexError::InvalidRecord);
                }
                first_offset.get_or_insert(extent.offset);
                prior_end = Some(end);
            }
            if logical_size > 0
                && count == 1
                && first_offset == Some(0)
                && prior_end == Some(logical_size)
            {
                return Err(IndexError::InvalidRecord);
            }
            let end = cursor.position();
            Ok(IndexContentView::Sparse(IndexSparseContentView {
                logical_size,
                extents: IndexExtentRange {
                    bytes: cursor_range(cursor, start, end)?,
                    count,
                },
            }))
        }
        _ => Err(IndexError::InvalidRecord),
    }
}

fn decode_extent_view<'a>(cursor: &mut Cursor<'a>) -> Result<IndexExtentView<'a>, IndexError> {
    Ok(IndexExtentView {
        offset: cursor.u64()?,
        length: cursor.u64()?,
        content: decode_descriptor_view(cursor)?,
    })
}

fn decode_descriptor_view<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<IndexObjectDescriptorView<'a>, IndexError> {
    let media_type =
        std::str::from_utf8(cursor.length_bytes()?).map_err(|_| IndexError::InvalidRecord)?;
    Ok(IndexObjectDescriptorView {
        media_type,
        digest: ObjectDigest::from_bytes(cursor.array::<32>()?),
        encoded_size: cursor.u64()?,
    })
}

fn decode_acl_entry(cursor: &mut Cursor<'_>) -> Result<AclEntry, IndexError> {
    let tag = cursor.byte()?;
    let qualifier = cursor.u32()?;
    let permissions = cursor.byte()?;
    if permissions > 7 {
        return Err(IndexError::InvalidRecord);
    }
    match (tag, qualifier) {
        (0, u32::MAX) => Ok(AclEntry::UserObject(permissions)),
        (1, uid) if uid != u32::MAX => Ok(AclEntry::NamedUser { uid, permissions }),
        (2, u32::MAX) => Ok(AclEntry::GroupObject(permissions)),
        (3, gid) if gid != u32::MAX => Ok(AclEntry::NamedGroup { gid, permissions }),
        (4, u32::MAX) => Ok(AclEntry::Mask(permissions)),
        (5, u32::MAX) => Ok(AclEntry::Other(permissions)),
        _ => Err(IndexError::InvalidRecord),
    }
}

const fn acl_identity(entry: AclEntry) -> (u8, u32) {
    match entry {
        AclEntry::UserObject(_) => (0, u32::MAX),
        AclEntry::NamedUser { uid, .. } => (1, uid),
        AclEntry::GroupObject(_) => (2, u32::MAX),
        AclEntry::NamedGroup { gid, .. } => (3, gid),
        AclEntry::Mask(_) => (4, u32::MAX),
        AclEntry::Other(_) => (5, u32::MAX),
    }
}

fn cursor_range<'a>(cursor: &Cursor<'a>, start: usize, end: usize) -> Result<&'a [u8], IndexError> {
    cursor
        .bytes
        .get(start..end)
        .ok_or(IndexError::InvalidRecord)
}
