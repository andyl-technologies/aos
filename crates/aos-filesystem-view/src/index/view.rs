//! Validated structural-index summaries and allocation-free borrowed views.

use super::wire::*;
use super::*;

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
    pub(super) bytes: &'a [u8],
    pub(super) descriptor: ObjectDescriptor,
    pub(super) summary: IndexSummary,
    pub(super) crosslinks: IndexCrosslinks,
    pub(super) layout: IndexLayout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IndexLayout {
    SequentialV1,
    PointLookupV2 {
        records_bytes: u64,
        lookup_slots: u64,
    },
    IterableV3 {
        records_bytes: u64,
        lookup_slots: u64,
        directory_slots: u64,
        root_nlink: u64,
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
            IndexLayout::IterableV3 { .. } => HEADER_BYTES_V3,
        };
        decode_record_view(self.bytes, offset, 0, self.descriptor.digest())
    }

    /// Re-resolves a private node handle through the authenticated format index.
    pub(super) fn authenticate_node(
        &self,
        node: &IndexNodeView<'_>,
    ) -> Result<IndexNodeView<'bytes>, IndexError> {
        if node.artifact != self.descriptor.digest() {
            return Err(IndexError::ForeignNode);
        }

        let authenticated_offset = if node.id == 0 {
            let root_offset = match self.layout {
                IndexLayout::SequentialV1 => HEADER_BYTES_V1,
                IndexLayout::PointLookupV2 { .. } => HEADER_BYTES_V2,
                IndexLayout::IterableV3 { .. } => HEADER_BYTES_V3,
            };
            let root_offset = u64::try_from(root_offset).map_err(|_| IndexError::InvalidRecord)?;
            if node.record_offset != root_offset {
                return Err(IndexError::InvalidRecord);
            }
            root_offset
        } else {
            match self.layout {
                IndexLayout::SequentialV1 => return Err(IndexError::InvalidRecord),
                IndexLayout::PointLookupV2 {
                    records_bytes,
                    lookup_slots,
                } => self.authenticate_v2_node(node, records_bytes, lookup_slots)?,
                IndexLayout::IterableV3 {
                    records_bytes,
                    lookup_slots,
                    directory_slots,
                    ..
                } => {
                    self.authenticate_v3_node(node, records_bytes, lookup_slots, directory_slots)?
                }
            }
        };
        let offset =
            usize::try_from(authenticated_offset).map_err(|_| IndexError::InvalidRecord)?;
        let decoded = decode_record_view(self.bytes, offset, node.id, self.descriptor.digest())?;
        if !same_node_identity(&decoded, node) {
            return Err(IndexError::InvalidRecord);
        }
        Ok(decoded)
    }

    fn authenticate_v2_node(
        &self,
        node: &IndexNodeView<'_>,
        records_bytes: u64,
        lookup_slots: u64,
    ) -> Result<u64, IndexError> {
        let table_offset = (HEADER_BYTES_V2 as u64)
            .checked_add(records_bytes)
            .ok_or(IndexError::InvalidRecord)?;
        let target_hash = lookup_hash(node.parent, node.name);
        let mut left = 0_u64;
        let mut right = lookup_slots;
        while left < right {
            let middle = left + (right - left) / 2;
            let slot = read_lookup_slot(self.bytes, table_offset, middle)?;
            if (slot.parent, slot.name_hash) < (node.parent, target_hash) {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        while left < lookup_slots {
            let slot = read_lookup_slot(self.bytes, table_offset, left)?;
            if (slot.parent, slot.name_hash) != (node.parent, target_hash) {
                break;
            }
            if slot.record_id == node.id && slot.record_offset == node.record_offset {
                return Ok(slot.record_offset);
            }
            left += 1;
        }
        Err(IndexError::InvalidRecord)
    }

    fn authenticate_v3_node(
        &self,
        node: &IndexNodeView<'_>,
        records_bytes: u64,
        lookup_slots: u64,
        directory_slots: u64,
    ) -> Result<u64, IndexError> {
        let table_offset = directory_table_offset(records_bytes, lookup_slots)?;
        let start = directory_lower_bound(self.bytes, table_offset, directory_slots, node.parent)?;
        let position = start
            .checked_add(u64::from(node.sibling_ordinal))
            .ok_or(IndexError::InvalidRecord)?;
        if position >= directory_slots {
            return Err(IndexError::InvalidRecord);
        }
        let slot = read_directory_slot(self.bytes, table_offset, position)?;
        if slot.parent != node.parent
            || slot.record_id != node.id
            || slot.record_offset != node.record_offset
        {
            return Err(IndexError::InvalidRecord);
        }
        Ok(slot.record_offset)
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
        let (header_bytes, records_bytes, lookup_slots) = match self.layout {
            IndexLayout::SequentialV1 => return Err(IndexError::PointLookupUnavailable),
            IndexLayout::PointLookupV2 {
                records_bytes,
                lookup_slots,
            } => (HEADER_BYTES_V2, records_bytes, lookup_slots),
            IndexLayout::IterableV3 {
                records_bytes,
                lookup_slots,
                ..
            } => (HEADER_BYTES_V3, records_bytes, lookup_slots),
        };
        if parent.artifact != self.descriptor.digest() || parent.kind != IndexNodeKind::Directory {
            return Err(IndexError::ForeignNode);
        }

        let target_hash = lookup_hash(parent.id, name.as_bytes());
        let table_offset = (header_bytes as u64)
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
        !matches!(self.layout, IndexLayout::SequentialV1)
    }

    /// Reports whether this artifact supports authenticated directory iteration.
    #[must_use]
    pub const fn supports_directory_iteration(&self) -> bool {
        matches!(self.layout, IndexLayout::IterableV3 { .. })
    }

    /// Returns a borrowed allocation-free range over canonical children.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::DirectoryIterationUnavailable`] for V1/V2,
    /// [`IndexError::ForeignNode`] for a foreign or non-directory node, or
    /// [`IndexError::InvalidRecord`] if internally authenticated offsets fail.
    pub fn directory_range<'index>(
        &'index self,
        directory: &IndexNodeView<'_>,
    ) -> Result<DirectoryRange<'index>, IndexError> {
        let IndexLayout::IterableV3 {
            records_bytes,
            lookup_slots,
            directory_slots,
            ..
        } = self.layout
        else {
            return Err(IndexError::DirectoryIterationUnavailable);
        };
        if directory.artifact != self.descriptor.digest()
            || directory.kind != IndexNodeKind::Directory
        {
            return Err(IndexError::ForeignNode);
        }
        let table_offset = directory_table_offset(records_bytes, lookup_slots)?;
        let start = directory_lower_bound(self.bytes, table_offset, directory_slots, directory.id)?;
        let end = directory_lower_bound(
            self.bytes,
            table_offset,
            directory_slots,
            directory.id.saturating_add(1),
        )?;
        Ok(DirectoryRange {
            bytes: self.bytes,
            artifact: self.descriptor.digest(),
            table_offset,
            start,
            length: end.checked_sub(start).ok_or(IndexError::InvalidRecord)?,
            parent: directory.id,
        })
    }

    /// Returns a borrowed allocation-free iterator over canonical children.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::directory_range`].
    pub fn directory_entries<'index>(
        &'index self,
        directory: &IndexNodeView<'_>,
    ) -> Result<DirectoryEntries<'index>, IndexError> {
        Ok(self.directory_range(directory)?.iter())
    }

    /// Returns the exact portable link count authenticated for a node.
    ///
    /// This operation is allocation-free and takes one parent-range binary
    /// search plus one direct sibling-ordinal slot access.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::DirectoryIterationUnavailable`] for V1/V2,
    /// [`IndexError::ForeignNode`] for a node from another artifact, or
    /// [`IndexError::InvalidRecord`] if the node is absent from the table.
    pub fn nlink(&self, node: &IndexNodeView<'_>) -> Result<u64, IndexError> {
        let IndexLayout::IterableV3 {
            records_bytes,
            lookup_slots,
            directory_slots,
            root_nlink,
        } = self.layout
        else {
            return Err(IndexError::DirectoryIterationUnavailable);
        };
        if node.artifact != self.descriptor.digest() {
            return Err(IndexError::ForeignNode);
        }
        if node.id == 0 {
            return Ok(root_nlink);
        }
        let table_offset = directory_table_offset(records_bytes, lookup_slots)?;
        let start = directory_lower_bound(self.bytes, table_offset, directory_slots, node.parent)?;
        let position = start
            .checked_add(u64::from(node.sibling_ordinal))
            .ok_or(IndexError::InvalidRecord)?;
        if position >= directory_slots {
            return Err(IndexError::InvalidRecord);
        }
        let slot = read_directory_slot(self.bytes, table_offset, position)?;
        if slot.parent != node.parent
            || slot.record_id != node.id
            || slot.record_offset != node.record_offset
        {
            return Err(IndexError::InvalidRecord);
        }
        Ok(slot.nlink)
    }
}

fn same_node_identity(left: &IndexNodeView<'_>, right: &IndexNodeView<'_>) -> bool {
    left.artifact == right.artifact
        && left.id == right.id
        && left.record_offset == right.record_offset
        && left.parent == right.parent
        && left.depth == right.depth
        && left.sibling_ordinal == right.sibling_ordinal
        && left.kind == right.kind
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
        && left.mtime_seconds == right.mtime_seconds
        && left.mtime_nanos == right.mtime_nanos
        && left.name == right.name
        && left.encoded_record == right.encoded_record
}

pub(super) fn directory_table_offset(
    records_bytes: u64,
    lookup_slots: u64,
) -> Result<u64, IndexError> {
    (HEADER_BYTES_V3 as u64)
        .checked_add(records_bytes)
        .and_then(|offset| {
            lookup_slots
                .checked_mul(LOOKUP_SLOT_BYTES as u64)
                .and_then(|bytes| offset.checked_add(bytes))
        })
        .ok_or(IndexError::InvalidRecord)
}

pub(super) fn directory_lower_bound(
    bytes: &[u8],
    table_offset: u64,
    slots: u64,
    parent: u64,
) -> Result<u64, IndexError> {
    let mut left = 0;
    let mut right = slots;
    while left < right {
        let middle = left + (right - left) / 2;
        if read_directory_slot(bytes, table_offset, middle)?.parent < parent {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    Ok(left)
}

/// Borrows a V3 directory's canonical child range without allocating.
#[derive(Clone, Copy)]
pub struct DirectoryRange<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) artifact: ObjectDigest,
    pub(super) table_offset: u64,
    pub(super) start: u64,
    pub(super) length: u64,
    pub(super) parent: u64,
}

impl<'a> DirectoryRange<'a> {
    /// Returns the exact child count.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Reports whether the directory has no children.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns one child by canonical sibling ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::InvalidRecord`] if an authenticated internal slot
    /// cannot be decoded or no longer matches its parent and ordinal.
    pub fn get(&self, ordinal: u64) -> Result<Option<DirectoryEntryView<'a>>, IndexError> {
        if ordinal >= self.length {
            return Ok(None);
        }
        let position = self
            .start
            .checked_add(ordinal)
            .ok_or(IndexError::InvalidRecord)?;
        let slot = read_directory_slot(self.bytes, self.table_offset, position)?;
        let offset = usize::try_from(slot.record_offset).map_err(|_| IndexError::InvalidRecord)?;
        let node = decode_record_view(self.bytes, offset, slot.record_id, self.artifact)?;
        if slot.parent != self.parent
            || node.parent != self.parent
            || u64::from(node.sibling_ordinal) != ordinal
        {
            return Err(IndexError::InvalidRecord);
        }
        Ok(Some(DirectoryEntryView {
            node,
            nlink: slot.nlink,
        }))
    }

    /// Iterates from the first canonical child without allocating.
    #[must_use]
    pub const fn iter(self) -> DirectoryEntries<'a> {
        DirectoryEntries {
            range: self,
            next: 0,
        }
    }
}

impl<'a> IntoIterator for DirectoryRange<'a> {
    type Item = Result<DirectoryEntryView<'a>, IndexError>;
    type IntoIter = DirectoryEntries<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterates borrowed V3 directory children without allocating.
pub struct DirectoryEntries<'a> {
    pub(super) range: DirectoryRange<'a>,
    pub(super) next: u64,
}

impl<'a> Iterator for DirectoryEntries<'a> {
    type Item = Result<DirectoryEntryView<'a>, IndexError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.range.length {
            return None;
        }
        let ordinal = self.next;
        self.next += 1;
        Some(
            self.range
                .get(ordinal)
                .and_then(|entry| entry.ok_or(IndexError::InvalidRecord)),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.range.length - self.next).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DirectoryEntries<'_> {}

/// Borrows one canonical directory entry and its exact link count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntryView<'a> {
    pub(super) node: IndexNodeView<'a>,
    pub(super) nlink: u64,
}

impl<'a> DirectoryEntryView<'a> {
    /// Returns the lazily decoded child record.
    #[must_use]
    pub const fn node(&self) -> &IndexNodeView<'a> {
        &self.node
    }

    /// Consumes the entry and returns its lazily decoded child record.
    #[must_use]
    pub const fn into_node(self) -> IndexNodeView<'a> {
        self.node
    }

    /// Returns the exact portable link count.
    #[must_use]
    pub const fn nlink(&self) -> u64 {
        self.nlink
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
    pub(super) artifact: ObjectDigest,
    pub(super) id: u64,
    pub(super) record_offset: u64,
    pub(super) parent: u64,
    pub(super) depth: u32,
    pub(super) sibling_ordinal: u32,
    pub(super) kind: IndexNodeKind,
    pub(super) mode: u16,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mtime_seconds: i64,
    pub(super) mtime_nanos: u32,
    pub(super) name: &'a [u8],
    pub(super) encoded_record: &'a [u8],
}

impl<'a> IndexNodeView<'a> {
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
    pub const fn name(&self) -> &'a [u8] {
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
