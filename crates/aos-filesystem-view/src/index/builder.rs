//! Structural-index staging types and streaming compiler.

use super::wire::*;
use super::*;

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
    pub(super) writer: W,
    pub(super) maximum_bytes: u64,
    pub(super) maximum_record_bytes: u64,
    pub(super) maximum_working_bytes: u64,
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
    pub(super) writer: W,
    pub(super) summary: IndexSummary,
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
    pub(super) writer: W,
    pub(super) compiler_abi: [u8; 32],
    pub(super) tree: ObjectDescriptor,
    pub(super) root: ObjectDescriptor,
    pub(super) tree_features: u32,
    pub(super) maximum_bytes: u64,
    pub(super) maximum_record_bytes: u64,
    pub(super) maximum_working_bytes: u64,
    pub(super) records: u64,
    pub(super) payload_bytes: u64,
    pub(super) payload_hash: Sha256,
    pub(super) entries: Vec<BuildEntry>,
    pub(super) format: BuildFormat,
    #[cfg(test)]
    pub(super) refuse_record_scratch_allocation: bool,
    #[cfg(test)]
    pub(super) lookup_capacity_floor: usize,
    #[cfg(test)]
    pub(super) directory_capacity_floor: usize,
    #[cfg(test)]
    pub(super) refuse_hardlink_allocation: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BuildFormat {
    V2,
    V3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BuildEntry {
    pub(super) lookup: LookupSlot,
    pub(super) sibling_ordinal: u32,
    pub(super) kind: IndexNodeKind,
    pub(super) hardlink_group: Option<ObjectDigest>,
}

pub(crate) struct PushIndexResult {
    pub(crate) record_id: u64,
    pub(crate) retained_working_bytes: u64,
    pub(crate) peak_working_bytes: u64,
}

pub(crate) struct FinishIndexResult<W> {
    pub(crate) staged: StagedIndex<W>,
    pub(crate) peak_working_bytes: u64,
}

impl<W: Write + Seek> StructuralIndexBuilder<W> {
    pub(crate) fn retained_working_bytes(&self) -> Result<u64, IndexError> {
        build_vector_charge(self.entries.capacity())
    }

    pub(crate) fn retained_working_bytes_after_push(&self) -> Result<u64, IndexError> {
        if self.records == 0 {
            return self.retained_working_bytes();
        }
        let required = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(IndexError::LimitExceeded)?;
        build_vector_charge(self.entries.capacity().max(required))
    }

    pub(crate) fn finish_working_bytes(&self) -> Result<u64, IndexError> {
        let slots = lookup_slot_count(self.records)?;
        let lookup_peak = self
            .retained_working_bytes()?
            .checked_add(lookup_vector_charge(slots)?)
            .ok_or(IndexError::LimitExceeded)?;
        if self.format == BuildFormat::V2 {
            return Ok(lookup_peak);
        }
        let hardlinks = self
            .entries
            .iter()
            .filter(|entry| entry.hardlink_group.is_some())
            .count();
        let directory_peak = self
            .retained_working_bytes()?
            .checked_add(directory_vector_charge(slots)?)
            .and_then(|bytes| bytes.checked_add(hardlink_vector_charge(hardlinks).ok()?))
            .ok_or(IndexError::LimitExceeded)?;
        Ok(lookup_peak.max(directory_peak))
    }

    pub(crate) fn finish_temporary_working_bytes(&self) -> Result<u64, IndexError> {
        let slots = lookup_slot_count(self.records)?;
        let lookup = lookup_vector_charge(slots)?;
        if self.format == BuildFormat::V2 {
            return Ok(lookup);
        }
        let hardlinks = self
            .entries
            .iter()
            .filter(|entry| entry.hardlink_group.is_some())
            .count();
        Ok(lookup.max(
            directory_vector_charge(slots)?
                .checked_add(hardlink_vector_charge(hardlinks)?)
                .ok_or(IndexError::LimitExceeded)?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn new(
        staging: IndexStaging<W>,
        compiler_abi: [u8; 32],
        tree: ObjectDescriptor,
        root: ObjectDescriptor,
        tree_features: u32,
    ) -> Result<Self, IndexError> {
        Self::new_with_format(
            staging,
            compiler_abi,
            tree,
            root,
            tree_features,
            BuildFormat::V2,
        )
    }

    pub(crate) fn new_v3(
        staging: IndexStaging<W>,
        compiler_abi: [u8; 32],
        tree: ObjectDescriptor,
        root: ObjectDescriptor,
        tree_features: u32,
    ) -> Result<Self, IndexError> {
        Self::new_with_format(
            staging,
            compiler_abi,
            tree,
            root,
            tree_features,
            BuildFormat::V3,
        )
    }

    pub(super) fn new_with_format(
        staging: IndexStaging<W>,
        compiler_abi: [u8; 32],
        tree: ObjectDescriptor,
        root: ObjectDescriptor,
        tree_features: u32,
        format: BuildFormat,
    ) -> Result<Self, IndexError> {
        let IndexStaging {
            mut writer,
            maximum_bytes,
            maximum_record_bytes,
            maximum_working_bytes,
        } = staging;
        let header_bytes = match format {
            BuildFormat::V2 => HEADER_BYTES_V2,
            BuildFormat::V3 => HEADER_BYTES_V3,
        };
        if maximum_bytes < header_bytes as u64 || maximum_record_bytes == 0 {
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
        match format {
            BuildFormat::V2 => writer.write_all(&[0; HEADER_BYTES_V2]),
            BuildFormat::V3 => writer.write_all(&[0; HEADER_BYTES_V3]),
        }
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
            entries: Vec::new(),
            format,
            #[cfg(test)]
            refuse_record_scratch_allocation: false,
            #[cfg(test)]
            lookup_capacity_floor: 0,
            #[cfg(test)]
            directory_capacity_floor: 0,
            #[cfg(test)]
            refuse_hardlink_allocation: false,
        })
    }

    /// Appends one expanded node after reserving its exact encoded size.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] for arithmetic/format limits or staging I/O.
    #[cfg(test)]
    pub(crate) fn push(&mut self, record: &IndexRecord<'_>) -> Result<u64, IndexError> {
        self.push_with_external(record, 0, self.maximum_working_bytes)
            .map(|result| result.record_id)
    }

    pub(crate) fn push_with_external(
        &mut self,
        record: &IndexRecord<'_>,
        external_working_bytes: u64,
        aggregate_maximum_working_bytes: u64,
    ) -> Result<PushIndexResult, IndexError> {
        let encoded_len = record_encoded_len(record)?;
        let record_bytes = u64::try_from(encoded_len).map_err(|_| IndexError::LimitExceeded)?;
        if record_bytes > self.maximum_record_bytes {
            return Err(IndexError::LimitExceeded);
        }
        let next_payload = self
            .payload_bytes
            .checked_add(record_bytes)
            .ok_or(IndexError::LimitExceeded)?;
        let header_bytes = self.header_bytes();
        let total = (header_bytes as u64)
            .checked_add(next_payload)
            .ok_or(IndexError::LimitExceeded)?;
        if total > self.maximum_bytes {
            return Err(IndexError::LimitExceeded);
        }

        let id = self.records;
        if id != 0 {
            let next_entries = self
                .entries
                .len()
                .checked_add(1)
                .ok_or(IndexError::LimitExceeded)?;
            let retained_bytes = build_vector_charge(self.entries.capacity().max(next_entries))?;
            if retained_bytes > self.maximum_working_bytes
                || external_working_bytes
                    .checked_add(retained_bytes)
                    .ok_or(IndexError::LimitExceeded)?
                    > aggregate_maximum_working_bytes
            {
                return Err(IndexError::LimitExceeded);
            }
            self.entries
                .try_reserve_exact(1)
                .map_err(|_| IndexError::AllocationRefused)?;
            let actual_retained = self.retained_working_bytes()?;
            if actual_retained > self.maximum_working_bytes
                || external_working_bytes
                    .checked_add(actual_retained)
                    .ok_or(IndexError::LimitExceeded)?
                    > aggregate_maximum_working_bytes
            {
                return Err(IndexError::LimitExceeded);
            }
        }

        let retained_before_scratch = self.retained_working_bytes()?;
        let modeled_peak = external_working_bytes
            .checked_add(retained_before_scratch)
            .and_then(|bytes| bytes.checked_add(byte_vector_charge(encoded_len).ok()?))
            .ok_or(IndexError::LimitExceeded)?;
        let modeled_internal_peak = retained_before_scratch
            .checked_add(byte_vector_charge(encoded_len)?)
            .ok_or(IndexError::LimitExceeded)?;
        if modeled_internal_peak > self.maximum_working_bytes
            || modeled_peak > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }
        #[cfg(test)]
        if self.refuse_record_scratch_allocation {
            return Err(IndexError::AllocationRefused);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_len)
            .map_err(|_| IndexError::AllocationRefused)?;
        let retained_working_bytes = self.retained_working_bytes()?;
        let peak_working_bytes = external_working_bytes
            .checked_add(retained_working_bytes)
            .and_then(|total| total.checked_add(byte_vector_charge(bytes.capacity()).ok()?))
            .ok_or(IndexError::LimitExceeded)?;
        let internal_peak = retained_working_bytes
            .checked_add(byte_vector_charge(bytes.capacity())?)
            .ok_or(IndexError::LimitExceeded)?;
        if internal_peak > self.maximum_working_bytes
            || peak_working_bytes > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }
        encode_record(&mut bytes, record)?;
        if bytes.len() != encoded_len {
            return Err(IndexError::InvalidRecord);
        }
        let record_offset = (header_bytes as u64)
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
            let (kind, hardlink_group) = match record.node {
                IndexNode::File { hardlink_group, .. } => (IndexNodeKind::File, hardlink_group),
                IndexNode::Directory { .. } => (IndexNodeKind::Directory, None),
                IndexNode::Symlink { .. } => (IndexNodeKind::Symlink, None),
            };
            self.entries.push(BuildEntry {
                lookup: LookupSlot {
                    parent: record.parent,
                    name_hash: lookup_hash(record.parent, record.name),
                    record_offset,
                    record_id: id,
                },
                sibling_ordinal: record.sibling_ordinal,
                kind,
                hardlink_group,
            });
        }
        Ok(PushIndexResult {
            record_id: id,
            retained_working_bytes,
            peak_working_bytes,
        })
    }

    /// Finalizes the header and returns the writer and index summary.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Io`] when seeking, writing, or flushing fails.
    #[cfg(test)]
    pub(crate) fn finish(self) -> Result<StagedIndex<W>, IndexError> {
        let maximum = self.maximum_working_bytes;
        self.finish_with_external(0, maximum)
            .map(|result| result.staged)
    }

    pub(crate) fn finish_with_external(
        mut self,
        external_working_bytes: u64,
        aggregate_maximum_working_bytes: u64,
    ) -> Result<FinishIndexResult<W>, IndexError> {
        if self.records == 0 {
            return Err(IndexError::InvalidRecord);
        }
        let records_bytes = self.payload_bytes;
        let lookup_slots = lookup_slot_count(self.records)?;
        let lookup_slots_u64 =
            u64::try_from(lookup_slots).map_err(|_| IndexError::LimitExceeded)?;
        let lookup_bytes = lookup_allocation_bytes(lookup_slots)?;
        let directory_bytes = if self.format == BuildFormat::V3 {
            directory_allocation_bytes(lookup_slots)?
        } else {
            0
        };
        let peak_lookup_working = self.finish_working_bytes()?;
        if peak_lookup_working > self.maximum_working_bytes
            || external_working_bytes
                .checked_add(peak_lookup_working)
                .ok_or(IndexError::LimitExceeded)?
                > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }
        let next_payload = records_bytes
            .checked_add(lookup_bytes)
            .and_then(|bytes| bytes.checked_add(directory_bytes))
            .ok_or(IndexError::LimitExceeded)?;
        let header_bytes = self.header_bytes();
        let total_bytes = (header_bytes as u64)
            .checked_add(next_payload)
            .ok_or(IndexError::LimitExceeded)?;
        if total_bytes > self.maximum_bytes {
            return Err(IndexError::LimitExceeded);
        }

        let mut table = Vec::new();
        #[cfg(test)]
        let lookup_capacity = lookup_slots.max(self.lookup_capacity_floor);
        #[cfg(not(test))]
        let lookup_capacity = lookup_slots;
        table
            .try_reserve_exact(lookup_capacity)
            .map_err(|_| IndexError::AllocationRefused)?;
        let actual_internal_lookup = self
            .retained_working_bytes()?
            .checked_add(lookup_vector_charge(table.capacity())?)
            .ok_or(IndexError::LimitExceeded)?;
        let actual_lookup_peak = external_working_bytes
            .checked_add(actual_internal_lookup)
            .ok_or(IndexError::LimitExceeded)?;
        if actual_internal_lookup > self.maximum_working_bytes
            || actual_lookup_peak > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }
        table.extend(self.entries.iter().map(|entry| entry.lookup));
        table.sort_unstable_by_key(|entry| (entry.parent, entry.name_hash, entry.record_id));
        for slot in table {
            let encoded = encode_lookup_slot(slot);
            self.writer.write_all(&encoded).map_err(IndexError::Io)?;
            self.payload_hash.update(encoded);
        }
        let root_nlink = if self.format == BuildFormat::V3 {
            self.write_directory_table(
                lookup_slots,
                external_working_bytes,
                aggregate_maximum_working_bytes,
            )?
        } else {
            (0, actual_lookup_peak)
        };
        let (root_nlink, directory_peak) = root_nlink;
        let peak_working_bytes = actual_lookup_peak.max(directory_peak);
        self.payload_bytes = next_payload;

        let payload_digest: [u8; 32] = self.payload_hash.finalize().into();
        let mut header = HeaderEncoder::new();
        header.put(MAGIC)?;
        header.u32(match self.format {
            BuildFormat::V2 => VERSION_V2,
            BuildFormat::V3 => VERSION_V3,
        })?;
        header.u32(header_bytes as u32)?;
        header.put(&self.compiler_abi)?;
        header.put(self.tree.digest().as_bytes())?;
        header.u64(self.tree.encoded_size())?;
        header.put(self.root.digest().as_bytes())?;
        header.u64(self.root.encoded_size())?;
        header.u32(self.tree_features)?;
        header.u32(0)?;
        header.u64(self.records)?;
        header.u64(self.payload_bytes)?;
        header.put(&payload_digest)?;
        header.u64(records_bytes)?;
        header.u64(lookup_slots_u64)?;
        header.u32(LOOKUP_SLOT_BYTES as u32)?;
        header.u32(LOOKUP_HASH_SHA256)?;
        header.u64(0)?;
        if self.format == BuildFormat::V3 {
            header.u64(lookup_slots_u64)?;
            header.u32(DIRECTORY_SLOT_BYTES as u32)?;
            header.u32(0)?;
            header.u64(root_nlink)?;
            header.u64(0)?;
        }
        let header = header.finish(header_bytes)?;
        self.writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.writer.write_all(header))
            .and_then(|_| self.writer.flush())
            .map_err(IndexError::Io)?;
        let expected_end = header_bytes as u64 + self.payload_bytes;
        let actual_end = self.writer.seek(SeekFrom::End(0)).map_err(IndexError::Io)?;
        if actual_end != expected_end {
            return Err(IndexError::UnexpectedStagingLength);
        }
        Ok(FinishIndexResult {
            staged: StagedIndex {
                writer: self.writer,
                summary: IndexSummary {
                    compiler_abi: self.compiler_abi,
                    tree_digest: self.tree.digest(),
                    tree_size: self.tree.encoded_size(),
                    root_digest: self.root.digest(),
                    root_size: self.root.encoded_size(),
                    records: self.records,
                    bytes: header_bytes as u64 + self.payload_bytes,
                },
            },
            peak_working_bytes,
        })
    }

    pub(super) fn header_bytes(&self) -> usize {
        match self.format {
            BuildFormat::V2 => HEADER_BYTES_V2,
            BuildFormat::V3 => HEADER_BYTES_V3,
        }
    }

    pub(super) fn write_directory_table(
        &mut self,
        slots: usize,
        external_working_bytes: u64,
        aggregate_maximum_working_bytes: u64,
    ) -> Result<(u64, u64), IndexError> {
        let mut directory = Vec::new();
        #[cfg(test)]
        let slots = slots.max(self.directory_capacity_floor);
        directory
            .try_reserve_exact(slots)
            .map_err(|_| IndexError::AllocationRefused)?;
        directory.extend(self.entries.iter().map(|entry| DirectoryBuildSlot {
            slot: DirectorySlot {
                parent: entry.lookup.parent,
                record_offset: entry.lookup.record_offset,
                record_id: entry.lookup.record_id,
                nlink: if entry.kind == IndexNodeKind::Directory {
                    2
                } else {
                    1
                },
            },
            sibling_ordinal: entry.sibling_ordinal,
        }));
        let with_directory = external_working_bytes
            .checked_add(self.retained_working_bytes()?)
            .and_then(|bytes| {
                bytes.checked_add(directory_vector_charge(directory.capacity()).ok()?)
            })
            .ok_or(IndexError::LimitExceeded)?;
        let internal_with_directory = self
            .retained_working_bytes()?
            .checked_add(directory_vector_charge(directory.capacity())?)
            .ok_or(IndexError::LimitExceeded)?;
        if internal_with_directory > self.maximum_working_bytes
            || with_directory > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }

        let mut hardlinks = Vec::new();
        let hardlink_count = self
            .entries
            .iter()
            .filter(|entry| entry.hardlink_group.is_some())
            .count();
        let modeled_with_hardlinks = with_directory
            .checked_add(hardlink_vector_charge(hardlink_count)?)
            .ok_or(IndexError::LimitExceeded)?;
        let modeled_internal = internal_with_directory
            .checked_add(hardlink_vector_charge(hardlink_count)?)
            .ok_or(IndexError::LimitExceeded)?;
        if modeled_internal > self.maximum_working_bytes
            || modeled_with_hardlinks > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }
        #[cfg(test)]
        if self.refuse_hardlink_allocation {
            return Err(IndexError::AllocationRefused);
        }
        hardlinks
            .try_reserve_exact(hardlink_count)
            .map_err(|_| IndexError::AllocationRefused)?;
        hardlinks.extend(self.entries.iter().filter_map(|entry| {
            entry.hardlink_group.map(|group| HardlinkSlot {
                group,
                record_id: entry.lookup.record_id,
            })
        }));
        let actual = with_directory
            .checked_add(hardlink_vector_charge(hardlinks.capacity())?)
            .ok_or(IndexError::LimitExceeded)?;
        let actual_internal = internal_with_directory
            .checked_add(hardlink_vector_charge(hardlinks.capacity())?)
            .ok_or(IndexError::LimitExceeded)?;
        if actual_internal > self.maximum_working_bytes || actual > aggregate_maximum_working_bytes
        {
            return Err(IndexError::LimitExceeded);
        }

        let mut root_nlink = 2_u64;
        for entry in &self.entries {
            if entry.kind == IndexNodeKind::Directory {
                if entry.lookup.parent == 0 {
                    root_nlink = root_nlink.checked_add(1).ok_or(IndexError::LimitExceeded)?;
                } else {
                    // Before the final canonical sort, slot `record_id - 1`
                    // is the corresponding non-root record. Preserve this
                    // direct checked mapping so fanout accounting stays O(n).
                    let parent = usize::try_from(
                        entry
                            .lookup
                            .parent
                            .checked_sub(1)
                            .ok_or(IndexError::InvalidRecord)?,
                    )
                    .map_err(|_| IndexError::LimitExceeded)?;
                    let slot = directory.get_mut(parent).ok_or(IndexError::InvalidRecord)?;
                    slot.slot.nlink = slot
                        .slot
                        .nlink
                        .checked_add(1)
                        .ok_or(IndexError::LimitExceeded)?;
                }
            }
        }
        hardlinks.sort_unstable();
        let mut start = 0;
        while start < hardlinks.len() {
            let mut end = start + 1;
            while end < hardlinks.len() && hardlinks[end].group == hardlinks[start].group {
                end += 1;
            }
            let nlink = u64::try_from(end - start).map_err(|_| IndexError::LimitExceeded)?;
            for member in &hardlinks[start..end] {
                // The same record-order invariant permits O(1) assignment of
                // every member count before the directory table is reordered.
                let index = usize::try_from(
                    member
                        .record_id
                        .checked_sub(1)
                        .ok_or(IndexError::InvalidRecord)?,
                )
                .map_err(|_| IndexError::LimitExceeded)?;
                directory
                    .get_mut(index)
                    .ok_or(IndexError::InvalidRecord)?
                    .slot
                    .nlink = nlink;
            }
            start = end;
        }
        directory.sort_unstable_by_key(|entry| {
            (
                entry.slot.parent,
                entry.sibling_ordinal,
                entry.slot.record_id,
            )
        });
        for slot in directory {
            let encoded = encode_directory_slot(slot.slot);
            self.writer.write_all(&encoded).map_err(IndexError::Io)?;
            self.payload_hash.update(encoded);
        }
        Ok((root_nlink, actual))
    }
}
