//! Authenticated metadata for one exact immutable pack inode.
//!
//! Stamp reuse applies only under a freshly authenticated placement generation
//! and the store protocol's immutable committed-pack contract. It is not a
//! substitute for byte authentication against adversarial timestamp forgery.
//! Every selected object still reaches its full ContentId and EOF check.

use super::*;

/// Retains rows under either its Original or the enclosing service cache.
pub(in crate::content_store::packed) struct Manifest {
    /// Contains strictly ordered, fully authenticated manifest entries.
    pub(in crate::content_store::packed) entries: Vec<PackManifestEntry>,
    /// Names the content-derived pack identity authenticated at loading.
    pub(in crate::content_store::packed) id: PackId,
    pub(in crate::content_store::packed) stamp: FileStamp,
    // Shared rows retain neither a request Original nor its credit. Only the
    // enclosing cache may call load_shared after its service admission.
    original: Option<DecodeBudget>,
    _credit: Option<DecodeScratch>,
}

/// Owns a preallocated active copy before borrowing any service rows.
pub(in crate::content_store::packed) struct ManifestCopy {
    entries: Vec<PackManifestEntry>,
    selection: Option<(PackId, FileStamp)>,
    original: DecodeBudget,
    // The row allocation closes before its Original credit returns.
    credit: DecodeScratch,
}

impl ManifestCopy {
    pub(in crate::content_store::packed) fn copy_from(
        &mut self,
        source: &Manifest,
        selected: ContentId,
    ) -> Result<(), StoreError> {
        if self.selection.is_some() || !self.entries.is_empty() {
            return Err(StoreError::Incompatible);
        }
        if source.entries.len() != self.entries.capacity() {
            return Err(StoreError::Corrupt { id: selected });
        }
        // PackManifestEntry contains only closed scalar fields. Exact capacity
        // was allocated before locking: this copy neither allocates nor calls
        // an Original, provider, filesystem or caller boundary.
        self.entries.extend_from_slice(&source.entries);
        self.selection = Some((source.id, source.stamp));
        Ok(())
    }

    pub(in crate::content_store::packed) fn finish(self) -> Result<Manifest, StoreError> {
        let (id, stamp) = self.selection.ok_or(StoreError::Incompatible)?;
        Ok(Manifest {
            entries: self.entries,
            id,
            stamp,
            original: Some(self.original),
            _credit: Some(self.credit),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::content_store::packed) struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    pub(in crate::content_store::packed) fn read(
        file: &File,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        checked_reader::check(original, boundary)?;
        let metadata = file.metadata().map_err(|source| StoreError::StreamIo {
            operation: "inspect-packed-inventory-pin",
            source,
        })?;
        if !metadata.is_file() {
            return Err(StoreError::Incompatible);
        }
        checked_reader::check(original, boundary)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

impl Manifest {
    /// Authenticates one complete pack manifest under its original account.
    ///
    /// # Errors
    /// Returns header, checksum, identity, original, allocation or quota refusal.
    pub(in crate::content_store::packed) fn load(
        file: &File,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let count = Self::row_count(file, backend, original, boundary)?;
        Self::load_with_count(file, backend, original, id, entry, boundary, count)
    }

    // The caller has checked the bounded header for selection. load_shared
    // still rereads that actual header and requires count == paid_rows before
    // allocating, so this does not elide the concurrent-mutation check.
    pub(in crate::content_store::packed) fn load_with_count(
        file: &File,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        count: usize,
    ) -> Result<Self, StoreError> {
        let bytes = Self::owned_bytes(count)?;
        let credit = original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| batch::admission_under(original, error))?;
        let mut manifest = Self::load_shared(file, backend, original, id, entry, boundary, count)?;
        manifest.original = Some(original.clone());
        manifest._credit = Some(credit);
        Ok(manifest)
    }

    pub(in crate::content_store::packed) fn prepare_copy(
        original: &DecodeBudget,
        count: usize,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<ManifestCopy, StoreError> {
        checked_reader::check(original, boundary)?;
        let credit = original
            .reserve_scratch_bytes(Self::owned_bytes(count)?)
            .map_err(|error| batch::admission_under(original, error))?;
        checked_reader::check(original, boundary)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|error| batch::allocation_under(original, error))?;
        if entries.capacity() != count {
            return Err(StoreError::Quota);
        }
        checked_reader::check(original, boundary)?;
        Ok(ManifestCopy {
            entries,
            selection: None,
            original: original.clone(),
            credit,
        })
    }

    fn owned_bytes(count: usize) -> Result<u64, StoreError> {
        count
            .checked_mul(std::mem::size_of::<PackManifestEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StoreError::Quota)
    }

    pub(in crate::content_store::packed) fn row_count(
        file: &File,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        let mut fixed = [0_u8; PACK_MAGIC.len() + 32 + 4 + 4];
        checked_io::read_exact_at(file, &mut fixed, 0, original, boundary)?;
        let mut cursor = format::PackedCursor::new(&fixed);
        if cursor.fixed(PACK_MAGIC.len())? != PACK_MAGIC
            || cursor.array_32()? != backend.configuration
        {
            return Err(StoreError::Incompatible);
        }
        let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
        if count == 0
            || count > MAX_PACK_ENTRIES
            || u64::from(cursor.u32()?) > MAX_PACK_MANIFEST_BYTES
        {
            return Err(StoreError::Incompatible);
        }
        Ok(count)
    }

    // Only the scoped service cache calls this after admitting the row array
    // and containing cache node. It retains no caller account or authority.
    pub(in crate::content_store::packed) fn load_shared(
        file: &File,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        paid_rows: usize,
    ) -> Result<Self, StoreError> {
        let stamp = FileStamp::read(file, original, boundary)?;
        let mut fixed = [0_u8; PACK_MAGIC.len() + 32 + 4 + 4];
        checked_io::read_exact_at(file, &mut fixed, 0, original, boundary)?;
        let mut cursor = format::PackedCursor::new(&fixed);
        if cursor.fixed(PACK_MAGIC.len())? != PACK_MAGIC
            || cursor.array_32()? != backend.configuration
        {
            return Err(StoreError::Incompatible);
        }
        let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Quota)?;
        let length = u64::from(cursor.u32()?);
        if count == 0 || count > MAX_PACK_ENTRIES || length > MAX_PACK_MANIFEST_BYTES {
            return Err(StoreError::Incompatible);
        }
        if count != paid_rows {
            return Err(StoreError::Corrupt { id });
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|error| batch::allocation_under(original, error))?;
        if entries.capacity() != count {
            return Err(StoreError::Quota);
        }
        checked::authenticate_manifest_into(
            file,
            checked::ManifestSelection {
                configuration: backend.configuration,
                id,
                entry,
                file_length: stamp.length,
            },
            original,
            boundary,
            &mut |candidate| {
                if entries.len() == count {
                    return Err(StoreError::Corrupt { id });
                }
                entries.push(candidate);
                Ok(())
            },
        )?;
        if entries.len() != count || FileStamp::read(file, original, boundary)? != stamp {
            return Err(StoreError::Corrupt { id });
        }
        checked_reader::check(original, boundary)?;
        #[cfg(test)]
        super::cost::authenticated(count, length);
        Ok(Self {
            entries,
            id: entry.pack,
            stamp,
            original: None,
            _credit: None,
        })
    }

    /// Checks an exact selected entry against the fresh pinned file.
    ///
    /// # Errors
    /// Refuses another original, a changed file stamp or mismatched coordinates.
    pub(in crate::content_store::packed) fn verify(
        &self,
        file: &File,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if self
            .original
            .as_ref()
            .is_some_and(|owner| !owner.same_account(original))
        {
            return Err(StoreError::Incompatible);
        }
        if FileStamp::read(file, original, boundary)? != self.stamp {
            return Err(StoreError::Corrupt { id });
        }
        self.verify_selection(id, entry)?;
        checked_reader::check(original, boundary)
    }

    pub(in crate::content_store::packed) fn verify_selection(
        &self,
        id: ContentId,
        entry: IndexEntry,
    ) -> Result<(), StoreError> {
        let position = self
            .entries
            .binary_search_by_key(&id, |candidate| candidate.id)
            .map_err(|_| StoreError::Corrupt { id })?;
        let found = &self.entries[position];
        if (found.offset, found.length) != (entry.offset, entry.length) || entry.pack != self.id {
            return Err(StoreError::Corrupt { id });
        }
        Ok(())
    }
}
