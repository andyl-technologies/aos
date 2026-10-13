//! Original-paid authenticated metadata for one exact immutable pack inode.
//!
//! Stamp reuse applies only under a freshly authenticated placement generation
//! and the store protocol's immutable committed-pack contract. It is not a
//! substitute for byte authentication against adversarial timestamp forgery.
//! Every selected object still reaches its full ContentId and EOF check.

use super::*;

/// Retains authenticated rows for one immutable pack and original owner.
pub(in crate::content_store::packed) struct Manifest {
    /// Contains strictly ordered, fully authenticated manifest entries.
    pub(in crate::content_store::packed) entries: Vec<PackManifestEntry>,
    /// Names the content-derived pack identity authenticated at loading.
    pub(in crate::content_store::packed) id: PackId,
    stamp: FileStamp,
    original: DecodeBudget,
    _credit: DecodeScratch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    fn read(
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
        let bytes = count
            .checked_mul(std::mem::size_of::<PackManifestEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(StoreError::Quota)?;
        let credit = original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| batch::admission_under(original, error))?;
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
        Ok(Self {
            entries,
            id: entry.pack,
            stamp,
            original: original.clone(),
            _credit: credit,
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
        if !self.original.same_account(original) {
            return Err(StoreError::Incompatible);
        }
        if FileStamp::read(file, original, boundary)? != self.stamp {
            return Err(StoreError::Corrupt { id });
        }
        let position = self
            .entries
            .binary_search_by_key(&id, |candidate| candidate.id)
            .map_err(|_| StoreError::Corrupt { id })?;
        let found = &self.entries[position];
        if (found.offset, found.length) != (entry.offset, entry.length) || entry.pack != self.id {
            return Err(StoreError::Corrupt { id });
        }
        checked_reader::check(original, boundary)
    }
}
