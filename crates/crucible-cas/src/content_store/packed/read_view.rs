//! Pins one authenticated Packed generation for a bounded RAM inventory walk.
//!
//! The caller's original account pays every buffer, control and descriptor.
//! One last-pack metadata cache is bounded by the existing manifest limit;
//! every selected object still uses the existing full ContentId EOF reader.

use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use std::os::unix::fs::MetadataExt;

use super::index_io::{Bytes, Operation};
use super::placement_index::{IndexSnapshot, Reader as IndexReader};

pub(crate) struct View {
    snapshot: IndexSnapshot,
    _state: checked_io::OwnedFile,
    _lifecycle: checked_io::OwnedFile,
    _credit: DecodeScratch,
}

impl View {
    pub(crate) fn begin(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        checked_reader::check(original, boundary)?;
        let credit = original
            .reserve_scratch_bytes(std::mem::size_of::<Self>() as u64)
            .map_err(|error| batch::admission_under(original, error))?;
        let lifecycle = checked_io::lock(backend, LIFECYCLE_LOCK_FILE, true, original, boundary)?;
        let state = checked_io::lock(backend, STATE_LOCK_FILE, false, original, boundary)?;
        let snapshot = IndexSnapshot::load(backend, original, boundary)?;
        checked_reader::check(original, boundary)?;
        Ok(Self {
            snapshot,
            _state: state,
            _lifecycle: lifecycle,
            _credit: credit,
        })
    }

    pub(crate) fn reader<'view>(
        &'view self,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Reader<'view>, StoreError> {
        let credit = original
            .reserve_scratch_bytes(std::mem::size_of::<Reader<'_>>() as u64)
            .map_err(|error| batch::admission_under(original, error))?;
        let mut operation = Operation {
            original: Some(original),
            boundary,
        };
        let index = self.snapshot.reader(backend, &mut operation)?;
        let page = operation.buffer(index_format::PAGE_BYTES)?;
        operation.check()?;
        Ok(Reader {
            index,
            page,
            last_pack: None,
            _credit: credit,
        })
    }
}

pub(crate) struct Reader<'view> {
    index: IndexReader<'view>,
    page: Bytes,
    last_pack: Option<CachedPack>,
    _credit: DecodeScratch,
}

impl Reader<'_> {
    pub(crate) fn lookup(
        &mut self,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        checked_reader::check(original, boundary)?;
        let entry = self
            .index
            .find_into(
                index_format::Key::object(id),
                &mut self.page,
                &mut Operation {
                    original: Some(original),
                    boundary,
                },
            )?
            .map(index_format::Value::entry)
            .transpose()?
            .ok_or(StoreError::NotFound { id })?;

        if self
            .last_pack
            .as_ref()
            .is_none_or(|pack| pack.id != entry.pack)
        {
            // Retire the prior pin before opening its replacement: the view
            // keeps at most two locks, one arena and one pack descriptor.
            self.last_pack = None;
            self.last_pack = Some(CachedPack::open(backend, original, id, entry, boundary)?);
        }
        let pack = self.last_pack.as_ref().ok_or(StoreError::Corrupt { id })?;
        pack.verify(original, id, entry, boundary)?;
        checked::source_from_pin(original, id, entry, pack.file.clone(), boundary)
    }
}

struct CachedPack {
    file: checked::PackPin,
    entries: Vec<PackManifestEntry>,
    id: PackId,
    stamp: FileStamp,
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

impl CachedPack {
    fn open(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let pin_credit = original
            .reserve_scratch_bytes(checked::PackPin::allocation_bytes())
            .map_err(|error| batch::admission_under(original, error))?;
        let name = index_io::pack_name(entry.pack);
        let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
        let path = checked_io::path(&backend.packs, name, original)?;
        let file = checked_io::open_file(path.as_path(), OFlags::RDONLY, "open-packed-checked-object", original, boundary)
            .map_err(|error| if matches!(&error, StoreError::StreamIo { source, .. } if source.kind() == io::ErrorKind::NotFound) {
                StoreError::Corrupt { id }
            } else { error })?;
        let stamp = FileStamp::read(file.file(), original, boundary)?;
        let mut fixed = [0_u8; PACK_MAGIC.len() + 32 + 4 + 4];
        checked_io::read_exact_at(file.file(), &mut fixed, 0, original, boundary)?;
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
            file.file(),
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
        if entries.len() != count || FileStamp::read(file.file(), original, boundary)? != stamp {
            return Err(StoreError::Corrupt { id });
        }
        checked_reader::check(original, boundary)?;
        let (file, descriptor) = file.into_parts();
        Ok(Self {
            file: checked::PackPin::with_resources(file, pin_credit, descriptor),
            entries,
            id: entry.pack,
            stamp,
            _credit: credit,
        })
    }

    fn verify(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let file = self.file.file().ok_or(StoreError::Corrupt { id })?;
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

#[cfg(test)]
mod tests;
