//! Pins one authenticated Packed generation for a bounded RAM inventory walk.
//!
//! The caller's Original pays the view, reader, active manifest and pack pin.
//! A physical service can supply authenticated rows, copied into independently
//! prepaid Original storage. Same-pack reads then use the ordinary manifest
//! path; every selected object still passes fresh stamp and complete EOF checks.

use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use std::os::unix::fs::MetadataExt;

use super::index_io::{Bytes, Operation};
use super::placement_index::{FreshRoot, IndexSnapshot, Reader as IndexReader};

#[cfg(test)]
pub(crate) mod cost;
pub(super) mod manifest;

pub(in crate::content_store::packed) use manifest::Manifest;

pub(crate) struct View {
    snapshot: IndexSnapshot,
    original: DecodeBudget,
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
        let snapshot = IndexSnapshot::read(backend, original, boundary)?;
        checked_reader::check(original, boundary)?;
        Ok(Self {
            snapshot,
            original: original.clone(),
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
        if !self.original.same_account(original) {
            return Err(StoreError::Incompatible);
        }
        let credit = original
            .reserve_scratch_bytes(std::mem::size_of::<Reader<'_>>() as u64)
            .map_err(|error| batch::admission_under(original, error))?;
        let mut operation = Operation {
            original: Some(original),
            boundary,
        };
        let index = self.snapshot.reader(backend, &mut operation)?;
        let page = operation.buffer(index_format::PAGE_BYTES)?;
        let root = if self.snapshot.header.arena.is_some() {
            Some(FreshRoot::new(&operation)?)
        } else {
            None
        };
        operation.check()?;
        Ok(Reader {
            index,
            original: original.clone(),
            generation: self.snapshot.digest(),
            page,
            root,
            last_pack: None,
            _credit: credit,
        })
    }
}

pub(crate) struct Reader<'view> {
    index: IndexReader<'view>,
    original: DecodeBudget,
    generation: [u8; 32],
    page: Bytes,
    root: Option<FreshRoot>,
    last_pack: Option<CachedPack>,
    _credit: DecodeScratch,
}

impl Reader<'_> {
    pub(crate) fn lookup(
        &mut self,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        physical: Option<&dyn super::super::StorePhysicalQuotaGuard>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        #[cfg(test)]
        cost::lookup();
        if !self.original.same_account(original) {
            return Err(StoreError::Incompatible);
        }
        checked_reader::check(original, boundary)?;
        let mut operation = Operation {
            original: Some(original),
            boundary,
        };
        let found = if let Some(root) = &mut self.root {
            self.index.find_into_reusing_root(
                index_format::Key::object(id),
                &mut self.page,
                root,
                &mut operation,
            )?
        } else {
            self.index.find_into(
                index_format::Key::object(id),
                &mut self.page,
                &mut operation,
            )?
        };
        let entry = found
            .map(index_format::Value::entry)
            .transpose()?
            .ok_or(StoreError::NotFound { id })?;

        if self
            .last_pack
            .as_ref()
            .is_none_or(|pack| pack.id != entry.pack)
        {
            #[cfg(test)]
            cost::switch_pack();
            // Retire the prior pin before opening its replacement: the view
            // keeps at most two locks, one arena and one pack descriptor.
            self.last_pack = None;
            self.last_pack = Some(CachedPack::open(
                backend,
                original,
                id,
                entry,
                physical.is_none(),
                boundary,
            )?);
        }
        let pack = self.last_pack.as_mut().ok_or(StoreError::Corrupt { id })?;
        if let Some(physical) = physical {
            if let Some(manifest) = &pack.manifest {
                manifest.verify(
                    pack.file.file().ok_or(StoreError::Corrupt { id })?,
                    original,
                    id,
                    entry,
                    boundary,
                )?;
            } else {
                let mut request = super::shared_cache::PackedManifestRead::new(
                    pack.file.file().ok_or(StoreError::Corrupt { id })?,
                    backend,
                    original,
                    id,
                    entry,
                    self.generation,
                    boundary,
                );
                physical.read_packed_manifest(&mut request)?;
                pack.manifest = request.finish()?;
            }
        } else {
            pack.verify(original, id, entry, boundary)?;
        }
        checked::source_from_pin(original, id, entry, pack.file.clone(), boundary)
    }
}

struct CachedPack {
    file: checked::PackPin,
    id: PackId,
    manifest: Option<Manifest>,
}

impl CachedPack {
    fn open(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        retain_manifest: bool,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let pin_credit = original
            .reserve_scratch_bytes(checked::PackPin::allocation_bytes())
            .map_err(|error| batch::admission_under(original, error))?;
        let name = index_io::pack_name(entry.pack);
        let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
        let path = checked_io::path(&backend.packs, name, original)?;
        let file = checked_io::open_file(
            path.as_path(),
            OFlags::RDONLY,
            "open-packed-checked-object",
            original,
            boundary,
        )
        .map_err(|error| {
            if matches!(&error, StoreError::StreamIo { source, .. }
                if source.kind() == io::ErrorKind::NotFound)
            {
                StoreError::Corrupt { id }
            } else {
                error
            }
        })?;
        let manifest = if retain_manifest {
            Some(Manifest::load(
                file.file(),
                backend,
                original,
                id,
                entry,
                boundary,
            )?)
        } else {
            None
        };
        checked_reader::check(original, boundary)?;
        let (file, descriptor) = file.into_parts();
        Ok(Self {
            file: checked::PackPin::with_resources(file, pin_credit, descriptor),
            id: entry.pack,
            manifest,
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
        self.manifest
            .as_ref()
            .ok_or(StoreError::Corrupt { id })?
            .verify(file, original, id, entry, boundary)
    }
}

#[cfg(test)]
mod tests;
