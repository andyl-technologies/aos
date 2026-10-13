//! One original-paid manifest retained across bounded archive source reads.
//!
//! Each read still opens its current paths and releases all locks and file
//! descriptors before returning. Reuse requires the same authenticated root
//! generation and the exact immutable pack inode stamp. Replacement retires
//! the previous manifest before admitting another one.

use super::read_view::Manifest;
use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Retains one manifest and its same-operation resource custody.
pub(crate) struct Session {
    manifest: Option<Manifest>,
    generation: Option<[u8; 32]>,
    configuration: [u8; 32],
    original: DecodeBudget,
    #[cfg(test)]
    pub(crate) authenticated_manifests: u64,
    _credit: DecodeScratch,
}

impl Session {
    /// Admits the concrete session before constructing its control.
    ///
    /// # Errors
    /// Returns original revocation, resource exhaustion or allocation refusal.
    pub(crate) fn new(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        let credit = original
            .reserve_scratch_array::<Self>(1)
            .map_err(|error| batch::admission_under(original, error))?;
        Ok(Self {
            manifest: None,
            generation: None,
            configuration: backend.configuration,
            original: original.clone(),
            #[cfg(test)]
            authenticated_manifests: 0,
            _credit: credit,
        })
    }

    /// Reads one object through fresh paths under the retained operation.
    ///
    /// # Errors
    /// Returns path, integrity, generation, original or quota refusal.
    pub(crate) fn lookup(
        &mut self,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        checked::lookup_cached(backend, original, id, self, boundary)
    }

    /// Binds reuse to the exact freshly authenticated root image.
    ///
    /// # Errors
    /// Refuses another original account or another backend configuration.
    pub(super) fn bind_generation(
        &mut self,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        generation: [u8; 32],
    ) -> Result<(), StoreError> {
        if !self.original.same_account(original) || self.configuration != backend.configuration {
            return Err(StoreError::Incompatible);
        }
        if self.generation != Some(generation) {
            self.manifest = None;
            self.generation = Some(generation);
        }
        Ok(())
    }

    /// Authenticates the fresh file using one bounded retained manifest.
    ///
    /// # Errors
    /// Returns pack integrity, identity, original or resource refusal.
    pub(super) fn authenticate(
        &mut self,
        file: &File,
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        id: ContentId,
        entry: IndexEntry,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if let Some(manifest) = &self.manifest
            && manifest.id == entry.pack
        {
            return manifest.verify(file, original, id, entry, boundary);
        }
        // Retire the old body and its loan before the replacement's admission.
        self.manifest = None;
        self.manifest = Some(Manifest::load(
            file, backend, original, id, entry, boundary,
        )?);
        #[cfg(test)]
        {
            self.authenticated_manifests += 1;
        }
        checked_reader::check(original, boundary)
    }
}
