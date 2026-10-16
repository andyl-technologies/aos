//! One original-paid archive session with bounded manifest selection state.
//!
//! Each read opens fresh paths and closes all locks and descriptors before
//! returning. An ordinary read retains one Original-paid manifest; a physical
//! service may retain shared rows while this session keeps only an inert
//! configuration/generation/pack/count hint. Reuse still checks the actual
//! immutable inode stamp, selected coordinates and complete object EOF.
//! Replacement retires ordinary rows before admitting another manifest.

use super::read_view::Manifest;
use super::*;
use crate::content_store::{batch, checked_reader};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Retains same-operation custody for one bounded archive read session.
pub(crate) struct Session {
    manifest: Option<Manifest>,
    // Session::new prepays this inline selection geometry through sizeof<Self>.
    manifest_hint: Option<super::shared_cache::ManifestHint>,
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
            manifest_hint: None,
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
        physical: Option<&dyn super::super::StorePhysicalQuotaGuard>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        checked::lookup_cached(backend, original, id, self, physical, boundary)
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
            self.manifest_hint = None;
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
        physical: Option<&dyn super::super::StorePhysicalQuotaGuard>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if let Some(manifest) = &self.manifest
            && manifest.id == entry.pack
        {
            return manifest.verify(file, original, id, entry, boundary);
        }
        if let Some(physical) = physical {
            self.manifest = None;
            let generation = self.generation.ok_or(StoreError::Incompatible)?;
            let mut request = super::shared_cache::PackedManifestRead::new(
                file, backend, original, id, entry, generation, boundary,
            )
            .with_retention_hint(self.manifest_hint.take());
            physical.read_packed_manifest(&mut request)?;
            #[cfg(test)]
            if request.authenticated() {
                self.authenticated_manifests += 1;
            }
            let hint = request.retention_hint();
            self.manifest = request.finish()?;
            self.manifest_hint = hint;
            return Ok(());
        }
        // Retire the old body and its loan before the replacement's admission.
        self.manifest = None;
        self.manifest_hint = None;
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
