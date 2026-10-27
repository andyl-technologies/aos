//! Selects real chunk serving or native sealing for the configured reassembly mode.
//!
//! Sealed results retain the original completed producer publication. They are
//! kernel file capabilities backed by that job's actual funding, not invented
//! consumer leases. Cache handoff completes original source retirement before
//! releasing producer protection; cancellation leaves the physical job owned.

use super::{NativeChunkedObject, NativeContentStore, native_failure};
use crate::host_cache::{
    NativeCacheHandoffReport, NativeInlinePublication, NativeManifestPublication,
    NativeSealedObjectLease,
};
use std::{fs::File, io};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::{
    host::{
        cache::ReassemblyMode,
        publication::{PublicationClaim, PublicationRecipe},
    },
    store::{ContentStore, StoreErrorKind, StoreFailure},
};

/// Owns the actual representation selected by native reassembly policy.
pub enum NativePreparedObject<'store> {
    /// Streams a fully verified multi-chunk object under finite consumer grants.
    Chunked(Box<NativeChunkedObject<'store>>),
    /// Retains an independently verified fs-verity publication and producer funding.
    Sealed(NativeSealedObject<'store>),
}

/// Retains a real whole-file publication on its original running native store.
///
/// Borrowed handles refer to the actual verified read-only fs-verity inode.
/// This value holds producer protection; it grants no guest authorization or
/// separately acknowledged consumer lease. Dropping it retains physical funding
/// on the owner until reconciliation. Call [`Self::into_cache`] after use to
/// complete native source cleanup and release producer ownership durably.
pub struct NativeSealedObject<'store> {
    store: &'store NativeContentStore,
    identity: Identity,
    publication: Publication,
}

enum Publication {
    Inline(NativeInlinePublication),
    Manifest(NativeManifestPublication),
}

impl NativeContentStore {
    /// Prepares an object using the implemented native reassembly policy.
    ///
    /// `never` streams multi-chunk objects; `always` publishes a whole sealed
    /// inode. Inline and single-chunk objects always take the direct sealing
    /// path. Canonical metadata selects a path only: the original native owner
    /// independently verifies all publication inputs and actual physical custody.
    /// No whole manifest plaintext allocation is needed for publication.
    ///
    /// # Errors
    /// Refuses unsupported identities, absent or invalid canonical metadata,
    /// corrupt plaintext or whole-file hashes, unavailable native grants,
    /// exhausted operator bounds, or failed native publication and accounting.
    /// Accepted physical work remains owned after errors or cancellation.
    pub async fn prepare_object(
        &self,
        identity: &Identity,
        mode: ReassemblyMode,
    ) -> Result<NativePreparedObject<'_>, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let publication = match identity.kind() {
            IdentityKind::Chunk => {
                let publication = self
                    .ready
                    .owner()
                    .publish_resident_inline(identity.clone())
                    .await
                    .map_err(|error| native_failure(error, identity))?;
                Publication::Inline(publication)
            }
            IdentityKind::Manifest => {
                let canonical = self.get(identity, None).await?;
                let descriptor = Descriptor::from_identity(&TERRANE_V1, identity, &canonical)
                    .map_err(|error| {
                        native_failure(io::Error::new(io::ErrorKind::InvalidData, error), identity)
                    })?;
                let claim = PublicationClaim::new(
                    self.ready.layout().layout().domain().to_owned(),
                    PublicationRecipe::Manifest {
                        object: descriptor,
                        canonical_manifest: canonical,
                    },
                    self.ready.layout().layout().chunk_profile(),
                )
                .map_err(|error| native_failure(error, identity))?;
                if !mode.requires_sealed_file(&claim) {
                    return self
                        .open_manifest_chunks(identity)
                        .await
                        .map(|object| NativePreparedObject::Chunked(Box::new(object)));
                }
                Publication::Manifest(
                    self.ready
                        .owner()
                        .publish_manifest(identity.clone())
                        .await
                        .map_err(|error| native_failure(error, identity))?,
                )
            }
            _ => return Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        };
        Ok(NativePreparedObject::Sealed(NativeSealedObject {
            store: self,
            identity: identity.clone(),
            publication,
        }))
    }
}

impl NativeSealedObject<'_> {
    /// Borrows the object identity checked against the actual sealed publication.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Borrows the independently verified canonical content declaration.
    pub fn claim(&self) -> &PublicationClaim {
        match &self.publication {
            Publication::Inline(publication) => publication.claim(),
            Publication::Manifest(publication) => publication.claim(),
        }
    }

    /// Borrows the actual verified read-only fs-verity inode for native use.
    ///
    /// The original producer job retains its funding while this object exists.
    /// Cloned descriptors can retain physical charge after cache handoff; only
    /// actual kernel quota observations establish when allocation is released.
    pub fn handle(&self) -> &File {
        match &self.publication {
            Publication::Inline(publication) => publication.handle(),
            Publication::Manifest(publication) => publication.handle(),
        }
    }

    /// Synchronizes an independent consumer pin over this complete sealed file.
    ///
    /// The acknowledged grant can retain delegated backing while this producer
    /// completes [`Self::into_cache`]. The consumer must separately renew or
    /// release its lease and retain its backing owner through actual worker and
    /// kernel closure. This operation grants no repository Read permission.
    ///
    /// # Errors
    /// Refuses an elapsed deadline, unavailable owner, exhausted resources,
    /// changed publication or native durability, integrity and quota failures.
    pub async fn pin_consumer(
        &self,
        expires: u64,
    ) -> Result<NativeSealedObjectLease, StoreFailure> {
        self.store
            .ready
            .owner()
            .pin_sealed_object(self.identity.clone(), expires)
            .await
            .map_err(|error| native_failure(error, &self.identity))
    }

    /// Finishes genuine source cleanup and transfers producer custody to the cache.
    ///
    /// Independent consumer pins remain live. Waiting uses the configured native
    /// retirement interval; the publisher still enforces its original deadline.
    ///
    /// # Errors
    /// Refuses unavailable timers or queues, active producer views, failed
    /// native cleanup, changed custody, durability or quota reconciliation.
    /// Accepted effects remain physically owned after errors or cancellation.
    pub async fn into_cache(self) -> Result<NativeCacheHandoffReport, StoreFailure> {
        let result = match self.publication {
            Publication::Inline(publication) => {
                publication
                    .complete_cache_handoff(self.store.ready.owner())
                    .await
            }
            Publication::Manifest(publication) => {
                publication
                    .complete_cache_handoff(self.store.ready.owner())
                    .await
            }
        };
        result.map_err(|error| native_failure(error, &self.identity))
    }
}
