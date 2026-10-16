//! Submits only genuinely retained metadata and keeps its pin with the backing.
//!
//! Durable receipt checks occur before the client RPC lock. Successful sealed
//! read accessors borrow immutable fields and never consult embedded state.

use std::{fs::File, os::fd::AsFd, sync::Arc};

use terrane::host::{
    cache::HostDomainLocation,
    publication::{PublicationClaim, PublicationRecipe, VerityBinding},
};

use super::super::wire::{BodyKey, BodyKind, Claim, Operation};
use super::{Client, Error, PeerPublishedObject, RequestPayload, invalidate, receipt};
use crate::host_cache::{NativeHostLayout, RetainedManifest};

/// Keeps verified manifest-backed bytes and their genuine durable pin together.
///
/// Read accessors take no embedded-state lock. The retained metadata receipt is
/// private, cannot be extracted and remains owned for the complete backing
/// lifetime. No raw file, retention identifier or boolean constructor exists.
pub struct PeerManifestPublishedObject {
    object: PeerPublishedObject<HostDomainLocation>,
    _retention: RetainedManifest,
}

impl PeerManifestPublishedObject {
    /// Borrows verified sealed bytes without consulting embedded metadata state.
    pub fn handle(&self) -> &File {
        self.object.handle()
    }

    /// Borrows the actual independently measured kernel binding without locking.
    pub fn binding(&self) -> &VerityBinding {
        self.object.binding()
    }

    /// Borrows the canonical reconstruction claim already verified for these bytes.
    pub fn claim(&self) -> &PublicationClaim {
        self.object.claim()
    }

    /// Borrows the retained root guard without consulting pin state.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.object.layout()
    }

    /// Borrows the publisher-issued inode token without acquiring a state lock.
    pub fn incarnation(&self) -> &[u8; 32] {
        self.object.incarnation()
    }
}

impl Client<HostDomainLocation> {
    /// Publishes manifest-backed plaintext using actual durable reconstruction custody.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign pin custody, another actual session/barrier, invalid
    /// manifest/profile/range data, readonly descriptor violations, unavailable
    /// publisher custody or failed kernel/content verification. Physical native
    /// work and durable pins are not cancelled or released by an uncertain reply.
    pub(crate) fn publish_manifest(
        &self,
        source: File,
        retained: RetainedManifest,
    ) -> Result<PeerManifestPublishedObject, Error> {
        self.manifest_exchange(Operation::Publish, Some(source), retained)
    }

    /// Adopts canonical manifest-backed bytes while retaining their actual metadata pin.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign retention, another actual client/barrier, invalid
    /// metadata, an absent canonical object and failed native or byte checks.
    pub(crate) fn adopt_manifest(
        &self,
        retained: RetainedManifest,
    ) -> Result<PeerManifestPublishedObject, Error> {
        self.manifest_exchange(Operation::Adopt, None, retained)
    }

    /// Inspects sealed manifest content through actual adoption and retained metadata.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign retention, another actual session/barrier, invalid
    /// metadata, missing native backing and failed native/content verification.
    pub(crate) fn inspect_manifest(
        &self,
        retained: RetainedManifest,
    ) -> Result<PeerManifestPublishedObject, Error> {
        self.manifest_exchange(Operation::InspectBody, None, retained)
    }

    fn manifest_exchange(
        &self,
        operation: Operation,
        source: Option<File>,
        retained: RetainedManifest,
    ) -> Result<PeerManifestPublishedObject, Error> {
        let session = retained.publisher_session();
        if !retained.matches_client(self)
            || !std::ptr::eq(self, session.as_ref())
            || !Arc::ptr_eq(&self.layout, retained.layout())
            || self.cache_incarnation != *retained.cache_incarnation()
        {
            return Err(Error::Invalid(
                "retained metadata belongs to another actual publisher session",
            ));
        }
        let context = session.recovery_context()?;
        // This may lock the metadata owner. It must precede, and never run
        // underneath, the client RPC mutex or an externally held owner mutex.
        retained.check_current()?;
        let claim = self.retained_claim(&retained)?;
        let range = retained.manifest_range();
        let descriptor = claim.descriptor().encode();
        let payload = RequestPayload {
            claim: Some(Claim {
                descriptor: descriptor.clone(),
                chunk_profile: self.config.chunk_profile_name.clone(),
                plaintext_size: claim.plaintext_size(),
                manifest_offset: range.start,
                manifest_length: range.length,
                retention_id: retained.retention_id().to_vec(),
            }),
            body: Some(BodyKey {
                kind: BodyKind::Sealed as i32,
                descriptor,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut state = self.lock()?;
        self.require_recovery_context(&state, &context)?;
        let mut files = Vec::with_capacity(2);
        if let Some(source) = &source {
            files.push(source.as_fd());
        }
        files.push(retained.metadata_file().as_fd());
        let received = self.exchange_payload_files(&mut state, operation, payload, &files)?;
        let object = match receipt::published(
            received,
            self.layout.clone(),
            self.config.identities.publish_uid,
            claim,
        ) {
            Ok(object) => object,
            Err(error) => {
                invalidate(&mut state);
                return Err(error);
            }
        };
        Ok(PeerManifestPublishedObject {
            object,
            _retention: retained,
        })
    }

    fn retained_claim(&self, retained: &RetainedManifest) -> Result<PublicationClaim, Error> {
        let original = retained.claim();
        let canonical = original
            .canonical_manifest()
            .ok_or(Error::Invalid("retained claim is not a manifest"))?;
        let range = retained.manifest_range();
        let metadata = retained.metadata_file().metadata()?;
        if original.domain() != self.layout.layout().domain()
            || range.length != original.descriptor().size()
            || range.length
                != u64::try_from(canonical.len())
                    .map_err(|_| Error::Invalid("manifest length overflow"))?
            || range
                .start
                .checked_add(range.length)
                .is_none_or(|end| end > metadata.len())
        {
            return Err(Error::Invalid(
                "retained manifest domain or physical range mismatch",
            ));
        }
        Ok(PublicationClaim::new(
            original.domain().to_owned(),
            PublicationRecipe::Manifest {
                object: original.descriptor().clone(),
                canonical_manifest: canonical.to_vec(),
            },
            self.layout.layout().chunk_profile(),
        )?)
    }
}
