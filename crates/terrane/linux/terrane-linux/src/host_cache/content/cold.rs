//! Prepares missing whole files from an original signed repository selection.
//!
//! Lower-store reads warm bounded inputs; only the native publisher establishes
//! whole-file custody. This operation retains producer funding and does not
//! disclose an authorized file grant. Its caller finishes the same scoped Read
//! through the ordinary native backing bridge before handing out a descriptor.

use super::diagnostic::stage;
use super::{NativePreparedObject, NativeReadDriver, NativeSealedObject, NativeSealedReadPolicy};
use std::{io, time::Duration};
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    manifest::Manifest,
    properties::{EffectiveProperties, PropertyName, Value},
    tree_format::ContentRef,
};
use terrane_sdk::{
    bucket::BucketBinding,
    guard::ReadStoragePolicy,
    host::cache::ReassemblyMode,
    repository::{Error, PreparedFileRead},
    store::{Clock, ContentStore, ContentUpload, MetaUpload, Store, StoreErrorKind, StoreFailure},
};
use tokio::time::{Instant, sleep, timeout_at};

struct ColdFilePolicy {
    mode: ReassemblyMode,
}

impl ReadStoragePolicy for ColdFilePolicy {
    fn validate(&self, properties: &EffectiveProperties<'_>) -> Result<(), StoreFailure> {
        NativeSealedReadPolicy.validate(properties)?;
        let expected = match self.mode {
            ReassemblyMode::Never => "never",
            ReassemblyMode::Always => "always",
        };
        if properties.get(PropertyName::Reassembly) != Some(&Value::Text(expected)) {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(())
    }
}

impl<S: ContentStore + BucketBinding> NativeReadDriver<S> {
    /// Fetches and seals a missing file selected by an original scoped Read.
    ///
    /// Signed erasure and reassembly requirements and the physical domain are
    /// checked before content I/O. Canonical manifest metadata selects bounded
    /// ordered chunk inputs; the actual publisher independently verifies their
    /// CDC positions, total length and whole-file hashes without allocating the
    /// complete plaintext. Multi-chunk files under `never` and the deferred
    /// `smart` mode cannot produce a whole-file result through this operation.
    ///
    /// The finite total budget includes lower circuit waits, native admission,
    /// consumer release grace, an actual lease sweep and publication. This is a
    /// fetch budget, independent of individual worker open deadlines. A serving
    /// owner must retain this future when an open waiter expires. Cancellation
    /// retains accepted work with the native owner, but does not itself promise
    /// completed cache handoff.
    ///
    /// The returned producer object must remain private until the original
    /// selection finishes through the ordinary native backing bridge. The
    /// caller completes its cache handoff even after a refused closing Read.
    /// Existing whole sealed files use that bridge directly, without this fetch.
    ///
    /// # Errors
    /// Refuses unsupported signed storage policy, another physical domain,
    /// invalid or overlarge budgets, manifest/size mismatches, input bounds,
    /// missing native admissions, elapsed deadlines and native verification,
    /// durability, quota or publication failures. No failure acknowledges release
    /// of accepted physical work or grants repository Read.
    pub async fn prepare_cold_file<T: Store, C: Clock>(
        &self,
        selection: &PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
        budget: Duration,
    ) -> Result<NativeSealedObject<'_>, Error> {
        let deadline = self.validate_cold_selection(selection, mode, budget)?;

        let prepared = timeout_at(deadline, self.prepare_cold_selected(selection, mode))
            .await
            .map_err(|_| StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }))?;
        // Synchronous verification in a final poll can cross the timer. It
        // must not turn an elapsed fetch budget into a successful preparation.
        if Instant::now() >= deadline {
            return Err(
                StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }).into(),
            );
        }
        prepared
    }

    /// Checks immutable cold-route constraints before even a warm native pin.
    pub(super) fn validate_cold_selection<T: Store, C: Clock>(
        &self,
        selection: &PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
        budget: Duration,
    ) -> Result<Instant, Error> {
        if budget.is_zero()
            || budget > Duration::from_secs(300)
            || !budget.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }
        let deadline = Instant::now() + budget;
        selection.validate_storage_policy(&ColdFilePolicy { mode })?;
        if selection.storage_domain() != self.native().ready.layout().layout().domain() {
            return Err(Error::Denied);
        }
        Ok(deadline)
    }

    async fn prepare_cold_selected<T: Store, C: Clock>(
        &self,
        selection: &PreparedFileRead<'_, T, C>,
        mode: ReassemblyMode,
    ) -> Result<NativeSealedObject<'_>, Error> {
        let native = self.native();
        let (kind, digest) = match selection.content() {
            ContentRef::Inline(digest) => (IdentityKind::Chunk, digest),
            ContentRef::Manifest(digest) => (IdentityKind::Manifest, digest),
        };
        let identity = TERRANE_V1
            .from_digest(kind, &digest)
            .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported))?;
        if kind == IdentityKind::Chunk && selection.size() > native.max_allocation_bytes as u64 {
            return Err(StoreFailure::new(StoreErrorKind::Capacity).into());
        }
        let canonical = stage("cold-reference-get", self.get(&identity, None)).await?;
        if kind == IdentityKind::Manifest {
            let manifest = Manifest::decode_verified(
                &canonical,
                native.ready.layout().layout().chunk_profile(),
                &identity,
            )
            .map_err(|error| {
                super::native_failure(io::Error::new(io::ErrorKind::InvalidData, error), &identity)
            })?;
            if manifest.size != selection.size() {
                return Err(StoreFailure::new(StoreErrorKind::Corrupt(
                    terrane_sdk::store::CorruptSubject::Identity(identity),
                ))
                .into());
            }
            if mode == ReassemblyMode::Never && manifest.chunks.len() > 1 {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
            }
            // Each occurrence can require its one-hop dictionary as well as
            // the chunk itself; the manifest occupies one additional request.
            if manifest.chunks.len().saturating_mul(2).saturating_add(1) > native.max_requests
                || manifest
                    .chunks
                    .iter()
                    .any(|chunk| chunk.length > native.max_allocation_bytes as u64)
            {
                return Err(StoreFailure::new(StoreErrorKind::Capacity).into());
            }
            for chunk in &manifest.chunks {
                let chunk = TERRANE_V1
                    .from_digest(IdentityKind::Chunk, &chunk.digest)
                    .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported))?;
                stage("cold-chunk-get", self.get(&chunk, None)).await?;
            }
            // Read-through warming is best effort. Only this strict original
            // native admission proves that all manifest dependencies reside.
            stage(
                "cold-manifest-admit",
                native.put(ContentUpload::Meta(MetaUpload::new(kind, &canonical)?)),
            )
            .await?;
        }

        // Released input grants still protect original source inodes. Time
        // schedules reconciliation; only the actual sweep permits transfer.
        let grace = native
            .ready
            .consumer_release_grace()
            .checked_add(Duration::from_secs(1))
            .filter(|delay| *delay <= Duration::from_secs(300))
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Capacity))?;
        sleep(grace).await;
        stage(
            "cold-consumer-sweep",
            native.ready.owner().sweep_consumer_leases(),
        )
        .await
        .map_err(|error| super::native_failure(error, &identity))?;

        match stage(
            "cold-object-prepare",
            native.prepare_object(&identity, mode),
        )
        .await?
        {
            NativePreparedObject::Sealed(object)
                if object.claim().plaintext_size() == selection.size() =>
            {
                Ok(object)
            }
            NativePreparedObject::Sealed(object) => {
                // Preserve independently verified cache data even when signed
                // file metadata selected a different logical length.
                let _ = object.into_cache().await;
                Err(StoreFailure::new(StoreErrorKind::Corrupt(
                    terrane_sdk::store::CorruptSubject::Identity(identity),
                ))
                .into())
            }
            NativePreparedObject::Chunked(object) => {
                object.close().await?;
                Err(StoreFailure::new(StoreErrorKind::Unsupported).into())
            }
        }
    }
}
