//! Closes one ordinary or already-held read under its actual namespace.
//!
//! Selected logical values are resolved once for this request. Every consumed
//! direct artifact retains its original physical recipe, and fresh selection
//! checks bracket the complete closing read. Nothing survives as permission for
//! another request, and this byte-only reader performs no repair or promotion.
//!
//! Test diagnostics measure the complete standalone selected request here.
//! Already-held callers use the catalog and closing groups without contributing
//! a duplicate whole-request interval. Inclusive groups can overlap.

use super::ranged_pack::RetainedMemberRanges;
use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::receipts::RecordRead;
use std::sync::Mutex;
use terrane_format::bucket::BucketKey;

/// Keeps actual original reads until this single request's closing boundary.
struct RequestReads<'request, F, C, V> {
    bucket: &'request FileBucket<F, C, V>,
    records: Mutex<Vec<RecordRead>>,
    members: Mutex<Vec<RetainedMemberRanges>>,
    bounded: bool,
    mode: super::ranged_pack::MemberReadMode,
}

/// Keeps ordinary selected-loss checks separate from unplaced admission inputs.
enum AuxiliaryPlacementCheck {
    RequireSelected,
    AllowUnplaced,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> CatalogReads for RequestReads<'_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn read_artifact(&self, key: &BucketKey) -> Result<RecordRead, StoreFailure> {
        let record = self.bucket.read_optional_ordinary_retained(key).await?;
        self.records
            .lock()
            .map_err(|_| files::layout_corrupt())?
            .push(record.clone());
        Ok(record)
    }

    async fn read_member(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Option<(Vec<u8>, usize)>, StoreFailure> {
        if !self.bounded {
            return Ok(None);
        }
        super::member_reads::read_member(
            self.bucket,
            catalog,
            identity,
            self,
            &self.members,
            self.mode,
        )
        .await
        .map(Some)
    }
}

impl<F, C, V> RequestReads<'_, F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Retains present ordinary data or a separately captured actual absence.
    async fn read_auxiliary_artifact(&self, key: &BucketKey) -> Result<RecordRead, StoreFailure> {
        let ordinary = self.bucket.read_optional_ordinary_retained(key).await?;
        let record = if ordinary.bytes().is_some() {
            ordinary
        } else {
            // Ordinary missing reads carry no closing recipe. Capture absence
            // independently before using it as recovery evidence, and refuse
            // a name that appeared between the two observations.
            let absent = self.bucket.read_optional_retained(key).await?;
            if absent.bytes().is_some() {
                return Err(files::layout_corrupt());
            }
            absent
        };
        self.records
            .lock()
            .map_err(|_| files::layout_corrupt())?
            .push(record.clone());
        Ok(record)
    }

    async fn close(
        self,
        observed: &SelectedObservation<'_>,
        catalog: &Catalog,
    ) -> Result<(), StoreFailure> {
        observed.revalidate().await?;

        // These are the SAME recipes captured before their original bodies.
        // Recapturing ancestry now would miss identical-byte reincarnation.
        for record in observed.physical_reads() {
            record.revalidate_retained(self.bucket.fs()).await?;
        }
        let records = self
            .records
            .into_inner()
            .map_err(|_| files::layout_corrupt())?;
        for record in &records {
            record.revalidate_retained(self.bucket.fs()).await?;
        }
        let members = self
            .members
            .into_inner()
            .map_err(|_| files::layout_corrupt())?;
        for member in members {
            member.revalidate(self.bucket.fs()).await?;
        }

        // These names are materialized caches, not selected logical values.
        // Preserve the ordinary closing layout refusal without reading their
        // contents as authority or resolving another selected projection.
        self.bucket
            .check_payload_namespace(&registered("CAPABILITIES")?)
            .await?;
        if let Some(generation) = catalog.capabilities.generation {
            self.bucket
                .check_payload_namespace(&registered(&format!(
                    "objects/index/{generation}/MANIFEST"
                ))?)
                .await?;
        }

        observed.revalidate().await
    }
}

impl<F, C, V> FileBucket<F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Reads one request with a single initial selected logical projection.
    ///
    /// # Errors
    /// Preserves ordinary content/range failures and refuses changed original
    /// physical inputs or current selection before returning verified bytes.
    pub(super) async fn get_selected_request(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
        mode: super::ranged_pack::MemberReadMode,
    ) -> Result<Vec<u8>, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::SelectedGet);
        #[cfg(test)]
        let mut trace = crate::ref_advance::PhaseTrace::new(
            &self.inner.clock,
            "content-get",
            identity.terrane_v1_digest().ok(),
            None,
            "content-get-exclusion-submitted",
        );
        let holder = SingleHeld::acquire_read_namespace(self).await?;
        #[cfg(test)]
        trace.mark("content-get-exclusion-acquired");
        let held = holder.source();
        let retained = match held.identity_proof().retained_namespace() {
            Ok(_) => true,
            Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported) => false,
            Err(error) => return Err(error),
        };
        if matches!(mode, super::ranged_pack::MemberReadMode::Ordinary) || !retained {
            // Unsupported retention remains ordinary read-only behavior under
            // this actual lock. It creates no original-recipe success claim.
            self.ensure_layout().await?;
            let bytes = self.get_locked_mode(identity, range, mode).await?;
            #[cfg(test)]
            trace.mark("content-get-value-returned");
            self.ensure_layout().await?;
            #[cfg(test)]
            trace.mark("content-get-closing-layout-checked");
            #[cfg(all(test, feature = "std", feature = "tokio"))]
            diagnostic.complete();
            return Ok(bytes);
        }

        #[cfg(test)]
        self.inner.content_observation.get(identity.kind());
        let observed = held.observe_publication_ordinary_retained().await?;
        let bytes = self
            .get_selected_observed_request(&observed, identity, range, mode)
            .await;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        if bytes.is_err() {
            diagnostic.finish_result(&bytes);
        }
        let bytes = bytes?;
        #[cfg(test)]
        trace.mark("content-get-value-returned");
        #[cfg(test)]
        trace.mark("content-get-closing-layout-checked");
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(bytes)
    }

    /// Verifies and closes one read beneath its caller's genuine observation.
    ///
    /// This helper neither acquires exclusion nor retains selected state beyond
    /// the current request. The caller selects its native route before consuming
    /// data; unsupported bindings keep their ordinary read path.
    ///
    /// # Errors
    /// Preserves content and range failures and refuses changed selected inputs,
    /// consumed artifact incarnations, ancestry or bounded member bytes.
    ///
    /// # Panics
    /// Test builds panic if the isolated closing-pause mutex is poisoned.
    pub(super) async fn get_selected_observed_request(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
        range: Option<ByteRange>,
        mode: super::ranged_pack::MemberReadMode,
    ) -> Result<Vec<u8>, StoreFailure> {
        let reads = RequestReads {
            bucket: self,
            records: Mutex::new(Vec::new()),
            members: Mutex::new(Vec::new()),
            bounded: range.is_some() && identity.kind() == IdentityKind::Chunk,
            mode,
        };
        // Selected CAPABILITIES and its manifest come from this complete actual
        // observation. Direct artifacts close together after body verification.
        let catalog = self.catalog_observed_with_reads(observed, &reads).await?;
        let bytes = self
            .get_catalog_body_with_reads(&catalog, identity, range, &reads)
            .await?;
        #[cfg(test)]
        self.inner.content_observation.before_get_close().await;

        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut closing =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::SelectedGetClosing);
        let closed = reads.close(observed, &catalog).await;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        closing.finish_result(&closed);
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        drop(closing);
        closed?;
        Ok(bytes)
    }
}

impl<F, C, V, const WRITABLE: bool> crate::bucket::held::HeldBucket<'_, F, C, V, WRITABLE>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Proves physical auxiliary loss beneath the caller's held selection.
    ///
    /// The caller must independently establish that this Node belongs only to
    /// an authorized derived closure. This grants neither bytes nor serving or
    /// publication authority and never changes ordinary store error taxonomy.
    ///
    /// # Errors
    /// Refuses foreign holders, unavailable inventory, changed selection or
    /// original read recipes, unsafe layouts and corrupt present artifacts.
    pub(crate) async fn index_auxiliary_absent(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
    ) -> Result<bool, StoreFailure> {
        self.check_index_auxiliary_placement(
            observed,
            identity,
            AuxiliaryPlacementCheck::RequireSelected,
        )
        .await?
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
    }

    /// Distinguishes unplaced auxiliary data from closed selected artifact loss.
    ///
    /// `None` means the authenticated selected catalog has no placement for this
    /// Node, leaving it to ordinary final admission. `Some(true)` proves physical
    /// loss of its selected artifacts; `Some(false)` means those artifacts verify.
    /// Every result closes the same original catalog and selection reads. The
    /// caller must independently prove the Node's authorized derived-only role;
    /// this observation grants no bytes, history, serving or publication authority.
    ///
    /// # Errors
    /// Refuses foreign observations, unsupported identities, unavailable reads,
    /// unserved placements, corrupt present artifacts and changed closing inputs.
    ///
    /// # Panics
    /// Test builds panic if the isolated closing-pause mutex is poisoned.
    pub(crate) async fn index_auxiliary_placement(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
    ) -> Result<Option<bool>, StoreFailure> {
        self.check_index_auxiliary_placement(
            observed,
            identity,
            AuxiliaryPlacementCheck::AllowUnplaced,
        )
        .await
    }

    async fn check_index_auxiliary_placement(
        &self,
        observed: &SelectedObservation<'_>,
        identity: &Identity,
        check: AuxiliaryPlacementCheck,
    ) -> Result<Option<bool>, StoreFailure> {
        self.identity_proof().retained_namespace()?;
        if identity.kind() != IdentityKind::Node {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if observed.identity().root() != self.root()
            || observed.identity().physical_identity() != self.physical_identity()
        {
            return Err(files::layout_corrupt());
        }
        observed.revalidate().await?;

        let bucket = self.bucket();
        let reads = RequestReads {
            bucket,
            records: Mutex::new(Vec::new()),
            members: Mutex::new(Vec::new()),
            bounded: false,
            mode: super::ranged_pack::MemberReadMode::Ordinary,
        };
        let catalog = bucket.catalog_observed_with_reads(observed, &reads).await?;
        if matches!(check, AuxiliaryPlacementCheck::AllowUnplaced) {
            if identity.profile() != TERRANE_V1.name() {
                return Err(files::malformed());
            }
            let hash = identity
                .terrane_v1_digest()
                .map_err(|_| files::malformed())?;
            let placed = catalog.shards.iter().any(|shard| {
                shard.shard() == hash[0]
                    && shard
                        .entries()
                        .binary_search_by_key(&hash, |record| *record.entry().hash())
                        .is_ok()
            });
            if !placed {
                // A missing catalog row differs from an unserved existing row.
                // Tombstones, quarantine, kind mismatch and exclusions still
                // pass through location's ordinary refusal below.
                #[cfg(test)]
                bucket.inner.content_observation.before_get_close().await;
                reads.close(observed, &catalog).await?;
                return Ok(None);
            }
        }
        let location = bucket.location(&catalog, identity)?;
        let id = location.pack();
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()))
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        let pack = reads
            .read_auxiliary_artifact(&registered(&id.pack_key())?)
            .await?;
        let index = reads
            .read_auxiliary_artifact(&registered(&id.index_key())?)
            .await?;

        // Missing bytes are a separate observed fact. A present bad companion
        // remains corruption even when the other artifact is genuinely absent.
        for (record, kind, digest, size) in [
            (
                &pack,
                IdentityKind::Pack,
                inventory.pack_hash,
                inventory.pack_size,
            ),
            (
                &index,
                IdentityKind::Index,
                inventory.index_hash,
                inventory.index_size,
            ),
        ] {
            if let Some(bytes) = record.bytes() {
                let artifact = TERRANE_V1
                    .from_digest(kind, &digest)
                    .map_err(|_| files::layout_corrupt())?;
                if bytes.len() as u64 != size {
                    return Err(corrupt(&artifact));
                }
                TERRANE_V1
                    .verify(&artifact, bytes)
                    .map_err(|_| corrupt(&artifact))?;
            }
        }

        if let Some(bytes) = pack.bytes() {
            let subject = TERRANE_V1
                .from_digest(IdentityKind::Pack, &inventory.pack_hash)
                .map_err(|_| files::layout_corrupt())?;
            let reader = crate::pack::PackReader::open(bytes).map_err(|_| corrupt(&subject))?;
            if reader.header().id() != id || !reader.entries().contains(location.entry()) {
                return Err(corrupt(&subject));
            }
            if let Some(index) = index.bytes() {
                reader
                    .check_index_object(index)
                    .map_err(|_| corrupt(&subject))?;
            }
        }
        if let Some(bytes) = index.bytes() {
            let subject = TERRANE_V1
                .from_digest(IdentityKind::Index, &inventory.index_hash)
                .map_err(|_| files::layout_corrupt())?;
            let generation = catalog
                .capabilities
                .generation
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
            let parsed = crate::pack::PackIndexSnapshot::decode(bytes, generation)
                .map_err(|_| corrupt(&subject))?;
            if parsed.header().id() != id || !parsed.entries().contains(location.entry()) {
                return Err(corrupt(&subject));
            }
        }
        let absent = pack.bytes().is_none() || index.bytes().is_none();
        #[cfg(test)]
        if matches!(check, AuxiliaryPlacementCheck::AllowUnplaced) {
            bucket.inner.content_observation.before_get_close().await;
        }
        reads.close(observed, &catalog).await?;
        Ok(Some(absent))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod held_tests;
