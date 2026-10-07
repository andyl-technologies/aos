//! Selects and verifies authoritative index generations without directory listing.

use super::{BucketBinding, FileBucket, files};
use crate::pack::{MergedShard, PackIndexSnapshot, RecordState};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_core::bucket::{
    BucketCapabilities, BucketKey, GenerationManifest, GenerationShard, Mutability, PackExclusion,
    PackInventoryEntry,
};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

/// Holds one verified selection and its complete conditional-write preimage.
pub(super) struct Catalog {
    /// The persisted profile, capabilities, and selected generation.
    pub capabilities: BucketCapabilities,
    /// The opaque complete bytes expected when advancing the generation pointer.
    pub capability_bytes: Vec<u8>,
    /// The exact immutable shards selected by the generation manifest.
    pub shards: Vec<MergedShard>,
    /// The separately admitted whole-pack and detached-index containers.
    pub inventory: Option<Vec<PackInventoryEntry>>,
    /// Complete active physical retirement incarnations, or legacy unknown.
    pub exclusions: Option<Vec<PackExclusion>>,
    /// Complete permanently unavailable pack IDs, or legacy unknown.
    pub burns: Option<Vec<[u8; 16]>>,
}

/// Groups verified ordinary container admission outputs.
pub(super) struct CatalogAdmission {
    /// The complete verified predecessor catalog.
    pub(super) catalog: Catalog,
    /// The actual newly sealed detached index.
    pub(super) new: PackIndexSnapshot,
    /// The actual new pack/index inventory binding.
    pub(super) inventory: PackInventoryEntry,
}

/// Groups one ordinary complete selected successor projection.
struct CatalogSuccessor<'input> {
    catalog: Catalog,
    generation: u64,
    shards: &'input [MergedShard],
}

/// Borrows optional actual repair and native operation observations.
///
/// Neither field is caller evidence: their closed producers retain the physical
/// preimages and current controls independently of this grouping.
pub(super) struct CatalogScope<'input, 'operation, 'held> {
    /// The actual missing-placement observation, if ordinary repair is required.
    pub(super) placement: Option<&'input super::missing_placement::Placement>,
    /// The actual retained native publication context, when called beneath staging.
    pub(super) context: Option<
        &'input crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext<
            'operation,
            'held,
        >,
    >,
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Verifies the explicitly selected manifest and all its listed artifacts.
    ///
    /// # Errors
    /// Rejects broken layout, profile, generation, or artifact bindings and
    /// propagates unavailable I/O. Listing never discovers a generation.
    pub(super) async fn catalog(&self) -> Result<Catalog, StoreFailure> {
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let capability_bytes = self
            .logical_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let capabilities =
            BucketCapabilities::decode(&capability_bytes).map_err(|_| files::layout_corrupt())?;
        self.validate_layout(&capabilities)?;
        let manifest = if let Some(generation) = capabilities.generation {
            let key = registered(&format!("objects/index/{generation}/MANIFEST"))?;
            let bytes = self
                .logical_optional(&key)
                .await?
                .ok_or_else(files::layout_corrupt)?;
            Some(GenerationManifest::decode(&bytes).map_err(|_| files::layout_corrupt())?)
        } else {
            None
        };
        self.verify_catalog(capability_bytes, capabilities, manifest)
            .await
    }

    /// Verifies direct artifacts named by one actual complete held selection.
    ///
    /// CAPABILITIES and MANIFEST come from the same freshly resolved chain.
    /// Every listed shard and filter retains its independent exact read and
    /// hash/size check; the caller revalidates the full observation before use.
    ///
    /// # Errors
    /// Rejects mismatched holders, incomplete or malformed selected values,
    /// incompatible profiles and unavailable or corrupt direct artifacts.
    pub(super) async fn catalog_observed(
        &self,
        observed: &super::publication::SelectedObservation<'_>,
    ) -> Result<Catalog, StoreFailure> {
        if observed.identity().root() != self.root() {
            return Err(files::layout_corrupt());
        }
        let capability_key = registered("CAPABILITIES")?;
        self.check_payload_namespace(&capability_key).await?;
        let capability_bytes = observed
            .logical()
            .get("CAPABILITIES")
            .and_then(Option::as_ref)
            .ok_or_else(files::layout_corrupt)?
            .clone();
        let capabilities =
            BucketCapabilities::decode(&capability_bytes).map_err(|_| files::layout_corrupt())?;
        self.validate_layout(&capabilities)?;
        let manifest = if let Some(generation) = capabilities.generation {
            let key = registered(&format!("objects/index/{generation}/MANIFEST"))?;
            self.check_payload_namespace(&key).await?;
            let bytes = observed
                .logical()
                .get(key.as_str())
                .and_then(Option::as_deref)
                .ok_or_else(files::layout_corrupt)?;
            Some(GenerationManifest::decode(bytes).map_err(|_| files::layout_corrupt())?)
        } else {
            None
        };
        self.verify_catalog(capability_bytes, capabilities, manifest)
            .await
    }

    async fn verify_catalog(
        &self,
        capability_bytes: Vec<u8>,
        capabilities: BucketCapabilities,
        manifest: Option<GenerationManifest>,
    ) -> Result<Catalog, StoreFailure> {
        let mut shards = Vec::new();
        let mut inventory = None;
        let mut exclusions = None;
        let mut burns = None;
        if let Some(manifest) = manifest {
            let generation = capabilities.generation.ok_or_else(files::layout_corrupt)?;
            inventory = manifest.inventory.clone();
            exclusions = manifest.exclusions.clone();
            burns = manifest.burns.clone();
            if manifest.generation != generation {
                return Err(files::layout_corrupt());
            }
            for entry in &manifest.shards {
                let shard = u8::try_from(entry.shard).map_err(|_| files::layout_corrupt())?;
                let bytes = self
                    .verified_artifact(
                        generation,
                        entry.shard,
                        "idx",
                        IdentityKind::Index,
                        entry.index_hash,
                        entry.index_size,
                    )
                    .await?;
                if let Some((hash, size)) = entry.filter {
                    self.verified_artifact(
                        generation,
                        entry.shard,
                        "flt",
                        IdentityKind::Filter,
                        hash,
                        size,
                    )
                    .await?;
                }
                shards.push(
                    MergedShard::decode(&bytes, generation, shard)
                        .map_err(|_| files::layout_corrupt())?,
                );
            }
        }
        Ok(Catalog {
            capabilities,
            capability_bytes,
            shards,
            inventory,
            exclusions,
            burns,
        })
    }

    async fn verified_artifact(
        &self,
        generation: u64,
        shard: u64,
        suffix: &str,
        kind: IdentityKind,
        hash: [u8; 32],
        size: u64,
    ) -> Result<Vec<u8>, StoreFailure> {
        let key = registered(&format!("objects/index/{generation}/{shard}.{suffix}"))?;
        let bytes = self
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let identity = TERRANE_V1
            .from_digest(kind, &hash)
            .map_err(|_| files::layout_corrupt())?;
        if bytes.len() as u64 != size {
            return Err(files::layout_corrupt());
        }
        TERRANE_V1
            .verify(&identity, &bytes)
            .map_err(|_| files::layout_corrupt())?;
        Ok(bytes)
    }

    /// Installs an immutable artifact or verifies identical existing bytes.
    ///
    /// # Errors
    /// Rejects non-immutable keys and differing existing bytes, and propagates
    /// durable filesystem failures.
    pub(super) async fn immutable(
        &self,
        key: &BucketKey,
        bytes: &[u8],
    ) -> Result<(), StoreFailure> {
        self.write_layout_locked().await?;
        if key.mutability() != Mutability::Immutable {
            return Err(files::malformed());
        }
        if !self.install(key, bytes, false).await? {
            let current = self
                .read_optional(key)
                .await?
                .ok_or_else(files::layout_corrupt)?;
            if current != bytes {
                return Err(files::layout_corrupt());
            }
        }
        Ok(())
    }

    /// Chooses a newer generation by skipping directly observed partial writes.
    ///
    /// # Errors
    /// Returns corruption on counter exhaustion and propagates failed exact
    /// key reads. Callers retain exclusion through subsequent publication.
    pub(super) async fn next_generation(&self, catalog: &Catalog) -> Result<u64, StoreFailure> {
        let mut generation = catalog
            .capabilities
            .generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(files::layout_corrupt)?;
        // Shard zero is always installed first. A crashed unpublished attempt
        // reserves its generation without making listing authoritative.
        loop {
            let first = registered(&format!("objects/index/{generation}/0.idx"))?;
            let manifest = registered(&format!("objects/index/{generation}/MANIFEST"))?;
            if self.read_optional(&first).await?.is_none()
                && self.read_optional(&manifest).await?.is_none()
            {
                return Ok(generation);
            }
            generation = generation
                .checked_add(1)
                .ok_or_else(files::layout_corrupt)?;
        }
    }

    /// Adds admitted bodies while retaining all prior exact placements and tombstones.
    ///
    /// # Errors
    /// Rejects inconsistent pack, shard, or inventory records and propagates
    /// publication failures. The caller retains stable exclusion throughout.
    pub(super) async fn publish_pack_catalog<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &super::publication::SelectedObservation<'_>,
        catalog: Catalog,
        new: PackIndexSnapshot,
        inventory: PackInventoryEntry,
    ) -> Result<(), StoreFailure> {
        self.publish_pack_catalog_observed(held, observed, catalog, new, inventory, None)
            .await
    }

    /// Publishes ordinary admission with an optional actual physical-loss observation.
    ///
    /// # Errors
    /// Refuses any different old Live row, selected binding, excluded incarnation,
    /// malformed successor or unacknowledged native durability.
    pub(super) async fn publish_pack_catalog_observed<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &super::publication::SelectedObservation<'_>,
        catalog: Catalog,
        new: PackIndexSnapshot,
        inventory: PackInventoryEntry,
        placement: Option<&super::missing_placement::Placement>,
    ) -> Result<(), StoreFailure> {
        self.publish_pack_catalog_contextual(
            held,
            observed,
            CatalogAdmission {
                catalog,
                new,
                inventory,
            },
            CatalogScope {
                placement,
                context: None,
            },
        )
        .await
    }

    /// Publishes the ordinary catalog successor with optional native checks.
    ///
    /// # Errors
    /// Preserves all ordinary catalog/placement failures and actual native
    /// expiry/control/acknowledgment refusal without changing Raw proof rules.
    pub(super) async fn publish_pack_catalog_contextual<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &super::publication::SelectedObservation<'_>,
        admission: CatalogAdmission,
        scope: CatalogScope<'_, '_, '_>,
    ) -> Result<(), StoreFailure> {
        let CatalogAdmission {
            mut catalog,
            new,
            inventory,
        } = admission;
        let CatalogScope { placement, context } = scope;
        if context.is_some() {
            held.retained_namespace()?;
        }

        self.write_layout_locked().await?;
        if self.physically_excluded(&catalog, new.header().id().as_bytes()) {
            // Even an exact artifact collision cannot re-admit an excluded
            // physical incarnation as the supposedly fresh placement.
            return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
        }
        let generation = self.next_generation(&catalog).await?;
        let mut prefixes = BTreeSet::from([0]);
        prefixes.extend(catalog.shards.iter().map(MergedShard::shard));
        prefixes.extend(new.entries().iter().map(|entry| entry.hash()[0]));
        let mut shards = Vec::new();
        let mut replaced = false;
        for prefix in prefixes {
            let delta = MergedShard::rebuild(
                prefix,
                generation,
                std::slice::from_ref(&new),
                &BTreeSet::new(),
                None,
                &BTreeSet::new(),
            )
            .map_err(|_| files::layout_corrupt())?;
            let mut records = BTreeMap::new();
            if let Some(previous) = catalog.shards.iter().find(|shard| shard.shard() == prefix) {
                for record in terrane_core::pack_format::decode_shard(&previous.encode(), prefix)
                    .map_err(|_| files::layout_corrupt())?
                {
                    records.insert(record.record.hash, record);
                }
            }
            for record in terrane_core::pack_format::decode_shard(&delta.encode(), prefix)
                .map_err(|_| files::layout_corrupt())?
            {
                // Fresh verified admission replaces only a retired placement;
                // physical authority overrides even a stale Live row.
                // Quarantine and other live entries remain authoritative; the old
                // physical pack's durable trash evidence is retained separately.
                match records.entry(record.record.hash) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(record);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry)
                        if placement.is_some_and(|placement| placement.matches(entry.get())) =>
                    {
                        let placement = placement.ok_or_else(files::layout_corrupt)?;
                        placement.check_replacement(observed, &catalog, entry.get())?;
                        if entry.get().record.hash != record.record.hash
                            || entry.get().record.kind != record.record.kind
                        {
                            return Err(files::layout_corrupt());
                        }
                        entry.insert(record);
                        replaced = true;
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry)
                        if entry.get().state != RecordState::Quarantine as u8
                            && (entry.get().state == RecordState::Tombstone as u8
                                || self.physically_excluded(&catalog, &entry.get().pack)) =>
                    {
                        // Replacing legacy state1 requires a binding that keeps
                        // exact physical retirement evidence for that old pack.
                        if !self.has_active_exclusion(&catalog, &entry.get().pack) {
                            return Err(StoreFailure::new(
                                crate::store::StoreErrorKind::Unsupported,
                            ));
                        }
                        entry.insert(record);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            }
            let bytes =
                terrane_core::pack_format::encode_shard(&records.into_values().collect::<Vec<_>>());
            shards.push(
                MergedShard::decode(&bytes, generation, prefix)
                    .map_err(|_| files::layout_corrupt())?,
            );
        }
        if placement.is_some() && !replaced {
            return Err(files::layout_corrupt());
        }
        self.add_inventory(&mut catalog, inventory)?;
        // The existing raw transition still advances loss_generation and clears
        // carried sources when the exact selected Live row changes.
        self.publish_shards_held_with_placement(
            held,
            observed,
            CatalogSuccessor {
                catalog,
                generation,
                shards: &shards,
            },
            CatalogScope { placement, context },
        )
        .await
    }

    /// Adds a uniquely named container without replacing a different binding.
    ///
    /// # Errors
    /// Returns corruption when an existing pack ID has different artifact metadata.
    pub(super) fn add_inventory(
        &self,
        catalog: &mut Catalog,
        entry: PackInventoryEntry,
    ) -> Result<(), StoreFailure> {
        let entries = catalog.inventory.get_or_insert_with(Vec::new);
        match entries.binary_search_by_key(&entry.pack_id, |entry| entry.pack_id) {
            Ok(position) if entries[position] != entry => Err(files::layout_corrupt()),
            Ok(_) => Ok(()),
            Err(position) => {
                entries.insert(position, entry);
                Ok(())
            }
        }
    }

    /// Publishes canonical catalog changes through the actual retained namespace.
    ///
    /// Immutable shard and manifest bytes become durable before the sole commit
    /// slot; complete portable acknowledgment precedes all materialized caches.
    ///
    /// # Errors
    /// Rejects mismatched holders, stale whole capability preimages, malformed
    /// catalog bindings, unavailable native retention and failed durable effects.
    pub(super) async fn publish_shards_held<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &super::publication::SelectedObservation<'_>,
        catalog: Catalog,
        generation: u64,
        shards: &[MergedShard],
    ) -> Result<(), StoreFailure> {
        self.publish_shards_held_with_placement(
            held,
            observed,
            CatalogSuccessor {
                catalog,
                generation,
                shards,
            },
            CatalogScope {
                placement: None,
                context: None,
            },
        )
        .await
    }

    async fn publish_shards_held_with_placement<const WRITABLE: bool>(
        &self,
        held: &super::held::HeldBucket<'_, F, C, V, WRITABLE>,
        observed: &super::publication::SelectedObservation<'_>,
        successor: CatalogSuccessor<'_>,
        scope: CatalogScope<'_, '_, '_>,
    ) -> Result<(), StoreFailure> {
        let CatalogSuccessor {
            mut catalog,
            generation,
            shards,
        } = successor;
        let CatalogScope { placement, context } = scope;
        if context.is_some() {
            held.retained_namespace()?;
        }

        if !std::ptr::eq(self, held.bucket())
            || observed
                .logical()
                .get("CAPABILITIES")
                .and_then(Option::as_ref)
                != Some(&catalog.capability_bytes)
        {
            return Err(files::layout_corrupt());
        }
        let previous_manifest = if placement.is_none() {
            None
        } else {
            let previous = catalog
                .capabilities
                .generation
                .ok_or_else(files::layout_corrupt)?;
            let key = registered(&format!("objects/index/{previous}/MANIFEST"))?;
            let bytes = observed
                .logical()
                .get(key.as_str())
                .and_then(Option::as_deref)
                .ok_or_else(files::layout_corrupt)?;
            Some(GenerationManifest::decode(bytes).map_err(|_| files::layout_corrupt())?)
        };
        let mut entries = Vec::new();
        let mut changes = Vec::new();
        for shard in shards {
            let bytes = shard.encode();
            let hash = TERRANE_V1
                .calculate(IdentityKind::Index, &bytes)
                .map_err(|_| files::layout_corrupt())?
                .terrane_v1_digest()
                .map_err(|_| files::layout_corrupt())?;
            let filter = previous_manifest.as_ref().and_then(|manifest| {
                manifest
                    .shards
                    .iter()
                    .find(|entry| {
                        entry.shard == u64::from(shard.shard())
                            && entry.index_hash == hash
                            && entry.index_size == bytes.len() as u64
                    })
                    .and_then(|entry| entry.filter)
            });
            if let Some((filter_hash, filter_size)) = filter {
                let previous = catalog
                    .capabilities
                    .generation
                    .ok_or_else(files::layout_corrupt)?;
                let old_key =
                    registered(&format!("objects/index/{previous}/{}.flt", shard.shard()))?;
                let filter_bytes = observed
                    .logical()
                    .get(old_key.as_str())
                    .and_then(Option::as_ref)
                    .ok_or_else(files::layout_corrupt)?
                    .clone();
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Filter, &filter_hash)
                    .map_err(|_| files::layout_corrupt())?;
                if filter_bytes.len() as u64 != filter_size {
                    return Err(files::layout_corrupt());
                }
                TERRANE_V1
                    .verify(&identity, &filter_bytes)
                    .map_err(|_| files::layout_corrupt())?;
                changes.push(terrane_core::gc::publication::LogicalChange {
                    key: registered(&format!("objects/index/{generation}/{}.flt", shard.shard()))?
                        .as_str()
                        .into(),
                    expected: None,
                    new: Some(filter_bytes),
                });
            }
            // Filters are optional. Only the changed shard omits its obsolete
            // filter; unchanged shard/filter bindings and bytes are preserved.
            entries.push(GenerationShard {
                shard: u64::from(shard.shard()),
                index_hash: hash,
                index_size: bytes.len() as u64,
                filter,
            });
            changes.push(terrane_core::gc::publication::LogicalChange {
                key: registered(&format!("objects/index/{generation}/{}.idx", shard.shard()))?
                    .as_str()
                    .into(),
                expected: None,
                new: Some(bytes),
            });
        }
        let timestamp = self
            .inner
            .clock
            .now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| files::malformed())?
            .as_secs();
        let manifest = GenerationManifest {
            generation,
            shards: entries,
            written_at: timestamp,
            cycle: previous_manifest
                .as_ref()
                .map_or(0, |manifest| manifest.cycle),
            inventory: catalog.inventory.clone(),
            exclusions: catalog.exclusions.clone(),
            burns: catalog.burns.clone(),
        };
        let manifest_bytes = manifest.encode().map_err(|_| files::malformed())?;
        changes.push(terrane_core::gc::publication::LogicalChange {
            key: registered(&format!("objects/index/{generation}/MANIFEST"))?
                .as_str()
                .into(),
            expected: None,
            new: Some(manifest_bytes),
        });
        catalog.capabilities.generation = Some(generation);
        changes.push(terrane_core::gc::publication::LogicalChange {
            key: "CAPABILITIES".into(),
            expected: Some(catalog.capability_bytes),
            new: Some(
                catalog
                    .capabilities
                    .encode()
                    .map_err(|_| files::malformed())?,
            ),
        });
        held.publish_backend_raw_contextual(observed, changes, placement, context)
            .await?;

        // Retain the existing independent artifact identity verification at its
        // exact registered key after native durable installation and selection.
        for entry in &manifest.shards {
            self.verified_artifact(
                generation,
                entry.shard,
                "idx",
                IdentityKind::Index,
                entry.index_hash,
                entry.index_size,
            )
            .await?;
        }
        Ok(())
    }

    /// Publishes verified shards, then the final manifest, then the selected pointer.
    ///
    /// # Errors
    /// Rejects broken bindings or a changed complete pointer preimage, and
    /// propagates durable I/O failures. Callers hold exclusion through the final
    /// directory sync; an I/O error after replacement can have visible effects.
    pub(super) async fn publish_shards(
        &self,
        mut catalog: Catalog,
        generation: u64,
        shards: &[MergedShard],
    ) -> Result<(), StoreFailure> {
        self.write_layout_locked().await?;
        let mut entries = Vec::new();
        for shard in shards {
            let bytes = shard.encode();
            let identity = TERRANE_V1
                .calculate(IdentityKind::Index, &bytes)
                .map_err(|_| files::layout_corrupt())?;
            let hash = identity
                .terrane_v1_digest()
                .map_err(|_| files::layout_corrupt())?;
            let key = registered(&format!("objects/index/{generation}/{}.idx", shard.shard()))?;
            self.immutable(&key, &bytes).await?;
            // Verify durable bytes before the manifest can promise them.
            self.verified_artifact(
                generation,
                u64::from(shard.shard()),
                "idx",
                IdentityKind::Index,
                hash,
                bytes.len() as u64,
            )
            .await?;
            entries.push(GenerationShard {
                shard: u64::from(shard.shard()),
                index_hash: hash,
                index_size: bytes.len() as u64,
                filter: None,
            });
        }
        let timestamp = self
            .inner
            .clock
            .now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| files::malformed())?
            .as_secs();
        let manifest = GenerationManifest {
            generation,
            shards: entries,
            written_at: timestamp,
            cycle: 0,
            inventory: catalog.inventory.clone(),
            exclusions: catalog.exclusions.clone(),
            burns: catalog.burns.clone(),
        };
        let bytes = manifest.encode().map_err(|_| files::malformed())?;
        let key = registered(&format!("objects/index/{generation}/MANIFEST"))?;
        self.immutable(&key, &bytes).await?;
        catalog.capabilities.generation = Some(generation);
        let bytes = catalog
            .capabilities
            .encode()
            .map_err(|_| files::malformed())?;
        let key = registered("CAPABILITIES")?;
        let selected = self.selected_publication_locked().await?;
        if selected
            .logical
            .get("CAPABILITIES")
            .and_then(Option::as_ref)
            != Some(&catalog.capability_bytes)
        {
            return Err(files::layout_corrupt());
        }
        let mut changes = vec![terrane_core::gc::publication::LogicalChange {
            key: key.as_str().into(),
            expected: Some(catalog.capability_bytes),
            new: Some(bytes),
        }];
        let manifest_key = format!("objects/index/{generation}/MANIFEST");
        let manifest_bytes = self
            .read_optional(&registered(&manifest_key)?)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        changes.push(terrane_core::gc::publication::LogicalChange {
            key: manifest_key,
            expected: None,
            new: Some(manifest_bytes),
        });
        for shard in shards {
            changes.push(terrane_core::gc::publication::LogicalChange {
                key: format!("objects/index/{generation}/{}.idx", shard.shard()),
                expected: None,
                new: Some(shard.encode()),
            });
        }
        self.publish_raw_locked(&selected, changes).await?;
        Ok(())
    }

    /// Enumerates body and container identities in one selected catalog snapshot.
    ///
    /// Manifest and shard integrity are verified while exclusion is held. Body
    /// verification is left to `get`, so recovery can identify and quarantine
    /// corrupt individual records. Later concurrent changes can make `get`
    /// return a typed absence; callers must not treat that as a complete rebuild.
    ///
    /// # Errors
    /// Returns corruption or unavailable I/O when the selected catalog cannot
    /// be verified. Directory listing never selects authoritative identities.
    pub async fn published_identities(
        &self,
        kind: IdentityKind,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        let catalog = self.catalog().await?;
        let identities = self.catalog_identities(&catalog, kind)?;
        let identities = if kind == IdentityKind::Index {
            // Detached aliases must name an eligible physical pack even when
            // copied burns have no old inventory/hash witness left to match.
            self.verified_catalog_identities(&catalog, identities)
                .await?
        } else {
            identities
        };
        self.ensure_layout().await?;
        Ok(identities)
    }

    /// Enumerates candidate identities from one verified catalog's selected rows.
    ///
    /// # Errors
    /// Rejects unknown index-retirement completeness and malformed identities.
    pub(super) fn catalog_identities(
        &self,
        catalog: &Catalog,
        kind: IdentityKind,
    ) -> Result<Vec<Identity>, StoreFailure> {
        if kind == IdentityKind::Index && !self.index_retirement_known(catalog) {
            return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
        }
        let mut identities = Vec::new();
        if let Some(entries) = &catalog.inventory {
            for entry in entries {
                if self.physically_excluded(catalog, &entry.pack_id) {
                    continue;
                }
                let hash = match kind {
                    IdentityKind::Pack => Some(entry.pack_hash),
                    IdentityKind::Index => Some(entry.index_hash),
                    _ => None,
                };
                if let Some(hash) = hash {
                    let identity = TERRANE_V1
                        .from_digest(kind, &hash)
                        .map_err(|_| files::layout_corrupt())?;
                    if !self.is_excluded(catalog, &identity)? {
                        identities.push(identity);
                    }
                }
            }
        }
        for shard in &catalog.shards {
            for record in shard.entries() {
                if record.state() == RecordState::Live
                    && !self.physically_excluded(catalog, record.pack().as_bytes())
                    && record.entry().kind().identity_kind() == kind
                {
                    let identity = TERRANE_V1
                        .from_digest(kind, record.entry().hash())
                        .map_err(|_| files::layout_corrupt())?;
                    if !self.is_excluded(catalog, &identity)? && !identities.contains(&identity) {
                        identities.push(identity);
                    }
                }
            }
        }
        Ok(identities)
    }

    /// Enumerates body-verified live identities from one selected generation.
    ///
    /// # Errors
    /// Returns corruption or unavailable I/O if the catalog or a live body cannot
    /// be verified. Directory listing never selects authoritative content.
    pub async fn live_identities(&self, kind: IdentityKind) -> Result<Vec<Identity>, StoreFailure> {
        let _guard = self.read_exclusion().await?;
        self.live_identities_locked(kind).await
    }

    /// Verifies live identities while a caller retains the bucket exclusion.
    ///
    /// # Errors
    /// Returns catalog, body verification, and binding failures.
    pub(super) async fn live_identities_locked(
        &self,
        kind: IdentityKind,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let catalog = self.catalog().await?;
        let identities = self.catalog_identities(&catalog, kind)?;
        let identities = self
            .verified_catalog_identities(&catalog, identities)
            .await?;
        self.ensure_layout().await?;
        Ok(identities)
    }

    /// Filters candidates through full body verification and physical association.
    ///
    /// # Errors
    /// Preserves absent bodies, corruption, and unavailable reads. Only a fully
    /// verified detached index naming a physically excluded pack is omitted.
    pub(super) async fn verified_catalog_identities(
        &self,
        catalog: &Catalog,
        identities: Vec<Identity>,
    ) -> Result<Vec<Identity>, StoreFailure> {
        let mut eligible = Vec::with_capacity(identities.len());
        for identity in identities {
            match self.verified_body_outcome(catalog, &identity).await? {
                super::content::VerifiedBody::Bytes(_) => eligible.push(identity),
                super::content::VerifiedBody::ExcludedDetachedIndex => {}
            }
        }
        Ok(eligible)
    }
}

pub(super) fn registered(key: &str) -> Result<BucketKey, StoreFailure> {
    BucketKey::parse(key).map_err(|_| files::malformed())
}
