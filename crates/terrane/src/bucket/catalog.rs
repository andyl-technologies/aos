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
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let capabilities =
            BucketCapabilities::decode(&capability_bytes).map_err(|_| files::layout_corrupt())?;
        self.validate_layout(&capabilities)?;
        let mut shards = Vec::new();
        let mut inventory = None;
        let mut exclusions = None;
        if let Some(generation) = capabilities.generation {
            let key = registered(&format!("objects/index/{generation}/MANIFEST"))?;
            let bytes = self
                .read_optional(&key)
                .await?
                .ok_or_else(files::layout_corrupt)?;
            let manifest =
                GenerationManifest::decode(&bytes).map_err(|_| files::layout_corrupt())?;
            inventory = manifest.inventory.clone();
            exclusions = manifest.exclusions.clone();
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

    /// Publishes known-empty retirement authority only after atomic fresh-root creation.
    ///
    /// # Errors
    /// Rejects an already selected generation and failed durable publication.
    pub(super) async fn initialize_fresh_catalog(
        &self,
        mut catalog: Catalog,
    ) -> Result<(), StoreFailure> {
        if catalog.capabilities.generation.is_some() {
            return Err(files::layout_corrupt());
        }
        catalog.inventory = Some(Vec::new());
        catalog.exclusions = Some(Vec::new());
        let generation = self.next_generation(&catalog).await?;
        let empty =
            MergedShard::rebuild(0, generation, &[], &BTreeSet::new(), None, &BTreeSet::new())
                .map_err(|_| files::layout_corrupt())?;
        self.publish_shards(catalog, generation, &[empty]).await
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
    pub(super) async fn publish_pack_catalog(
        &self,
        mut catalog: Catalog,
        new: PackIndexSnapshot,
        inventory: PackInventoryEntry,
    ) -> Result<(), StoreFailure> {
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
        self.add_inventory(&mut catalog, inventory)?;
        self.publish_shards(catalog, generation, &shards).await
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
        if !self
            .replace_conditionally(&key, Some(&catalog.capability_bytes), &bytes)
            .await?
        {
            return Err(files::layout_corrupt());
        }
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
        self.ensure_layout().await?;
        Ok(identities)
    }

    fn catalog_identities(
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
        for identity in &identities {
            self.verified_body(&catalog, identity).await?;
        }
        self.ensure_layout().await?;
        Ok(identities)
    }
}

pub(super) fn registered(key: &str) -> Result<BucketKey, StoreFailure> {
    BucketKey::parse(key).map_err(|_| files::malformed())
}
