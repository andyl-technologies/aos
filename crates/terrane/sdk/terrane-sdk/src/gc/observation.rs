//! Reads complete selected inventories and metadata under a genuine held namespace.
//!
//! These observations retain physical preimages but grant no checkpoint or deletion
//! authority. The metadata adapter rejects data-body reads before opening a pack.

use super::{SelectedObservation, corrupt, unsupported};
use crate::bucket::BucketBinding;
use crate::bucket::held::{HeldBucket, HeldWatch};
use crate::bucket::publication::receipts::RecordRead;
use crate::pack::{
    MergedShard, PackClass, PackId, PackIndexSnapshot, PackReader, RawBodyDecoder, RecordState,
};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload,
    ContentValidator, IdentityPrefix, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    StoreErrorKind, StoreFailure,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use terrane_format::bucket::{
    BucketCapabilities, BucketKey, GenerationManifest, PackInventoryEntry,
};
use terrane_format::derivation::Memo;
use terrane_format::derived::AttrRecord;
use terrane_format::gc::publication::CommittedSelection;
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_format::refs::{RefClass, RefLogRecord, RefName, RefRecord};

#[path = "observation/containers.rs"]
mod containers;

#[path = "observation/metadata_placement.rs"]
mod metadata_placement;

pub(crate) use containers::CollectionCatalog;

/// Contains one exact inventoried commit-bearing ref and its selected history.
pub(crate) struct RootRef {
    /// Canonical complete ref name.
    pub(crate) name: RefName,
    /// Whole current selected record, absent for a removed name.
    pub(crate) current: Option<RefRecord>,
    /// Exact candidate-selected history, including an absent name's predecessor.
    pub(crate) logs: Vec<RefLogRecord>,
}

/// Reads one registered collector key without substituting it for logical selection.
///
/// # Errors
/// Rejects unregistered keys and failed or unsafe physical observations.
pub(crate) async fn record<F, B, V>(
    held: &HeldBucket<'_, F, B, V, true>,
    key: &str,
) -> Result<RecordRead, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let key = BucketKey::parse(key).map_err(|_| corrupt())?;
    held.bucket().read_optional_observed(&key).await
}

/// Resolves commit-bearing selected names and logs under the retained holder.
///
/// Opaque Notes remain in the whole selection fences and are omitted from roots.
///
/// # Errors
/// Refuses incomplete inventory/history, unknown selections and malformed whole
/// commit-bearing records.
pub(crate) async fn inventory<F, B, V>(
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
    reads: &mut Vec<RecordRead>,
) -> Result<Vec<RootRef>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    observed.revalidate().await?;
    let bytes = observed
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let capabilities = BucketCapabilities::decode(bytes).map_err(|_| corrupt())?;
    let names = capabilities.ref_names.ok_or_else(unsupported)?;
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let parsed = RefName::parse(&name).map_err(|_| corrupt())?;
        let key = BucketKey::ref_record(&name).map_err(|_| corrupt())?;
        let value = observed
            .logical()
            .get(key.as_str())
            .ok_or_else(corrupt)?
            .as_deref();
        if parsed.class() == RefClass::Notes {
            // D-83 keeps these exact names and whole values in `observed` and
            // its retained publication fences. Opaque sidecars never establish
            // content edges, even when their bytes resemble a RefRecord.
            continue;
        }
        let current = value
            .map(RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        let branch = matches!(
            parsed.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        );
        let logs = if branch {
            let selection = observed
                .state()
                .branches
                .iter()
                .find(|row| row.name == name)
                .ok_or_else(corrupt)?;
            match &selection.selection {
                CommittedSelection::Unknown => return Err(unsupported()),
                CommittedSelection::Never if current.is_none() => Vec::new(),
                CommittedSelection::Never => return Err(corrupt()),
                CommittedSelection::Selected(last) => {
                    if current
                        .as_ref()
                        .is_some_and(|record| record != last.as_ref())
                    {
                        return Err(corrupt());
                    }
                    held.bucket()
                        .committed_logs_observed(&name, last.as_ref().clone(), reads)
                        .await?
                }
            }
        } else {
            Vec::new()
        };
        result.push(RootRef {
            name: parsed,
            current,
            logs,
        });
    }
    observed.revalidate().await?;
    Ok(result)
}

/// Restricts the historical Guard's content access to verified metadata packs.
pub(crate) struct MetadataStore<'operation, 'held, F, B, V> {
    held: &'operation HeldBucket<'held, F, B, V, true>,
    reads: Mutex<Vec<RecordRead>>,
    identities: Mutex<Vec<Identity>>,
    selected: BTreeMap<String, Option<Vec<u8>>>,
    bodies: Mutex<BTreeMap<(u8, terrane_format::identity::Digest), Vec<u8>>>,
    packs: Mutex<BTreeMap<PackId, Arc<CachedMetadataPack>>>,
    parsed_catalog: Mutex<Option<Arc<crate::bucket::catalog::Catalog>>>,
    session: &'operation crate::gc::runner::session::Session,
    restore: Mutex<Option<RestoreCandidate>>,
}

/// Retains verified physical container bytes without admitting any member body.
struct CachedMetadataPack {
    inventory: PackInventoryEntry,
    index: RecordRead,
    pack: RecordRead,
}

#[derive(Clone)]
struct RestoreCandidate {
    inventory: terrane_format::bucket::PackInventoryEntry,
    snapshot: PackIndexSnapshot,
    check: crate::selected_bridge::OwnedFinalCheck,
}

impl<'operation, 'held, F, B, V> MetadataStore<'operation, 'held, F, B, V> {
    /// Borrows a real holder; no namespace or storage binding is manufactured.
    pub(crate) fn new(
        held: &'operation HeldBucket<'held, F, B, V, true>,
        observed: &SelectedObservation<'_>,
        session: &'operation crate::gc::runner::session::Session,
    ) -> Self {
        Self {
            held,
            reads: Mutex::new(Vec::new()),
            identities: Mutex::new(Vec::new()),
            selected: observed.logical().clone(),
            bodies: Mutex::new(BTreeMap::new()),
            packs: Mutex::new(BTreeMap::new()),
            parsed_catalog: Mutex::new(None),
            session,
            restore: Mutex::new(None),
        }
    }

    /// Returns all genuine metadata reads performed by this observation.
    ///
    /// # Errors
    /// Rejects poisoned observation synchronization.
    pub(crate) fn reads(&self) -> Result<Vec<RecordRead>, StoreFailure> {
        Ok(self.reads.lock().map_err(|_| corrupt())?.clone())
    }

    /// Returns the exact identities fetched through authenticated historical reads.
    ///
    /// # Errors
    /// Rejects poisoned observation synchronization.
    pub(crate) fn identities(&self) -> Result<Vec<Identity>, StoreFailure> {
        Ok(self.identities.lock().map_err(|_| corrupt())?.clone())
    }
}

impl<F, B, V> CapabilityReport for MetadataStore<'_, '_, F, B, V> {
    fn capabilities(&self) -> &Capabilities {
        self.held.capabilities()
    }
}

impl<F, B, V> MetadataStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Checks the actual held adapter, selected projection and live Session binding.
    ///
    /// # Errors
    /// Refuses another HeldBucket or Session reference, differing selected logical
    /// bytes, changed namespace identity/role or unavailable native retention.
    /// This checks observation binding only; current trust and asynchronous whole
    /// selected revalidation remain the closed producer's separate obligations.
    pub(crate) fn check_binding(
        &self,
        held: &HeldBucket<'_, F, B, V, true>,
        observed: &SelectedObservation<'_>,
        session: &crate::gc::runner::session::Session,
    ) -> Result<(), StoreFailure> {
        session.recheck()?;
        if !std::ptr::eq(self.held, held)
            || !std::ptr::eq(self.session, session)
            || self.selected != *observed.logical()
            || held.root() != observed.identity().root()
            || held.physical_identity() != observed.identity().physical_identity()
            || !observed.identity().writable()
        {
            return Err(unsupported());
        }
        held.retained_namespace()?;
        observed.identity().retained_namespace()?;
        Ok(())
    }

    /// Enables only the exact native candidate's nonquarantined metadata reads.
    ///
    /// # Errors
    /// Refuses another backend, changed pair, incomplete catalog, missing active
    /// exclusion, selected permanent burn or a second candidate configuration.
    pub(crate) async fn enable_restore(
        &self,
        pair: &crate::store::native_publication_effects::NativeRestorePair,
    ) -> Result<(), StoreFailure> {
        pair.check_root(self.held.root())
            .map_err(crate::selected_bridge::native_restore_failure)?;
        let catalog = self.collection_catalog().await?;
        let row = pair.inventory();
        if !catalog.inventory()?.contains(row)
            || !catalog
                .exclusions()?
                .iter()
                .any(|exclusion| exclusion.pack_id == row.pack_id)
            || catalog.burns()?.binary_search(&row.pack_id).is_ok()
        {
            return Err(unsupported());
        }
        let mut candidate = self.restore.lock().map_err(|_| corrupt())?;
        if candidate.is_some() {
            return Err(unsupported());
        }
        *candidate = Some(RestoreCandidate {
            inventory: row.clone(),
            snapshot: pair.snapshot().clone(),
            check: crate::selected_bridge::OwnedFinalCheck::restore_continuity(pair),
        });
        Ok(())
    }

    fn restore_candidate(&self) -> Result<Option<RestoreCandidate>, StoreFailure> {
        let candidate = self.restore.lock().map_err(|_| corrupt())?.clone();
        if let Some(candidate) = &candidate {
            candidate.check.recheck()?;
        }
        Ok(candidate)
    }

    fn permits_restore(
        &self,
        candidate: Option<&RestoreCandidate>,
        row: &crate::pack::MergedEntry,
    ) -> bool {
        candidate.is_some_and(|candidate| {
            row.pack().as_bytes() == &candidate.inventory.pack_id
                && row.state() != RecordState::Quarantine
                && candidate
                    .snapshot
                    .entries()
                    .iter()
                    .any(|entry| entry == row.entry())
        })
    }

    /// Shares parsed data only within this adapter's fixed held selection.
    ///
    /// Actual misses retain all of their physical preimages before choosing a
    /// cache winner. No history, current decision or protected control is cached.
    async fn catalog(&self) -> Result<Arc<crate::bucket::catalog::Catalog>, StoreFailure> {
        self.session.recheck()?;
        let cached = self.parsed_catalog.lock().map_err(|_| corrupt())?.clone();
        if let Some(catalog) = cached {
            self.session.recheck()?;
            return Ok(catalog);
        }

        let catalog = Arc::new(self.load_catalog().await?);
        self.session.recheck()?;
        self.parsed_catalog
            .lock()
            .map_err(|_| corrupt())?
            .get_or_insert_with(|| Arc::clone(&catalog));
        Ok(catalog)
    }

    /// Decodes a complete catalog while recording each actual artifact read.
    ///
    /// Partial failure preserves earlier read preimages and publishes no cache.
    async fn load_catalog(&self) -> Result<crate::bucket::catalog::Catalog, StoreFailure> {
        let capability_bytes = self
            .selected
            .get("CAPABILITIES")
            .and_then(Option::as_ref)
            .ok_or_else(corrupt)?
            .clone();
        let capabilities = BucketCapabilities::decode(&capability_bytes).map_err(|_| corrupt())?;
        let generation = capabilities.generation.ok_or_else(corrupt)?;
        let key = format!("objects/index/{generation}/MANIFEST");
        let manifest = GenerationManifest::decode(
            self.selected
                .get(&key)
                .and_then(Option::as_deref)
                .ok_or_else(corrupt)?,
        )
        .map_err(|_| corrupt())?;
        if manifest.generation != generation {
            return Err(corrupt());
        }
        let mut shards = Vec::with_capacity(manifest.shards.len());
        for shard in &manifest.shards {
            self.session.recheck()?;
            let read = record(
                self.held,
                &format!("objects/index/{generation}/{}.idx", shard.shard),
            )
            .await?;
            let bytes = read.bytes().ok_or_else(corrupt)?;
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Index, &shard.index_hash)
                .map_err(|_| corrupt())?;
            if bytes.len() as u64 != shard.index_size {
                return Err(corrupt());
            }
            TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
            shards.push(
                MergedShard::decode(
                    bytes,
                    generation,
                    u8::try_from(shard.shard).map_err(|_| corrupt())?,
                )
                .map_err(|_| corrupt())?,
            );
            self.reads.lock().map_err(|_| corrupt())?.push(read);
            if let Some((hash, size)) = shard.filter {
                let read = record(
                    self.held,
                    &format!("objects/index/{generation}/{}.flt", shard.shard),
                )
                .await?;
                let bytes = read.bytes().ok_or_else(corrupt)?;
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Filter, &hash)
                    .map_err(|_| corrupt())?;
                if bytes.len() as u64 != size {
                    return Err(corrupt());
                }
                TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
                self.reads.lock().map_err(|_| corrupt())?.push(read);
            }
        }
        Ok(crate::bucket::catalog::Catalog {
            capabilities,
            capability_bytes,
            shards,
            inventory: manifest.inventory,
            exclusions: manifest.exclusions,
            burns: manifest.burns,
        })
    }

    /// Inspects canonical side records without declaring every discovered row live.
    ///
    /// The walker independently verifies producer and occurrence compatibility.
    /// Inspection retains physical preimages; a subsequent semantic `get` still
    /// records the identity even when inspection already cached its body.
    ///
    /// # Errors
    /// Rejects incomplete selected inventories, malformed records, unsafe reads,
    /// poisoned sessions and conflicting content identities.
    pub(crate) async fn attribute_records(
        &self,
    ) -> Result<Vec<(Identity, AttrRecord)>, StoreFailure> {
        self.side_records(IdentityKind::Attribute, |identity, bytes| {
            let record = AttrRecord::decode(bytes).map_err(|_| corrupt())?;
            if record.identity().map_err(|_| corrupt())? != *identity {
                return Err(corrupt());
            }
            Ok(record)
        })
        .await
    }

    /// Inspects advisory Memos without introducing their claimed roots or recipes.
    ///
    /// The walker retains a record only after independently reaching its output
    /// Node. Inspection alone records physical preimages, never semantic marks.
    ///
    /// # Errors
    /// Rejects incomplete selected inventories, malformed or misaddressed records,
    /// unsafe physical reads and poisoned or expired observation sessions.
    pub(crate) async fn memo_records(&self) -> Result<Vec<(Identity, Memo)>, StoreFailure> {
        self.side_records(IdentityKind::Memo, |identity, bytes| {
            let record = Memo::decode(bytes).map_err(|_| corrupt())?;
            if record.identity().map_err(|_| corrupt())?
                != identity.terrane_v1_digest().map_err(|_| corrupt())?
            {
                return Err(corrupt());
            }
            Ok(record)
        })
        .await
    }

    /// Checks each selected association before reading the next physical body.
    ///
    /// Keeping decoding within the loop preserves the first refusal and final
    /// Session check of the existing Attribute observation.
    async fn side_records<R>(
        &self,
        kind: IdentityKind,
        decode: impl Fn(&Identity, &[u8]) -> Result<R, StoreFailure>,
    ) -> Result<Vec<(Identity, R)>, StoreFailure> {
        self.session.recheck()?;
        let catalog = self.catalog().await?;
        if catalog.inventory.is_none() || catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(unsupported());
        }

        let candidate = self.restore_candidate()?;
        let identities = catalog
            .shards
            .iter()
            .flat_map(|shard| shard.entries())
            .filter(|row| {
                row.entry().kind().identity_kind() == kind
                    && ((row.state() == RecordState::Live
                        && !self
                            .held
                            .bucket()
                            .physically_excluded(&catalog, row.pack().as_bytes()))
                        || self.permits_restore(candidate.as_ref(), row))
            })
            .map(|row| *row.entry().hash())
            .collect::<BTreeSet<_>>();
        let mut records = Vec::with_capacity(identities.len());
        for hash in identities {
            let identity = TERRANE_V1.from_digest(kind, &hash).map_err(|_| corrupt())?;
            let bytes = self.metadata(&identity, false).await?;
            let record = decode(&identity, &bytes)?;
            records.push((identity, record));
        }
        self.session.recheck()?;
        Ok(records)
    }

    async fn metadata(
        &self,
        identity: &Identity,
        retain_identity: bool,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.session.recheck()?;
        if matches!(
            identity.kind(),
            IdentityKind::Chunk | IdentityKind::Pack | IdentityKind::Index | IdentityKind::Filter
        ) {
            return Err(unsupported());
        }
        let hash = identity.terrane_v1_digest().map_err(|_| corrupt())?;
        // The transient kind discriminator is never serialized or treated as a
        // registered format value. The profile check above fixes the domain set.
        let cache_key = (identity.kind() as u8, hash);
        if let Some(bytes) = self
            .bodies
            .lock()
            .map_err(|_| corrupt())?
            .get(&cache_key)
            .cloned()
        {
            if retain_identity {
                self.identities
                    .lock()
                    .map_err(|_| corrupt())?
                    .push(identity.clone());
            }
            return Ok(bytes);
        }
        let bucket = self.held.bucket();
        let catalog = self.catalog().await?;
        if catalog.inventory.is_none() || catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(unsupported());
        }
        let candidate = self.restore_candidate()?;
        let selected_row = catalog
            .shards
            .iter()
            .find(|shard| shard.shard() == hash[0])
            .and_then(|shard| {
                shard
                    .entries()
                    .iter()
                    .find(|row| row.entry().hash() == &hash)
            });
        // Sticky identity quarantine blocks every maintenance placement. A fresh
        // selected Live row is preserved even when a recorded physical loss
        // requires candidate-only metadata for current-history verification.
        if selected_row.is_some_and(|row| row.state() == RecordState::Quarantine) {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        let candidate_entry = candidate.as_ref().and_then(|candidate| {
            candidate
                .snapshot
                .entries()
                .iter()
                .find(|entry| {
                    entry.hash() == &hash && entry.kind().identity_kind() == identity.kind()
                })
                .map(|entry| {
                    (
                        crate::pack::PackId::from_random_bytes(candidate.inventory.pack_id),
                        entry.clone(),
                    )
                })
        });
        let ordinary = selected_row.filter(|row| {
            row.entry().kind().identity_kind() == identity.kind()
                && ((row.state() == RecordState::Live
                    && !bucket.physically_excluded(&catalog, row.pack().as_bytes()))
                    || self.permits_restore(candidate.as_ref(), row))
        });
        let (mut id, mut location) = if let Some(row) = ordinary {
            let mut location = (row.pack(), row.entry().clone());
            if let Some(candidate_entry) = candidate_entry
                && row.pack() != candidate_entry.0
            {
                let primary_index = bucket
                    .read_optional_observed(
                        &BucketKey::parse(&row.pack().index_key()).map_err(|_| corrupt())?,
                    )
                    .await?;
                if let Some(bytes) = primary_index.bytes() {
                    let inventory = catalog
                        .inventory
                        .as_ref()
                        .and_then(|rows| {
                            rows.iter()
                                .find(|entry| entry.pack_id == *row.pack().as_bytes())
                        })
                        .ok_or_else(corrupt)?;
                    if u64::try_from(bytes.len()).map_err(|_| corrupt())? != inventory.index_size {
                        return Err(corrupt());
                    }

                    let identity = TERRANE_V1
                        .from_digest(IdentityKind::Index, &inventory.index_hash)
                        .map_err(|_| corrupt())?;
                    TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;

                    let header = PackIndexSnapshot::decode(
                        bytes,
                        catalog.capabilities.generation.ok_or_else(corrupt)?,
                    )
                    .map_err(|_| corrupt())?;
                    if header.header().id() != row.pack()
                        || header.header().class() != PackClass::Meta
                        || !header.entries().contains(row.entry())
                    {
                        return Err(corrupt());
                    }

                    let primary = bucket
                        .read_optional_observed(
                            &BucketKey::parse(&row.pack().pack_key()).map_err(|_| corrupt())?,
                        )
                        .await?;
                    if primary.bytes().is_none() {
                        location = candidate_entry;
                    }
                    self.reads
                        .lock()
                        .map_err(|_| corrupt())?
                        .extend([primary_index, primary]);
                } else {
                    self.reads
                        .lock()
                        .map_err(|_| corrupt())?
                        .push(primary_index);
                    location = candidate_entry;
                }
            }
            location
        } else {
            candidate_entry
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))?
        };
        let cached = self.packs.lock().map_err(|_| corrupt())?.get(&id).cloned();
        let mut acquired = None;
        let container = match cached {
            Some(container) => container,
            None => {
                let container = match self.read_metadata_pack(&catalog, id).await? {
                    Some(container) => container,
                    None => {
                        // Restoration preserves a fresh Live row even when its
                        // physical pack was lost. Only actual absence permits
                        // another currently eligible, fully verified placement.
                        let recovered = self
                            .recover_missing_metadata(&catalog, identity, id)
                            .await?;
                        id = recovered.0;
                        location = recovered.1;
                        recovered.2
                    }
                };
                let container = Arc::new(container);
                acquired = Some(Arc::clone(&container));
                container
            }
        };
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()))
            .ok_or_else(corrupt)?;
        if &container.inventory != inventory {
            return Err(corrupt());
        }
        let reader =
            PackReader::open(container.pack.bytes().ok_or_else(corrupt)?).map_err(|_| corrupt())?;
        // Membership, kind, canonical body and identity remain requested-member
        // checks, even when another identity already verified the same container.
        if !reader.entries().contains(&location) {
            return Err(corrupt());
        }
        let body = reader
            .read(location.kind(), &hash, &RawBodyDecoder)
            .map_err(|_| corrupt())?;
        self.session.recheck()?;
        if let Some(container) = acquired {
            // Every actual successful miss retains its own preimages, including
            // concurrent misses. Sharing bytes never drops conflicting reads.
            self.reads
                .lock()
                .map_err(|_| corrupt())?
                .extend([container.index.clone(), container.pack.clone()]);
            self.packs
                .lock()
                .map_err(|_| corrupt())?
                .entry(id)
                .or_insert(container);
        }
        if retain_identity {
            self.identities
                .lock()
                .map_err(|_| corrupt())?
                .push(identity.clone());
        }
        self.bodies
            .lock()
            .map_err(|_| corrupt())?
            .insert(cache_key, body.clone());
        Ok(body)
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, B, V> ContentStore for MetadataStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        Err(unsupported())
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range.is_some() {
            return Err(unsupported());
        }
        self.metadata(identity, true).await
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Err(unsupported())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(unsupported())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, B, V> RefStore for MetadataStore<'_, '_, F, B, V>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    type Watch = HeldWatch;
    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.held.read_selected_ref(name).await
    }

    async fn ref_cas(
        &self,
        _: &str,
        _: Option<&RefRecord>,
        _: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        Err(unsupported())
    }

    async fn ref_log_append(
        &self,
        _: &str,
        _: u64,
        _: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        Err(unsupported())
    }

    async fn ref_log_read(&self, name: &str, seq: u64) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.held.ref_log_read(name, seq).await
    }

    async fn ref_watch(&self, _: &str, _: u64) -> Result<HeldWatch, StoreFailure> {
        Err(unsupported())
    }
}
