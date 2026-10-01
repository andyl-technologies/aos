//! Reads complete selected inventories and metadata under a genuine held namespace.
//!
//! These observations retain physical preimages but grant no checkpoint or deletion
//! authority. The metadata adapter rejects data-body reads before opening a pack.

use super::{SelectedObservation, corrupt, unsupported};
use crate::bucket::BucketBinding;
use crate::bucket::held::{HeldBucket, HeldWatch};
use crate::bucket::publication::receipts::RecordRead;
use crate::pack::{
    MergedShard, PackClass, PackIndexSnapshot, PackReader, RawBodyDecoder, RecordState,
};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload,
    ContentValidator, IdentityPrefix, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    StoreErrorKind, StoreFailure,
};
use std::{collections::BTreeMap, sync::Mutex};
use terrane_core::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_core::gc::publication::CommittedSelection;
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::refs::{RefClass, RefLogRecord, RefName, RefRecord};

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
    bodies: Mutex<BTreeMap<(u8, terrane_core::identity::Digest), Vec<u8>>>,
    session: &'operation crate::gc::runner::session::Session,
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
            session,
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
    async fn catalog(&self) -> Result<crate::bucket::catalog::Catalog, StoreFailure> {
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

    async fn metadata(&self, identity: &Identity) -> Result<Vec<u8>, StoreFailure> {
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
            return Ok(bytes);
        }
        let bucket = self.held.bucket();
        let catalog = self.catalog().await?;
        if catalog.inventory.is_none() || catalog.exclusions.is_none() || catalog.burns.is_none() {
            return Err(unsupported());
        }
        let location = catalog
            .shards
            .iter()
            .find(|shard| shard.shard() == hash[0])
            .and_then(|shard| {
                shard
                    .entries()
                    .iter()
                    .find(|row| row.entry().hash() == &hash)
            })
            .filter(|row| {
                row.state() == RecordState::Live
                    && row.entry().kind().identity_kind() == identity.kind()
                    && !bucket.physically_excluded(&catalog, row.pack().as_bytes())
            })
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))?;
        let id = location.pack();
        let index = bucket
            .read_optional_observed(&BucketKey::parse(&id.index_key()).map_err(|_| corrupt())?)
            .await?;
        let index_bytes = index.bytes().ok_or_else(corrupt)?;
        let snapshot = PackIndexSnapshot::decode(
            index_bytes,
            catalog.capabilities.generation.ok_or_else(corrupt)?,
        )
        .map_err(|_| corrupt())?;
        if snapshot.header().id() != id || snapshot.header().class() != PackClass::Meta {
            return Err(corrupt());
        }
        let entry = catalog
            .inventory
            .as_ref()
            .and_then(|entries| entries.iter().find(|entry| entry.pack_id == *id.as_bytes()))
            .ok_or_else(corrupt)?;
        if index_bytes.len() as u64 != entry.index_size {
            return Err(corrupt());
        }
        let index_identity = TERRANE_V1
            .from_digest(IdentityKind::Index, &entry.index_hash)
            .map_err(|_| corrupt())?;
        TERRANE_V1
            .verify(&index_identity, index_bytes)
            .map_err(|_| corrupt())?;
        let pack = bucket
            .read_optional_observed(&BucketKey::parse(&id.pack_key()).map_err(|_| corrupt())?)
            .await?;
        let bytes = pack.bytes().ok_or_else(corrupt)?;
        if bytes.len() as u64 != entry.pack_size {
            return Err(corrupt());
        }
        let pack_identity = TERRANE_V1
            .from_digest(IdentityKind::Pack, &entry.pack_hash)
            .map_err(|_| corrupt())?;
        TERRANE_V1
            .verify(&pack_identity, bytes)
            .map_err(|_| corrupt())?;
        let reader = PackReader::open(bytes).map_err(|_| corrupt())?;
        reader
            .check_index_object(index_bytes)
            .map_err(|_| corrupt())?;
        if !reader.entries().contains(location.entry()) {
            return Err(corrupt());
        }
        let body = reader
            .read(location.entry().kind(), &hash, &RawBodyDecoder)
            .map_err(|_| corrupt())?;
        self.session.recheck()?;
        let mut reads = self.reads.lock().map_err(|_| corrupt())?;
        reads.extend([index, pack]);
        self.identities
            .lock()
            .map_err(|_| corrupt())?
            .push(identity.clone());
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
        self.metadata(identity).await
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
