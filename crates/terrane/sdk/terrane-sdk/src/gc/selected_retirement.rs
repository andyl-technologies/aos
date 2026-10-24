//! Qualifies one initial unburned retirement from actual current roots and native age.
//!
//! The closed producer owns the complete current qualifier and executor-produced
//! pack/index pair. It lists candidates independently of selected inventory,
//! preserves every unrelated placement and preserves independently completed eligible source lineage. The
//! returned Tombstone acknowledges Trash creation only, never deletion progress.

use crate::bucket::BucketBinding;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::{self, MetadataStore};
use crate::bucket::publication::receipts::RecordRead;
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::{MergedShard, PackId, RecordState};
use crate::selected_bridge::CheckedCurrentCollection;
use crate::store::native_publication_effects::NativeCurrentPair;
use crate::store::{Clock, ContentValidator, LocalFs, NativeEffectFailure, StoreFailure};
use std::collections::BTreeSet;
use terrane_format::bucket::{BucketKey, GenerationManifest, GenerationShard, PackExclusion};
use terrane_format::gc::publication::{LogicalChange, PublicationState, RemovedPack};
use terrane_format::gc::{GcRoots, GcState, Tombstone, Windows};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Owns the genuine current proof and native pair for one fixed exclusion transition.
///
/// All fields are private to this producer. Decoded Tombstone, catalog, marks or
/// caller timestamps cannot construct it. Its effects require the same held
/// namespace and complete refreshed controls through durable acknowledgment.
pub(crate) struct CheckedRetirement<'operation, 'held> {
    current: CheckedCurrentCollection<'operation, 'held>,
    pair: NativeCurrentPair,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    reads: Vec<RecordRead>,
    tombstone: Tombstone,
    fence_key: String,
    fence_bytes: Vec<u8>,
}

impl<'operation, 'held> CheckedRetirement<'operation, 'held> {
    /// Borrows the independently completed current-root and control proof.
    pub(crate) fn current(&self) -> &CheckedCurrentCollection<'operation, 'held> {
        &self.current
    }

    /// Borrows the executor-produced actual retained pair, without descriptor access.
    pub(crate) fn pair(&self) -> &NativeCurrentPair {
        &self.pair
    }

    /// Borrows the whole proposed successor with independently completed carried sources.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows only the fixed catalog-generation logical changes.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows exact candidate/index and generation-reservation observations.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }

    /// Borrows the exact current fence at its canonical immutable cycle/revision key.
    pub(crate) fn fence(&self) -> (&str, &[u8]) {
        (&self.fence_key, &self.fence_bytes)
    }

    /// Borrows the fixed first-retirement Trash body without creation or elapsed authority.
    pub(crate) fn tombstone(&self) -> &Tombstone {
        &self.tombstone
    }

    /// Derives the removed witness only from the executor-qualified inventory association.
    pub(crate) fn removed(&self) -> RemovedPack {
        RemovedPack {
            pack: self.pair.inventory().pack_id,
            index: self.pair.inventory().index_hash,
        }
    }
}

fn native_failure(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => io_failure(error),
    }
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(crate::store::StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("publication".into()),
    ))
}

fn io_failure(error: std::io::Error) -> StoreFailure {
    let kind = if error.kind() == std::io::ErrorKind::Unsupported {
        crate::store::StoreErrorKind::Unsupported
    } else {
        crate::store::StoreErrorKind::Unavailable { retry_after: None }
    };
    StoreFailure::with_source(kind, error)
}

async fn listed_candidates<F: LocalFs>(
    fs: &F,
    root: &std::path::Path,
) -> Result<BTreeSet<std::path::PathBuf>, StoreFailure> {
    let base = root.join("objects/pack");
    let directories = match fs.read_dir(&base).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(io_failure(error)),
    };
    let mut result = BTreeSet::new();
    for directory in directories {
        if directory.parent() != Some(base.as_path()) {
            return Err(corrupt());
        }
        let metadata = fs.symlink_metadata(&directory).await.map_err(io_failure)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(corrupt());
        }
        for path in fs.read_dir(&directory).await.map_err(io_failure)? {
            if path.parent() != Some(directory.as_path()) {
                return Err(corrupt());
            }
            let key = path
                .strip_prefix(root)
                .map_err(|_| corrupt())?
                .to_str()
                .ok_or_else(corrupt)?;
            if BucketKey::parse(key).is_ok() && key.ends_with(".pack") {
                result.insert(path);
            }
        }
    }
    Ok(result)
}

async fn next_generation<F, B, V>(
    held: &crate::bucket::held::HeldBucket<'_, F, B, V, true>,
    old: u64,
    reads: &mut Vec<RecordRead>,
) -> Result<u64, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let mut generation = old.checked_add(1).ok_or_else(corrupt)?;
    loop {
        let first =
            collection_observation::record(held, &format!("objects/index/{generation}/0.idx"))
                .await?;
        let manifest =
            collection_observation::record(held, &format!("objects/index/{generation}/MANIFEST"))
                .await?;
        let missing = first.bytes().is_none() && manifest.bytes().is_none();
        reads.extend([first, manifest]);
        if missing {
            return Ok(generation);
        }
        generation = generation.checked_add(1).ok_or_else(corrupt)?;
    }
}

/// Retains the complete selected destination history for first-cycle use only.
///
/// A checkpoint that already inventories this ID truncates its earlier history.
/// Missing Trash/journal alone never establishes that an incarnation is fresh.
async fn first_incarnation<F, B, V>(
    held: &crate::bucket::held::HeldBucket<'_, F, B, V, true>,
    observed: &crate::bucket::publication::SelectedObservation<'_>,
    pack: &[u8; 16],
    cycle: u64,
    reads: &mut Vec<RecordRead>,
) -> Result<(), StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let mut pointer = observed.snapshot().clone();
    let mut seen = BTreeSet::new();
    let mut successor: Option<terrane_format::gc::publication::PortableSnapshot> = None;
    loop {
        if !seen.insert(pointer.key.clone()) {
            return Err(corrupt());
        }
        let read = collection_observation::record(held, &pointer.key).await?;
        let bytes = read.bytes().ok_or_else(corrupt)?;
        pointer.check_snapshot(bytes).map_err(|_| corrupt())?;
        let snapshot = terrane_format::gc::publication::PortableSnapshot::decode(bytes)
            .map_err(|_| corrupt())?;
        if snapshot.origin != observed.state().binding {
            return Err(corrupt());
        }
        if let Some(next) = &successor {
            next.check_predecessor(&pointer, bytes)
                .map_err(|_| corrupt())?;
        } else if snapshot.revision != observed.state().revision {
            return Err(corrupt());
        }
        let genesis = snapshot.predecessor.is_none();
        for entry in &snapshot.projection {
            if entry.key.starts_with("objects/index/") && entry.key.ends_with("/MANIFEST") {
                let manifest =
                    GenerationManifest::decode(entry.value.as_deref().ok_or_else(corrupt)?)
                        .map_err(|_| corrupt())?;
                let exclusions = manifest
                    .exclusions
                    .as_ref()
                    .ok_or_else(|| StoreFailure::new(crate::store::StoreErrorKind::Unsupported))?;
                if exclusions
                    .iter()
                    .any(|row| &row.pack_id == pack && row.cycle == cycle)
                    || genesis
                        && manifest
                            .inventory
                            .as_ref()
                            .is_none_or(|rows| rows.iter().any(|row| &row.pack_id == pack))
                {
                    return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
                }
            }
        }
        if genesis {
            let cap = snapshot
                .projection
                .iter()
                .find(|row| row.key == "CAPABILITIES")
                .and_then(|row| row.value.as_deref())
                .ok_or_else(corrupt)?;
            let cap =
                terrane_format::bucket::BucketCapabilities::decode(cap).map_err(|_| corrupt())?;
            if let Some(generation) = cap.generation
                && !snapshot.projection.iter().any(|row| {
                    row.key == format!("objects/index/{generation}/MANIFEST") && row.value.is_some()
                })
            {
                return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
            }
            reads.push(read);
            return Ok(());
        }
        pointer = snapshot.predecessor.clone().ok_or_else(corrupt)?;
        successor = Some(snapshot);
        reads.push(read);
    }
}

/// Checks first-use refusal against an actual selected chain without producing authority.
///
/// # Errors
/// Refuses an earlier same-cycle exclusion, truncated imported inventory or invalid chain.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) async fn check_first_incarnation<F, B, V>(
    held: &crate::bucket::held::HeldBucket<'_, F, B, V, true>,
    observed: &crate::bucket::publication::SelectedObservation<'_>,
    pack: &[u8; 16],
    cycle: u64,
) -> Result<(), StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    first_incarnation(held, observed, pack, cycle, &mut Vec::new()).await
}

async fn catalog_changes<F, B, V>(
    held: &crate::bucket::held::HeldBucket<'_, F, B, V, true>,
    reads: &mut Vec<RecordRead>,
    current: &CheckedCurrentCollection<'_, '_>,
    catalog: &collection_observation::CollectionCatalog,
    pair: &NativeCurrentPair,
    generation: u64,
    now: u64,
) -> Result<Vec<LogicalChange>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let pack = pair.inventory().pack_id;
    let (roots, _) = current.selected_checkpoint();
    let mut exclusions = catalog.exclusions()?.to_vec();
    let position = match exclusions.binary_search_by_key(&pack, |entry| entry.pack_id) {
        Err(position) => position,
        Ok(_) => return Err(corrupt()),
    };
    exclusions.insert(
        position,
        PackExclusion {
            pack_id: pack,
            cycle: roots.cycle,
            epoch: current.effect_context().lease().epoch,
        },
    );
    let old_generation = catalog.capabilities().generation.ok_or_else(corrupt)?;
    let old_manifest = GenerationManifest::decode(
        current
            .observed()
            .logical()
            .get(&format!("objects/index/{old_generation}/MANIFEST"))
            .and_then(Option::as_deref)
            .ok_or_else(corrupt)?,
    )
    .map_err(|_| corrupt())?;
    let mut shards = Vec::new();
    let mut changes = Vec::new();
    for previous in catalog.shards() {
        let mut records =
            terrane_format::pack_format::decode_shard(&previous.encode(), previous.shard())
                .map_err(|_| corrupt())?;
        for record in &mut records {
            if record.pack == pack && record.state == RecordState::Live as u8 {
                // Every carried row is preserved byte-for-byte except this exact
                // candidate's Live->Tombstone state. Fresh Q and quarantine win.
                let entry = pair
                    .snapshot()
                    .entries()
                    .iter()
                    .find(|entry| entry.hash() == &record.record.hash)
                    .ok_or_else(corrupt)?;
                if entry.offset() != record.record.offset
                    || entry.body_len() != record.record.body_len
                    || entry.plaintext_len() != record.record.plaintext_len
                    || entry.codec() as u8 != record.record.codec
                    || entry.kind() as u8 != record.record.kind
                {
                    return Err(corrupt());
                }
                record.state = RecordState::Tombstone as u8;
            }
        }
        let bytes = terrane_format::pack_format::encode_shard(&records);
        MergedShard::decode(&bytes, generation, previous.shard()).map_err(|_| corrupt())?;
        let hash = TERRANE_V1
            .calculate(IdentityKind::Index, &bytes)
            .map_err(|_| corrupt())?
            .terrane_v1_digest()
            .map_err(|_| corrupt())?;
        let old_row = old_manifest
            .shards
            .iter()
            .find(|row| row.shard == u64::from(previous.shard()))
            .ok_or_else(corrupt)?;
        let mut filter = None;
        if bytes == previous.encode() {
            if old_row.index_hash != hash
                || old_row.index_size != u64::try_from(bytes.len()).map_err(|_| corrupt())?
            {
                return Err(corrupt());
            }
            if let Some((filter_hash, filter_size)) = old_row.filter {
                let read = collection_observation::record(
                    held,
                    &format!("objects/index/{old_generation}/{}.flt", previous.shard()),
                )
                .await?;
                let body = read.bytes().ok_or_else(corrupt)?;
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Filter, body)
                    .map_err(|_| corrupt())?;
                if body.len() as u64 != filter_size
                    || identity.terrane_v1_digest().map_err(|_| corrupt())? != filter_hash
                {
                    return Err(corrupt());
                }
                changes.push(LogicalChange {
                    key: format!("objects/index/{generation}/{}.flt", previous.shard()),
                    expected: None,
                    new: Some(body.to_vec()),
                });
                reads.push(read);
                filter = old_row.filter;
            }
        }
        // BKT-4's optional three-field entry omits a changed shard's filter;
        // readers then consult the complete shard. Unchanged filters are kept.
        shards.push(GenerationShard {
            shard: u64::from(previous.shard()),
            index_hash: hash,
            index_size: u64::try_from(bytes.len()).map_err(|_| corrupt())?,
            filter,
        });
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.idx", previous.shard()),
            expected: None,
            new: Some(bytes),
        });
    }
    let manifest = GenerationManifest {
        generation,
        shards,
        written_at: now,
        cycle: roots.cycle,
        inventory: Some(catalog.inventory()?.to_vec()),
        exclusions: Some(exclusions),
        burns: Some(catalog.burns()?.to_vec()),
    };
    changes.push(LogicalChange {
        key: format!("objects/index/{generation}/MANIFEST"),
        expected: None,
        new: Some(manifest.encode().map_err(|_| corrupt())?),
    });
    let mut capabilities = catalog.capabilities().clone();
    capabilities.generation = Some(generation);
    changes.push(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: Some(catalog.capability_bytes().to_vec()),
        new: Some(capabilities.encode().map_err(|_| corrupt())?),
    });
    changes.sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
    Ok(changes)
}

/// Selects and genuinely creates Trash for at most one independently eligible listed pack.
///
/// The caller renews before acquiring the holder and keeps an actual Session
/// operation alive. A None result means this listing contains no new eligible
/// candidate; imported Unknown, unsafe incarnations and failures remain typed.
/// A requested identifier only narrows the candidates after full current proof;
/// it never supplies eligibility, native age or publication permission.
///
/// # Errors
/// Refuses incomplete catalog/current proof, lost lease, young or changed native
/// versions, unknown creation journals, active/burned candidates, failed checked
/// arithmetic, selected barrier durability or Trash creator acknowledgment.
pub(crate) async fn retire_one<F, B, V, C>(
    guard: &Guard<crate::bucket::FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    checkpoint: (&GcRoots, &GcState),
    windows: Windows,
    requested: Option<PackId>,
) -> Result<Option<Tombstone>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    session.recheck()?;
    #[cfg(test)]
    retirement_stage("holder", None);
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    #[cfg(test)]
    retirement_stage("initial-observation", None);
    let observed = held.observe_publication_unrepaired().await?;
    #[cfg(test)]
    retirement_stage("current-qualification", None);
    let current = super::native_current_collection::qualify_retirement(
        guard, authority, session, &held, &observed, checkpoint, windows,
    )
    .await?;
    #[cfg(test)]
    retirement_stage("catalog", None);
    let metadata = MetadataStore::new(&held, &observed, session);
    let catalog = metadata.collection_catalog().await?;
    #[cfg(test)]
    retirement_stage("candidate-listing", None);
    let listed = listed_candidates(held.fs(), held.root()).await?;
    #[cfg(test)]
    retirement_stage("candidate-selection", None);
    for row in catalog.inventory()? {
        let pack = PackId::from_random_bytes(row.pack_id);
        if requested.is_some_and(|requested| requested != pack) {
            continue;
        }
        if !listed.contains(&held.root().join(pack.pack_key()))
            || catalog.burns()?.binary_search(&row.pack_id).is_ok()
            || catalog
                .exclusions()?
                .binary_search_by_key(&row.pack_id, |entry| entry.pack_id)
                .is_ok()
        {
            continue;
        }
        session.recheck()?;
        let read = metadata.pack_index(&catalog, pack).await?;
        if !current.members_unmarked(read.snapshot()) {
            continue;
        }
        let pair = crate::store::native_publication_effects::observe_current_pair(
            held.fs(),
            &observed,
            &read,
        )
        .await?;
        if pair.inventory() != row
            || pair.snapshot() != read.snapshot()
            || !current.members_unmarked(pair.snapshot())
        {
            return Err(corrupt().into());
        }
        let modified = pair.pair_modified_unix_seconds().map_err(native_failure)?;
        let now = session.recheck()?;
        if !windows.sweep_age(now, modified) {
            continue;
        }
        #[cfg(test)]
        retirement_stage("candidate-selected", Some(*pack.as_bytes()));
        let mut reads = metadata.reads()?;
        first_incarnation(
            &held,
            &observed,
            &row.pack_id,
            checkpoint.0.cycle,
            &mut reads,
        )
        .await?;
        let generation = next_generation(
            &held,
            catalog.capabilities().generation.ok_or_else(corrupt)?,
            &mut reads,
        )
        .await?;
        #[cfg(test)]
        retirement_stage("catalog-changes", Some(*pack.as_bytes()));
        let changes = catalog_changes(
            &held, &mut reads, &current, &catalog, &pair, generation, now,
        )
        .await?;
        let mut next = observed.state().clone();
        next.revision = next.revision.checked_add(1).ok_or_else(corrupt)?;
        next.loss_generation = next.loss_generation.checked_add(1).ok_or_else(corrupt)?;
        next.sources = current
            .sources()
            .ok_or_else(corrupt)?
            .lineages()
            .iter()
            .map(|(row, _)| row.clone())
            .collect();
        let mut logical = observed.logical().clone();
        for change in &changes {
            logical.insert(change.key.clone(), change.new.clone());
        }
        #[cfg(test)]
        retirement_stage("successor-validation", Some(*pack.as_bytes()));
        held.validate_collection_successor(&observed, session, &next, &logical)
            .await?;
        let tombstone = Tombstone {
            pack: row.pack_id,
            cycle: checkpoint.0.cycle,
            timestamp: now,
            removed: u64::try_from(pair.snapshot().entries().len()).map_err(|_| corrupt())?,
            epoch: session.lease().epoch,
        };
        let fence_key = format!("gc/{}/fence/{}", tombstone.cycle, observed.state().revision);
        let fence_bytes = current.fence().encode().map_err(|_| corrupt())?;
        #[cfg(test)]
        retirement_stage("current-revalidation", Some(*pack.as_bytes()));
        current.revalidate().await?;
        let checked = CheckedRetirement {
            current,
            pair,
            next,
            changes,
            reads,
            tombstone,
            fence_key,
            fence_bytes,
        };
        #[cfg(test)]
        retirement_stage("native-publication", Some(*pack.as_bytes()));
        crate::store::native_publication_effects::collection_retirement::publish_checked(
            held.fs(),
            &checked,
        )
        .await?;
        #[cfg(test)]
        retirement_stage("after-observation", Some(*pack.as_bytes()));
        let after = held.observe_publication_unrepaired().await?;
        let mut expected = observed.logical().clone();
        for change in checked.changes() {
            expected.insert(change.key.clone(), change.new.clone());
        }
        if after.state() != checked.next() || after.logical() != &expected {
            return Err(corrupt().into());
        }
        session.recheck()?;
        #[cfg(test)]
        retirement_stage("complete", Some(*pack.as_bytes()));
        return Ok(Some(checked.tombstone().clone()));
    }
    current.revalidate().await?;
    session.recheck()?;
    #[cfg(test)]
    retirement_stage("no-candidate", None);
    Ok(None)
}

/// Reports phase boundaries without supplying collector time or authority.
#[cfg(test)]
fn retirement_stage(phase: &'static str, pack: Option<[u8; 16]>) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!(
            "gc-retirement-stage phase={phase} pack={pack:?} process_at={:?}",
            crate::diagnostic_clock::tick(),
        );
    }
}
