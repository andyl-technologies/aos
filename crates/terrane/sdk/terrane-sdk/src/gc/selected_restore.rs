//! Qualifies exact current restoration and closed local ownership cancellation.
//!
//! The closed producer derives its selector, catalog successor and maintenance
//! pair under actual exclusion. A separately checked local owner is durably
//! cancelled before exclusion clearing; remote and copied owners remain refused.
//! It carries no old marks, creator or age claim.

use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::{self, MetadataStore};
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::{MergedShard, RecordState};
use crate::selected_bridge::CheckedRestoreCurrent;
use crate::store::native_publication_effects::NativeRestorePair;
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::bucket::{GenerationManifest, GenerationShard, PackExclusion};
use terrane_format::gc::Windows;
use terrane_format::gc::publication::{LogicalChange, PublicationState};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Owns current authority only for durable cancellation, without a restore successor.
pub(crate) struct CheckedLocalCancellation<'operation, 'held> {
    current: CheckedRestoreCurrent<'operation, 'held>,
    pair: NativeRestorePair,
    exclusion: PackExclusion,
}

impl<'operation, 'held> CheckedLocalCancellation<'operation, 'held> {
    /// Borrows independently current roots, controls and the whole lease.
    pub(crate) fn current(&self) -> &CheckedRestoreCurrent<'operation, 'held> {
        &self.current
    }

    /// Borrows the exact retained cancellation pair.
    pub(crate) fn pair(&self) -> &NativeRestorePair {
        &self.pair
    }

    /// Borrows the independently selected active exclusion.
    pub(crate) fn exclusion(&self) -> &PackExclusion {
        &self.exclusion
    }
}

/// Owns one exact privately qualified restoration transition and native pair.
pub(crate) struct CheckedRestore<'operation, 'held> {
    current: CheckedRestoreCurrent<'operation, 'held>,
    pair: NativeRestorePair,
    exclusion: PackExclusion,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    reads: Vec<RecordRead>,
}

impl<'operation, 'held> CheckedRestore<'operation, 'held> {
    /// Borrows complete independently current qualification.
    pub(crate) fn current(&self) -> &CheckedRestoreCurrent<'operation, 'held> {
        &self.current
    }

    /// Borrows actual native maintenance descriptors, without creator permission.
    pub(crate) fn pair(&self) -> &NativeRestorePair {
        &self.pair
    }

    /// Borrows the exact active selector derived from current selection.
    pub(crate) fn exclusion(&self) -> &PackExclusion {
        &self.exclusion
    }

    /// Borrows the checked whole successor with unchanged loss and selected sources.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows only fixed canonical restore-generation changes.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows actual generation reservations and catalog preimages.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("publication".into()),
    ))
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
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

/// Borrows the actual maintenance pair and its exact selected exclusion together.
struct CatalogRestore<'a> {
    pair: &'a NativeRestorePair,
    exclusion: &'a PackExclusion,
}

async fn catalog_changes<F, B, V>(
    held: &crate::bucket::held::HeldBucket<'_, F, B, V, true>,
    reads: &mut Vec<RecordRead>,
    current: &CheckedRestoreCurrent<'_, '_>,
    catalog: &collection_observation::CollectionCatalog,
    candidate: CatalogRestore<'_>,
    generation: u64,
    now: u64,
) -> Result<Vec<LogicalChange>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let CatalogRestore { pair, exclusion } = candidate;
    let pack = pair.inventory().pack_id;
    let mut exclusions = catalog.exclusions()?.to_vec();
    let position = exclusions
        .binary_search_by_key(&pack, |entry| entry.pack_id)
        .map_err(|_| corrupt())?;
    if &exclusions[position] != exclusion {
        return Err(corrupt());
    }
    exclusions.remove(position);

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
    let mut prefixes = std::collections::BTreeSet::from([0]);
    prefixes.extend(catalog.shards().iter().map(MergedShard::shard));
    prefixes.extend(
        pair.snapshot()
            .entries()
            .iter()
            .map(|entry| entry.hash()[0]),
    );
    for prefix in prefixes {
        let previous = catalog
            .shards()
            .iter()
            .find(|shard| shard.shard() == prefix);
        let previous_bytes = previous.map(MergedShard::encode);
        let old_records = previous_bytes
            .as_deref()
            .map(|bytes| terrane_format::pack_format::decode_shard(bytes, prefix))
            .transpose()
            .map_err(|_| corrupt())?
            .unwrap_or_default();
        let mut records = old_records
            .iter()
            .map(|row| (row.record.hash, row.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        for entry in pair
            .snapshot()
            .entries()
            .iter()
            .filter(|entry| entry.hash()[0] == prefix)
        {
            let candidate = terrane_format::pack_format::MergedRecord {
                record: terrane_format::pack_format::Record {
                    hash: *entry.hash(),
                    offset: entry.offset(),
                    body_len: entry.body_len(),
                    plaintext_len: entry.plaintext_len(),
                    codec: entry.codec() as u8,
                    kind: entry.kind() as u8,
                    dictionary_id: 0,
                },
                pack,
                state: RecordState::Live as u8,
            };
            if let Some(old) = records.get(entry.hash()) {
                if old.state == RecordState::Quarantine as u8 {
                    continue;
                }
                let excluded = catalog
                    .exclusions()?
                    .iter()
                    .any(|row| row.pack_id == old.pack)
                    || catalog.burns()?.binary_search(&old.pack).is_ok()
                    || catalog
                        .shards()
                        .iter()
                        .flat_map(|shard| shard.entries())
                        .any(|row| {
                            row.state() == RecordState::Tombstone
                                && row.pack().as_bytes() == &old.pack
                        });
                if old.state == RecordState::Live as u8 && !excluded {
                    continue;
                }
                if old.pack == pack && old.record != candidate.record {
                    return Err(corrupt());
                }
            }
            records.insert(*entry.hash(), candidate);
        }
        let bytes =
            terrane_format::pack_format::encode_shard(&records.into_values().collect::<Vec<_>>());
        MergedShard::decode(&bytes, generation, prefix).map_err(|_| corrupt())?;
        let hash = TERRANE_V1
            .calculate(IdentityKind::Index, &bytes)
            .map_err(|_| corrupt())?
            .terrane_v1_digest()
            .map_err(|_| corrupt())?;
        let old_row = old_manifest
            .shards
            .iter()
            .find(|row| row.shard == u64::from(prefix));
        let mut filter = None;
        if previous_bytes.as_deref() == Some(bytes.as_slice()) {
            let old_row = old_row.ok_or_else(corrupt)?;
            if old_row.index_hash != hash
                || old_row.index_size != u64::try_from(bytes.len()).map_err(|_| corrupt())?
            {
                return Err(corrupt());
            }
            if let Some((filter_hash, filter_size)) = old_row.filter {
                let read = collection_observation::record(
                    held,
                    &format!("objects/index/{old_generation}/{}.flt", prefix),
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
                    key: format!("objects/index/{generation}/{}.flt", prefix),
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
            shard: u64::from(prefix),
            index_hash: hash,
            index_size: u64::try_from(bytes.len()).map_err(|_| corrupt())?,
            filter,
        });
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.idx", prefix),
            expected: None,
            new: Some(bytes),
        });
    }
    let manifest = GenerationManifest {
        generation,
        shards,
        written_at: now,
        cycle: old_manifest.cycle,
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

/// Restores only an exact current active binding after fresh complete qualification.
///
/// # Errors
/// Preserves typed storage/Guard failures and refuses incomplete selected data,
/// remote or copied burns/owners, unqualified local ownership, missing or unsafe
/// pairs, and failed cancellation or restoration durability.
pub(crate) async fn restore_pack<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &mut Session,
    settings: (u64, Windows),
    requested: &PackExclusion,
) -> Result<bool, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    session.recheck()?;
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    let mut retained = None;
    let mut cancelled = false;
    loop {
        // Every lease-only transition discards the previous selection and plans.
        let renewal_controls = {
            let observed = held.observe_publication_unrepaired().await?;
            let metadata = MetadataStore::new(&held, &observed, session);
            let catalog = metadata.collection_catalog().await?;
            let Some(exclusion) = catalog
                .exclusions()?
                .iter()
                .find(|row| row.pack_id == requested.pack_id)
            else {
                return if cancelled {
                    Err(unsupported().into())
                } else {
                    Ok(false)
                };
            };
            if exclusion != requested {
                return if cancelled {
                    Err(unsupported().into())
                } else {
                    Ok(false)
                };
            }
            if catalog.burns()?.binary_search(&requested.pack_id).is_ok()
                || observed
                    .state()
                    .burn_owners
                    .as_ref()
                    .ok_or_else(unsupported)?
                    .iter()
                    .any(|row| row.pack == requested.pack_id)
            {
                return Err(unsupported().into());
            }
            let read = metadata
                .pack_index(
                    &catalog,
                    crate::pack::PackId::from_random_bytes(requested.pack_id),
                )
                .await?;
            let owned =
                crate::store::native_publication_effects::collection_local_deletion::restore_owner(
                    held.fs(),
                    &observed,
                    exclusion,
                    catalog.capabilities().generation.ok_or_else(corrupt)?,
                )
                .await?;
            if cancelled && owned.is_none() {
                return Err(unsupported().into());
            }
            let pair = if let Some(receipt) = &owned {
                crate::store::native_publication_effects::observe_cancellation_pair(
                    held.fs(),
                    &observed,
                    &read,
                    exclusion,
                    std::sync::Arc::clone(receipt),
                )
                .await?
            } else {
                crate::store::native_publication_effects::observe_restore_pair(
                    held.fs(),
                    &observed,
                    &read,
                    exclusion,
                )
                .await?
            };
            let current = match retained.as_ref() {
                Some(controls) => {
                    super::native_current_collection::qualify_restore_retained(
                        guard,
                        authority,
                        session,
                        &held,
                        &observed,
                        (settings, Some(controls)),
                        &pair,
                    )
                    .await?
                }
                None => {
                    super::native_current_collection::qualify_restore(
                        guard, authority, session, &held, &observed, settings, &pair,
                    )
                    .await?
                }
            };
            if let Some(owned) = owned.filter(|_| !cancelled) {
                let checked = CheckedLocalCancellation {
                    current,
                    pair,
                    exclusion: exclusion.clone(),
                };
                crate::store::native_publication_effects::collection_restore::cancel_local_owner(
                    held.fs(),
                    &checked,
                    owned,
                )
                .await?;
                // This receipt owns the same actual Original lock through renewal and
                // the next complete qualification; no reacquisition or decoded permit.
                let controls = checked.current().effect_context().controls();
                if controls.len() != 1 {
                    return Err(unsupported().into());
                }
                controls.first().cloned().ok_or_else(unsupported)?
            } else {
                let mut reads = metadata.reads()?;
                let generation = next_generation(
                    &held,
                    catalog.capabilities().generation.ok_or_else(corrupt)?,
                    &mut reads,
                )
                .await?;
                let changes = catalog_changes(
                    &held,
                    &mut reads,
                    &current,
                    &catalog,
                    CatalogRestore {
                        pair: &pair,
                        exclusion,
                    },
                    generation,
                    session.recheck()?,
                )
                .await?;
                let mut next = observed.state().clone();
                next.revision = next.revision.checked_add(1).ok_or_else(corrupt)?;
                let mut logical = observed.logical().clone();
                for change in &changes {
                    if logical.get(&change.key).and_then(Option::as_ref) != change.expected.as_ref()
                    {
                        return Err(corrupt().into());
                    }
                    logical.insert(change.key.clone(), change.new.clone());
                }
                held.validate_collection_successor(&observed, session, &next, &logical)
                    .await?;
                current.revalidate().await?;
                let checked = CheckedRestore {
                    current,
                    pair,
                    exclusion: exclusion.clone(),
                    next,
                    changes,
                    reads,
                };
                crate::store::native_publication_effects::collection_restore::publish_checked(
                    held.fs(),
                    &checked,
                )
                .await?;
                return Ok(true);
            }
        };
        // All old borrowed observations/checks and successor expectations have
        // ended before mutating Session's genuinely acknowledged whole lease.
        let collector = crate::gc::lease::Collector::new(guard, authority);
        let mut context = collector.held(&held, Some(&renewal_controls)).await?;
        session.renew_held(&mut context).await?;
        drop(context);
        retained = Some(renewal_controls);
        cancelled = true;
    }
}
