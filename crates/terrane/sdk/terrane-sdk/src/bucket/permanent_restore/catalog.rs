//! Builds a fresh-placement catalog delta while preserving permanent ownership.
//!
//! Quarantine and unrelated live placements remain exact. Only the checked
//! permanent family's stale or tombstoned body rows move to the new pack; its
//! burn, active physical exclusion and old inventory bindings remain selected.

use super::super::{BucketBinding, catalog::Catalog, containers::ContainerArtifacts};
use crate::pack::{MergedShard, PackIndexSnapshot, RecordState};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::bucket::{GenerationManifest, GenerationShard};
use terrane_format::gc::publication::LogicalChange;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Constructs canonical backend-only changes from verified fresh artifacts.
///
/// # Errors
/// Refuses missing owner burns, malformed predecessors, generation overflow,
/// changed container identities and noncanonical catalog encodings.
pub(super) fn changes<F, B, V>(
    bucket: &super::super::FileBucket<F, B, V>,
    observed: &super::super::publication::SelectedObservation<'_>,
    mut catalog: Catalog,
    owned: [u8; 16],
    artifacts: &ContainerArtifacts,
) -> Result<Vec<LogicalChange>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let corrupt = super::super::publication::corrupt;
    if !catalog
        .burns
        .as_ref()
        .is_some_and(|burns| burns.contains(&owned))
        || !bucket.physically_excluded(&catalog, &owned)
    {
        return Err(corrupt());
    }
    let previous_generation = catalog.capabilities.generation.ok_or_else(corrupt)?;
    let previous_key = format!("objects/index/{previous_generation}/MANIFEST");
    let previous = GenerationManifest::decode(
        observed
            .logical()
            .get(&previous_key)
            .and_then(Option::as_deref)
            .ok_or_else(corrupt)?,
    )
    .map_err(|_| corrupt())?;
    let generation = previous_generation.checked_add(1).ok_or_else(corrupt)?;
    let index = PackIndexSnapshot::decode(artifacts.index(), generation).map_err(|_| corrupt())?;
    if bucket.physically_excluded(&catalog, index.header().id().as_bytes()) {
        return Err(corrupt());
    }
    bucket.add_inventory(&mut catalog, artifacts.inventory().clone())?;

    let mut prefixes = BTreeSet::from([0]);
    prefixes.extend(catalog.shards.iter().map(MergedShard::shard));
    prefixes.extend(index.entries().iter().map(|entry| entry.hash()[0]));
    let mut changes = Vec::new();
    let mut shards = Vec::new();
    for prefix in prefixes {
        let mut records = BTreeMap::new();
        if let Some(previous) = catalog.shards.iter().find(|shard| shard.shard() == prefix) {
            for row in terrane_format::pack_format::decode_shard(&previous.encode(), prefix)
                .map_err(|_| corrupt())?
            {
                records.insert(row.record.hash, row);
            }
        }
        let delta = MergedShard::rebuild(
            prefix,
            generation,
            std::slice::from_ref(&index),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
        )
        .map_err(|_| corrupt())?;
        for row in terrane_format::pack_format::decode_shard(&delta.encode(), prefix)
            .map_err(|_| corrupt())?
        {
            match records.entry(row.record.hash) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(mut entry)
                    if entry.get().pack == owned
                        && entry.get().state != RecordState::Quarantine as u8 =>
                {
                    if entry.get().record.kind != row.record.kind {
                        return Err(corrupt());
                    }
                    entry.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        let bytes =
            terrane_format::pack_format::encode_shard(&records.into_values().collect::<Vec<_>>());
        MergedShard::decode(&bytes, generation, prefix).map_err(|_| corrupt())?;
        let hash = TERRANE_V1
            .calculate(IdentityKind::Index, &bytes)
            .map_err(|_| corrupt())?
            .terrane_v1_digest()
            .map_err(|_| corrupt())?;
        shards.push(GenerationShard {
            shard: u64::from(prefix),
            index_hash: hash,
            index_size: bytes.len() as u64,
            filter: None,
        });
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{prefix}.idx"),
            expected: None,
            new: Some(bytes),
        });
    }
    let written_at = bucket
        .inner
        .clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| corrupt())?
        .as_secs();
    let manifest = GenerationManifest {
        generation,
        shards,
        written_at,
        cycle: previous.cycle,
        inventory: catalog.inventory,
        exclusions: catalog.exclusions,
        burns: catalog.burns,
    };
    changes.push(LogicalChange {
        key: format!("objects/index/{generation}/MANIFEST"),
        expected: None,
        new: Some(manifest.encode().map_err(|_| corrupt())?),
    });
    catalog.capabilities.generation = Some(generation);
    changes.push(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: Some(catalog.capability_bytes),
        new: Some(catalog.capabilities.encode().map_err(|_| corrupt())?),
    });
    changes.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(changes)
}
