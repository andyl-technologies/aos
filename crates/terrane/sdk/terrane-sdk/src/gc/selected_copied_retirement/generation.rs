//! Builds a fresh copied exclusion generation without changing DATA placement.
//!
//! Every existing shard/filter body, inventory member and burn remains exact.
//! Only the copied family's destination exclusion incarnation changes. New
//! names carry real protected absence observations rather than caller promises.

use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{collection_observation, receipts::RecordRead};
use crate::selected_bridge::native_copied_placement::CheckedDataPlacement;
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest, PackExclusion};
use terrane_format::gc::publication::LogicalChange;
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Retains exact generation changes and independently observed name predicates.
pub(super) struct GenerationProposal {
    /// Sorted whole logical changes preserving all existing DATA catalog rows.
    pub(super) changes: Vec<LogicalChange>,
    /// Actual prior bodies and fresh-name absences consumed by publication.
    pub(super) reads: Vec<RecordRead>,
}

fn refusal() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-copied-preparation",
        pattern: "fresh destination exclusion generation".into(),
    })
}

/// Observes and proposes the one fresh destination catalog generation.
///
/// # Errors
/// Refuses inconsistent current inventory/shards, unknown exclusion completeness,
/// occupied successor names, changed DATA/current controls or expired leases.
pub(super) async fn propose<F, B, V>(
    data: &CheckedDataPlacement<'_, '_>,
    held: &HeldBucket<'_, F, B, V, true>,
    cycle: u64,
) -> Result<GenerationProposal, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    data.revalidate().await?;
    if held.root() != data.observed().identity().root()
        || held.physical_identity() != data.observed().identity().physical_identity()
    {
        return Err(refusal());
    }
    let before = BucketCapabilities::decode(data.capabilities()).map_err(|_| refusal())?;
    let old = before.generation.ok_or_else(refusal)?;
    let generation = old.checked_add(1).ok_or_else(refusal)?;
    let mut manifest = GenerationManifest::decode(data.manifest()).map_err(|_| refusal())?;
    if manifest.generation != old {
        return Err(refusal());
    }
    let exclusions = manifest.exclusions.as_mut().ok_or_else(refusal)?;
    let exclusion = PackExclusion {
        pack_id: data.pack(),
        cycle,
        epoch: data.session().lease().epoch,
    };
    // Permanent source recovery may already have cleared its active binding.
    // Copied burn visibility still requires a genuine NEW destination barrier;
    // an old source binding is neither a prerequisite nor destination evidence.
    match exclusions.binary_search_by_key(&data.pack(), |row| row.pack_id) {
        Ok(position) => exclusions[position] = exclusion,
        Err(position) => exclusions.insert(position, exclusion),
    }

    let mut reads = Vec::new();
    let mut changes = Vec::new();
    for shard in &manifest.shards {
        for (suffix, expected) in [
            (
                "idx",
                Some((IdentityKind::Index, shard.index_hash, shard.index_size)),
            ),
            (
                "flt",
                shard
                    .filter
                    .map(|(hash, size)| (IdentityKind::Filter, hash, size)),
            ),
        ] {
            let next_key = format!("objects/index/{generation}/{}.{suffix}", shard.shard);
            let absent = collection_observation::record(held, &next_key).await?;
            if absent.bytes().is_some() || absent.metadata().is_some() {
                return Err(refusal());
            }
            reads.push(absent);
            let Some((kind, hash, size)) = expected else {
                continue;
            };
            let prior_key = format!("objects/index/{old}/{}.{suffix}", shard.shard);
            let prior = collection_observation::record(held, &prior_key).await?;
            let bytes = prior.bytes().ok_or_else(refusal)?;
            let identity = TERRANE_V1.from_digest(kind, &hash).map_err(|_| refusal())?;
            TERRANE_V1.verify(&identity, bytes).map_err(|_| refusal())?;
            if u64::try_from(bytes.len()).map_err(|_| refusal())? != size
                || data
                    .observed()
                    .logical()
                    .get(&prior_key)
                    .and_then(Option::as_deref)
                    != Some(bytes)
            {
                return Err(refusal());
            }
            changes.push(LogicalChange {
                key: next_key,
                expected: None,
                new: Some(bytes.to_vec()),
            });
            reads.push(prior);
        }
    }
    manifest.generation = generation;
    manifest.cycle = cycle;
    manifest.written_at = data.session().recheck()?;
    let key = format!("objects/index/{generation}/MANIFEST");
    let absent = collection_observation::record(held, &key).await?;
    if absent.bytes().is_some() || absent.metadata().is_some() {
        return Err(refusal());
    }
    reads.push(absent);
    changes.push(LogicalChange {
        key,
        expected: None,
        new: Some(manifest.encode().map_err(|_| refusal())?),
    });
    let mut after = before;
    after.generation = Some(generation);
    changes.push(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: Some(data.capabilities().to_vec()),
        new: Some(after.encode().map_err(|_| refusal())?),
    });
    changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    data.revalidate().await?;
    Ok(GenerationProposal { changes, reads })
}
