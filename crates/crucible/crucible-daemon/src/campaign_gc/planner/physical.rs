//! Physical-inventory merge that turns reachability into a candidate manifest.
//!
//! Each physical leaf is inventoried under its own fence into a sorted run of
//! placements. One merge then walks every leaf's placements, the reachable
//! set, and the pending write-back set together in identity order:
//!
//! - an unreachable placement becomes an unreachable candidate;
//! - for a reachable identity, the cache policy picks the best unique required
//!   copy of each length and lists every eligible cache placement, unless a
//!   pending write-back transfer still owns the identity.
//!
//! Each leaf's candidates leave the merge in identity order in their own
//! scratch run, and the runs are concatenated in backend order, which is the
//! manifest's canonical order. Records never leave the process:
//!
//! ```text
//! candidate record (48 bytes): id record || logical_length:u64be
//!                              || reason:u8 || required_target:u16be
//!   reason 0 unreachable, 1 reachable cache
//! ```

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::error::Error as StdError;
use std::io;
use std::sync::Arc;

use crucible_store::content_store::{
    BlobInventorySummary, ContentId, ObjectKind, PhysicalStorageIdentity, StoreError,
    StoreGraphPhysicalRetention,
};

use super::super::CampaignGcBlobInventoryBasis;
use super::super::manifest::{
    CampaignGcCandidate, CampaignGcCandidateManifest, CampaignGcCandidateManifestWriter,
};
use super::super::spill::{
    GcWorkDirectory, ID_RECORD_BYTES, IdRecord, InventorySortError, PLACEMENT_RECORD_BYTES,
    SortedIds, SpillFile, SpillWriter, decode_id, field, placement_id, placement_length,
    sort_inventory,
};
use super::{CampaignGcInventoryTarget, CampaignGcPhysicalStore, CampaignGcPlanningError};

const CANDIDATE_RECORD_BYTES: usize = ID_RECORD_BYTES + 8 + 1 + 2;
const REASON_UNREACHABLE: u8 = 0;
const REASON_REACHABLE_CACHE: u8 = 1;

type CandidateRecord = [u8; CANDIDATE_RECORD_BYTES];

/// Sorted reachability inputs shared by every physical planning strategy.
pub(in crate::campaign_gc) struct PhysicalPlanningInputs<'a> {
    pub(in crate::campaign_gc) directory: &'a Arc<GcWorkDirectory>,
    pub(in crate::campaign_gc) reachable: &'a SpillFile,
    pub(in crate::campaign_gc) pending_write_back: &'a SpillFile,
}

/// Candidate manifest and fenced physical bases from one planning pass.
pub(in crate::campaign_gc) struct PlannedPhysical {
    pub(in crate::campaign_gc) candidates: CampaignGcCandidateManifest,
    pub(in crate::campaign_gc) physical_basis: Vec<CampaignGcBlobInventoryBasis>,
}

/// How a reachable placement participates in cache reclamation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PlacementRole {
    Required,
    Cache,
    Ignored,
}

/// Graph-derived cache policy for a reachable identity's placements.
struct GraphCachePolicy<'graph, 'store> {
    physical: &'store [CampaignGcPhysicalStore<'graph>],
    summaries: &'store [BlobInventorySummary],
    unaliased: Vec<bool>,
}

impl<'graph, 'store> GraphCachePolicy<'graph, 'store> {
    fn new(
        physical: &'store [CampaignGcPhysicalStore<'graph>],
        summaries: &'store [BlobInventorySummary],
    ) -> Self {
        let mut aliases = BTreeMap::<PhysicalStorageIdentity, usize>::new();
        for summary in summaries {
            *aliases.entry(summary.storage_identity()).or_default() += 1;
        }
        let unaliased = summaries
            .iter()
            .map(|summary| aliases.get(&summary.storage_identity()).copied() == Some(1))
            .collect();
        Self {
            physical,
            summaries,
            unaliased,
        }
    }

    /// Classifies one placement; an aliased identity never takes part.
    fn role(&self, target: usize, kind: ObjectKind) -> PlacementRole {
        if !self.unaliased[target] {
            return PlacementRole::Ignored;
        }
        match self.physical[target]
            .graph()
            .retention(kind)
            .unwrap_or(StoreGraphPhysicalRetention::Required)
        {
            StoreGraphPhysicalRetention::Required => PlacementRole::Required,
            StoreGraphPhysicalRetention::Cache => PlacementRole::Cache,
        }
    }

    fn identity(&self, target: usize) -> PhysicalStorageIdentity {
        self.summaries[target].storage_identity()
    }

    /// Orders required copies by physical identity and then backend name.
    fn source_key(&self, target: usize) -> (PhysicalStorageIdentity, &str) {
        (self.identity(target), self.physical[target].backend())
    }
}

/// Plans unreachable placements only, for leaves without graph policy.
#[cfg(test)]
pub(super) fn plan_unreachable_physical<'a, E, P>(
    physical: &[P],
    inputs: PhysicalPlanningInputs<'_>,
) -> Result<PlannedPhysical, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let mut summaries = Vec::with_capacity(physical.len());
    let mut placements = Vec::with_capacity(physical.len());
    for target in physical {
        let (summary, sorted) = inventory_placements(*target, inputs.directory)?;
        summaries.push(summary);
        placements.push(sorted);
    }
    let candidates = merge_candidates(physical, &placements, &inputs, None)?;
    Ok(PlannedPhysical {
        candidates,
        physical_basis: physical_basis(&summaries)?,
    })
}

/// Plans unreachable placements and policy-approved reachable cache copies.
pub(super) fn plan_policy_aware_physical<E>(
    physical: &[CampaignGcPhysicalStore<'_>],
    inputs: PhysicalPlanningInputs<'_>,
) -> Result<PlannedPhysical, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let mut summaries = Vec::with_capacity(physical.len());
    let mut placements = Vec::with_capacity(physical.len());
    for target in physical {
        let (summary, sorted) = inventory_placements(*target, inputs.directory)?;
        summaries.push(summary);
        placements.push(sorted);
    }
    let policy = GraphCachePolicy::new(physical, &summaries);
    let candidates = merge_candidates(physical, &placements, &inputs, Some(&policy))?;
    Ok(PlannedPhysical {
        candidates,
        physical_basis: physical_basis(&summaries)?,
    })
}

fn physical_basis<E>(
    summaries: &[BlobInventorySummary],
) -> Result<Vec<CampaignGcBlobInventoryBasis>, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    Ok(summaries
        .iter()
        .map(CampaignGcBlobInventoryBasis::from_summary)
        .collect::<Result<Vec<_>, _>>()?)
}

/// Inventories one leaf under its fence into a sorted placement run.
///
/// The fence covers only the visit; sorting the spilled runs needs no
/// administrative authority.
fn inventory_placements<'a, E, P>(
    target: P,
    directory: &Arc<GcWorkDirectory>,
) -> Result<(BlobInventorySummary, SpillFile), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let sorted = {
        let mut fence = target
            .admin()
            .acquire_inventory_fence()
            .map_err(|source| blob_error(target, source))?;
        sort_inventory(fence.as_mut(), directory)
    };
    let (summary, placements) = sorted.map_err(|source| match source {
        InventorySortError::Store(source) => blob_error(target, source),
        InventorySortError::Spill(source) => CampaignGcPlanningError::Spill(source),
    })?;
    if summary.backend() != target.backend() {
        return Err(CampaignGcPlanningError::BackendIdentityMismatch {
            expected: target.backend().to_owned(),
            actual: summary.backend().to_owned(),
        });
    }
    Ok((summary, placements))
}

/// Merges every leaf's placements with reachability into the manifest.
fn merge_candidates<'a, E, P>(
    physical: &[P],
    placements: &[SpillFile],
    inputs: &PhysicalPlanningInputs<'_>,
    policy: Option<&GraphCachePolicy<'_, '_>>,
) -> Result<CampaignGcCandidateManifest, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let spill = CampaignGcPlanningError::Spill;
    let mut readers = placements
        .iter()
        .map(SpillFile::reader::<PLACEMENT_RECORD_BYTES>)
        .collect::<io::Result<Vec<_>>>()
        .map_err(spill)?;
    let mut outputs = physical
        .iter()
        .map(|_| SpillWriter::<CANDIDATE_RECORD_BYTES>::create(inputs.directory, "candidates"))
        .collect::<io::Result<Vec<_>>>()
        .map_err(spill)?;
    let mut reachable = SortedIds::open(inputs.reachable).map_err(spill)?;
    let mut pending = SortedIds::open(inputs.pending_write_back).map_err(spill)?;

    let mut heap = BinaryHeap::with_capacity(readers.len());
    for (target, reader) in readers.iter_mut().enumerate() {
        if let Some(record) = reader.next_record().map_err(spill)? {
            heap.push(Reverse((record, target)));
        }
    }

    // One identity's placements across all leaves form a group; a leaf
    // contributes at most one placement to it.
    let mut group = Vec::<(usize, u64)>::new();
    while let Some(Reverse((first, first_target))) = heap.pop() {
        let key = placement_id(&first);
        group.clear();
        let mut next = Some((first, first_target));
        while let Some((record, target)) = next.take() {
            if group.iter().any(|(seen, _)| *seen == target) {
                return Err(blob_error(
                    physical[target],
                    StoreError::InvalidComposition {
                        reason: "campaign GC physical inventory lists one object twice",
                    },
                ));
            }
            group.push((target, placement_length(&record)));
            if let Some(refill) = readers[target].next_record().map_err(spill)? {
                heap.push(Reverse((refill, target)));
            }
            if heap
                .peek()
                .is_some_and(|Reverse((head, _))| placement_id(head) == key)
            {
                next = heap.pop().map(|Reverse(entry)| entry);
            }
        }

        let is_reachable = reachable.contains(&key).map_err(spill)?;
        let is_pending = pending.contains(&key).map_err(spill)?;
        if !is_reachable {
            for (target, length) in &group {
                outputs[*target]
                    .push(&candidate_record(&key, *length, REASON_UNREACHABLE, 0))
                    .map_err(spill)?;
            }
        } else if let Some(policy) = policy {
            plan_cache_group(policy, &key, &group, is_pending, &mut outputs)?;
        }
    }

    let runs = outputs
        .into_iter()
        .map(SpillWriter::finish)
        .collect::<io::Result<Vec<_>>>()
        .map_err(spill)?;
    write_manifest(physical, &runs, inputs.directory)
}

/// Adds every eligible cache placement of one reachable identity.
///
/// Each length's source is the unique required placement with the smallest
/// (physical identity, backend) key on a different physical identity. A
/// source is authenticated to EOF between matching inventory generations
/// before any cache placement relies on it, even when a pending write-back
/// transfer then keeps the cache placement out of the manifest.
fn plan_cache_group<E>(
    policy: &GraphCachePolicy<'_, '_>,
    key: &IdRecord,
    group: &[(usize, u64)],
    is_pending: bool,
    outputs: &mut [SpillWriter<CANDIDATE_RECORD_BYTES>],
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let id = decode_id(key).map_err(CampaignGcPlanningError::Spill)?;
    let mut sources = Vec::<(u64, usize)>::new();
    for (target, length) in group {
        if policy.role(*target, id.kind()) != PlacementRole::Required {
            continue;
        }
        match sources
            .iter_mut()
            .find(|(source_length, _)| source_length == length)
        {
            Some((_, source)) if policy.source_key(*target) < policy.source_key(*source) => {
                *source = *target;
            }
            Some(_) => {}
            None => sources.push((*length, *target)),
        }
    }

    let mut authenticated = Vec::<usize>::new();
    for (cache, length) in group {
        if policy.role(*cache, id.kind()) != PlacementRole::Cache {
            continue;
        }
        let source = sources
            .iter()
            .find(|(source_length, source)| {
                source_length == length && policy.identity(*source) != policy.identity(*cache)
            })
            .map(|(_, source)| *source);
        let Some(source) = source else {
            continue;
        };
        if !authenticated.contains(&source) {
            authenticate_required_copy(
                policy.physical[source],
                id,
                *length,
                &policy.summaries[source],
            )?;
            authenticated.push(source);
        }
        if !is_pending {
            let source = u16::try_from(source).map_err(|_| {
                CampaignGcPlanningError::Plan(
                    super::super::CampaignGcPlanError::InvalidPhysicalInventoryCount,
                )
            })?;
            outputs[*cache]
                .push(&candidate_record(
                    key,
                    *length,
                    REASON_REACHABLE_CACHE,
                    source,
                ))
                .map_err(CampaignGcPlanningError::Spill)?;
        }
    }
    Ok(())
}

/// Concatenates each leaf's candidate run, in backend order, into the manifest.
fn write_manifest<'a, E, P>(
    physical: &[P],
    runs: &[SpillFile],
    directory: &Arc<GcWorkDirectory>,
) -> Result<CampaignGcCandidateManifest, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let spill = CampaignGcPlanningError::Spill;
    let mut writer = CampaignGcCandidateManifestWriter::create(directory)?;
    for (target, run) in physical.iter().zip(runs) {
        let mut records = run.reader::<CANDIDATE_RECORD_BYTES>().map_err(spill)?;
        while let Some(record) = records.next_record().map_err(spill)? {
            let id = decode_id(&record[..ID_RECORD_BYTES]).map_err(spill)?;
            let length = u64::from_be_bytes(field(&record, ID_RECORD_BYTES));
            let candidate = match record[ID_RECORD_BYTES + 8] {
                REASON_UNREACHABLE => CampaignGcCandidate::new(target.backend(), id, length)?,
                _ => {
                    let source =
                        usize::from(u16::from_be_bytes(field(&record, ID_RECORD_BYTES + 9)));
                    CampaignGcCandidate::new_reachable_cache(
                        target.backend(),
                        id,
                        length,
                        physical[source].backend(),
                    )?
                }
            };
            writer.push(&candidate)?;
        }
    }
    Ok(writer.finish()?)
}

/// Authenticates one required source copy between matching inventory scans.
fn authenticate_required_copy<E>(
    target: CampaignGcPhysicalStore<'_>,
    id: ContentId,
    logical_length: u64,
    expected: &BlobInventorySummary,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    validate_required_copy_inventory(target, id, logical_length, expected)?;
    let handle = target
        .graph()
        .read(id)
        .map_err(|source| blob_error(target, source))?;
    if handle.logical_length() != logical_length {
        return Err(blob_error(
            target,
            StoreError::InvalidComposition {
                reason: "campaign GC required-copy logical length changed",
            },
        ));
    }
    handle
        .copy_to(&mut io::sink())
        .map_err(|source| blob_error(target, source))?;
    validate_required_copy_inventory(target, id, logical_length, expected)
}

fn validate_required_copy_inventory<E>(
    target: CampaignGcPhysicalStore<'_>,
    id: ContentId,
    logical_length: u64,
    expected: &BlobInventorySummary,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let mut observed = false;
    let mut fence = target
        .admin()
        .acquire_inventory_fence()
        .map_err(|source| blob_error(target, source))?;
    let summary = fence
        .visit_inventory(&mut |candidate| {
            if candidate.id() == id && candidate.logical_length() == logical_length {
                observed = true;
            }
            Ok(())
        })
        .map_err(|source| blob_error(target, source))?;
    if !observed || summary != *expected {
        return Err(CampaignGcPlanningError::RequiredCopyBasisChanged {
            backend: target.backend().to_owned(),
            id,
        });
    }
    Ok(())
}

fn blob_error<'a, E, P>(target: P, source: StoreError) -> CampaignGcPlanningError<E>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    CampaignGcPlanningError::Blob {
        backend: target.backend().to_owned(),
        source,
    }
}

fn candidate_record(
    key: &IdRecord,
    logical_length: u64,
    reason: u8,
    source: u16,
) -> CandidateRecord {
    let mut record = [0_u8; CANDIDATE_RECORD_BYTES];
    record[..ID_RECORD_BYTES].copy_from_slice(key);
    record[ID_RECORD_BYTES..ID_RECORD_BYTES + 8].copy_from_slice(&logical_length.to_be_bytes());
    record[ID_RECORD_BYTES + 8] = reason;
    record[ID_RECORD_BYTES + 9..].copy_from_slice(&source.to_be_bytes());
    record
}
