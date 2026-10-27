//! Pre-deletion revalidation joins for one journaled GC apply.
//!
//! The journaled candidates are re-sorted by identity into the apply's
//! private scratch directory, then merge-joined against the reproduced
//! pending write-back and reachable sets and, per leaf, against a sorted
//! fenced inventory. No step holds a complete set in memory. The scratch
//! record is:
//!
//! ```text
//! candidate record (50 bytes): id record || backend:u16be || reason:u8
//!                              || required_backend:u16be || logical_length:u64be
//!   backend indexes the plan's physical list; reason 0 unreachable,
//!   1 reachable cache; required_backend is 0xffff when not configured
//! ```

use std::error::Error as StdError;
use std::io;
use std::sync::Arc;

use crucible_store::content_store::{ContentId, StoreError, StoreGraphPhysicalRetention};

use super::super::planner::CampaignGcInventoryTarget;
use super::super::spill::{
    ExternalSorter, GcWorkDirectory, ID_RECORD_BYTES, IdRecord, InventorySortError,
    PLACEMENT_RECORD_BYTES, RUN_RECORDS, SortedIds, SpillFile, decode_id, encode_id, field,
    placement_id, placement_length, sort_inventory,
};
use super::super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidate, CampaignGcCandidateManifest,
    CampaignGcCandidateReason, CampaignGcPhysicalStore, DirectoryCampaignGcJournal,
};
use super::{
    CampaignGcApplyError, physical_index, validate_required_copy_fence,
    validate_unique_policy_identity,
};

const CANDIDATE_RECORD_BYTES: usize = ID_RECORD_BYTES + 2 + 1 + 2 + 8;
const REASON_UNREACHABLE: u8 = 0;
const REASON_REACHABLE_CACHE: u8 = 1;
const UNCONFIGURED_BACKEND: u16 = u16::MAX;

type CandidateRecord = [u8; CANDIDATE_RECORD_BYTES];

/// Identity-sorted candidates and reproduced reachability for one apply.
pub(super) struct RevalidatedSets {
    pub(super) candidates: SpillFile,
    pub(super) reachable: SpillFile,
}

/// One decoded identity-sorted candidate record.
struct SortedCandidate {
    key: IdRecord,
    backend: usize,
    reachable_cache: bool,
    required_backend: Option<usize>,
    logical_length: u64,
}

impl SortedCandidate {
    fn decode(record: &CandidateRecord) -> Self {
        let required = u16::from_be_bytes(field(record, ID_RECORD_BYTES + 3));
        Self {
            key: field(record, 0),
            backend: usize::from(u16::from_be_bytes(field(record, ID_RECORD_BYTES))),
            reachable_cache: record[ID_RECORD_BYTES + 2] == REASON_REACHABLE_CACHE,
            required_backend: (required != UNCONFIGURED_BACKEND).then_some(usize::from(required)),
            logical_length: u64::from_be_bytes(field(record, ID_RECORD_BYTES + 5)),
        }
    }

    fn id<E>(&self) -> Result<ContentId, CampaignGcApplyError<E>>
    where
        E: StdError + 'static,
    {
        decode_id(&self.key).map_err(CampaignGcApplyError::Spill)
    }
}

/// Streams the identity-sorted candidate run.
fn for_each_sorted_candidate<E>(
    candidates: &SpillFile,
    visit: &mut dyn FnMut(SortedCandidate) -> Result<(), CampaignGcApplyError<E>>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut reader = candidates
        .reader::<CANDIDATE_RECORD_BYTES>()
        .map_err(CampaignGcApplyError::Spill)?;
    while let Some(record) = reader.next_record().map_err(CampaignGcApplyError::Spill)? {
        visit(SortedCandidate::decode(&record))?;
    }
    Ok(())
}

/// Re-sorts every journaled candidate by identity, then backend.
pub(super) fn sort_candidates<'a, E, P>(
    manifest: &CampaignGcCandidateManifest,
    physical: &[P],
    directory: &Arc<GcWorkDirectory>,
) -> Result<SpillFile, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let mut sorter =
        ExternalSorter::<CANDIDATE_RECORD_BYTES>::new(directory, "apply-candidates", RUN_RECORDS);
    for candidate in manifest.iter()? {
        let candidate = candidate?;
        sorter
            .push(candidate_record(&candidate, physical)?)
            .map_err(CampaignGcApplyError::Spill)?;
    }
    sorter.finish().map_err(CampaignGcApplyError::Spill)
}

fn candidate_record<'a, E, P>(
    candidate: &CampaignGcCandidate,
    physical: &[P],
) -> Result<CandidateRecord, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let backend = backend_tag(physical_index(physical, candidate.backend())?)?;
    // An unknown required backend is reported by the policy check, in its
    // planned precedence, rather than while indexing.
    let (reason, required) = match candidate.reason() {
        CampaignGcCandidateReason::Unreachable => (REASON_UNREACHABLE, UNCONFIGURED_BACKEND),
        CampaignGcCandidateReason::ReachableCache { required_backend } => (
            REASON_REACHABLE_CACHE,
            physical_index::<E, P>(physical, required_backend)
                .ok()
                .map_or(Ok(UNCONFIGURED_BACKEND), backend_tag)?,
        ),
    };
    let mut record = [0_u8; CANDIDATE_RECORD_BYTES];
    record[..ID_RECORD_BYTES].copy_from_slice(&encode_id(candidate.id()));
    record[ID_RECORD_BYTES..ID_RECORD_BYTES + 2].copy_from_slice(&backend.to_be_bytes());
    record[ID_RECORD_BYTES + 2] = reason;
    record[ID_RECORD_BYTES + 3..ID_RECORD_BYTES + 5].copy_from_slice(&required.to_be_bytes());
    record[ID_RECORD_BYTES + 5..].copy_from_slice(&candidate.logical_length().to_be_bytes());
    Ok(record)
}

fn backend_tag<E>(index: usize) -> Result<u16, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    u16::try_from(index)
        .ok()
        .filter(|tag| *tag != UNCONFIGURED_BACKEND)
        .ok_or(CampaignGcApplyError::PhysicalInputsChanged)
}

/// Fails if a pending write-back transfer now owns a planned cache eviction.
pub(super) fn reject_pending_cache_candidates<'a, E, P>(
    physical: &[P],
    candidates: &SpillFile,
    pending_write_back: &SpillFile,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let mut pending = SortedIds::open(pending_write_back).map_err(CampaignGcApplyError::Spill)?;
    for_each_sorted_candidate(candidates, &mut |candidate| {
        if candidate.reachable_cache
            && pending
                .contains(&candidate.key)
                .map_err(CampaignGcApplyError::Spill)?
        {
            return Err(CampaignGcApplyError::CandidateBecameWriteBackPending {
                backend: physical[candidate.backend].backend().to_owned(),
                id: candidate.id()?,
            });
        }
        Ok(())
    })
}

/// Fails if a planned unreachable placement is reachable again.
pub(super) fn reject_reachable_candidates<E>(
    candidates: &SpillFile,
    reachable: &SpillFile,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut reachable = SortedIds::open(reachable).map_err(CampaignGcApplyError::Spill)?;
    for_each_sorted_candidate(candidates, &mut |candidate| {
        if !candidate.reachable_cache
            && reachable
                .contains(&candidate.key)
                .map_err(CampaignGcApplyError::Spill)?
        {
            return Err(CampaignGcApplyError::CandidateBecameReachable {
                id: candidate.id()?,
            });
        }
        Ok(())
    })
}

/// Rechecks cache policy and authenticates each distinct required source.
///
/// Candidates arrive in identity order, so the sources authenticated for one
/// identity are tracked only until the next identity begins.
pub(super) fn authenticate_policy_sources<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
    sets: &RevalidatedSets,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut reachable = SortedIds::open(&sets.reachable).map_err(CampaignGcApplyError::Spill)?;
    let mut current: Option<IdRecord> = None;
    let mut authenticated = Vec::<usize>::new();
    for_each_sorted_candidate(&sets.candidates, &mut |candidate| {
        if !candidate.reachable_cache {
            return Ok(());
        }
        if current != Some(candidate.key) {
            current = Some(candidate.key);
            authenticated.clear();
        }
        let id = candidate.id()?;
        let cache_index = candidate.backend;
        let source_index = candidate
            .required_backend
            .ok_or(CampaignGcApplyError::PhysicalInputsChanged)?;
        let cache = physical[cache_index];
        let source = physical[source_index];
        let kind = id.kind();
        let is_reachable = reachable
            .contains(&candidate.key)
            .map_err(CampaignGcApplyError::Spill)?;
        if !is_reachable
            || cache_index == source_index
            || cache.graph().retention(kind) != Some(StoreGraphPhysicalRetention::Cache)
            || source.graph().retention(kind) != Some(StoreGraphPhysicalRetention::Required)
        {
            return Err(CampaignGcApplyError::CandidatePolicyChanged {
                backend: cache.backend().to_owned(),
                id,
            });
        }

        let cache_identity = validate_unique_policy_identity(
            journal,
            &journal.plan().physical()[cache_index],
            cache.backend(),
        )?;
        let source_identity = validate_unique_policy_identity(
            journal,
            &journal.plan().physical()[source_index],
            source.backend(),
        )?;
        if cache_identity == source_identity {
            return Err(CampaignGcApplyError::AliasedRequiredCopy {
                backend: cache.backend().to_owned(),
                required_backend: source.backend().to_owned(),
            });
        }

        if authenticated.contains(&source_index) {
            return Ok(());
        }
        authenticated.push(source_index);
        let expected = &journal.plan().physical()[source_index];
        authenticate_required_copy(source, expected, id, candidate.logical_length)
    })
}

/// Reads one required source copy to EOF between matching fenced scans.
fn authenticate_required_copy<E>(
    source: CampaignGcPhysicalStore<'_>,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    validate_required_copy_fence(source, expected, id, logical_length)?;
    let handle = source
        .graph()
        .read(id)
        .map_err(|source_error| CampaignGcApplyError::Blob {
            backend: source.backend().to_owned(),
            source: source_error,
        })?;
    if handle.logical_length() != logical_length {
        return Err(CampaignGcApplyError::RequiredCopyChanged {
            backend: source.backend().to_owned(),
            id,
        });
    }
    handle
        .copy_to(&mut io::sink())
        .map_err(|source_error| CampaignGcApplyError::Blob {
            backend: source.backend().to_owned(),
            source: source_error,
        })?;
    // EOF authentication precedes the second generation validation. The
    // matching terminal basis makes those exact bytes authoritative for
    // the later paired-fence check.
    validate_required_copy_fence(source, expected, id, logical_length)
}

/// Reproduces one leaf's planned basis and every planned placement on it.
///
/// The inventory is sorted under the leaf's fence and then merge-joined with
/// that backend's candidates, which the manifest stores in identity order.
/// Every inventory placement of a candidate identity counts, so a duplicated
/// placement also fails closed.
pub(super) fn validate_physical_inventory<'a, E, P>(
    target: &P,
    planned: &CampaignGcBlobInventoryBasis,
    candidates: &CampaignGcCandidateManifest,
    directory: &Arc<GcWorkDirectory>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let blob_error = |source| CampaignGcApplyError::Blob {
        backend: target.backend().to_owned(),
        source,
    };
    let sorted = {
        let mut fence = target
            .admin()
            .acquire_inventory_fence()
            .map_err(blob_error)?;
        sort_inventory(fence.as_mut(), directory)
    };
    let (inventory, placements) = sorted.map_err(|source| match source {
        InventorySortError::Store(source) => blob_error(source),
        InventorySortError::Spill(source) => CampaignGcApplyError::Spill(source),
    })?;

    let mut expected = candidates.iter_backend(target.backend())?;
    let mut next_expected = expected.next().transpose()?;
    let mut placements = placements
        .reader::<PLACEMENT_RECORD_BYTES>()
        .map_err(CampaignGcApplyError::Spill)?;
    let mut observed_candidates = 0_u64;
    while let Some(placement) = placements
        .next_record()
        .map_err(CampaignGcApplyError::Spill)?
    {
        let key = placement_id(&placement);
        while next_expected
            .as_ref()
            .is_some_and(|candidate| encode_id(candidate.id()) < key)
        {
            next_expected = expected.next().transpose()?;
        }
        let Some(candidate) = next_expected
            .as_ref()
            .filter(|candidate| encode_id(candidate.id()) == key)
        else {
            continue;
        };
        if candidate.logical_length() != placement_length(&placement) {
            return Err(blob_error(StoreError::InvalidComposition {
                reason: "campaign GC candidate logical length changed",
            }));
        }
        observed_candidates = observed_candidates
            .checked_add(1)
            .ok_or_else(|| blob_error(StoreError::Quota))?;
    }
    // Drain the range so a malformed tail is reported rather than ignored.
    for candidate in expected {
        candidate?;
    }

    let current = CampaignGcBlobInventoryBasis::from_summary(&inventory)?;
    if current != *planned {
        return Err(CampaignGcApplyError::PhysicalBasisChanged {
            backend: target.backend().to_owned(),
        });
    }
    if observed_candidates != candidates.backend_candidates(target.backend()) {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(())
}
