//! Exact-generation destructive apply for one journaled single-host GC plan.

use std::error::Error as StdError;
use std::io;

use crucible_campaign::{
    CampaignFactId, CampaignName, CampaignRepository, CampaignRepositoryError, ConfigurationId,
};
use crucible_cas::content_store::{
    BlobInventoryFence, ContentId, PlannedDeleteDisposition, RefStoreAdmin, StoreError,
    StoreGraphAdmin, StoreGraphPhysicalRetention, WriteBackRetentionAdmin,
};
use thiserror::Error;

use crate::{
    AssignmentRetentionAdmin, AssignmentRetentionInventoryError, AssignmentRetentionRoot,
    AssignmentRetentionVisitorError, CampaignTransferJournalError, CampaignTransferRetentionAdmin,
    ExactPinRetentionAdmin, ExactPinRetentionError,
};
#[cfg(target_os = "linux")]
use crate::{HotCheckpointFallbackRetentionAdmin, HotCheckpointFallbackRetentionError};

#[cfg(target_os = "linux")]
use super::CampaignGcHotCheckpointRoots;
use super::roots::{CampaignGcRootInventoryError, RootAccumulator, inventory_authoritative_refs};
use super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidateManifest, CampaignGcCandidateReason,
    CampaignGcJournalError, CampaignGcJournalPhase, CampaignGcManifestError,
    CampaignGcPhysicalStore, CampaignGcPlanError, CampaignGcPlanVersion,
    CampaignGcRetentionSources, CampaignGcRootManifest, DirectoryCampaignGcJournal,
    MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES,
};

/// Terminal disposition of one idempotent campaign GC apply request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGcApplyStatus {
    /// This call deleted every candidate and durably completed the journal.
    Applied,
    /// The journal was already durably complete before this call.
    AlreadyComplete,
}

/// Terminal counters for one completed campaign GC apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignGcApplyReport {
    status: CampaignGcApplyStatus,
    candidates: u64,
    unreachable_candidates: u64,
    reachable_cache_candidates: u64,
    logical_bytes: u64,
}

impl CampaignGcApplyReport {
    /// Returns whether this call applied deletion or observed prior completion.
    #[must_use]
    pub const fn status(self) -> CampaignGcApplyStatus {
        self.status
    }

    /// Returns the exact number of candidate placements in the completed plan.
    #[must_use]
    pub const fn candidates(self) -> u64 {
        self.candidates
    }

    /// Returns completed unreachable-placement deletions.
    #[must_use]
    pub const fn unreachable_candidates(self) -> u64 {
        self.unreachable_candidates
    }

    /// Returns completed reachable read-through cache deletions.
    #[must_use]
    pub const fn reachable_cache_candidates(self) -> u64 {
        self.reachable_cache_candidates
    }

    /// Returns the exact planned logical bytes across those placements.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }
}

/// Revalidates and destructively applies one exact journaled single-host plan.
///
/// Apply acquires fences in the fixed order ref publication/namespace,
/// exact-pin selections, ledger, hot-checkpoint fallbacks, pending write-back
/// transfers, then physical
/// leaves in canonical backend order. It reproduces the exact ref, current
/// exact-pin roots, ledger, root-manifest, and every
/// physical-inventory basis before durably entering `Applying`. Root fences
/// remain held throughout. Version 1 reacquires each physical leaf and retains
/// its fence through that leaf's unreachable deletions. Version 2 reacquires
/// paired cache/source fences in physical-identity order, revalidates both exact
/// placements, and advances the cache's rolling post-delete basis. Aliased v2
/// identities fail closed before deletion.
/// The construction-time `store_graph` capability supplies both the graph
/// identity and every physical leaf; independently supplied graph hashes or
/// deletion capabilities are not accepted by this public boundary.
/// Omitting `exact_pins` is valid only when the complete authoritative campaign
/// inventory contains no current exact pin. This catalog-free entry point is
/// valid only when no managed hot-checkpoint pool exists; configured pools must
/// use `apply_single_host_campaign_gc_with_hot_checkpoints` on Linux.
///
/// A journal reopened in `Applying` is intentionally not resumed because at
/// least one backend generation may already have advanced. The operator must
/// retain that recovery evidence and create a fresh plan/journal.
///
/// # Errors
///
/// Returns [`CampaignGcApplyError`] before deletion if any exact basis changed,
/// or after durable `Applying` if deletion or final journal persistence fails.
/// An error after `Applying` requires a fresh plan and must not reuse this one.
pub fn apply_single_host_campaign_gc<L>(
    journal: &mut DirectoryCampaignGcJournal,
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    apply_single_host_campaign_gc_with_physical(
        journal,
        CampaignGcApplySources::new(repository, refs, ledger, write_back, exact_pins),
        crucible_campaign::CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

/// Applies a GC plan while retaining every incomplete archive-transfer object.
///
/// The transfer inventory fence follows write-back in the fixed operational
/// root lock order and remains held through candidate deletion.
///
/// # Errors
///
/// Returns [`CampaignGcApplyError`] under the same conditions as
/// [`apply_single_host_campaign_gc`], and when transfer-root inventory is
/// invalid or differs from the planned root set.
// crucible-lint: allow rust-allow -- GC apply keeps each authenticated store, fence, and plan authority explicit.
#[allow(clippy::too_many_arguments)]
pub fn apply_single_host_campaign_gc_with_transfers<'a, L>(
    journal: &mut DirectoryCampaignGcJournal,
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    transfers: &'a dyn CampaignTransferRetentionAdmin,
    exact_pins: Option<&'a mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    apply_single_host_campaign_gc_with_physical(
        journal,
        CampaignGcApplySources::new_with_retention_sources(
            repository,
            refs,
            ledger,
            write_back,
            CampaignGcRetentionSources::with_transfers(exact_pins, transfers),
        ),
        crucible_campaign::CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

/// Applies a GC plan while retaining every durable hot-checkpoint fallback.
///
/// This is the production single-host boundary when a hot-checkpoint manager
/// is configured. The fallback inventory fence remains held through physical
/// deletion, so a catalog replacement or removal cannot race the exact root
/// comparison and candidate deletion.
///
/// # Errors
///
/// Returns [`CampaignGcApplyError`] under the same conditions as
/// [`apply_single_host_campaign_gc`], and additionally when the fallback
/// catalog cannot provide a complete authenticated inventory.
#[cfg(target_os = "linux")]
pub fn apply_single_host_campaign_gc_with_hot_checkpoints<L>(
    journal: &mut DirectoryCampaignGcJournal,
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    roots: CampaignGcHotCheckpointRoots<'_>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    apply_single_host_campaign_gc_with_physical(
        journal,
        CampaignGcApplySources::new_with_retention_sources(
            repository,
            refs,
            ledger,
            write_back,
            roots.into_sources(),
        ),
        crucible_campaign::CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

pub(crate) struct CampaignGcApplySources<'repository, 'refs, 'ledger, 'write_back, 'retention, L> {
    repository: &'repository CampaignRepository,
    refs: &'refs dyn RefStoreAdmin,
    ledger: &'ledger mut L,
    write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
    retention: CampaignGcRetentionSources<'retention>,
}

impl<'repository, 'refs, 'ledger, 'write_back, 'retention, L>
    CampaignGcApplySources<'repository, 'refs, 'ledger, 'write_back, 'retention, L>
{
    pub(crate) const fn new(
        repository: &'repository CampaignRepository,
        refs: &'refs dyn RefStoreAdmin,
        ledger: &'ledger mut L,
        write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
        exact_pins: Option<&'retention mut dyn ExactPinRetentionAdmin>,
    ) -> Self {
        Self {
            repository,
            refs,
            ledger,
            write_back,
            retention: CampaignGcRetentionSources::without_hot_checkpoints(exact_pins),
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) const fn new_with_hot_checkpoints(
        repository: &'repository CampaignRepository,
        refs: &'refs dyn RefStoreAdmin,
        ledger: &'ledger mut L,
        write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
        exact_pins: Option<&'retention mut dyn ExactPinRetentionAdmin>,
        hot_fallbacks: Option<&'retention dyn HotCheckpointFallbackRetentionAdmin>,
    ) -> Self {
        Self {
            repository,
            refs,
            ledger,
            write_back,
            retention: CampaignGcRetentionSources {
                exact_pins,
                transfers: None,
                hot_fallbacks,
            },
        }
    }

    pub(super) const fn new_with_retention_sources(
        repository: &'repository CampaignRepository,
        refs: &'refs dyn RefStoreAdmin,
        ledger: &'ledger mut L,
        write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
        retention: CampaignGcRetentionSources<'retention>,
    ) -> Self {
        Self {
            repository,
            refs,
            ledger,
            write_back,
            retention,
        }
    }
}

pub(crate) fn apply_single_host_campaign_gc_with_physical<L>(
    journal: &mut DirectoryCampaignGcJournal,
    sources: CampaignGcApplySources<'_, '_, '_, '_, '_, L>,
    store_graph: crucible_campaign::CampaignHash,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let CampaignGcApplySources {
        repository,
        refs,
        ledger,
        write_back,
        retention,
    } = sources;
    let exact_pins = retention.exact_pins;
    if journal.phase() == CampaignGcJournalPhase::Complete {
        return Ok(apply_report(
            journal,
            CampaignGcApplyStatus::AlreadyComplete,
        ));
    }
    if journal.phase() == CampaignGcJournalPhase::Applying {
        return Err(CampaignGcApplyError::InterruptedJournal);
    }
    if journal.plan().store_graph() != store_graph {
        return Err(CampaignGcApplyError::StoreGraphChanged);
    }
    validate_physical_basis(journal, physical)?;

    let mut ref_fence = refs
        .acquire_ref_inventory_fence()
        .map_err(CampaignGcApplyError::Ref)?;
    let mut exact_pin_fence = exact_pins
        .map(ExactPinRetentionAdmin::acquire_exact_pin_retention_fence)
        .transpose()
        .map_err(CampaignGcApplyError::ExactPin)?;
    let mut ledger_fence = ledger
        .acquire_retention_fence()
        .map_err(CampaignGcApplyError::Ledger)?;
    #[cfg(target_os = "linux")]
    let mut hot_fallback_fence = retention
        .hot_fallbacks
        .map(HotCheckpointFallbackRetentionAdmin::acquire_hot_checkpoint_retention_fence)
        .transpose()
        .map_err(CampaignGcApplyError::HotFallback)?;
    let mut write_back_fence = write_back
        .map(WriteBackRetentionAdmin::acquire_write_back_retention_fence)
        .transpose()
        .map_err(CampaignGcApplyError::WriteBack)?;
    let mut transfer_fence = retention
        .transfers
        .map(CampaignTransferRetentionAdmin::acquire_campaign_transfer_retention_fence)
        .transpose()
        .map_err(CampaignGcApplyError::Transfer)?;

    let mut roots = RootAccumulator::default();
    let ref_summary = inventory_authoritative_refs(
        repository,
        ref_fence.as_mut(),
        &mut exact_pin_fence,
        &mut roots,
    )
    .map_err(map_root_inventory_error)?;
    if ref_summary.generation() != journal.plan().ref_generation()
        || ref_summary.refs() != journal.plan().refs()
    {
        return Err(CampaignGcApplyError::RefBasisChanged);
    }

    let ledger_summary = ledger_fence
        .visit_roots(&mut |root| {
            let id = match root {
                AssignmentRetentionRoot::Observation(observation) => observation.content_id(),
                AssignmentRetentionRoot::ExactCheckpoint(checkpoint) => checkpoint.content_id(),
                AssignmentRetentionRoot::FindingCandidate(candidate) => candidate.content_id(),
            };
            roots
                .insert(id)
                .map_err(|()| AssignmentRetentionVisitorError::LimitExceeded)
        })
        .map_err(|source| match source {
            AssignmentRetentionInventoryError::Backend(source) => {
                CampaignGcApplyError::Ledger(source)
            }
            AssignmentRetentionInventoryError::Visitor(_) => CampaignGcApplyError::LedgerVisitor,
        })?;
    if ledger_summary.generation() != journal.plan().ledger_generation()
        || ledger_summary.attempt_records() != journal.plan().attempt_records()
        || ledger_summary.observation_roots() != journal.plan().observation_roots()
        || ledger_summary.checkpoint_roots() != journal.plan().checkpoint_roots()
    {
        return Err(CampaignGcApplyError::LedgerBasisChanged);
    }
    #[cfg(target_os = "linux")]
    if let Some(fence) = hot_fallback_fence.as_mut() {
        fence
            .visit_roots(&mut |root| {
                roots
                    .insert(root)
                    .map_err(|()| HotCheckpointFallbackRetentionError::Visitor)
            })
            .map_err(CampaignGcApplyError::HotFallback)?;
    }
    if let Some(fence) = write_back_fence.as_mut() {
        fence
            .visit_roots(&mut |root| roots.insert(root.id()).map_err(|()| StoreError::Quota))
            .map_err(CampaignGcApplyError::WriteBack)?;
    }
    if let Some(fence) = transfer_fence.as_mut() {
        fence
            .visit_roots(&mut |root| {
                roots
                    .insert_direct(root.id())
                    .map_err(|()| StoreError::Quota)
            })
            .map_err(CampaignGcApplyError::Transfer)?;
    }
    let current_roots = CampaignGcRootManifest::new(roots.unique.iter().copied())?;
    if current_roots != *journal.roots() {
        return Err(CampaignGcApplyError::RootSetChanged);
    }
    // Root-manifest v1 binds unique IDs but predates direct-versus-transitive
    // archive roots. Recompute current reachability under the classified root
    // inventory so promoting an archive object to an operational root cannot
    // leave its newly required descendants eligible under an older plan.
    let mut current_reachable = repository
        .authenticated_closure_ids(roots.ordinary.iter().copied())
        .map_err(CampaignGcApplyError::Campaign)?;
    current_reachable.extend(roots.direct.iter().copied());
    if let Some(candidate) = journal.candidates().iter().find(|candidate| {
        matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable)
            && current_reachable.contains(&candidate.id())
    }) {
        return Err(CampaignGcApplyError::CandidateBecameReachable { id: candidate.id() });
    }

    for (target, planned) in physical.iter().zip(journal.plan().physical()) {
        let mut fence = target.admin().acquire_inventory_fence().map_err(|source| {
            CampaignGcApplyError::Blob {
                backend: target.backend().to_owned(),
                source,
            }
        })?;
        validate_physical_inventory(target, planned, journal.candidates(), fence.as_mut())?;
    }

    if journal.plan().version() == CampaignGcPlanVersion::V2 {
        authenticate_policy_sources(journal, physical, &current_reachable)?;
    }

    journal.begin_apply()?;
    match journal.plan().version() {
        CampaignGcPlanVersion::V1 => apply_v1_candidates(journal, physical)?,
        CampaignGcPlanVersion::V2 => apply_v2_candidates(journal, physical)?,
    }
    journal.mark_complete()?;
    Ok(apply_report(journal, CampaignGcApplyStatus::Applied))
}

fn apply_report(
    journal: &DirectoryCampaignGcJournal,
    status: CampaignGcApplyStatus,
) -> CampaignGcApplyReport {
    CampaignGcApplyReport {
        status,
        candidates: journal.plan().candidates().candidates(),
        unreachable_candidates: journal.candidates().unreachable_candidates(),
        reachable_cache_candidates: journal.candidates().reachable_cache_candidates(),
        logical_bytes: journal.plan().candidates().logical_bytes(),
    }
}

fn apply_v1_candidates<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    for (target, planned) in physical.iter().zip(journal.plan().physical()) {
        let mut fence = acquire_physical_fence(*target)?;
        validate_physical_inventory(target, planned, journal.candidates(), fence.as_mut())?;
        for candidate in journal.candidates().for_backend(target.backend()) {
            delete_exact_candidate(*target, fence.as_mut(), candidate.id())?;
        }
    }
    Ok(())
}

fn authenticate_policy_sources<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
    current_reachable: &std::collections::BTreeSet<ContentId>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut authenticated = std::collections::BTreeSet::new();
    for candidate in journal.candidates().iter() {
        let CampaignGcCandidateReason::ReachableReadThroughCache { required_backend } =
            candidate.reason()
        else {
            continue;
        };
        let cache_index = physical_index(physical, candidate.backend())?;
        let source_index = physical_index(physical, required_backend)?;
        let kind = candidate.id().kind();
        let cache_role = physical[cache_index]
            .graph()
            .and_then(|graph| graph.retention(kind));
        let source_role = physical[source_index]
            .graph()
            .and_then(|graph| graph.retention(kind));
        if !current_reachable.contains(&candidate.id())
            || candidate.backend() == required_backend
            || cache_role != Some(StoreGraphPhysicalRetention::ReadThroughCache)
            || source_role != Some(StoreGraphPhysicalRetention::Required)
        {
            return Err(CampaignGcApplyError::CandidatePolicyChanged {
                backend: candidate.backend().to_owned(),
                id: candidate.id(),
            });
        }

        let cache_identity = validate_unique_policy_identity(
            journal,
            &journal.plan().physical()[cache_index],
            candidate.backend(),
        )?;
        let source_identity = validate_unique_policy_identity(
            journal,
            &journal.plan().physical()[source_index],
            required_backend,
        )?;
        if cache_identity == source_identity {
            return Err(CampaignGcApplyError::AliasedRequiredCopy {
                backend: candidate.backend().to_owned(),
                required_backend: required_backend.clone(),
            });
        }

        if !authenticated.insert((required_backend.as_str(), candidate.id())) {
            continue;
        }
        let source = physical[source_index];
        let expected = &journal.plan().physical()[source_index];
        validate_required_copy_fence(source, expected, candidate.id(), candidate.logical_length())?;

        let graph = source
            .graph()
            .ok_or(CampaignGcApplyError::PhysicalInputsChanged)?;
        let handle =
            graph
                .read(candidate.id())
                .map_err(|source_error| CampaignGcApplyError::Blob {
                    backend: source.backend().to_owned(),
                    source: source_error,
                })?;
        if handle.logical_length() != candidate.logical_length() {
            return Err(CampaignGcApplyError::RequiredCopyChanged {
                backend: source.backend().to_owned(),
                id: candidate.id(),
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
        validate_required_copy_fence(source, expected, candidate.id(), candidate.logical_length())?;
    }
    Ok(())
}

fn apply_v2_candidates<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut rolling = journal.plan().physical().to_vec();
    for candidate in journal.candidates().iter() {
        let cache_index = physical_index(physical, candidate.backend())?;
        match candidate.reason() {
            CampaignGcCandidateReason::Unreachable => {
                let updated = delete_v2_single(
                    physical[cache_index],
                    &rolling[cache_index],
                    candidate.id(),
                    candidate.logical_length(),
                )?;
                rolling[cache_index] = updated;
            }
            CampaignGcCandidateReason::ReachableReadThroughCache { required_backend } => {
                let source_index = physical_index(physical, required_backend)?;
                let cache_identity = validate_unique_policy_identity(
                    journal,
                    &rolling[cache_index],
                    candidate.backend(),
                )?;
                let source_identity = validate_unique_policy_identity(
                    journal,
                    &rolling[source_index],
                    required_backend,
                )?;
                if cache_identity == source_identity {
                    return Err(CampaignGcApplyError::AliasedRequiredCopy {
                        backend: candidate.backend().to_owned(),
                        required_backend: required_backend.clone(),
                    });
                }
                let updated = delete_v2_paired(
                    physical[cache_index],
                    &rolling[cache_index],
                    physical[source_index],
                    &rolling[source_index],
                    candidate.id(),
                    candidate.logical_length(),
                    cache_identity < source_identity,
                )?;
                rolling[cache_index] = updated;
            }
        }
    }
    Ok(())
}

fn delete_v2_single<E>(
    target: CampaignGcPhysicalStore<'_>,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut fence = acquire_physical_fence(target)?;
    validate_fenced_placement(target, expected, id, logical_length, fence.as_mut())?;
    delete_exact_candidate(target, fence.as_mut(), id)?;
    refreshed_basis_after_delete(target, expected, id, logical_length, fence.as_mut())
}

fn delete_v2_paired<E>(
    cache: CampaignGcPhysicalStore<'_>,
    cache_expected: &CampaignGcBlobInventoryBasis,
    source: CampaignGcPhysicalStore<'_>,
    source_expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
    cache_first: bool,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    if cache_first {
        let mut cache_fence = acquire_physical_fence(cache)?;
        let mut source_fence = acquire_physical_fence(source)?;
        delete_with_paired_fences(
            cache,
            cache_expected,
            cache_fence.as_mut(),
            source,
            source_expected,
            source_fence.as_mut(),
            id,
            logical_length,
        )
    } else {
        let mut source_fence = acquire_physical_fence(source)?;
        let mut cache_fence = acquire_physical_fence(cache)?;
        delete_with_paired_fences(
            cache,
            cache_expected,
            cache_fence.as_mut(),
            source,
            source_expected,
            source_fence.as_mut(),
            id,
            logical_length,
        )
    }
}

// crucible-lint: allow rust-allow -- The two exact fenced bases are the deletion safety boundary.
#[allow(clippy::too_many_arguments)]
fn delete_with_paired_fences<E>(
    cache: CampaignGcPhysicalStore<'_>,
    cache_expected: &CampaignGcBlobInventoryBasis,
    cache_fence: &mut dyn BlobInventoryFence,
    source: CampaignGcPhysicalStore<'_>,
    source_expected: &CampaignGcBlobInventoryBasis,
    source_fence: &mut dyn BlobInventoryFence,
    id: ContentId,
    logical_length: u64,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    validate_fenced_placement(cache, cache_expected, id, logical_length, cache_fence)?;
    validate_fenced_placement::<E>(source, source_expected, id, logical_length, source_fence)
        .map_err(|_| CampaignGcApplyError::RequiredCopyChanged {
            backend: source.backend().to_owned(),
            id,
        })?;
    delete_exact_candidate(cache, cache_fence, id)?;
    refreshed_basis_after_delete(cache, cache_expected, id, logical_length, cache_fence)
}

fn validate_required_copy_fence<E>(
    source: CampaignGcPhysicalStore<'_>,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut fence = acquire_physical_fence(source)?;
    validate_fenced_placement::<E>(source, expected, id, logical_length, fence.as_mut()).map_err(
        |_| CampaignGcApplyError::RequiredCopyChanged {
            backend: source.backend().to_owned(),
            id,
        },
    )
}

fn validate_fenced_placement<E>(
    target: CampaignGcPhysicalStore<'_>,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
    fence: &mut dyn BlobInventoryFence,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut found = false;
    let summary = fence
        .visit_inventory(&mut |record| {
            if record.id() == id && record.logical_length() == logical_length {
                found = true;
            }
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = CampaignGcBlobInventoryBasis::from_policy_aware_summary(&summary)?;
    if !found || current != *expected {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(())
}

fn refreshed_basis_after_delete<E>(
    target: CampaignGcPhysicalStore<'_>,
    prior: &CampaignGcBlobInventoryBasis,
    deleted: ContentId,
    logical_length: u64,
    fence: &mut dyn BlobInventoryFence,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut still_present = false;
    let summary = fence
        .visit_inventory(&mut |record| {
            still_present |= record.id() == deleted;
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = CampaignGcBlobInventoryBasis::from_policy_aware_summary(&summary)?;
    let expected_objects = prior.objects().checked_sub(1);
    let expected_bytes = prior.logical_bytes().checked_sub(logical_length);
    if still_present
        || current.storage_identity() != prior.storage_identity()
        || Some(current.objects()) != expected_objects
        || Some(current.logical_bytes()) != expected_bytes
        || current.generation() == prior.generation()
    {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(current)
}

fn delete_exact_candidate<E>(
    target: CampaignGcPhysicalStore<'_>,
    fence: &mut dyn BlobInventoryFence,
    id: ContentId,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    match fence
        .delete_candidate(id)
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })? {
        PlannedDeleteDisposition::Deleted => Ok(()),
        PlannedDeleteDisposition::AlreadyAbsent => Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        }),
    }
}

fn acquire_physical_fence<'a, E>(
    target: CampaignGcPhysicalStore<'a>,
) -> Result<Box<dyn BlobInventoryFence + 'a>, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    target
        .admin()
        .acquire_inventory_fence()
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })
}

fn physical_index<E>(
    physical: &[CampaignGcPhysicalStore<'_>],
    backend: &str,
) -> Result<usize, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    physical
        .binary_search_by_key(&backend, |target| target.backend())
        .map_err(|_| CampaignGcApplyError::PhysicalInputsChanged)
}

fn validate_unique_policy_identity<E>(
    journal: &DirectoryCampaignGcJournal,
    basis: &CampaignGcBlobInventoryBasis,
    backend: &str,
) -> Result<crucible_cas::content_store::PhysicalStorageIdentity, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let identity = basis
        .storage_identity()
        .ok_or(CampaignGcApplyError::PhysicalInputsChanged)?;
    if journal
        .plan()
        .physical()
        .iter()
        .filter(|candidate| candidate.storage_identity() == Some(identity))
        .count()
        != 1
    {
        return Err(CampaignGcApplyError::AliasedPhysicalBoundary {
            backend: backend.to_owned(),
        });
    }
    Ok(identity)
}

/// Failure to revalidate or apply one exact journaled campaign GC plan.
#[derive(Debug, Error)]
pub enum CampaignGcApplyError<E>
where
    E: StdError + 'static,
{
    /// A prior apply may have deleted candidates; this plan cannot be resumed.
    #[error("campaign GC journal records an interrupted apply; create a fresh plan")]
    InterruptedJournal,
    /// The current store graph differs from the planned composition.
    #[error("campaign GC store graph changed after planning")]
    StoreGraphChanged,
    /// The configured physical capabilities do not exactly match the plan.
    #[error("campaign GC physical capability list does not match the plan")]
    PhysicalInputsChanged,
    /// The authoritative ref namespace generation or count changed.
    #[error("campaign GC ref inventory changed after planning")]
    RefBasisChanged,
    /// The assignment-ledger generation or counters changed.
    #[error("campaign GC assignment-retention inventory changed after planning")]
    LedgerBasisChanged,
    /// The exact deduplicated logical root set changed.
    #[error("campaign GC logical root set changed after planning")]
    RootSetChanged,
    /// One complete physical inventory no longer matches its planned basis.
    #[error("campaign GC physical inventory changed for backend {backend}")]
    PhysicalBasisChanged {
        /// Stable physical backend identifier.
        backend: String,
    },
    /// Planned candidate membership or logical length changed.
    #[error("campaign GC candidate set changed for backend {backend}")]
    CandidateSetChanged {
        /// Stable physical backend identifier.
        backend: String,
    },
    /// The authoritative ref namespace could not be fenced or enumerated.
    #[error("campaign GC ref revalidation failed")]
    Ref(#[source] StoreError),
    /// The assignment ledger could not be fenced or enumerated.
    #[error("campaign GC assignment-retention revalidation failed")]
    Ledger(#[source] E),
    /// The assignment-ledger root visitor exhausted the manifest bound.
    #[error("campaign GC assignment-retention root limit exceeded")]
    LedgerVisitor,
    /// Pending write-back roots could not be fenced or enumerated.
    #[error("campaign GC write-back retention revalidation failed")]
    WriteBack(#[source] StoreError),
    /// Incomplete archive-transfer roots could not be revalidated.
    #[error("campaign GC transfer retention revalidation failed")]
    Transfer(#[source] CampaignTransferJournalError),
    /// Durable hot-checkpoint fallback roots could not be fenced or enumerated.
    #[error("campaign GC hot-checkpoint fallback revalidation failed")]
    #[cfg(target_os = "linux")]
    HotFallback(#[source] HotCheckpointFallbackRetentionError),
    /// One authoritative campaign snapshot or pin projection failed authentication.
    #[error(transparent)]
    Campaign(#[from] CampaignRepositoryError),
    /// The exact-pin materialization journal could not be fenced or read.
    #[error("campaign GC exact-pin materialization revalidation failed")]
    ExactPin(#[source] ExactPinRetentionError),
    /// An authoritative campaign ref had an invalid namespace or snapshot ID.
    #[error("campaign GC authoritative campaign ref is invalid: {name}")]
    InvalidCampaignRef {
        /// Exact invalid authoritative ref spelling.
        name: String,
    },
    /// An archive ref had an invalid namespace, target, or inventory.
    #[error("campaign GC authoritative archive ref is invalid: {name}")]
    InvalidArchiveRef {
        /// Exact invalid archive ref spelling.
        name: String,
    },
    /// A planned deletion became reachable under the current classified roots.
    #[error("campaign GC candidate {id} became reachable after planning")]
    CandidateBecameReachable {
        /// Newly reachable planned candidate.
        id: ContentId,
    },
    /// A v2 candidate no longer has its planned graph-derived retention roles.
    #[error("campaign GC candidate {id} on backend {backend} no longer satisfies cache policy")]
    CandidatePolicyChanged {
        /// Physical backend selected for cache eviction.
        backend: String,
        /// Reachable logical object whose placement policy changed.
        id: ContentId,
    },
    /// A v2 cache candidate shares its physical namespace with its source.
    #[error("campaign GC cache backend {backend} aliases required backend {required_backend}")]
    AliasedRequiredCopy {
        /// Cache backend selected for deletion.
        backend: String,
        /// Required backend that must be physically independent.
        required_backend: String,
    },
    /// A v2 cache or source identity is represented by several graph nodes.
    #[error("campaign GC physical identity for backend {backend} is aliased")]
    AliasedPhysicalBoundary {
        /// Backend whose physical identity is not unique in the plan.
        backend: String,
    },
    /// An authenticated required copy changed before paired deletion.
    #[error("campaign GC required copy {id} changed on backend {backend}")]
    RequiredCopyChanged {
        /// Required physical backend.
        backend: String,
        /// Reachable logical object requiring an independent placement.
        id: ContentId,
    },
    /// A current exact semantic pin has no matching selected checkpoint.
    #[error(
        "campaign {campaign:?} configuration {configuration} exact pin {pin_fact} has no current materialization"
    )]
    MissingExactPinMaterialization {
        /// Exact campaign containing the semantic pin.
        campaign: CampaignName,
        /// Exact semantic configuration requiring materialization.
        configuration: ConfigurationId,
        /// Latest accepted pin fact that must own the selection.
        pin_fact: CampaignFactId,
    },
    /// A physical blob leaf could not be fenced, enumerated, or mutated.
    #[error("campaign GC physical apply failed for backend {backend}")]
    Blob {
        /// Stable physical backend identifier.
        backend: String,
        /// Backend inventory or deletion failure.
        #[source]
        source: StoreError,
    },
    /// The durable external journal could not advance.
    #[error(transparent)]
    Journal(#[from] CampaignGcJournalError),
    /// A reproduced root manifest violated its fixed bound.
    #[error(transparent)]
    Manifest(#[from] CampaignGcManifestError),
    /// A physical inventory basis was invalid.
    #[error(transparent)]
    Plan(#[from] CampaignGcPlanError),
}

fn map_root_inventory_error<E>(source: CampaignGcRootInventoryError) -> CampaignGcApplyError<E>
where
    E: StdError + 'static,
{
    match source {
        CampaignGcRootInventoryError::Ref(source) => CampaignGcApplyError::Ref(source),
        CampaignGcRootInventoryError::Campaign(source) => CampaignGcApplyError::Campaign(source),
        CampaignGcRootInventoryError::ExactPin(source) => CampaignGcApplyError::ExactPin(source),
        CampaignGcRootInventoryError::InvalidCampaignRef { name } => {
            CampaignGcApplyError::InvalidCampaignRef { name }
        }
        CampaignGcRootInventoryError::InvalidArchiveRef { name } => {
            CampaignGcApplyError::InvalidArchiveRef { name }
        }
        CampaignGcRootInventoryError::MissingExactPinMaterialization {
            campaign,
            configuration,
            pin_fact,
        } => CampaignGcApplyError::MissingExactPinMaterialization {
            campaign,
            configuration,
            pin_fact,
        },
        CampaignGcRootInventoryError::Limit => {
            CampaignGcApplyError::Manifest(CampaignGcManifestError::EntryLimit)
        }
    }
}

fn validate_physical_basis<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    if physical.is_empty()
        || physical.len() > MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES
        || physical.len() != journal.plan().physical().len()
        || physical
            .iter()
            .zip(journal.plan().physical())
            .any(|(actual, planned)| actual.backend() != planned.backend())
    {
        return Err(CampaignGcApplyError::PhysicalInputsChanged);
    }
    let covered_candidates = physical.iter().try_fold(0_usize, |total, target| {
        total.checked_add(journal.candidates().for_backend(target.backend()).len())
    });
    if covered_candidates != Some(journal.candidates().len()) {
        return Err(CampaignGcApplyError::PhysicalInputsChanged);
    }
    Ok(())
}

fn validate_physical_inventory<E>(
    target: &CampaignGcPhysicalStore<'_>,
    planned: &CampaignGcBlobInventoryBasis,
    candidates: &CampaignGcCandidateManifest,
    fence: &mut dyn BlobInventoryFence,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let expected_candidates = candidates.for_backend(target.backend());
    let mut observed_candidates = 0_usize;
    let inventory = fence
        .visit_inventory(&mut |record| {
            if let Ok(index) =
                expected_candidates.binary_search_by(|candidate| candidate.compare_id(record.id()))
            {
                if expected_candidates[index].logical_length() != record.logical_length() {
                    return Err(StoreError::InvalidComposition {
                        reason: "campaign GC candidate logical length changed",
                    });
                }
                observed_candidates = observed_candidates
                    .checked_add(1)
                    .ok_or(StoreError::Quota)?;
            }
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = basis_for_planned_summary(planned, &inventory)?;
    if current != *planned {
        return Err(CampaignGcApplyError::PhysicalBasisChanged {
            backend: target.backend().to_owned(),
        });
    }
    if observed_candidates != expected_candidates.len() {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(())
}

fn basis_for_planned_summary(
    planned: &CampaignGcBlobInventoryBasis,
    summary: &crucible_cas::content_store::BlobInventorySummary,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcPlanError> {
    if planned.storage_identity().is_some() {
        CampaignGcBlobInventoryBasis::from_policy_aware_summary(summary)
    } else {
        CampaignGcBlobInventoryBasis::from_summary(summary)
    }
}
