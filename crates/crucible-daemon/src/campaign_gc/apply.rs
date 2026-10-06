//! Exact-generation destructive apply for one journaled single-host GC plan.

use super::reachability::Reachability;

use std::error::Error as StdError;

use crucible_campaign::{
    CampaignFactId, CampaignName, CampaignRepository, CampaignRepositoryError, ConfigurationId,
};
use crucible_cas::content_store::{
    BlobInventoryFence, ContentId, PlannedDeleteDisposition, RefStoreAdmin, StoreError,
    StoreGraphPhysicalAdmin, StoreGraphPhysicalRetention, WriteBackRetentionAdmin,
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
#[cfg(test)]
use super::CampaignGcRawPhysicalStore;
use super::planner::CampaignGcInventoryTarget;
use super::roots::{CampaignGcRootInventoryError, RootAccumulator, inventory_authoritative_refs};
use super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidateManifest, CampaignGcCandidateReason,
    CampaignGcJournalError, CampaignGcJournalPhase, CampaignGcMaintenance, CampaignGcManifestError,
    CampaignGcOperationContext, CampaignGcPhysicalStore, CampaignGcPlanError,
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

    /// Returns completed reachable cache deletions.
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
/// remain held throughout. Each physical leaf stays fenced through its
/// unreachable deletions. Cache reclamation acquires paired cache/source fences
/// in physical-identity order, revalidates both exact placements, and advances
/// the cache's rolling post-delete basis. Aliased identities fail closed before
/// deletion.
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
    maintenance: CampaignGcMaintenance<'_, '_, '_>,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    maintenance
        .operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
    let store_graph = maintenance.graph;
    let _borrowed_resources = maintenance
        .operation
        .reserve_array::<StoreGraphPhysicalAdmin<'_>>(store_graph.physical_count())
        .map_err(CampaignGcApplyError::Reachability)?;
    let borrowed = store_graph.physical();
    let _physical_resources = maintenance
        .operation
        .reserve_array::<CampaignGcPhysicalStore<'_>>(borrowed.len())
        .map_err(CampaignGcApplyError::Reachability)?;
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(borrowed.len())
        .map_err(|source| {
            CampaignGcApplyError::Reachability(StoreError::StreamIo {
                operation: "reserve GC physical boundary roster",
                source: std::io::Error::other(source),
            })
        })?;
    for entry in borrowed.iter().copied() {
        physical.push(CampaignGcPhysicalStore::from_graph_leaf(entry)?);
    }
    apply_single_host_campaign_gc_with_physical(
        journal,
        CampaignGcApplySources::new(repository, refs, ledger, write_back, exact_pins),
        crucible_campaign::CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
        maintenance.operation,
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
    maintenance: CampaignGcMaintenance<'_, '_, '_>,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    maintenance
        .operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
    let store_graph = maintenance.graph;
    let _borrowed_resources = maintenance
        .operation
        .reserve_array::<StoreGraphPhysicalAdmin<'_>>(store_graph.physical_count())
        .map_err(CampaignGcApplyError::Reachability)?;
    let borrowed = store_graph.physical();
    let _physical_resources = maintenance
        .operation
        .reserve_array::<CampaignGcPhysicalStore<'_>>(borrowed.len())
        .map_err(CampaignGcApplyError::Reachability)?;
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(borrowed.len())
        .map_err(|source| {
            CampaignGcApplyError::Reachability(StoreError::StreamIo {
                operation: "reserve GC physical boundary roster",
                source: std::io::Error::other(source),
            })
        })?;
    for entry in borrowed.iter().copied() {
        physical.push(CampaignGcPhysicalStore::from_graph_leaf(entry)?);
    }
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
        maintenance.operation,
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
    maintenance: CampaignGcMaintenance<'_, '_, '_>,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    maintenance
        .operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
    let store_graph = maintenance.graph;
    let _borrowed_resources = maintenance
        .operation
        .reserve_array::<StoreGraphPhysicalAdmin<'_>>(store_graph.physical_count())
        .map_err(CampaignGcApplyError::Reachability)?;
    let borrowed = store_graph.physical();
    let _physical_resources = maintenance
        .operation
        .reserve_array::<CampaignGcPhysicalStore<'_>>(borrowed.len())
        .map_err(CampaignGcApplyError::Reachability)?;
    let mut physical = Vec::new();
    physical
        .try_reserve_exact(borrowed.len())
        .map_err(|source| {
            CampaignGcApplyError::Reachability(StoreError::StreamIo {
                operation: "reserve GC physical boundary roster",
                source: std::io::Error::other(source),
            })
        })?;
    for entry in borrowed.iter().copied() {
        physical.push(CampaignGcPhysicalStore::from_graph_leaf(entry)?);
    }
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
        maintenance.operation,
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
    operation: &CampaignGcOperationContext<'_>,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    apply_single_host_campaign_gc_with_physical_strategy(
        journal,
        sources,
        store_graph,
        physical,
        operation,
        authenticate_policy_sources,
        apply_candidates,
    )
}

#[cfg(test)]
pub(crate) fn apply_single_host_campaign_gc_with_raw_physical<L>(
    journal: &mut DirectoryCampaignGcJournal,
    sources: CampaignGcApplySources<'_, '_, '_, '_, '_, L>,
    store_graph: crucible_campaign::CampaignHash,
    physical: &[CampaignGcRawPhysicalStore<'_>],
    operation: &CampaignGcOperationContext<'_>,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    apply_single_host_campaign_gc_with_physical_strategy(
        journal,
        sources,
        store_graph,
        physical,
        operation,
        |_journal, _physical, _current_reachable, _operation| Ok(()),
        apply_raw_candidates,
    )
}

fn apply_single_host_campaign_gc_with_physical_strategy<'a, L, P, A, D>(
    journal: &mut DirectoryCampaignGcJournal,
    sources: CampaignGcApplySources<'_, '_, '_, '_, '_, L>,
    store_graph: crucible_campaign::CampaignHash,
    physical: &[P],
    operation: &CampaignGcOperationContext<'_>,
    authenticate: A,
    delete: D,
) -> Result<CampaignGcApplyReport, CampaignGcApplyError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
    P: CampaignGcInventoryTarget<'a>,
    A: FnOnce(
        &DirectoryCampaignGcJournal,
        &[P],
        &Reachability,
        &CampaignGcOperationContext<'_>,
    ) -> Result<(), CampaignGcApplyError<L::Error>>,
    D: FnOnce(
        &DirectoryCampaignGcJournal,
        &[P],
        &CampaignGcOperationContext<'_>,
    ) -> Result<(), CampaignGcApplyError<L::Error>>,
{
    operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
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
    if journal.phase() == CampaignGcJournalPhase::Cancelled {
        return Err(CampaignGcApplyError::CancelledJournal);
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

    let _root_resources = operation
        .reserve_root_accumulator()
        .map_err(CampaignGcApplyError::Reachability)?;
    let mut roots = RootAccumulator::default();
    let ref_summary = inventory_authoritative_refs(
        repository,
        ref_fence.as_mut(),
        &mut exact_pin_fence,
        &mut roots,
        operation,
    )
    .map_err(map_root_inventory_error)?;
    if ref_summary.generation() != journal.plan().ref_generation()
        || ref_summary.refs() != journal.plan().refs()
    {
        return Err(CampaignGcApplyError::RefBasisChanged);
    }

    let mut ledger_operation_failure = None;
    let ledger_result = ledger_fence.visit_roots(&mut |root| {
        if let Err(source) = operation.check() {
            ledger_operation_failure = Some(source);
            return Err(AssignmentRetentionVisitorError::LimitExceeded);
        }
        let id = match root {
            AssignmentRetentionRoot::Observation(observation) => observation.content_id(),
            AssignmentRetentionRoot::ExactCheckpoint(checkpoint) => checkpoint.content_id(),
            AssignmentRetentionRoot::FindingCandidate(candidate) => candidate.content_id(),
        };
        roots
            .insert(id)
            .map_err(|()| AssignmentRetentionVisitorError::LimitExceeded)
    });
    if let Some(source) = ledger_operation_failure {
        return Err(CampaignGcApplyError::Reachability(source));
    }
    let ledger_summary = ledger_result.map_err(|source| match source {
        AssignmentRetentionInventoryError::Backend(source) => CampaignGcApplyError::Ledger(source),
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
        let mut operation_failure = None;
        let result = fence.visit_roots(&mut |root| {
            if let Err(source) = operation.check() {
                operation_failure = Some(source);
                return Err(HotCheckpointFallbackRetentionError::Visitor);
            }
            roots
                .insert(root)
                .map_err(|()| HotCheckpointFallbackRetentionError::Visitor)
        });
        if let Some(source) = operation_failure {
            return Err(CampaignGcApplyError::Reachability(source));
        }
        result.map_err(CampaignGcApplyError::HotFallback)?;
    }
    if let Some(fence) = write_back_fence.as_mut() {
        fence
            .visit_roots(&mut |root| {
                operation.check()?;
                roots
                    .insert_pending_write_back(root.id())
                    .map_err(|()| StoreError::Quota)
            })
            .map_err(CampaignGcApplyError::WriteBack)?;
    }
    if let Some(fence) = transfer_fence.as_mut() {
        fence
            .visit_roots(&mut |root| {
                operation.check()?;
                roots
                    .insert_direct(root.id())
                    .map_err(|()| StoreError::Quota)
            })
            .map_err(CampaignGcApplyError::Transfer)?;
    }
    if let Some(candidate) = journal.candidates().iter().find(|candidate| {
        matches!(
            candidate.reason(),
            CampaignGcCandidateReason::ReachableCache { .. }
        ) && roots.pending_write_back.contains(&candidate.id())
    }) {
        return Err(CampaignGcApplyError::CandidateBecameWriteBackPending {
            backend: candidate.backend().to_owned(),
            id: candidate.id(),
        });
    }
    let current_roots = CampaignGcRootManifest::new(roots.unique.iter().copied(), operation)?;
    if current_roots != *journal.roots() {
        return Err(CampaignGcApplyError::RootSetChanged);
    }
    // The root manifest binds unique IDs while the live inventory also
    // classifies direct and transitive roots. Recompute reachability from that
    // classification so promoting an archive object to an operational root
    // cannot leave its newly required descendants eligible for deletion.
    let current_reachable = Reachability::authenticate(
        repository,
        roots.ordinary.iter().copied(),
        roots.direct.iter().copied(),
        ref_fence.as_ref(),
        operation,
    )
    .map_err(CampaignGcApplyError::Reachability)?;
    for candidate in journal.candidates().iter() {
        operation
            .check()
            .map_err(CampaignGcApplyError::Reachability)?;
        if matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable)
            && current_reachable
                .contains(&candidate.id())
                .map_err(CampaignGcApplyError::Reachability)?
        {
            return Err(CampaignGcApplyError::CandidateBecameReachable { id: candidate.id() });
        }
    }
    for (target, planned) in physical.iter().zip(journal.plan().physical()) {
        let mut fence = target.admin().acquire_inventory_fence().map_err(|source| {
            CampaignGcApplyError::Blob {
                backend: target.backend().to_owned(),
                source,
            }
        })?;
        validate_physical_inventory(
            target,
            planned,
            journal.candidates(),
            fence.as_mut(),
            operation,
        )?;
    }

    authenticate(journal, physical, &current_reachable, operation)?;

    operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
    journal.begin_apply()?;
    delete(journal, physical, operation)?;
    operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
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

fn authenticate_policy_sources<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
    current_reachable: &Reachability,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut authenticated = std::collections::BTreeSet::new();
    for candidate in journal.candidates().iter() {
        operation
            .check()
            .map_err(CampaignGcApplyError::Reachability)?;
        let CampaignGcCandidateReason::ReachableCache { required_backend } = candidate.reason()
        else {
            continue;
        };
        let cache_index = physical_index(physical, candidate.backend())?;
        let source_index = physical_index(physical, required_backend)?;
        let kind = candidate.id().kind();
        let cache_role = physical[cache_index].graph().retention(kind);
        let source_role = physical[source_index].graph().retention(kind);
        if !current_reachable
            .contains(&candidate.id())
            .map_err(CampaignGcApplyError::Reachability)?
            || candidate.backend() == required_backend
            || cache_role != Some(StoreGraphPhysicalRetention::Cache)
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
        validate_required_copy_fence(
            source,
            expected,
            candidate.id(),
            candidate.logical_length(),
            operation,
        )?;

        let graph = source.graph();
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
        operation
            .authenticate_handle(&handle)
            .map_err(|source_error| CampaignGcApplyError::Blob {
                backend: source.backend().to_owned(),
                source: source_error,
            })?;
        // EOF authentication precedes the second generation validation. The
        // matching terminal basis makes those exact bytes authoritative for
        // the later paired-fence check.
        validate_required_copy_fence(
            source,
            expected,
            candidate.id(),
            candidate.logical_length(),
            operation,
        )?;
    }
    Ok(())
}

fn apply_candidates<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcPhysicalStore<'_>],
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let _rolling_slots = operation
        .reserve_array::<CampaignGcBlobInventoryBasis>(journal.plan().physical().len())
        .map_err(CampaignGcApplyError::Reachability)?;
    let label_bytes = journal
        .plan()
        .physical()
        .iter()
        .try_fold(0_u64, |total, basis| {
            total
                .checked_add(u64::try_from(basis.backend().len()).map_err(|_| StoreError::Quota)?)
                .ok_or(StoreError::Quota)
        })
        .map_err(CampaignGcApplyError::Reachability)?;
    let _rolling_labels = operation
        .reserve_bytes(label_bytes)
        .map_err(CampaignGcApplyError::Reachability)?;
    let mut rolling = Vec::new();
    rolling
        .try_reserve_exact(journal.plan().physical().len())
        .map_err(|source| {
            CampaignGcApplyError::Reachability(StoreError::StreamIo {
                operation: "reserve GC rolling physical bases",
                source: std::io::Error::other(source),
            })
        })?;
    rolling.extend(journal.plan().physical().iter().cloned());
    for (index, target) in physical.iter().copied().enumerate() {
        rolling[index] =
            apply_unreachable_batch(target, &rolling[index], journal.candidates(), operation)?;
    }

    // Required-copy cache eviction still uses its two independently fenced
    // physical bases. Unreachable deletions cannot remove a reachable source.
    for candidate in journal.candidates().iter() {
        let CampaignGcCandidateReason::ReachableCache { required_backend } = candidate.reason()
        else {
            continue;
        };
        operation
            .check()
            .map_err(CampaignGcApplyError::Reachability)?;
        let cache_index = physical_index(physical, candidate.backend())?;
        let source_index = physical_index(physical, required_backend)?;
        let cache_identity =
            validate_unique_policy_identity(journal, &rolling[cache_index], candidate.backend())?;
        let source_identity =
            validate_unique_policy_identity(journal, &rolling[source_index], required_backend)?;
        if cache_identity == source_identity {
            return Err(CampaignGcApplyError::AliasedRequiredCopy {
                backend: candidate.backend().to_owned(),
                required_backend: required_backend.clone(),
            });
        }
        rolling[cache_index] = delete_paired(
            physical[cache_index],
            &rolling[cache_index],
            physical[source_index],
            &rolling[source_index],
            candidate.id(),
            candidate.logical_length(),
            (cache_identity < source_identity, operation),
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn apply_raw_candidates<E>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[CampaignGcRawPhysicalStore<'_>],
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    if journal
        .candidates()
        .iter()
        .any(|candidate| !matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable))
    {
        return Err(CampaignGcApplyError::PhysicalInputsChanged);
    }
    for (target, prior) in physical.iter().copied().zip(journal.plan().physical()) {
        apply_unreachable_batch(target, prior, journal.candidates(), operation)?;
    }
    Ok(())
}

fn apply_unreachable_batch<'a, E, P>(
    target: P,
    prior: &CampaignGcBlobInventoryBasis,
    candidates: &CampaignGcCandidateManifest,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let selected = candidates.for_backend(target.backend());
    let mut deleted = 0_u64;
    let mut deleted_bytes = 0_u64;
    for candidate in selected
        .iter()
        .filter(|candidate| matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable))
    {
        deleted = deleted
            .checked_add(1)
            .ok_or(CampaignGcPlanError::CountOverflow)?;
        deleted_bytes = deleted_bytes
            .checked_add(candidate.logical_length())
            .ok_or(CampaignGcPlanError::CountOverflow)?;
    }
    if deleted == 0 {
        return Ok(prior.clone());
    }

    // This one exclusive physical fence binds the complete initial inventory
    // and every deletion. Other writers cannot change the namespace between
    // candidates; only the bounded selected batch mutates its generation.
    let mut fence = acquire_physical_fence(target)?;
    validate_physical_inventory(&target, prior, candidates, fence.as_mut(), operation)?;
    for candidate in selected
        .iter()
        .filter(|candidate| matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable))
    {
        delete_exact_candidate(target, fence.as_mut(), candidate.id(), operation)?;
    }
    let summary = fence
        .visit_inventory(&mut |record| {
            operation.check()?;
            if let Ok(index) =
                selected.binary_search_by(|candidate| candidate.compare_id(record.id()))
                && matches!(
                    selected[index].reason(),
                    CampaignGcCandidateReason::Unreachable
                )
            {
                return Err(StoreError::InvalidComposition {
                    reason: "GC deleted candidate remains in the physical inventory",
                });
            }
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = CampaignGcBlobInventoryBasis::from_summary(&summary)?;
    if current.storage_identity() != prior.storage_identity()
        || current.generation() == prior.generation()
        || Some(current.objects()) != prior.objects().checked_sub(deleted)
        || Some(current.logical_bytes()) != prior.logical_bytes().checked_sub(deleted_bytes)
    {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(current)
}

fn delete_paired<E>(
    cache: CampaignGcPhysicalStore<'_>,
    cache_expected: &CampaignGcBlobInventoryBasis,
    source: CampaignGcPhysicalStore<'_>,
    source_expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
    ordering: (bool, &CampaignGcOperationContext<'_>),
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let (cache_first, operation) = ordering;
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
            operation,
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
            operation,
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
    operation: &CampaignGcOperationContext<'_>,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    validate_fenced_placement(
        cache,
        cache_expected,
        id,
        logical_length,
        cache_fence,
        operation,
    )?;
    validate_fenced_placement::<E, _>(
        source,
        source_expected,
        id,
        logical_length,
        source_fence,
        operation,
    )
    .map_err(|error| match error {
        CampaignGcApplyError::Blob { .. } | CampaignGcApplyError::Reachability(_) => error,
        _ => CampaignGcApplyError::RequiredCopyChanged {
            backend: source.backend().to_owned(),
            id,
        },
    })?;
    delete_exact_candidate(cache, cache_fence, id, operation)?;
    refreshed_basis_after_delete(
        cache,
        cache_expected,
        id,
        logical_length,
        cache_fence,
        operation,
    )
}

fn validate_required_copy_fence<E>(
    source: CampaignGcPhysicalStore<'_>,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
{
    let mut fence = acquire_physical_fence(source)?;
    validate_fenced_placement::<E, _>(
        source,
        expected,
        id,
        logical_length,
        fence.as_mut(),
        operation,
    )
    .map_err(|error| match error {
        CampaignGcApplyError::Blob { .. } | CampaignGcApplyError::Reachability(_) => error,
        _ => CampaignGcApplyError::RequiredCopyChanged {
            backend: source.backend().to_owned(),
            id,
        },
    })
}

fn validate_fenced_placement<'a, E, P>(
    target: P,
    expected: &CampaignGcBlobInventoryBasis,
    id: ContentId,
    logical_length: u64,
    fence: &mut dyn BlobInventoryFence,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let mut found = false;
    let summary = fence
        .visit_inventory(&mut |record| {
            operation.check()?;
            if record.id() == id && record.logical_length() == logical_length {
                found = true;
            }
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = CampaignGcBlobInventoryBasis::from_summary(&summary)?;
    if !found || current != *expected {
        return Err(CampaignGcApplyError::CandidateSetChanged {
            backend: target.backend().to_owned(),
        });
    }
    Ok(())
}

fn refreshed_basis_after_delete<'a, E, P>(
    target: P,
    prior: &CampaignGcBlobInventoryBasis,
    deleted: ContentId,
    logical_length: u64,
    fence: &mut dyn BlobInventoryFence,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<CampaignGcBlobInventoryBasis, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let mut still_present = false;
    let summary = fence
        .visit_inventory(&mut |record| {
            operation.check()?;
            still_present |= record.id() == deleted;
            Ok(())
        })
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    let current = CampaignGcBlobInventoryBasis::from_summary(&summary)?;
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

fn delete_exact_candidate<'a, E, P>(
    target: P,
    fence: &mut dyn BlobInventoryFence,
    id: ContentId,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    operation
        .check()
        .map_err(CampaignGcApplyError::Reachability)?;
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

fn acquire_physical_fence<'a, E, P>(
    target: P,
) -> Result<Box<dyn BlobInventoryFence + 'a>, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    target
        .admin()
        .acquire_inventory_fence()
        .map_err(|source| CampaignGcApplyError::Blob {
            backend: target.backend().to_owned(),
            source,
        })
}

fn physical_index<'a, E, P>(physical: &[P], backend: &str) -> Result<usize, CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
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
    let identity = basis.storage_identity();
    if journal
        .plan()
        .physical()
        .iter()
        .filter(|candidate| candidate.storage_identity() == identity)
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
    /// The operator cancelled this plan before deletion began.
    #[error("campaign GC journal records a cancelled plan; create a fresh plan")]
    CancelledJournal,
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
    /// Authenticated disk-backed reachability could not be revalidated.
    #[error("campaign GC reachability marking failed")]
    Reachability(#[source] StoreError),
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
    /// A planned cache eviction became owned by a pending write-back journal.
    #[error(
        "campaign GC candidate {id} on backend {backend} became pending write-back after planning"
    )]
    CandidateBecameWriteBackPending {
        /// Cache backend selected for deletion.
        backend: String,
        /// Planned cache candidate now protected by the write-back fence.
        id: ContentId,
    },
    /// A candidate no longer has its planned graph-derived retention roles.
    #[error("campaign GC candidate {id} on backend {backend} no longer satisfies cache policy")]
    CandidatePolicyChanged {
        /// Physical backend selected for cache eviction.
        backend: String,
        /// Reachable logical object whose placement policy changed.
        id: ContentId,
    },
    /// A cache candidate shares its physical namespace with its source.
    #[error("campaign GC cache backend {backend} aliases required backend {required_backend}")]
    AliasedRequiredCopy {
        /// Cache backend selected for deletion.
        backend: String,
        /// Required backend that must be physically independent.
        required_backend: String,
    },
    /// A cache or source identity is represented by several graph nodes.
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

fn validate_physical_basis<'a, E, P>(
    journal: &DirectoryCampaignGcJournal,
    physical: &[P],
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
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

fn validate_physical_inventory<'a, E, P>(
    target: &P,
    planned: &CampaignGcBlobInventoryBasis,
    candidates: &CampaignGcCandidateManifest,
    fence: &mut dyn BlobInventoryFence,
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), CampaignGcApplyError<E>>
where
    E: StdError + 'static,
    P: CampaignGcInventoryTarget<'a>,
{
    let expected_candidates = candidates.for_backend(target.backend());
    let mut observed_candidates = 0_usize;
    let inventory = fence
        .visit_inventory(&mut |record| {
            operation.check()?;
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
    let current = CampaignGcBlobInventoryBasis::from_summary(&inventory)?;
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
