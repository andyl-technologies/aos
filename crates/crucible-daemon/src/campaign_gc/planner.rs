//! Generation-bound non-destructive GC planning for one single-host store graph.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::io;

use crucible_campaign::{
    CampaignFactId, CampaignHash, CampaignName, CampaignRepository, CampaignRepositoryError,
    ConfigurationId,
};
use crucible_cas::content_store::{
    BlobInventoryRecord, BlobInventorySummary, BlobStoreAdmin, PhysicalStorageIdentity,
    RefStoreAdmin, StoreError, StoreGraphAdmin, StoreGraphPhysicalAdmin,
    StoreGraphPhysicalRetention, WriteBackRetentionAdmin,
};
use thiserror::Error;

use crate::{
    AssignmentRetentionAdmin, AssignmentRetentionInventoryError, AssignmentRetentionRoot,
    AssignmentRetentionSummary, AssignmentRetentionVisitorError, CampaignTransferJournalError,
    CampaignTransferRetentionAdmin, ExactPinRetentionAdmin, ExactPinRetentionError,
};
#[cfg(target_os = "linux")]
use crate::{HotCheckpointFallbackRetentionAdmin, HotCheckpointFallbackRetentionError};

#[cfg(target_os = "linux")]
use super::CampaignGcHotCheckpointRoots;
use super::roots::{CampaignGcRootInventoryError, RootAccumulator, inventory_authoritative_refs};
use super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidate, CampaignGcCandidateManifest,
    CampaignGcCandidateReason, CampaignGcManifestError, CampaignGcPlan, CampaignGcPlanError,
    CampaignGcRetentionSources, CampaignGcRootManifest, MAX_CAMPAIGN_GC_MANIFEST_ENTRIES,
    MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES, validate_backend_id,
};

/// One named physical blob leaf and its separate inventory authority.
#[derive(Clone, Copy)]
pub struct CampaignGcPhysicalStore<'a> {
    backend: &'a str,
    admin: &'a dyn BlobStoreAdmin,
    graph: Option<StoreGraphPhysicalAdmin<'a>>,
}

impl<'a> CampaignGcPhysicalStore<'a> {
    /// Binds a physical backend name to its administrative capability.
    ///
    /// The name must equal the backend identity returned by its fenced
    /// inventory. Construction does not acquire the fence.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::InvalidBackendId`] if `backend` violates
    /// the canonical v1 identifier grammar.
    pub fn new(
        backend: &'a str,
        admin: &'a dyn BlobStoreAdmin,
    ) -> Result<Self, CampaignGcPlanError> {
        validate_backend_id(backend)?;
        Ok(Self {
            backend,
            admin,
            graph: None,
        })
    }

    /// Binds one physical leaf borrowed from a separately held graph admin.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::InvalidBackendId`] if the admitted graph
    /// node ID violates the canonical GC backend identifier grammar.
    pub fn from_graph_leaf(
        physical: StoreGraphPhysicalAdmin<'a>,
    ) -> Result<Self, CampaignGcPlanError> {
        validate_backend_id(physical.node().as_str())?;
        Ok(Self {
            backend: physical.node().as_str(),
            admin: physical.admin(),
            graph: Some(physical),
        })
    }

    /// Returns the physical backend identifier.
    #[must_use]
    pub const fn backend(self) -> &'a str {
        self.backend
    }

    pub(super) const fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin
    }

    pub(super) const fn graph(self) -> Option<StoreGraphPhysicalAdmin<'a>> {
        self.graph
    }
}

/// Complete non-destructive output of one single-host GC planning pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcPreparedPlan {
    plan: CampaignGcPlan,
    roots: CampaignGcRootManifest,
    candidates: CampaignGcCandidateManifest,
    reachable_objects: u64,
    unreachable_candidates: u64,
    reachable_cache_candidates: u64,
}

impl CampaignGcPreparedPlan {
    /// Returns the small generation-bound canonical plan header.
    #[must_use]
    pub const fn plan(&self) -> &CampaignGcPlan {
        &self.plan
    }

    /// Returns the exact logical roots authenticated during planning.
    #[must_use]
    pub const fn roots(&self) -> &CampaignGcRootManifest {
        &self.roots
    }

    /// Returns the exact physical placements authorized for deletion.
    #[must_use]
    pub const fn candidates(&self) -> &CampaignGcCandidateManifest {
        &self.candidates
    }

    /// Returns the number of unique authenticated reachable logical objects.
    #[must_use]
    pub const fn reachable_objects(&self) -> u64 {
        self.reachable_objects
    }

    /// Returns placements authorized because their logical object is unreachable.
    #[must_use]
    pub const fn unreachable_candidates(&self) -> u64 {
        self.unreachable_candidates
    }

    /// Returns reachable read-through cache placements authorized by v2 policy.
    #[must_use]
    pub const fn reachable_cache_candidates(&self) -> u64 {
        self.reachable_cache_candidates
    }

    #[cfg(test)]
    pub(super) fn with_candidate_manifest_for_test(
        mut self,
        candidates: CampaignGcCandidateManifest,
    ) -> Self {
        self.plan.candidates = candidates.summary();
        self.unreachable_candidates = candidates.unreachable_candidates();
        self.reachable_cache_candidates = candidates.reachable_cache_candidates();
        self.candidates = candidates;
        self
    }
}

/// Builds a complete generation-bound deletion plan without mutating storage.
///
/// Ref, exact-pin selection, and assignment-ledger fences are used only long
/// enough to authenticate the exact root manifest and terminal generations.
/// Every fenced campaign ref is authenticated as a snapshot; each current
/// exact pin must resolve to a journal selection bound to its latest pin fact.
/// The repository then authenticates the union of those logical closures.
/// Finally each physical leaf is inventoried under its own fence. Unreachable
/// placements enter every candidate manifest. A reachable read-through cache
/// placement enters a v2 manifest only when a physically independent required
/// copy is authenticated to EOF between matching inventory generations.
/// `store_graph` supplies both the exact canonical graph identity and its
/// construction-time physical capabilities, so those bases cannot be mixed.
///
/// This operation deliberately does not delete. A later apply must reacquire
/// every fence, reproduce the root and physical generations, and additionally
/// exclude an in-flight campaign transaction across its children-before-ref
/// publication window and every pending write-back transfer through its
/// children-before-journal window. Omitting `exact_pins` is valid only when the
/// complete authoritative campaign inventory contains no current exact pin.
/// This catalog-free entry point is valid only when no managed hot-checkpoint
/// pool exists; configured pools must use
/// `plan_single_host_campaign_gc_with_hot_checkpoints` on Linux.
///
/// # Errors
///
/// Returns [`CampaignGcPlanningError`] if any administrative inventory is
/// incomplete, a root closure is missing or invalid, a manifest bound is
/// exceeded, physical backend identities are inconsistent, or the terminal
/// plan cannot be represented canonically. Visitor prefixes are discarded on
/// every error.
pub fn plan_single_host_campaign_gc<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CampaignGcPlanningError::Plan)?;
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        write_back,
        CampaignGcRetentionSources::without_hot_checkpoints(exact_pins),
        CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

/// Builds a GC plan while retaining every incomplete archive-transfer object.
///
/// Transfer records are inventoried after write-back roots under the fixed
/// ref, exact-pin, ledger, hot-fallback, write-back, transfer lock order. Their
/// roots are direct archive-boundary objects and are not traversed as complete
/// campaign closures.
///
/// # Errors
///
/// Returns [`CampaignGcPlanningError`] under the same conditions as
/// [`plan_single_host_campaign_gc`], and when transfer inventory is invalid.
pub fn plan_single_host_campaign_gc_with_transfers<'a, L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    transfers: &'a dyn CampaignTransferRetentionAdmin,
    exact_pins: Option<&'a mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CampaignGcPlanningError::Plan)?;
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        write_back,
        CampaignGcRetentionSources::with_transfers(exact_pins, transfers),
        CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

/// Builds a GC plan that also retains every durable hot-checkpoint fallback.
///
/// This is the production single-host boundary when a hot-checkpoint manager
/// is configured. Its fallback fence is held through root discovery exactly
/// like assignment and write-back operational retention sources.
///
/// # Errors
///
/// Returns [`CampaignGcPlanningError`] under the same conditions as
/// [`plan_single_host_campaign_gc`], and additionally when the fallback
/// catalog cannot provide a complete authenticated inventory.
#[cfg(target_os = "linux")]
pub fn plan_single_host_campaign_gc_with_hot_checkpoints<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    roots: CampaignGcHotCheckpointRoots<'_>,
    store_graph: &StoreGraphAdmin,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let borrowed = store_graph.physical();
    let physical = borrowed
        .iter()
        .copied()
        .map(CampaignGcPhysicalStore::from_graph_leaf)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CampaignGcPlanningError::Plan)?;
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        write_back,
        roots.into_sources(),
        CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

#[cfg(test)]
pub(crate) fn plan_single_host_campaign_gc_with_physical<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&mut dyn ExactPinRetentionAdmin>,
    store_graph: CampaignHash,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        write_back,
        CampaignGcRetentionSources::without_hot_checkpoints(exact_pins),
        store_graph,
        physical,
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn plan_single_host_campaign_gc_with_physical_and_hot_checkpoints<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    root_sources: CampaignGcHotCheckpointRoots<'_>,
    store_graph: CampaignHash,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        write_back,
        root_sources.into_sources(),
        store_graph,
        physical,
    )
}

pub(super) fn plan_single_host_campaign_gc_with_physical_and_root_sources<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    root_sources: CampaignGcRetentionSources<'_>,
    store_graph: CampaignHash,
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    validate_physical_inputs(physical).map_err(CampaignGcPlanningError::Plan)?;
    let exact_pins = root_sources.exact_pins;

    let mut roots = RootAccumulator::default();
    let mut ref_fence = refs
        .acquire_ref_inventory_fence()
        .map_err(CampaignGcPlanningError::Ref)?;
    let mut exact_fence = exact_pins
        .map(ExactPinRetentionAdmin::acquire_exact_pin_retention_fence)
        .transpose()
        .map_err(CampaignGcPlanningError::ExactPin)?;
    let ref_summary =
        inventory_authoritative_refs(repository, ref_fence.as_mut(), &mut exact_fence, &mut roots)
            .map_err(map_root_inventory_error)?;
    let ledger_summary = inventory_ledger(ledger, &mut roots)?;
    #[cfg(target_os = "linux")]
    inventory_hot_fallbacks(root_sources.hot_fallbacks, &mut roots)?;
    inventory_write_back(write_back, &mut roots)?;
    inventory_transfers(root_sources.transfers, &mut roots)?;
    let root_manifest = CampaignGcRootManifest::new(roots.unique.iter().copied())?;

    let mut reachable = repository
        .authenticated_closure_ids(roots.ordinary.iter().copied())
        .map_err(CampaignGcPlanningError::Campaign)?;
    reachable.extend(roots.direct.iter().copied());
    let reachable_objects = u64::try_from(reachable.len())
        .map_err(|_| CampaignGcPlanningError::Manifest(CampaignGcManifestError::EntryLimit))?;

    let graph_aware = physical.iter().all(|target| target.graph().is_some());
    if !graph_aware && physical.iter().any(|target| target.graph().is_some()) {
        return Err(CampaignGcPlanningError::Plan(
            CampaignGcPlanError::InvalidPhysicalInventoryCount,
        ));
    }
    let planned = if graph_aware {
        plan_policy_aware_physical(physical, &reachable)?
    } else {
        plan_unreachable_physical(physical, &reachable)?
    };
    let candidate_manifest = if graph_aware {
        CampaignGcCandidateManifest::new_policy_aware(planned.candidates)?
    } else {
        CampaignGcCandidateManifest::new(planned.candidates)?
    };
    let plan = if graph_aware {
        CampaignGcPlan::new_policy_aware(
            store_graph,
            root_manifest.id(),
            ref_summary,
            ledger_summary,
            candidate_manifest.summary(),
            planned.physical_basis,
        )?
    } else {
        CampaignGcPlan::new(
            store_graph,
            root_manifest.id(),
            ref_summary,
            ledger_summary,
            candidate_manifest.summary(),
            planned.physical_basis,
        )?
    };
    Ok(CampaignGcPreparedPlan {
        plan,
        roots: root_manifest,
        candidates: candidate_manifest,
        reachable_objects,
        unreachable_candidates: planned.unreachable_candidates,
        reachable_cache_candidates: planned.reachable_cache_candidates,
    })
}

struct PlannedPhysical {
    candidates: Vec<CampaignGcCandidate>,
    physical_basis: Vec<CampaignGcBlobInventoryBasis>,
    unreachable_candidates: u64,
    reachable_cache_candidates: u64,
}

fn plan_unreachable_physical<E>(
    physical: &[CampaignGcPhysicalStore<'_>],
    reachable: &BTreeSet<crucible_cas::content_store::ContentId>,
) -> Result<PlannedPhysical, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let mut candidates = Vec::new();
    let mut physical_basis = Vec::with_capacity(physical.len());
    for target in physical {
        let mut fence = target.admin.acquire_inventory_fence().map_err(|source| {
            CampaignGcPlanningError::Blob {
                backend: target.backend.to_owned(),
                source,
            }
        })?;
        let summary = fence
            .visit_inventory(&mut |record| {
                if !reachable.contains(&record.id()) {
                    if candidates.len() >= MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
                        return Err(StoreError::Quota);
                    }
                    candidates.push(
                        CampaignGcCandidate::new(
                            target.backend,
                            record.id(),
                            record.logical_length(),
                        )
                        .map_err(|_| StoreError::InvalidComposition {
                            reason: "campaign GC candidate manifest backend is invalid",
                        })?,
                    );
                }
                Ok(())
            })
            .map_err(|source| CampaignGcPlanningError::Blob {
                backend: target.backend.to_owned(),
                source,
            })?;
        if summary.backend() != target.backend {
            return Err(CampaignGcPlanningError::BackendIdentityMismatch {
                expected: target.backend.to_owned(),
                actual: summary.backend().to_owned(),
            });
        }
        physical_basis.push(CampaignGcBlobInventoryBasis::from_summary(&summary)?);
    }
    Ok(PlannedPhysical {
        unreachable_candidates: candidates.len() as u64,
        reachable_cache_candidates: 0,
        candidates,
        physical_basis,
    })
}

#[derive(Clone)]
struct ObservedPlacement {
    target: usize,
    identity: PhysicalStorageIdentity,
    record: BlobInventoryRecord,
    role: StoreGraphPhysicalRetention,
}

fn plan_policy_aware_physical<E>(
    physical: &[CampaignGcPhysicalStore<'_>],
    reachable: &BTreeSet<crucible_cas::content_store::ContentId>,
) -> Result<PlannedPhysical, CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let mut candidates = Vec::new();
    let mut summaries = Vec::with_capacity(physical.len());
    let mut observed = Vec::new();
    let mut aliases = BTreeMap::<PhysicalStorageIdentity, usize>::new();

    for (target_index, target) in physical.iter().enumerate() {
        let graph = target.graph().ok_or(CampaignGcPlanningError::Plan(
            CampaignGcPlanError::InvalidPhysicalInventoryCount,
        ))?;
        let mut reachable_records = Vec::new();
        let mut fence = target.admin.acquire_inventory_fence().map_err(|source| {
            CampaignGcPlanningError::Blob {
                backend: target.backend.to_owned(),
                source,
            }
        })?;
        let summary = fence
            .visit_inventory(&mut |record| {
                if reachable.contains(&record.id()) {
                    if observed.len().saturating_add(reachable_records.len())
                        >= MAX_CAMPAIGN_GC_MANIFEST_ENTRIES
                    {
                        return Err(StoreError::Quota);
                    }
                    reachable_records.push(record);
                } else {
                    if candidates.len() >= MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
                        return Err(StoreError::Quota);
                    }
                    candidates.push(
                        CampaignGcCandidate::new(
                            target.backend,
                            record.id(),
                            record.logical_length(),
                        )
                        .map_err(|_| StoreError::InvalidComposition {
                            reason: "campaign GC candidate manifest backend is invalid",
                        })?,
                    );
                }
                Ok(())
            })
            .map_err(|source| CampaignGcPlanningError::Blob {
                backend: target.backend.to_owned(),
                source,
            })?;
        if summary.backend() != target.backend {
            return Err(CampaignGcPlanningError::BackendIdentityMismatch {
                expected: target.backend.to_owned(),
                actual: summary.backend().to_owned(),
            });
        }
        *aliases.entry(summary.storage_identity()).or_default() += 1;
        for record in reachable_records {
            observed.push(ObservedPlacement {
                target: target_index,
                identity: summary.storage_identity(),
                record,
                role: graph
                    .retention(record.id().kind())
                    .unwrap_or(StoreGraphPhysicalRetention::Required),
            });
        }
        summaries.push(summary);
    }

    let mut domain_roles = BTreeMap::<
        (
            PhysicalStorageIdentity,
            crucible_cas::content_store::ObjectKind,
        ),
        StoreGraphPhysicalRetention,
    >::new();
    for placement in &observed {
        domain_roles
            .entry((placement.identity, placement.record.id().kind()))
            .and_modify(|role| *role = (*role).max(placement.role))
            .or_insert(placement.role);
    }

    let mut required_placements =
        BTreeMap::<crucible_cas::content_store::ContentId, BTreeMap<u64, usize>>::new();
    for (placement_index, placement) in observed.iter().enumerate() {
        if aliases.get(&placement.identity).copied() != Some(1)
            || domain_roles.get(&(placement.identity, placement.record.id().kind()))
                != Some(&StoreGraphPhysicalRetention::Required)
        {
            continue;
        }

        required_placements
            .entry(placement.record.id())
            .or_default()
            .entry(placement.record.logical_length())
            .and_modify(|current_index| {
                let current = &observed[*current_index];
                let current_key = (current.identity, physical[current.target].backend);
                let replacement_key = (placement.identity, physical[placement.target].backend);
                if replacement_key < current_key {
                    *current_index = placement_index;
                }
            })
            .or_insert(placement_index);
    }

    let mut authenticated_sources = BTreeSet::new();
    let mut cache_candidates = 0_u64;
    for cache in &observed {
        let cache_role = domain_roles
            .get(&(cache.identity, cache.record.id().kind()))
            .copied()
            .unwrap_or(StoreGraphPhysicalRetention::Required);
        if cache_role != StoreGraphPhysicalRetention::ReadThroughCache
            || aliases.get(&cache.identity).copied() != Some(1)
        {
            continue;
        }

        let source = required_placements
            .get(&cache.record.id())
            .and_then(|by_length| by_length.get(&cache.record.logical_length()))
            .map(|source_index| &observed[*source_index])
            .filter(|source| source.identity != cache.identity);
        let Some(source) = source else {
            continue;
        };
        let source_target = physical[source.target];
        if authenticated_sources.insert((source_target.backend.to_owned(), source.record.id())) {
            authenticate_required_copy(source_target, source.record, &summaries[source.target])?;
        }
        if candidates.len() >= MAX_CAMPAIGN_GC_MANIFEST_ENTRIES {
            return Err(CampaignGcPlanningError::Manifest(
                CampaignGcManifestError::EntryLimit,
            ));
        }
        candidates.push(CampaignGcCandidate::new_reachable_read_through_cache(
            physical[cache.target].backend,
            cache.record.id(),
            cache.record.logical_length(),
            source_target.backend,
        )?);
        cache_candidates =
            cache_candidates
                .checked_add(1)
                .ok_or(CampaignGcPlanningError::Manifest(
                    CampaignGcManifestError::CountOverflow,
                ))?;
    }

    let physical_basis = summaries
        .iter()
        .map(CampaignGcBlobInventoryBasis::from_policy_aware_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let unreachable_candidates = candidates
        .iter()
        .filter(|candidate| matches!(candidate.reason(), CampaignGcCandidateReason::Unreachable))
        .count() as u64;
    Ok(PlannedPhysical {
        candidates,
        physical_basis,
        unreachable_candidates,
        reachable_cache_candidates: cache_candidates,
    })
}

fn authenticate_required_copy<E>(
    target: CampaignGcPhysicalStore<'_>,
    record: BlobInventoryRecord,
    expected: &BlobInventorySummary,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    validate_required_copy_inventory(target, record, expected)?;
    let graph = target.graph().ok_or(CampaignGcPlanningError::Plan(
        CampaignGcPlanError::InvalidPhysicalInventoryCount,
    ))?;
    let handle = graph
        .read(record.id())
        .map_err(|source| CampaignGcPlanningError::Blob {
            backend: target.backend.to_owned(),
            source,
        })?;
    if handle.logical_length() != record.logical_length() {
        return Err(CampaignGcPlanningError::Blob {
            backend: target.backend.to_owned(),
            source: StoreError::InvalidComposition {
                reason: "campaign GC required-copy logical length changed",
            },
        });
    }
    handle
        .copy_to(&mut io::sink())
        .map_err(|source| CampaignGcPlanningError::Blob {
            backend: target.backend.to_owned(),
            source,
        })?;
    validate_required_copy_inventory(target, record, expected)
}

fn validate_required_copy_inventory<E>(
    target: CampaignGcPhysicalStore<'_>,
    record: BlobInventoryRecord,
    expected: &BlobInventorySummary,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let mut observed = false;
    let mut fence = target.admin().acquire_inventory_fence().map_err(|source| {
        CampaignGcPlanningError::Blob {
            backend: target.backend().to_owned(),
            source,
        }
    })?;
    let summary = fence
        .visit_inventory(&mut |candidate| {
            if candidate.id() == record.id()
                && candidate.logical_length() == record.logical_length()
            {
                observed = true;
            }
            Ok(())
        })
        .map_err(|source| CampaignGcPlanningError::Blob {
            backend: target.backend().to_owned(),
            source,
        })?;
    if !observed || summary != *expected {
        return Err(CampaignGcPlanningError::RequiredCopyBasisChanged {
            backend: target.backend().to_owned(),
            id: record.id(),
        });
    }
    Ok(())
}

/// Failure to build one non-destructive generation-bound campaign GC plan.
#[derive(Debug, Error)]
pub enum CampaignGcPlanningError<E>
where
    E: StdError + 'static,
{
    /// The authoritative ref namespace could not be fenced or enumerated.
    #[error("campaign GC ref inventory failed")]
    Ref(#[source] StoreError),
    /// The assignment ledger could not be fenced or enumerated.
    #[error("campaign GC assignment-retention inventory failed")]
    Ledger(#[source] E),
    /// The assignment-ledger root visitor exhausted the manifest bound.
    #[error("campaign GC assignment-retention root limit exceeded")]
    LedgerVisitor,
    /// A pending write-back root set could not be fenced or enumerated.
    #[error("campaign GC write-back retention inventory failed")]
    WriteBack(#[source] StoreError),
    /// An incomplete archive-transfer root set could not be inventoried.
    #[error("campaign GC transfer retention inventory failed")]
    Transfer(#[source] CampaignTransferJournalError),
    /// The durable hot-checkpoint fallback catalog could not be inventoried.
    #[error("campaign GC hot-checkpoint fallback inventory failed")]
    #[cfg(target_os = "linux")]
    HotFallback(#[source] HotCheckpointFallbackRetentionError),
    /// The exact-pin materialization journal could not be fenced or read.
    #[error("campaign GC exact-pin materialization inventory failed")]
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
    /// A physical blob leaf could not be fenced or enumerated.
    #[error("campaign GC physical inventory failed for backend {backend}")]
    Blob {
        /// Stable physical backend identifier.
        backend: String,
        /// Backend inventory failure.
        #[source]
        source: StoreError,
    },
    /// A physical capability returned a different backend identity.
    #[error("campaign GC physical backend identity mismatch: expected {expected}, got {actual}")]
    BackendIdentityMismatch {
        /// Name configured by the maintenance owner.
        expected: String,
        /// Name authenticated by the inventory fence.
        actual: String,
    },
    /// A required source placement or its physical generation changed.
    #[error("campaign GC required-copy basis changed for {id} on backend {backend}")]
    RequiredCopyBasisChanged {
        /// Stable physical backend identifier.
        backend: String,
        /// Reachable object that must remain independently readable.
        id: crucible_cas::content_store::ContentId,
    },
    /// One logical root closure was unavailable or invalid.
    #[error(transparent)]
    Campaign(#[from] CampaignRepositoryError),
    /// A root or candidate manifest violated a bound or canonical rule.
    #[error(transparent)]
    Manifest(#[from] CampaignGcManifestError),
    /// The terminal plan header was inconsistent or unrepresentable.
    #[error(transparent)]
    Plan(#[from] CampaignGcPlanError),
}

#[cfg(target_os = "linux")]
fn inventory_hot_fallbacks<E>(
    hot_fallbacks: Option<&dyn HotCheckpointFallbackRetentionAdmin>,
    roots: &mut RootAccumulator,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let Some(hot_fallbacks) = hot_fallbacks else {
        return Ok(());
    };
    let mut fence = hot_fallbacks
        .acquire_hot_checkpoint_retention_fence()
        .map_err(CampaignGcPlanningError::HotFallback)?;
    fence
        .visit_roots(&mut |root| {
            roots
                .insert(root)
                .map_err(|()| HotCheckpointFallbackRetentionError::Visitor)
        })
        .map_err(CampaignGcPlanningError::HotFallback)?;
    Ok(())
}

fn map_root_inventory_error<E>(source: CampaignGcRootInventoryError) -> CampaignGcPlanningError<E>
where
    E: StdError + 'static,
{
    match source {
        CampaignGcRootInventoryError::Ref(source) => CampaignGcPlanningError::Ref(source),
        CampaignGcRootInventoryError::Campaign(source) => CampaignGcPlanningError::Campaign(source),
        CampaignGcRootInventoryError::ExactPin(source) => CampaignGcPlanningError::ExactPin(source),
        CampaignGcRootInventoryError::InvalidCampaignRef { name } => {
            CampaignGcPlanningError::InvalidCampaignRef { name }
        }
        CampaignGcRootInventoryError::InvalidArchiveRef { name } => {
            CampaignGcPlanningError::InvalidArchiveRef { name }
        }
        CampaignGcRootInventoryError::MissingExactPinMaterialization {
            campaign,
            configuration,
            pin_fact,
        } => CampaignGcPlanningError::MissingExactPinMaterialization {
            campaign,
            configuration,
            pin_fact,
        },
        CampaignGcRootInventoryError::Limit => {
            CampaignGcPlanningError::Manifest(CampaignGcManifestError::EntryLimit)
        }
    }
}

fn inventory_ledger<L>(
    ledger: &mut L,
    roots: &mut RootAccumulator,
) -> Result<AssignmentRetentionSummary, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    let mut fence = ledger
        .acquire_retention_fence()
        .map_err(CampaignGcPlanningError::Ledger)?;
    fence
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
                CampaignGcPlanningError::Ledger(source)
            }
            AssignmentRetentionInventoryError::Visitor(_) => CampaignGcPlanningError::LedgerVisitor,
        })
}

fn inventory_write_back<E>(
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    roots: &mut RootAccumulator,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let Some(write_back) = write_back else {
        return Ok(());
    };
    let mut fence = write_back
        .acquire_write_back_retention_fence()
        .map_err(CampaignGcPlanningError::WriteBack)?;
    fence
        .visit_roots(&mut |root| {
            // A journal entry owns one independently transferred object. It
            // may be an internal Merkle node whose ancestor path, and thus
            // root-relative depth, is intentionally absent here.
            roots
                .insert_direct(root.id())
                .map_err(|()| StoreError::Quota)
        })
        .map_err(CampaignGcPlanningError::WriteBack)?;
    Ok(())
}

fn inventory_transfers<E>(
    transfers: Option<&dyn CampaignTransferRetentionAdmin>,
    roots: &mut RootAccumulator,
) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    let Some(transfers) = transfers else {
        return Ok(());
    };
    let mut fence = transfers
        .acquire_campaign_transfer_retention_fence()
        .map_err(CampaignGcPlanningError::Transfer)?;
    fence
        .visit_roots(&mut |root| {
            roots
                .insert_direct(root.id())
                .map_err(|()| StoreError::Quota)
        })
        .map_err(CampaignGcPlanningError::Transfer)?;
    Ok(())
}

fn validate_physical_inputs(
    physical: &[CampaignGcPhysicalStore<'_>],
) -> Result<(), CampaignGcPlanError> {
    if physical.is_empty() || physical.len() > MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES {
        return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
    }
    if physical
        .windows(2)
        .any(|pair| pair[0].backend >= pair[1].backend)
    {
        return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
    }
    Ok(())
}
