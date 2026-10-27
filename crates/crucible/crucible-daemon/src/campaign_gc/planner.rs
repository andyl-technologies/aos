//! Generation-bound non-destructive GC planning for one single-host store graph.
//!
//! Planning never holds a complete root, closure, or inventory set in memory.
//! Roots are classified through one external sort, the authenticated closure
//! streams into a second, and [`physical`] merges each leaf's sorted
//! placements against them. Every scratch file lives in one private work
//! directory inside the caller's `spill_parent`; the prepared plan's manifest
//! handles keep it alive, and it is removed when they and every error path
//! drop it.

mod physical;

use std::error::Error as StdError;
use std::io;
use std::path::Path;

use crucible_campaign::{
    CampaignFactId, CampaignHash, CampaignName, CampaignRepository, CampaignRepositoryError,
    ConfigurationId,
};
use crucible_store::content_store::{
    BlobStoreAdmin, RefStoreAdmin, StoreError, StoreGraphAdmin, StoreGraphPhysicalAdmin,
    WriteBackRetentionAdmin,
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
use super::roots::{
    CampaignGcRootInventoryError, ReachabilityError, RootAccumulator, RootClassificationError,
    authenticated_reachable, inventory_authoritative_refs,
};
use super::spill::create_work_directory;
use super::{
    CampaignGcCandidateManifest, CampaignGcManifestError, CampaignGcPlan, CampaignGcPlanError,
    CampaignGcRetentionSources, CampaignGcRootManifest, MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES,
    validate_backend_id,
};
#[cfg(test)]
use physical::plan_unreachable_physical;
use physical::{PhysicalPlanningInputs, PlannedPhysical, plan_policy_aware_physical};

/// One named physical blob leaf and its separate inventory authority.
#[derive(Clone, Copy)]
pub(super) struct CampaignGcPhysicalStore<'a> {
    graph: StoreGraphPhysicalAdmin<'a>,
}

impl<'a> CampaignGcPhysicalStore<'a> {
    /// Binds one physical leaf borrowed from a separately held graph admin.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcPlanError::InvalidBackendId`] if the admitted graph
    /// node ID violates the canonical GC backend identifier grammar.
    pub(super) fn from_graph_leaf(
        physical: StoreGraphPhysicalAdmin<'a>,
    ) -> Result<Self, CampaignGcPlanError> {
        validate_backend_id(physical.node().as_str())?;
        Ok(Self { graph: physical })
    }

    /// Returns the physical backend identifier.
    #[must_use]
    pub(super) fn backend(self) -> &'a str {
        self.graph.node().as_str()
    }

    pub(super) const fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.graph.admin()
    }

    pub(super) const fn graph(self) -> StoreGraphPhysicalAdmin<'a> {
        self.graph
    }
}

pub(super) trait CampaignGcInventoryTarget<'a>: Copy {
    fn backend(self) -> &'a str;

    fn admin(self) -> &'a dyn BlobStoreAdmin;
}

impl<'a> CampaignGcInventoryTarget<'a> for CampaignGcPhysicalStore<'a> {
    fn backend(self) -> &'a str {
        self.backend()
    }

    fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin()
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct CampaignGcRawPhysicalStore<'a> {
    backend: &'a str,
    admin: &'a dyn BlobStoreAdmin,
}

#[cfg(test)]
impl<'a> CampaignGcRawPhysicalStore<'a> {
    pub(super) fn new(
        backend: &'a str,
        admin: &'a dyn BlobStoreAdmin,
    ) -> Result<Self, CampaignGcPlanError> {
        validate_backend_id(backend)?;
        Ok(Self { backend, admin })
    }

    pub(super) const fn backend(self) -> &'a str {
        self.backend
    }

    pub(super) const fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin
    }
}

#[cfg(test)]
impl<'a> CampaignGcInventoryTarget<'a> for CampaignGcRawPhysicalStore<'a> {
    fn backend(self) -> &'a str {
        self.backend()
    }

    fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin()
    }
}

/// Complete non-destructive output of one single-host GC planning pass.
///
/// The root and candidate manifests are handles to files in the planner's
/// private work directory, which stays on disk until this plan and every
/// manifest handle cloned from it are dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcPreparedPlan {
    plan: CampaignGcPlan,
    roots: CampaignGcRootManifest,
    candidates: CampaignGcCandidateManifest,
    reachable_objects: u64,
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
        self.candidates.unreachable_candidates()
    }

    /// Returns reachable cache placements authorized by current policy.
    #[must_use]
    pub const fn reachable_cache_candidates(&self) -> u64 {
        self.candidates.reachable_cache_candidates()
    }

    #[cfg(test)]
    pub(super) fn with_candidate_manifest_for_test(
        mut self,
        candidates: CampaignGcCandidateManifest,
    ) -> Self {
        self.plan.candidates = candidates.summary();
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
/// placements enter every candidate manifest. A reachable cache
/// placement enters the manifest only when a physically independent required
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
/// pool exists; /// configured pools must use
/// `plan_single_host_campaign_gc_with_hot_checkpoints` on Linux.
///
/// Root, closure, and inventory sets are sorted externally in a private
/// directory created inside `spill_parent`, which must be an existing
/// directory on persistent storage, never a memory-backed file system. The
/// directory is removed on every error and once the returned plan is dropped.
///
/// # Errors
///
/// Returns [`CampaignGcPlanningError`] if any administrative inventory is
/// incomplete, a root closure is missing or invalid, a manifest bound is
/// exceeded, a physical inventory lists one object twice, physical backend
/// identities are inconsistent, scratch storage fails, or the terminal plan
/// cannot be represented canonically. Visitor prefixes are discarded on every
/// error.
pub fn plan_single_host_campaign_gc<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
    spill_parent: &Path,
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
        CampaignGcPlanningRoots {
            write_back,
            retention: CampaignGcRetentionSources::without_hot_checkpoints(exact_pins),
        },
        CampaignGcPlanningScope {
            store_graph: CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
            physical: &physical,
            spill_parent,
        },
        plan_policy_aware_physical,
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
/// Scratch storage follows the same `spill_parent` rules.
// crucible-lint: allow rust-allow -- GC planning keeps each store, root source, and scratch path explicit.
#[allow(clippy::too_many_arguments)]
pub fn plan_single_host_campaign_gc_with_transfers<'a, L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    transfers: &'a dyn CampaignTransferRetentionAdmin,
    exact_pins: Option<&'a mut dyn ExactPinRetentionAdmin>,
    store_graph: &StoreGraphAdmin,
    spill_parent: &Path,
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
        CampaignGcPlanningRoots {
            write_back,
            retention: CampaignGcRetentionSources::with_transfers(exact_pins, transfers),
        },
        CampaignGcPlanningScope {
            store_graph: CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
            physical: &physical,
            spill_parent,
        },
        plan_policy_aware_physical,
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
/// catalog cannot provide a complete authenticated inventory. Scratch storage
/// follows the same `spill_parent` rules.
#[cfg(target_os = "linux")]
pub fn plan_single_host_campaign_gc_with_hot_checkpoints<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    roots: CampaignGcHotCheckpointRoots<'_>,
    store_graph: &StoreGraphAdmin,
    spill_parent: &Path,
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
        CampaignGcPlanningRoots {
            write_back,
            retention: roots.into_sources(),
        },
        CampaignGcPlanningScope {
            store_graph: CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
            physical: &physical,
            spill_parent,
        },
        plan_policy_aware_physical,
    )
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- GC planning keeps each store, root source, and scratch path explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_single_host_campaign_gc_with_physical<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&mut dyn ExactPinRetentionAdmin>,
    store_graph: CampaignHash,
    physical: &[CampaignGcRawPhysicalStore<'_>],
    spill_parent: &Path,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        CampaignGcPlanningRoots {
            write_back,
            retention: CampaignGcRetentionSources::without_hot_checkpoints(exact_pins),
        },
        CampaignGcPlanningScope {
            store_graph,
            physical,
            spill_parent,
        },
        plan_unreachable_physical,
    )
}

#[cfg(all(test, target_os = "linux"))]
// crucible-lint: allow rust-allow -- GC planning keeps each store, root source, and scratch path explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_single_host_campaign_gc_with_physical_and_hot_checkpoints<L>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    write_back: Option<&dyn WriteBackRetentionAdmin>,
    root_sources: CampaignGcHotCheckpointRoots<'_>,
    store_graph: CampaignHash,
    physical: &[CampaignGcRawPhysicalStore<'_>],
    spill_parent: &Path,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
{
    plan_single_host_campaign_gc_with_physical_and_root_sources(
        repository,
        refs,
        ledger,
        CampaignGcPlanningRoots {
            write_back,
            retention: root_sources.into_sources(),
        },
        CampaignGcPlanningScope {
            store_graph,
            physical,
            spill_parent,
        },
        plan_unreachable_physical,
    )
}

/// Store graph, physical leaves, and scratch location for one planning pass.
struct CampaignGcPlanningScope<'scope, P> {
    store_graph: CampaignHash,
    physical: &'scope [P],
    spill_parent: &'scope Path,
}

struct CampaignGcPlanningRoots<'write_back, 'retention> {
    write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
    retention: CampaignGcRetentionSources<'retention>,
}

fn plan_single_host_campaign_gc_with_physical_and_root_sources<'a, L, P, F>(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    ledger: &mut L,
    roots: CampaignGcPlanningRoots<'_, '_>,
    scope: CampaignGcPlanningScope<'_, P>,
    plan_physical: F,
) -> Result<CampaignGcPreparedPlan, CampaignGcPlanningError<L::Error>>
where
    L: AssignmentRetentionAdmin,
    L::Error: StdError + Send + Sync + 'static,
    P: CampaignGcInventoryTarget<'a>,
    F: FnOnce(
        &[P],
        PhysicalPlanningInputs<'_>,
    ) -> Result<PlannedPhysical, CampaignGcPlanningError<L::Error>>,
{
    let CampaignGcPlanningScope {
        store_graph,
        physical,
        spill_parent,
    } = scope;
    validate_physical_inputs(physical).map_err(CampaignGcPlanningError::Plan)?;
    let CampaignGcPlanningRoots {
        write_back,
        retention: root_sources,
    } = roots;
    let exact_pins = root_sources.exact_pins;
    let directory = create_work_directory(spill_parent).map_err(CampaignGcPlanningError::Spill)?;

    let mut roots = RootAccumulator::new(&directory);
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
    let classified = roots
        .finish(&directory)
        .map_err(map_root_classification_error)?;

    let reachable = authenticated_reachable(repository, &classified, &directory)
        .map_err(map_reachability_error)?;
    let planned = plan_physical(
        physical,
        PhysicalPlanningInputs {
            directory: &directory,
            reachable: &reachable,
            pending_write_back: &classified.pending_write_back,
        },
    )?;

    let plan = CampaignGcPlan::new(
        store_graph,
        classified.manifest.id(),
        ref_summary,
        ledger_summary,
        planned.candidates.summary(),
        planned.physical_basis,
    )?;
    Ok(CampaignGcPreparedPlan {
        plan,
        roots: classified.manifest,
        candidates: planned.candidates,
        reachable_objects: reachable.records(),
    })
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
        id: crucible_store::content_store::ContentId,
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
    /// Private scratch storage for external sorting failed.
    #[error("campaign GC scratch storage failed")]
    Spill(#[source] io::Error),
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
    let visited = fence.visit_roots(&mut |root| {
        roots
            .insert(root)
            .map_err(|()| HotCheckpointFallbackRetentionError::Visitor)
    });
    take_root_spill_error(roots)?;
    visited.map_err(CampaignGcPlanningError::HotFallback)?;
    Ok(())
}

fn map_root_inventory_error<E>(source: CampaignGcRootInventoryError) -> CampaignGcPlanningError<E>
where
    E: StdError + 'static,
{
    match source {
        CampaignGcRootInventoryError::Spill(source) => CampaignGcPlanningError::Spill(source),
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

fn map_root_classification_error<E>(source: RootClassificationError) -> CampaignGcPlanningError<E>
where
    E: StdError + 'static,
{
    match source {
        RootClassificationError::Spill(source) => CampaignGcPlanningError::Spill(source),
        RootClassificationError::Manifest(source) => CampaignGcPlanningError::Manifest(source),
    }
}

fn map_reachability_error<E>(source: ReachabilityError) -> CampaignGcPlanningError<E>
where
    E: StdError + 'static,
{
    match source {
        ReachabilityError::Spill(source) => CampaignGcPlanningError::Spill(source),
        ReachabilityError::Campaign(source) => CampaignGcPlanningError::Campaign(source),
    }
}

/// Reports a root spill failure in place of the visitor error it caused.
fn take_root_spill_error<E>(roots: &mut RootAccumulator) -> Result<(), CampaignGcPlanningError<E>>
where
    E: StdError + 'static,
{
    roots
        .take_spill_error()
        .map_or(Ok(()), |source| Err(CampaignGcPlanningError::Spill(source)))
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
    let visited = fence.visit_roots(&mut |root| {
        let id = match root {
            AssignmentRetentionRoot::Observation(observation) => observation.content_id(),
            AssignmentRetentionRoot::ExactCheckpoint(checkpoint) => checkpoint.content_id(),
            AssignmentRetentionRoot::FindingCandidate(candidate) => candidate.content_id(),
        };
        roots
            .insert(id)
            .map_err(|()| AssignmentRetentionVisitorError::LimitExceeded)
    });
    take_root_spill_error(roots)?;
    visited.map_err(|source| match source {
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
    let visited = fence.visit_roots(&mut |root| {
        // A journal entry owns one independently transferred object. It
        // may be an internal Merkle node whose ancestor path, and thus
        // root-relative depth, is intentionally absent here.
        roots
            .insert_pending_write_back(root.id())
            .map_err(|()| StoreError::Quota)
    });
    take_root_spill_error(roots)?;
    visited.map_err(CampaignGcPlanningError::WriteBack)?;
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
    let visited = fence.visit_roots(&mut |root| {
        roots
            .insert_direct(root.id())
            .map_err(|()| StoreError::Quota)
    });
    take_root_spill_error(roots)?;
    visited.map_err(CampaignGcPlanningError::Transfer)?;
    Ok(())
}

fn validate_physical_inputs<'a, P>(physical: &[P]) -> Result<(), CampaignGcPlanError>
where
    P: CampaignGcInventoryTarget<'a>,
{
    if physical.is_empty() || physical.len() > MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES {
        return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
    }
    if physical
        .windows(2)
        .any(|pair| pair[0].backend() >= pair[1].backend())
    {
        return Err(CampaignGcPlanError::InvalidPhysicalInventoryCount);
    }
    Ok(())
}
