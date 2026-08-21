//! Generation-bound non-destructive GC planning for one single-host store graph.

use std::error::Error as StdError;

use crucible_campaign::{
    CampaignFactId, CampaignHash, CampaignName, CampaignRepository, CampaignRepositoryError,
    ConfigurationId,
};
use crucible_cas::content_store::{
    BlobStoreAdmin, RefStoreAdmin, StoreError, StoreGraphAdmin, StoreGraphPhysicalAdmin,
    WriteBackRetentionAdmin,
};
use thiserror::Error;

use crate::{
    AssignmentRetentionAdmin, AssignmentRetentionInventoryError, AssignmentRetentionRoot,
    AssignmentRetentionSummary, AssignmentRetentionVisitorError, ExactPinRetentionAdmin,
    ExactPinRetentionError,
};

use super::roots::{CampaignGcRootInventoryError, RootAccumulator, inventory_authoritative_refs};
use super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidate, CampaignGcCandidateManifest,
    CampaignGcManifestError, CampaignGcPlan, CampaignGcPlanError, CampaignGcRootManifest,
    MAX_CAMPAIGN_GC_MANIFEST_ENTRIES, MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES, validate_backend_id,
};

/// One named physical blob leaf and its separate inventory authority.
#[derive(Clone, Copy)]
pub struct CampaignGcPhysicalStore<'a> {
    backend: &'a str,
    admin: &'a dyn BlobStoreAdmin,
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
        Ok(Self { backend, admin })
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
        Self::new(physical.node().as_str(), physical.admin())
    }

    /// Returns the physical backend identifier.
    #[must_use]
    pub const fn backend(self) -> &'a str {
        self.backend
    }

    pub(super) const fn admin(self) -> &'a dyn BlobStoreAdmin {
        self.admin
    }
}

/// Complete non-destructive output of one single-host GC planning pass.
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

    /// Returns the exact physical placements found unreachable.
    #[must_use]
    pub const fn candidates(&self) -> &CampaignGcCandidateManifest {
        &self.candidates
    }

    /// Returns the number of unique authenticated reachable logical objects.
    #[must_use]
    pub const fn reachable_objects(&self) -> u64 {
        self.reachable_objects
    }
}

/// Builds a complete generation-bound deletion plan without mutating storage.
///
/// Ref, exact-pin selection, and assignment-ledger fences are used only long
/// enough to authenticate the exact root manifest and terminal generations.
/// Every fenced campaign ref is authenticated as a snapshot; each current
/// exact pin must resolve to a journal selection bound to its latest pin fact.
/// The repository then authenticates the union of those logical closures.
/// Finally each physical
/// leaf is inventoried under its own fence and every placement whose logical
/// ID is absent from the reachable union enters the candidate manifest.
/// `store_graph` supplies both the exact canonical graph identity and its
/// construction-time physical capabilities, so those bases cannot be mixed.
///
/// This operation deliberately does not delete. A later apply must reacquire
/// every fence, reproduce the root and physical generations, and additionally
/// exclude an in-flight campaign transaction across its children-before-ref
/// publication window and every pending write-back transfer through its
/// children-before-journal window. Omitting `exact_pins` is valid only when the
/// complete authoritative campaign inventory contains no current exact pin.
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
    plan_single_host_campaign_gc_with_physical(
        repository,
        refs,
        ledger,
        write_back,
        exact_pins,
        CampaignHash::from_bytes(store_graph.configuration_id().as_bytes()),
        &physical,
    )
}

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
    validate_physical_inputs(physical).map_err(CampaignGcPlanningError::Plan)?;

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
    inventory_write_back(write_back, &mut roots)?;
    let root_manifest = CampaignGcRootManifest::new(roots.unique.iter().copied())?;

    let reachable = repository
        .authenticated_closure_ids(root_manifest.iter())
        .map_err(CampaignGcPlanningError::Campaign)?;
    let reachable_objects = u64::try_from(reachable.len())
        .map_err(|_| CampaignGcPlanningError::Manifest(CampaignGcManifestError::EntryLimit))?;

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

    let candidate_manifest = CampaignGcCandidateManifest::new(candidates)?;
    let plan = CampaignGcPlan::new(
        store_graph,
        root_manifest.id(),
        ref_summary,
        ledger_summary,
        candidate_manifest.summary(),
        physical_basis,
    )?;
    Ok(CampaignGcPreparedPlan {
        plan,
        roots: root_manifest,
        candidates: candidate_manifest,
        reachable_objects,
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
    /// The exact-pin materialization journal could not be fenced or read.
    #[error("campaign GC exact-pin materialization inventory failed")]
    ExactPin(#[source] ExactPinRetentionError),
    /// An authoritative campaign ref had an invalid namespace or snapshot ID.
    #[error("campaign GC authoritative campaign ref is invalid: {name}")]
    InvalidCampaignRef {
        /// Exact invalid authoritative ref spelling.
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
        .visit_roots(&mut |root| roots.insert(root.id()).map_err(|()| StoreError::Quota))
        .map_err(CampaignGcPlanningError::WriteBack)?;
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
