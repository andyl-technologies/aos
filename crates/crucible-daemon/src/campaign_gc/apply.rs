//! Exact-generation destructive apply for one journaled single-host GC plan.

use std::error::Error as StdError;

use crucible_campaign::{
    CampaignFactId, CampaignName, CampaignRepository, CampaignRepositoryError, ConfigurationId,
};
use crucible_cas::content_store::{
    BlobInventoryFence, PlannedDeleteDisposition, RefStoreAdmin, StoreError, StoreGraphAdmin,
    WriteBackRetentionAdmin,
};
use thiserror::Error;

use crate::{
    AssignmentRetentionAdmin, AssignmentRetentionInventoryError, AssignmentRetentionRoot,
    AssignmentRetentionVisitorError, ExactPinRetentionAdmin, ExactPinRetentionError,
};

use super::roots::{CampaignGcRootInventoryError, RootAccumulator, inventory_authoritative_refs};
use super::{
    CampaignGcBlobInventoryBasis, CampaignGcCandidateManifest, CampaignGcJournalError,
    CampaignGcJournalPhase, CampaignGcManifestError, CampaignGcPhysicalStore, CampaignGcPlanError,
    CampaignGcRootManifest, DirectoryCampaignGcJournal, MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES,
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

    /// Returns the exact planned logical bytes across those placements.
    #[must_use]
    pub const fn logical_bytes(self) -> u64 {
        self.logical_bytes
    }
}

/// Revalidates and destructively applies one exact journaled single-host plan.
///
/// Apply acquires fences in the fixed order ref publication/namespace,
/// exact-pin selections, ledger, pending write-back transfers, then physical
/// leaves in canonical backend order. It reproduces the exact ref, current
/// exact-pin roots, ledger, root-manifest, and every
/// physical-inventory basis before durably entering `Applying`. Root fences
/// remain held throughout. Each physical leaf is then reacquired, revalidated
/// against the same plan, and retained through its candidate deletions. This
/// sequential second pass avoids deadlock if a misconfigured store graph aliases
/// one physical lock.
/// The construction-time `store_graph` capability supplies both the graph
/// identity and every physical leaf; independently supplied graph hashes or
/// deletion capabilities are not accepted by this public boundary.
/// Omitting `exact_pins` is valid only when the complete authoritative campaign
/// inventory contains no current exact pin.
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

pub(crate) struct CampaignGcApplySources<'repository, 'refs, 'ledger, 'write_back, 'exact, L> {
    repository: &'repository CampaignRepository,
    refs: &'refs dyn RefStoreAdmin,
    ledger: &'ledger mut L,
    write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
    exact_pins: Option<&'exact mut dyn ExactPinRetentionAdmin>,
}

impl<'repository, 'refs, 'ledger, 'write_back, 'exact, L>
    CampaignGcApplySources<'repository, 'refs, 'ledger, 'write_back, 'exact, L>
{
    pub(crate) const fn new(
        repository: &'repository CampaignRepository,
        refs: &'refs dyn RefStoreAdmin,
        ledger: &'ledger mut L,
        write_back: Option<&'write_back dyn WriteBackRetentionAdmin>,
        exact_pins: Option<&'exact mut dyn ExactPinRetentionAdmin>,
    ) -> Self {
        Self {
            repository,
            refs,
            ledger,
            write_back,
            exact_pins,
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
        exact_pins,
    } = sources;
    let summary = journal.plan().candidates();
    if journal.phase() == CampaignGcJournalPhase::Complete {
        return Ok(CampaignGcApplyReport {
            status: CampaignGcApplyStatus::AlreadyComplete,
            candidates: summary.candidates(),
            logical_bytes: summary.logical_bytes(),
        });
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
    let mut write_back_fence = write_back
        .map(WriteBackRetentionAdmin::acquire_write_back_retention_fence)
        .transpose()
        .map_err(CampaignGcApplyError::WriteBack)?;

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
    if let Some(fence) = write_back_fence.as_mut() {
        fence
            .visit_roots(&mut |root| roots.insert(root.id()).map_err(|()| StoreError::Quota))
            .map_err(CampaignGcApplyError::WriteBack)?;
    }
    let current_roots = CampaignGcRootManifest::new(roots.unique.iter().copied())?;
    if current_roots != *journal.roots() {
        return Err(CampaignGcApplyError::RootSetChanged);
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

    journal.begin_apply()?;
    for (target, planned) in physical.iter().zip(journal.plan().physical()) {
        let mut fence = target.admin().acquire_inventory_fence().map_err(|source| {
            CampaignGcApplyError::Blob {
                backend: target.backend().to_owned(),
                source,
            }
        })?;
        validate_physical_inventory(target, planned, journal.candidates(), fence.as_mut())?;
        for candidate in journal.candidates().for_backend(target.backend()) {
            match fence.delete_candidate(candidate.id()).map_err(|source| {
                CampaignGcApplyError::Blob {
                    backend: target.backend().to_owned(),
                    source,
                }
            })? {
                PlannedDeleteDisposition::Deleted => {}
                PlannedDeleteDisposition::AlreadyAbsent => {
                    return Err(CampaignGcApplyError::CandidateSetChanged {
                        backend: target.backend().to_owned(),
                    });
                }
            }
        }
    }
    journal.mark_complete()?;
    Ok(CampaignGcApplyReport {
        status: CampaignGcApplyStatus::Applied,
        candidates: summary.candidates(),
        logical_bytes: summary.logical_bytes(),
    })
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
