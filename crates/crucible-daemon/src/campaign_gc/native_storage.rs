//! Storage-only native qualification using the existing fenced GC algorithm.
//!
//! The caller supplies the actual quota-wrapped physical and reference admins,
//! original Directory ledger, and the same finite Service operation throughout
//! planning, durable journal publication, and apply. This grants no guest-state
//! or deployment paging qualification.

use std::path::Path;

use crucible_campaign::{CampaignHash, CampaignRepository};
use crucible_cas::content_store::{BlobStoreAdmin, RefStoreAdmin};

use super::*;
use crate::{AssignmentLedgerError, DirectoryAssignmentLedger};

/// Original failures from the shared storage-only qualification algorithm.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeStorageGcError {
    #[error(transparent)]
    Plan(#[from] CampaignGcPlanError),
    #[error(transparent)]
    Planning(#[from] CampaignGcPlanningError<AssignmentLedgerError>),
    #[error(transparent)]
    Journal(#[from] CampaignGcJournalError),
    #[error(transparent)]
    Apply(#[from] CampaignGcApplyError<AssignmentLedgerError>),
    #[error("storage qualification GC journal did not complete its exact batch")]
    Incomplete,
}

pub(crate) fn collect_one_batch(
    repository: &CampaignRepository,
    refs: &dyn RefStoreAdmin,
    blobs: &dyn BlobStoreAdmin,
    ledger: &mut DirectoryAssignmentLedger,
    operation: &CampaignGcOperationContext<'_>,
    journal_root: &Path,
) -> Result<(u64, u64), NativeStorageGcError> {
    let backend = repository.blob_backend();
    let physical = CampaignGcRawPhysicalStore::new(backend.name(), blobs)?;
    let graph = CampaignHash::derive(
        "crucible.storage-scale.physical-graph.v1",
        backend.name().as_bytes(),
    );
    let planned = plan_single_host_campaign_gc_with_physical(
        repository,
        refs,
        ledger,
        None,
        None,
        graph,
        (&[physical], operation),
    )?;
    let reachable = planned.reachable_objects();
    let candidates = planned.candidates().len() as u64;
    let (mut journal, _) = DirectoryCampaignGcJournal::create(journal_root, &planned, operation)?;
    let report = apply_single_host_campaign_gc_with_physical(
        &mut journal,
        apply::CampaignGcApplySources::new(repository, refs, ledger, None, None),
        graph,
        &[physical],
        operation,
    )?;
    if report.candidates() != candidates || journal.phase() != CampaignGcJournalPhase::Complete {
        return Err(NativeStorageGcError::Incomplete);
    }
    Ok((reachable, report.candidates()))
}
