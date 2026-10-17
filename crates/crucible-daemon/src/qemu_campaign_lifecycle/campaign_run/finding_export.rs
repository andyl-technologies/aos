//! Preserves the original final-snapshot finding-export source path.
//!
//! Checked campaign transcripts live in the neutral owner. Original public proof
//! aliases and error identities remain unchanged; this path grants no native
//! execution or checkpoint materialization authority.

use crucible_campaign::{CampaignName, CampaignPrincipal, CampaignSnapshotId};

pub(crate) use crate::campaign_finding_export::FindingExportClient;
pub use crate::campaign_finding_export::{
    GuardedCampaignFindingExport, GuardedCampaignFindingObjectProof,
    GuardedCampaignFindingOccurrenceObjectProof, GuardedCampaignFindingOccurrenceProof,
    GuardedCampaignFindingProof, GuardedCampaignFindingQueryProof,
    GuardedCampaignFindingTriageReplayProof, GuardedCampaignFindingTriageReplaySegmentProof,
    GuardedCampaignFindingTriageReplaySet,
};

#[cfg(test)]
pub(crate) use crate::campaign_finding_export::retained_response_material;

/// Delegates original final-snapshot capture without changing its error type.
///
/// # Errors
///
/// Returns the original checked-client, cancellation, finite-budget, or proof
/// validation failure from the neutral capture owner.
pub(super) fn capture_final_finding_export<C, E>(
    client: &C,
    principal: &CampaignPrincipal,
    campaign: &CampaignName,
    snapshot: CampaignSnapshotId,
    cancellation: &crate::ExecutionCancellation,
) -> Result<GuardedCampaignFindingExport, crate::GuardedDefaultCampaignRunError<E>>
where
    C: FindingExportClient,
    E: std::error::Error + 'static,
{
    crate::campaign_finding_export::capture_final_finding_export(
        client,
        principal,
        campaign,
        snapshot,
        cancellation,
    )
}
