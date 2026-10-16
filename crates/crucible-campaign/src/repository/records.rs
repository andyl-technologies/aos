//! Strict campaign record publication, loading, and cross-record validation.

use super::projection::PlannerCandidateProjectionCache;
use super::*;
use crate::IntegerValue;

/// Scenario definition and artifact shared by every link of an attempt chain.
type AttemptLineage = (ScenarioDefId, ScenarioArtifactId);

/// Links one cold continuation-chain validation may add to the attempt cache.
///
/// Kept well below the cache capacity so one long chain cannot flush every
/// other entry; cache hits extend a validated chain one origin at a time
/// beyond this prefix.
pub(super) const MAX_ATTEMPT_CHAIN_CACHE_FILL: usize = MAX_CHOICE_VALIDATION_CACHE_ENTRIES / 4;

fn charge_selection_resolution_record(
    envelope: &ObjectEnvelope,
    canonical_bytes: usize,
    charged: &mut BTreeSet<ContentId>,
    charged_bytes: &mut usize,
    maximum_canonical_bytes: usize,
) -> Result<(), CampaignRepositoryError> {
    if !charged.insert(envelope.content_id()) {
        return Ok(());
    }
    *charged_bytes =
        charged_bytes
            .checked_add(canonical_bytes)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "selection resolution byte accounting overflow",
            })?;
    if *charged_bytes > maximum_canonical_bytes {
        return Err(CampaignRepositoryError::SelectionResolutionBudgetExceeded {
            maximum_canonical_bytes,
        });
    }
    Ok(())
}

mod admission;
mod branch;
mod choice;
mod load;
mod observation;
mod planner;
mod storage;
