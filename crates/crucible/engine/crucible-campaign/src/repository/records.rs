//! Strict campaign record publication, loading, and cross-record validation.

use super::projection::PlannerCandidateProjectionCache;
use super::*;
use crate::IntegerValue;

const MAX_AFTER_ATTEMPT_ORIGIN_DEPTH: usize = 4096;

type PendingAttemptContinuation = (ContentId, Attempt, (ScenarioDefId, ScenarioArtifactId));

fn cache_attempt_continuation_prefix(
    cache: &mut ChoiceValidationCache,
    requested: ContentId,
    pending: Vec<PendingAttemptContinuation>,
    mut validated: ValidatedAttempt,
) -> Result<Attempt, CampaignRepositoryError> {
    for (id, attempt, lineage) in pending.into_iter().rev() {
        if lineage != validated.lineage {
            return Err(integrity("attempt-continuation-lineage-mismatch"));
        }
        let origin_depth = validated
            .origin_depth
            .checked_add(1)
            .ok_or_else(|| integrity("attempt-continuation-origin-depth-exceeded"))?;
        if origin_depth > MAX_AFTER_ATTEMPT_ORIGIN_DEPTH {
            return Err(integrity("attempt-continuation-origin-depth-exceeded"));
        }

        validated = ValidatedAttempt {
            attempt,
            path: validated.path,
            lineage,
            origin_depth,
        };
        cache.validated_attempts.insert(id, validated.clone());
    }

    if validated.attempt.id()?.content_id() != requested {
        return Err(integrity("attempt-continuation-cache-root-mismatch"));
    }
    Ok(validated.attempt)
}

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
