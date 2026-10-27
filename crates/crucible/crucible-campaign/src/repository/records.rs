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

mod admission;
mod branch;
mod choice;
mod load;
mod observation;
mod planner;
mod storage;
