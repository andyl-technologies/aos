//! Canonical branch requests, proposals, attempts, and lazy expansion state.
//!
//! These records are portable data interpreted by the campaign coordinator and
//! pure planner. They never contain executable closures, native continuations,
//! daemon reservations, worker handles, or materialization locations.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    AdmissionOrdinal, AttemptAdmissionId, AttemptId, BranchEdgeId, BranchPathId, BranchPointId,
    BranchRequestId, CampaignCodecError, CampaignCommandId, CampaignPolicyId, CampaignSnapshotId,
    CampaignViewId, CandidateGeneratorSpecId, ChoiceDomain, ChoiceDomainId, ChoiceOpportunity,
    ChoiceOpportunityId, ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId,
    DebugSessionId, ExpansionStateId, PlannerEngineId, PlannerInvocationId, PlannerState,
    PlannerStateId, PlannerStepId, PolicyArtifactId, ProposalId, SelectionId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const PLANNER_STEP_SCHEMA_VERSION: u32 = 3;
const EXPANSION_STATE_SCHEMA_VERSION: u32 = 2;
const MAX_FINITE_VALUES: usize = 4096;
const MAX_BRANCH_PATH_EDGES: usize = 65_536;
const MAX_STEP_BRANCH_REQUESTS: usize = 4096;
const MAX_STEP_PROPOSALS: usize = 4096;
const MAX_GUIDANCE_TERMS: usize = 4096;
const MAX_CONTINUATIONS: usize = 65_536;
const MAX_EXPANSION_PAGE_ITEMS: usize = 10_000;
const MAX_EXACT_RECORD_BYTES: usize = 32 * 1024 * 1024;

mod attempt;
mod planner;
mod projection;
mod proposal;
mod request;

pub use attempt::*;
pub use planner::*;
pub use projection::*;
pub use proposal::*;
pub use request::*;

fn add_cause_child(children: &mut Vec<(String, ContentId)>, cause: BranchRequestCause) {
    match cause {
        BranchRequestCause::Planner(invocation) => {
            children.push(("planner-invocation".to_owned(), invocation.content_id()));
        }
        BranchRequestCause::ExhaustivePolicy(policy) => {
            children.push(("policy".to_owned(), policy.content_id()));
        }
        BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
    }
}

fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    require_schema_version(actual, RECORD_SCHEMA_VERSION)
}

fn require_schema_version(actual: u32, expected: u32) -> Result<(), CampaignCodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported exploration record schema version",
        })
    }
}

fn decode_exact_record<T: Canonical>(
    bytes: &[u8],
    limit: &'static str,
) -> Result<T, CampaignCodecError> {
    if bytes.len() > MAX_EXACT_RECORD_BYTES {
        return Err(CampaignCodecError::LimitExceeded { limit });
    }

    codec::decode(bytes)
}
