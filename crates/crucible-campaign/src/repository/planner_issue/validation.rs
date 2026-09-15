//! Planner-issue validation state and authenticated bases.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum IssueProjectionMode {
    Preflight,
    Publish,
    Validate {
        target_exploration: ContentId,
        target_accounting: ContentId,
    },
}

impl IssueProjectionMode {
    pub(super) const fn publishes(self) -> bool {
        matches!(self, Self::Publish)
    }

    pub(super) const fn validates_import(self) -> bool {
        matches!(self, Self::Validate { .. })
    }
}

pub(super) struct IssueGeneratorValidation {
    pub(super) validated: BTreeSet<(
        CandidateGeneratorSpecId,
        ChoiceDomainId,
        Option<ProbabilityModelId>,
    )>,
    pub(super) remaining: usize,
}

pub(super) struct PlannerIssueAttemptBasis<'a> {
    pub(super) snapshot: &'a LoadedSnapshot,
    pub(super) lineage: &'a CampaignLineage,
    pub(super) request: &'a BranchRequest,
    pub(super) opportunity: &'a ChoiceOpportunity,
    pub(super) domain: &'a ChoiceDomain,
    pub(super) parent_path: &'a BranchPath,
}

#[derive(Clone, Copy)]
pub(super) struct PlannerIssueProposalBasis<'a> {
    pub(super) request: &'a BranchRequest,
    pub(super) domain: &'a ChoiceDomain,
    pub(super) feedback_projection: Option<&'a crate::BranchPuctProjection>,
}

impl IssueGeneratorValidation {
    pub(super) fn new() -> Self {
        Self {
            validated: BTreeSet::new(),
            remaining: MAX_ISSUE_GENERATOR_VALIDATION_OBJECTS,
        }
    }
}
