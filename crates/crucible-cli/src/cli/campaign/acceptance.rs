//! Structured branch-acceptance counts and compact human rendering.

use crucible_campaign::{BranchAcceptanceCount, BranchAcceptanceSummary};
use serde::Serialize;

/// JSON projection of one exact count or inclusive bound.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(super) enum CampaignAcceptanceCountReport {
    /// The repository owner proved the exact count.
    Exact { count: u64 },
    /// The repository owner proved only inclusive bounds.
    Range { minimum: u64, maximum: u64 },
}

impl CampaignAcceptanceCountReport {
    pub(super) fn render(self) -> String {
        match self {
            Self::Exact { count } => count.to_string(),
            Self::Range { minimum, maximum } => format!("{minimum}..={maximum}"),
        }
    }
}

impl From<BranchAcceptanceCount> for CampaignAcceptanceCountReport {
    fn from(value: BranchAcceptanceCount) -> Self {
        match value {
            BranchAcceptanceCount::Exact(count) => Self::Exact { count },
            BranchAcceptanceCount::Range(range) => Self::Range {
                minimum: range.minimum(),
                maximum: range.maximum(),
            },
        }
    }
}

/// Machine-readable proposal and attempt limits for one request.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct CampaignBranchBudgetReport {
    pub(super) maximum_proposals: u64,
    pub(super) maximum_attempts: u64,
}

/// Flattened CAPI-12 branch-acceptance projection.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct CampaignBranchAcceptanceSummaryReport {
    pub(super) validated_cardinality: CampaignAcceptanceCountReport,
    pub(super) deduplicated_existing_edges: CampaignAcceptanceCountReport,
    pub(super) remaining_lazy_candidates: CampaignAcceptanceCountReport,
    pub(super) budget: CampaignBranchBudgetReport,
    pub(super) summary_provenance: &'static str,
}

impl CampaignBranchAcceptanceSummaryReport {
    pub(super) fn new(summary: BranchAcceptanceSummary, recorded: bool) -> Self {
        Self {
            validated_cardinality: summary.validated_cardinality().into(),
            deduplicated_existing_edges: summary.deduplicated_existing_edges().into(),
            remaining_lazy_candidates: summary.remaining_lazy_candidates().into(),
            budget: CampaignBranchBudgetReport {
                maximum_proposals: summary.maximum_proposals(),
                maximum_attempts: summary.maximum_attempts(),
            },
            summary_provenance: if recorded {
                "recorded"
            } else {
                "legacy-recomputed"
            },
        }
    }

    pub(super) fn human_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("validated_cardinality", self.validated_cardinality.render()),
            (
                "deduplicated_edges",
                self.deduplicated_existing_edges.render(),
            ),
            (
                "remaining_candidates",
                self.remaining_lazy_candidates.render(),
            ),
            (
                "maximum_proposals",
                self.budget.maximum_proposals.to_string(),
            ),
            ("maximum_attempts", self.budget.maximum_attempts.to_string()),
            ("summary_provenance", self.summary_provenance.to_owned()),
        ]
    }
}
