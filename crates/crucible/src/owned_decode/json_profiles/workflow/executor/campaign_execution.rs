//! Owns the required semantic work of the inline campaign coordinator.
//!
//! Planning allowances, scans, retention and grants are explicit operator
//! inputs. A grant describes a requested campaign command; only the retained
//! service policy may authorize it. No deadline or polling clock is created.
//!
//! ```json
//! {
//!   "planner": {"exhaustive": {"search": "breadthFirst"}},
//!   "planningBudget": {
//!     "branchRequests": 1, "proposals": 1, "inputObjects": 16384,
//!     "inputBytes": 33554432, "fuel": 4096
//!   },
//!   "plannerScanLimit": 100, "executorScanLimit": 100,
//!   "retention": "discard", "grant": {"proposals": 1, "attempts": 1}
//! }
//! ```

use serde::Deserialize;

/// Deserializes the complete required coordinator contract.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CampaignExecution {
    /// Selects the canonical planner matching the campaign's authored policy.
    pub planner: CampaignExecutionPlanner,
    /// Bounds one planner invocation independently of the campaign grant.
    pub planning_budget: CampaignExecutionPlanningBudget,
    /// Bounds one authenticated planner scan page.
    pub planner_scan_limit: u32,
    /// Bounds one authenticated executor accounting scan page.
    pub executor_scan_limit: usize,
    /// Selects exact checkpoint retention for an accepted execution.
    pub retention: CampaignExecutionRetention,
    /// Specifies the semantic allowance requested through the real authorizer.
    pub grant: CampaignExecutionGrant,
}

/// Deserializes the exact canonical planner family.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CampaignExecutionPlanner {
    /// Selects exhaustive frontier expansion using an explicit search order.
    Exhaustive {
        /// Specifies the complete canonical search strategy.
        search: CampaignExecutionSearch,
    },
    /// Selects the canonical PUCT implementation for tree-search policy.
    TreeSearch,
    /// Selects the canonical Beam implementation for Beam policy.
    Beam,
}

/// Deserializes the explicit canonical exhaustive search order.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CampaignExecutionSearch {
    /// Selects the shallowest prospective child first.
    BreadthFirst,
    /// Selects the deepest prospective child first.
    DepthFirst,
    /// Selects the canonical seeded priority score.
    Priority {
        /// Specifies the exact strategy-local seed, independently of campaign identity.
        seed: [u8; 32],
    },
}

/// Deserializes all five independent planner allowances.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CampaignExecutionPlanningBudget {
    /// Bounds branch requests in one planner invocation.
    pub branch_requests: u32,
    /// Bounds proposals in one planner invocation.
    pub proposals: u32,
    /// Bounds canonical input objects in one planner invocation.
    pub input_objects: u32,
    /// Bounds canonical input bytes in one planner invocation.
    pub input_bytes: u64,
    /// Bounds deterministic planner fuel in one invocation.
    pub fuel: u64,
}

/// Deserializes the exact checkpoint-retention intent.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CampaignExecutionRetention {
    /// Selects no exact closure retained solely for the assignment.
    Discard,
    /// Selects exact retention only after a modeled failure.
    RetainOnFailure,
    /// Selects exact retention after every completed execution.
    RetainAlways,
}

/// Deserializes an explicitly requested semantic campaign allowance.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CampaignExecutionGrant {
    /// Specifies additional campaign proposals requested from the real authorizer.
    pub proposals: u64,
    /// Specifies additional semantic attempts requested from the real authorizer.
    pub attempts: u64,
}
