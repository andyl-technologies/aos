//! Closed contracts for bounded, provider-neutral package repair.
//!
//! The controller constructs [`AgentTaskV1`] from trusted run state and treats
//! [`AgentResultV1`] as untrusted input. Neither contract grants authority to
//! select releases, mutate Git, accept candidates, or decide gate outcomes.

use std::path::Path;

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::envelope::GitObjectId;
use crate::identity::{PlanId, RunId, UnitId};
use crate::inventory::RiskLevel;

/// Maximum UTF-8 patch bytes accepted from one agent response.
pub const MAX_AGENT_PATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum retained prose bytes accepted from one agent response.
pub const MAX_AGENT_EXPLANATION_BYTES: usize = 32 * 1024;

/// Classifies a trusted failure presented to a repair agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairFailureKind {
    /// A downstream patch no longer applies.
    PatchApply,
    /// Package compilation or linking failed.
    PackageBuild,
    /// A package-specific test failed.
    PackageTest,
}

/// Carries one bounded, controller-observed repair failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RepairFailure {
    /// Typed failure class determining agent eligibility.
    pub kind: RepairFailureKind,
    /// Planned gate identity when the failure came from a gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
    /// Digest of the complete retained controller log.
    pub log_digest: Sha256Digest,
    /// Sanitized UTF-8 excerpt, bounded independently from the full log.
    pub excerpt: String,
}

/// Identifies one file copied into the disposable agent view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentContextFile {
    /// Repository-relative path in the disposable view.
    pub path: String,
    /// Digest of the exact bytes supplied to the worker.
    pub digest: Sha256Digest,
    /// File size in bytes.
    pub bytes: u64,
    /// Whether a returned patch may modify this path.
    pub writable: bool,
}

/// Enumerates typed operations the agent may request from the controller.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentOperation {
    /// Read a file already present in the disposable view.
    ReadContext,
    /// Search text within approved context paths.
    SearchContext,
    /// Return one unified textual patch.
    ProposePatch,
    /// Ask the controller to run the package's immutable quick gates.
    RequestQuickGate,
    /// Ask the maintainer to approve additional readable or writable scope.
    RequestScope,
    /// Stop with a bounded question for the maintainer.
    AskMaintainer,
}

/// Fixes resource limits for one model invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentBudget {
    /// Attempts remaining including this invocation.
    pub remaining_attempts: u32,
    /// Maximum wall time for the worker process.
    pub wall_seconds: u64,
    /// Maximum complete stdout bytes accepted from the adapter.
    pub output_bytes: u64,
    /// Maximum patch bytes inside the result.
    pub patch_bytes: u64,
    /// Optional provider token ceiling passed as data, never trusted usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_limit: Option<u64>,
}

/// Gives a local adapter one closed repair problem and no policy authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentTaskV1 {
    /// Selects the exact task schema.
    pub schema: String,
    /// Durable run receiving a potential repair attempt.
    pub run_id: RunId,
    /// Immutable plan constraining the repair.
    pub plan_id: PlanId,
    /// Attempt that the proposed patch would create.
    pub attempt: u32,
    /// Exact plan base commit.
    pub base_commit: GitObjectId,
    /// Exact current worktree HEAD commit.
    pub head_commit: GitObjectId,
    /// Digest of the complete current candidate tree state.
    pub tree_digest: Sha256Digest,
    /// Update unit being repaired.
    pub unit_id: UnitId,
    /// Already selected package target; the agent cannot change it.
    pub target_version: String,
    /// Risk floor fixed by package policy.
    pub risk: RiskLevel,
    /// Controller-observed eligible failure.
    pub failure: RepairFailure,
    /// Complete file manifest copied into the disposable view.
    pub context: Vec<AgentContextFile>,
    /// Typed operations the adapter may request.
    pub allowed_operations: Vec<AgentOperation>,
    /// Exact paths an accepted patch may modify.
    pub writable_paths: Vec<String>,
    /// Immutable quick gates required after any accepted proposal.
    pub required_gate_ids: Vec<String>,
    /// Invocation resource limits.
    pub budget: AgentBudget,
    /// Explicitly marks all upstream text and logs as untrusted data.
    pub untrusted_data: bool,
}

impl AgentTaskV1 {
    /// Validates identities, context scope, operations, and budgets.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible schema, unsafe or duplicate paths,
    /// malformed failure data, incomplete authority limits, or invalid budget.
    pub fn validate(&self) -> Result<()> {
        if self.schema != crate::PACKAGE_UPDATE_AGENT_TASK_V1
            || self.attempt == 0
            || self.target_version.is_empty()
            || self.target_version.len() > 512
            || !self.untrusted_data
        {
            bail!("repair-agent task header is invalid");
        }
        self.base_commit.validate()?;
        self.head_commit.validate()?;
        if self.base_commit.algorithm != self.head_commit.algorithm {
            bail!("repair-agent task mixes Git object formats");
        }
        if self.failure.excerpt.len() > 64 * 1024
            || self.failure.excerpt.bytes().any(|byte| byte == 0)
            || self.failure.gate_id.as_ref().is_some_and(|id| {
                id.is_empty() || id.len() > 128 || id.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            bail!("repair-agent failure context is invalid");
        }
        if self.context.is_empty() || self.context.len() > 128 {
            bail!("repair-agent context manifest is empty or oversized");
        }
        let mut context_paths = std::collections::BTreeSet::new();
        let mut writable_context = std::collections::BTreeSet::new();
        for file in &self.context {
            validate_relative_path(&file.path)?;
            if file.bytes > 8 * 1024 * 1024 || !context_paths.insert(file.path.as_str()) {
                bail!("repair-agent context file is oversized or duplicated");
            }
            if file.writable {
                writable_context.insert(file.path.as_str());
            }
        }
        let mut writable = std::collections::BTreeSet::new();
        for path in &self.writable_paths {
            validate_relative_path(path)?;
            if !writable.insert(path.as_str()) || !writable_context.contains(path.as_str()) {
                bail!("repair-agent writable scope is invalid");
            }
        }
        if writable.is_empty() {
            bail!("repair-agent task grants no patch output scope");
        }
        let operations = self
            .allowed_operations
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if operations.len() != self.allowed_operations.len()
            || !operations.contains(&AgentOperation::ProposePatch)
            || !operations.contains(&AgentOperation::AskMaintainer)
        {
            bail!("repair-agent operation grant is invalid");
        }
        if self.required_gate_ids.is_empty()
            || self.required_gate_ids.len() > 256
            || self.required_gate_ids.iter().any(|id| {
                id.is_empty() || id.len() > 128 || id.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            bail!("repair-agent required gate set is invalid");
        }
        if self.budget.remaining_attempts == 0
            || self.budget.remaining_attempts > 8
            || !(10..=7_200).contains(&self.budget.wall_seconds)
            || self.budget.output_bytes == 0
            || self.budget.output_bytes > 16 * 1024 * 1024
            || self.budget.patch_bytes == 0
            || self.budget.patch_bytes > MAX_AGENT_PATCH_BYTES as u64
            || self
                .budget
                .token_limit
                .is_some_and(|limit| limit == 0 || limit > 2_000_000)
        {
            bail!("repair-agent budget is invalid");
        }
        Ok(())
    }
}

/// Classifies one untrusted agent response without granting it authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentResultDisposition {
    /// The worker returned a patch for gateway inspection.
    ProposedPatch,
    /// The worker needs paths or semantic scope not present in the task.
    ScopeRequired,
    /// The worker needs a maintainer decision.
    MaintainerQuestion,
    /// The worker could not produce a useful proposal.
    NoProposal,
}

/// Requests one explicit expansion without changing task authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScopeRequest {
    /// Repository-relative path requested for a later task generation.
    pub path: String,
    /// Whether the worker asks to propose changes to this path.
    pub writable: bool,
    /// Bounded reason displayed to the maintainer.
    pub reason: String,
}

/// Reports adapter usage as an untrusted informational claim.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentUsage {
    /// Claimed input tokens, if the adapter can report them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Claimed output tokens, if the adapter can report them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Complete adapter wall time in milliseconds.
    pub elapsed_ms: u64,
}

/// Returns one closed untrusted repair proposal to the controller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentResultV1 {
    /// Selects the exact result schema.
    pub schema: String,
    /// Digest of the canonical task consumed by the adapter.
    pub task_digest: Sha256Digest,
    /// Structural result class.
    pub disposition: AgentResultDisposition,
    /// Unified Git patch, present only for a patch proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// Bounded rationale treated only as display data.
    pub explanation: String,
    /// Explicit scope requests for a later maintainer-approved task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_requests: Vec<ScopeRequest>,
    /// Claimed test descriptions retained for context but never trusted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimed_tests: Vec<String>,
    /// Claimed resource usage retained for cost visibility.
    pub usage: AgentUsage,
}

impl AgentResultV1 {
    /// Validates the closed response shape and bounded untrusted fields.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible schema, disposition/content mismatch,
    /// unsafe scope requests, or oversized patch, prose, tests, or usage.
    pub fn validate_for(&self, task: &AgentTaskV1) -> Result<()> {
        task.validate()?;
        let expected = Sha256Digest::of_canonical(crate::PACKAGE_UPDATE_AGENT_TASK_V1, task)?;
        if self.schema != crate::PACKAGE_UPDATE_AGENT_RESULT_V1 || self.task_digest != expected {
            bail!("repair-agent result does not bind the exact task");
        }
        let has_patch = self.patch.as_ref().is_some_and(|patch| !patch.is_empty());
        if (self.disposition == AgentResultDisposition::ProposedPatch) != has_patch
            || self.patch.as_ref().is_some_and(|patch| {
                patch.len() > task.budget.patch_bytes as usize
                    || patch.len() > MAX_AGENT_PATCH_BYTES
                    || patch.bytes().any(|byte| byte == 0)
            })
            || self.explanation.len() > MAX_AGENT_EXPLANATION_BYTES
            || self.explanation.bytes().any(|byte| byte == 0)
        {
            bail!("repair-agent result payload is invalid");
        }
        if self.scope_requests.len() > 32
            || (self.disposition == AgentResultDisposition::ScopeRequired
                && self.scope_requests.is_empty())
            || (self.disposition != AgentResultDisposition::ScopeRequired
                && !self.scope_requests.is_empty())
        {
            bail!("repair-agent scope request shape is invalid");
        }
        for request in &self.scope_requests {
            validate_relative_path(&request.path)?;
            if request.reason.is_empty()
                || request.reason.len() > 4096
                || request.reason.bytes().any(|byte| byte == 0)
            {
                bail!("repair-agent scope request is invalid");
            }
        }
        if self.claimed_tests.len() > 64
            || self.claimed_tests.iter().any(|test| {
                test.is_empty() || test.len() > 4096 || test.bytes().any(|byte| byte == 0)
            })
            || self.usage.elapsed_ms > task.budget.wall_seconds.saturating_mul(1_000)
        {
            bail!("repair-agent claimed test or usage data is invalid");
        }
        let claimed_tokens = self
            .usage
            .input_tokens
            .unwrap_or(0)
            .saturating_add(self.usage.output_tokens.unwrap_or(0));
        if task
            .budget
            .token_limit
            .is_some_and(|limit| claimed_tokens > limit)
        {
            bail!("repair-agent claimed token usage exceeds its task budget");
        }
        Ok(())
    }
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::CurDir
                    | std::path::Component::RootDir
            )
        })
    {
        bail!("repair-agent path is unsafe");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{GitObjectFormat, GitObjectId};
    use crate::inventory::RiskLevel;

    fn task() -> Result<AgentTaskV1> {
        Ok(AgentTaskV1 {
            schema: crate::PACKAGE_UPDATE_AGENT_TASK_V1.to_string(),
            run_id: RunId::parse("run-fixture")?,
            plan_id: PlanId::parse("plan-fixture")?,
            attempt: 1,
            base_commit: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "0123456789012345678901234567890123456789".to_string(),
            },
            head_commit: GitObjectId {
                algorithm: GitObjectFormat::Sha1,
                value: "0123456789012345678901234567890123456789".to_string(),
            },
            tree_digest: Sha256Digest::of_bytes(b"tree"),
            unit_id: UnitId::parse("zlib-1")?,
            target_version: "1.3.2".to_string(),
            risk: RiskLevel::Normal,
            failure: RepairFailure {
                kind: RepairFailureKind::PackageBuild,
                gate_id: Some("build-zlib".to_string()),
                log_digest: Sha256Digest::of_bytes(b"log"),
                excerpt: "compiler failure".to_string(),
            },
            context: vec![AgentContextFile {
                path: "pkgs/development/zlib.nix".to_string(),
                digest: Sha256Digest::of_bytes(b"source"),
                bytes: 6,
                writable: true,
            }],
            allowed_operations: vec![
                AgentOperation::ReadContext,
                AgentOperation::ProposePatch,
                AgentOperation::AskMaintainer,
            ],
            writable_paths: vec!["pkgs/development/zlib.nix".to_string()],
            required_gate_ids: vec!["build-zlib".to_string()],
            budget: AgentBudget {
                remaining_attempts: 2,
                wall_seconds: 900,
                output_bytes: 1024 * 1024,
                patch_bytes: 1024 * 1024,
                token_limit: Some(100_000),
            },
            untrusted_data: true,
        })
    }

    #[test]
    fn task_and_bound_result_validate() -> Result<()> {
        let task = task()?;
        task.validate()?;
        let result = AgentResultV1 {
            schema: crate::PACKAGE_UPDATE_AGENT_RESULT_V1.to_string(),
            task_digest: Sha256Digest::of_canonical(crate::PACKAGE_UPDATE_AGENT_TASK_V1, &task)?,
            disposition: AgentResultDisposition::ProposedPatch,
            patch: Some(
                "diff --git a/pkgs/development/zlib.nix b/pkgs/development/zlib.nix\n".to_string(),
            ),
            explanation: "Adjust the package expression.".to_string(),
            scope_requests: Vec::new(),
            claimed_tests: Vec::new(),
            usage: AgentUsage {
                elapsed_ms: 1,
                ..AgentUsage::default()
            },
        };
        result.validate_for(&task)
    }

    #[test]
    fn result_cannot_rebind_task_or_smuggle_scope() -> Result<()> {
        let task = task()?;
        let mut result = AgentResultV1 {
            schema: crate::PACKAGE_UPDATE_AGENT_RESULT_V1.to_string(),
            task_digest: Sha256Digest::of_bytes(b"another task"),
            disposition: AgentResultDisposition::NoProposal,
            patch: None,
            explanation: String::new(),
            scope_requests: Vec::new(),
            claimed_tests: Vec::new(),
            usage: AgentUsage::default(),
        };
        assert!(result.validate_for(&task).is_err());
        result.task_digest =
            Sha256Digest::of_canonical(crate::PACKAGE_UPDATE_AGENT_TASK_V1, &task)?;
        result.scope_requests.push(ScopeRequest {
            path: "../.git/config".to_string(),
            writable: true,
            reason: "needed".to_string(),
        });
        assert!(result.validate_for(&task).is_err());
        Ok(())
    }
}
