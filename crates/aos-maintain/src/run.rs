//! Durable local run identity and rebuildable state projection.
//!
//! The append-only journal remains authoritative. This compact record is the
//! validated projection used for cached status, worktree reconciliation, and
//! command routing.

use std::path::Path;

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::PACKAGE_UPDATE_RUN_V1;
use crate::envelope::GitObjectId;
use crate::identity::{ComponentId, PlanId, RunId, SourceSlotId};
use crate::workflow::{GateOutcome, RunState};

/// Projects the current durable state of one local maintenance run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdateRunV1 {
    /// Selects the exact closed run-record schema.
    pub schema: String,
    /// Stable local run identity.
    pub run_id: RunId,
    /// Immutable plan executed by this run.
    pub plan_id: PlanId,
    /// Canonical digest of the immutable plan.
    pub plan_digest: Sha256Digest,
    /// Current state reduced from the verified journal.
    pub state: RunState,
    /// Dedicated repository-compliant local branch.
    pub branch: String,
    /// Absolute path of the managed isolated worktree.
    pub worktree: String,
    /// Whether the managed worktree was explicitly removed after completion.
    #[serde(default)]
    pub worktree_cleaned: bool,
    /// Exact commit from which the worktree was created.
    pub base_commit: GitObjectId,
    /// Current attempt number, starting with deterministic attempt zero.
    pub attempt: u32,
    /// Creation time in Unix seconds, used only for display and retention.
    pub created_at_unix: u64,
    /// Last durable transition time in Unix seconds.
    pub updated_at_unix: u64,
}

impl PackageUpdateRunV1 {
    /// Validates paths, branch policy, identity, and temporal bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, unsafe branch/worktree,
    /// malformed Git identity, or an invalid timestamp relationship.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_UPDATE_RUN_V1 {
            bail!("unsupported package update run schema");
        }
        self.base_commit.validate()?;
        if !self.branch.starts_with("dplecki/upgrade-")
            || self.branch.len() > 160
            || !self.branch.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'/' | b'.')
            })
        {
            bail!("maintenance run branch violates repository policy");
        }
        let worktree = Path::new(&self.worktree);
        if !worktree.is_absolute()
            || worktree.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            bail!("maintenance run worktree path is unsafe");
        }
        if self.updated_at_unix < self.created_at_unix {
            bail!("maintenance run timestamps are inconsistent");
        }
        Ok(())
    }
}

/// Records one bounded source transfer used by deterministic materialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedSource {
    /// Component owning the source slot.
    pub component: ComponentId,
    /// Stable source slot within the component.
    pub slot: SourceSlotId,
    /// Planned URL that completed successfully after allowed redirects.
    pub requested_url: String,
    /// Final response URL retained for origin review.
    pub final_url: String,
    /// Computed Nix SRI SHA-256 hash.
    pub hash: String,
    /// Complete response size.
    pub bytes: u64,
}

/// Captures deterministic attempt-zero outputs needed for reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializationRecordV1 {
    /// Selects the exact closed materialization schema.
    pub schema: String,
    /// Run receiving this attempt.
    pub run_id: RunId,
    /// Plan authorizing every mutation and download.
    pub plan_id: PlanId,
    /// Zero for the initial deterministic attempt.
    pub attempt: u32,
    /// Successfully resolved source identities.
    pub sources: Vec<MaterializedSource>,
    /// Digest of the canonical textual patch after formatting.
    pub patch_digest: Sha256Digest,
    /// Exact changed repository-relative paths.
    pub changed_paths: Vec<String>,
    /// Observation time in Unix seconds.
    pub completed_at_unix: u64,
}

impl MaterializationRecordV1 {
    /// Validates identity, bounds, path safety, and source uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, nonzero initial attempt,
    /// duplicate source, unsafe path/URL, or oversized evidence.
    pub fn validate(&self) -> Result<()> {
        if self.schema != crate::PACKAGE_UPDATE_MATERIALIZATION_V1 || self.attempt != 0 {
            bail!("unsupported deterministic materialization record");
        }
        if self.sources.len() > 128
            || self.changed_paths.is_empty()
            || self.changed_paths.len() > 64
        {
            bail!("materialization evidence collection is empty or oversized");
        }
        let mut identities = std::collections::BTreeSet::new();
        for source in &self.sources {
            if !identities.insert((&source.component, &source.slot))
                || source.hash.len() > 128
                || !source.hash.starts_with("sha256-")
                || source.requested_url.len() > 8192
                || source.final_url.len() > 8192
            {
                bail!("materialized source identity is invalid or duplicated");
            }
        }
        for changed in &self.changed_paths {
            let path = Path::new(changed);
            if !changed.starts_with("pkgs/")
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
                bail!("materialization changed path is unsafe");
            }
        }
        Ok(())
    }
}

/// Records one exact planned gate invocation and bounded result identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateResult {
    /// Planned gate identity.
    pub gate_id: String,
    /// Exact argument vector executed without shell interpolation.
    pub argv: Vec<String>,
    /// Logical outcome derived from the child exit status.
    pub outcome: GateOutcome,
    /// Numeric child exit code when normal process exit occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Digest of retained bounded combined output.
    pub log_digest: Sha256Digest,
    /// Retained output byte count.
    pub log_bytes: u64,
    /// Observed wall duration in milliseconds.
    pub elapsed_ms: u64,
}

/// Binds a complete quick or final gate execution to one candidate patch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateResultsV1 {
    /// Selects the exact closed gate-results schema.
    pub schema: String,
    /// Run receiving the results.
    pub run_id: RunId,
    /// Plan defining every gate.
    pub plan_id: PlanId,
    /// Either `quick` or `final`.
    pub phase: String,
    /// Candidate patch identity for pre-commit quick gates.
    pub candidate_digest: Sha256Digest,
    /// Complete planned results in plan order.
    pub results: Vec<GateResult>,
    /// Observation time in Unix seconds.
    pub completed_at_unix: u64,
}

impl GateResultsV1 {
    /// Validates phase, collection bounds, gate uniqueness, and log bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, invalid phase, duplicate
    /// gate, malformed invocation, or oversized output identity.
    pub fn validate(&self) -> Result<()> {
        if self.schema != crate::PACKAGE_UPDATE_GATE_RESULTS_V1
            || !matches!(self.phase.as_str(), "quick" | "final")
            || self.results.is_empty()
            || self.results.len() > 256
        {
            bail!("gate results header is invalid");
        }
        let mut ids = std::collections::BTreeSet::new();
        for result in &self.results {
            if result.gate_id.is_empty()
                || !ids.insert(result.gate_id.as_str())
                || result.argv.first().map(String::as_str) != Some("aos")
                || result.argv.len() > 16
                || result.log_bytes > 8 * 1024 * 1024
            {
                bail!("gate result is invalid or duplicated");
            }
        }
        Ok(())
    }

    /// Reports whether every planned gate succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.results
            .iter()
            .all(|result| result.outcome == GateOutcome::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_projection_rejects_unmanaged_branches_and_relative_worktrees() -> Result<()> {
        let run = PackageUpdateRunV1 {
            schema: PACKAGE_UPDATE_RUN_V1.to_string(),
            run_id: RunId::parse("run-fixture")?,
            plan_id: PlanId::parse("plan-fixture")?,
            plan_digest: Sha256Digest::of_bytes(b"plan"),
            state: RunState::Planned,
            branch: "feature/unsafe".to_string(),
            worktree: "relative".to_string(),
            worktree_cleaned: false,
            base_commit: GitObjectId {
                algorithm: crate::envelope::GitObjectFormat::Sha1,
                value: "0123456789012345678901234567890123456789".to_string(),
            },
            attempt: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        };
        assert!(run.validate().is_err());
        Ok(())
    }
}
