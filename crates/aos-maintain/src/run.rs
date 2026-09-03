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
use crate::identity::{ArtifactSlotId, ComponentId, PlanId, RunId, SourceSlotId};
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
    /// Candidate patch digest explicitly accepted by the maintainer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_candidate: Option<Sha256Digest>,
    /// Exact local candidate commit created with maintainer Git identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_commit: Option<GitObjectId>,
    /// Canonical final local evidence digest, when complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<Sha256Digest>,
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
        if let Some(commit) = &self.candidate_commit {
            commit.validate()?;
            if commit.algorithm != self.base_commit.algorithm {
                bail!("candidate commit uses another Git object format");
            }
        }
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
    /// Exact selected upstream identity whose bytes were resolved.
    pub upstream_id: String,
    /// Planned URL that completed successfully after allowed redirects.
    pub requested_url: String,
    /// Final response URL retained for origin review.
    pub final_url: String,
    /// Computed Nix SRI SHA-256 hash.
    pub hash: String,
    /// Complete response size.
    pub bytes: u64,
    /// Assurance established independently of the content hash.
    pub assurance: SourceAssuranceOutcome,
}

/// Records one generated fixed-output artifact resolved by its typed builder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedArtifact {
    /// Stable artifact slot within the update unit.
    pub slot: ArtifactSlotId,
    /// Exact candidate derivation realized with the controller's fake hash.
    pub derivation: String,
    /// Prior hash that the immutable plan required before materialization.
    pub expected_hash: String,
    /// Computed recursive SRI SHA-256 hash written into the package contract.
    pub hash: String,
}

/// Records what the trusted resolver established about source authenticity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceAssuranceOutcome {
    /// An allowlisted HTTPS origin and redirect policy protected acquisition.
    OriginIntegrity,
    /// A separately anchored checksum or signature authenticated the bytes.
    VerifiedAuthentic,
    /// Required assurance evidence was unavailable.
    Unknown,
    /// Presented assurance evidence failed verification.
    Failed,
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
    /// Generated fixed-output artifacts resolved in dependency order.
    #[serde(default)]
    pub artifacts: Vec<MaterializedArtifact>,
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
                || source.upstream_id.is_empty()
                || source.upstream_id.len() > 512
                || source.requested_url.len() > 8192
                || source.final_url.len() > 8192
                || !matches!(
                    source.assurance,
                    SourceAssuranceOutcome::OriginIntegrity
                        | SourceAssuranceOutcome::VerifiedAuthentic
                )
            {
                bail!("materialized source identity is invalid or duplicated");
            }
        }
        if self.artifacts.len() > 128 {
            bail!("materialized artifact collection is oversized");
        }
        let mut artifact_slots = std::collections::BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifact_slots.insert(&artifact.slot)
                || !artifact.derivation.starts_with("/nix/store/")
                || !artifact.derivation.ends_with(".drv")
                || !artifact.expected_hash.starts_with("sha256-")
                || !artifact.hash.starts_with("sha256-")
                || artifact.expected_hash.len() > 128
                || artifact.hash.len() > 128
            {
                bail!("materialized artifact identity is invalid or duplicated");
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

/// Records one human-authorized repair patch applied after attempt zero.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RepairAttemptV1 {
    /// Selects the exact repair-attempt schema.
    pub schema: String,
    /// Run receiving the attempt.
    pub run_id: RunId,
    /// Immutable update plan retained as the outer authority boundary.
    pub plan_id: PlanId,
    /// Monotonic attempt number greater than zero.
    pub attempt: u32,
    /// Attempt whose candidate tree was repaired.
    pub parent_attempt: u32,
    /// Canonical task digest shown to the adapter.
    pub task_digest: Sha256Digest,
    /// Canonical untrusted result digest accepted by the maintainer.
    pub result_digest: Sha256Digest,
    /// Exact proposal patch digest confirmed by the maintainer.
    pub proposal_digest: Sha256Digest,
    /// Cumulative base-to-candidate patch digest after applying the proposal.
    pub candidate_digest: Sha256Digest,
    /// Exact repository-relative paths changed by the cumulative candidate.
    pub changed_paths: Vec<String>,
    /// Observation time in Unix seconds.
    pub completed_at_unix: u64,
}

impl RepairAttemptV1 {
    /// Validates identities, monotonicity, and bounded path scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, a non-monotonic attempt,
    /// or empty, oversized, duplicated, or unsafe changed paths.
    pub fn validate(&self) -> Result<()> {
        if self.schema != crate::PACKAGE_UPDATE_REPAIR_ATTEMPT_V1
            || self.attempt == 0
            || self.parent_attempt.checked_add(1) != Some(self.attempt)
            || self.changed_paths.is_empty()
            || self.changed_paths.len() > 64
        {
            bail!("repair attempt header is invalid");
        }
        let mut paths = std::collections::BTreeSet::new();
        for value in &self.changed_paths {
            let path = Path::new(value);
            if !value.starts_with("pkgs/")
                || path.is_absolute()
                || path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir
                            | std::path::Component::CurDir
                            | std::path::Component::RootDir
                    )
                })
                || !paths.insert(value.as_str())
            {
                bail!("repair attempt changed path is unsafe or duplicated");
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

/// Records the fail-closed local boundary used for candidate-controlled work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfinementEvidence {
    /// Stable implementation and policy identity.
    pub backend: String,
    /// Kernel Landlock ABI observed before execution.
    pub landlock_abi: u32,
    /// Digest of the ordered filesystem grants supplied to the backend.
    pub filesystem_policy_digest: Sha256Digest,
    /// Digest of the process resource ceilings supplied to the backend.
    pub resource_limits_digest: Sha256Digest,
    /// Whether a private user namespace was requested and verified.
    pub private_user_namespace: bool,
    /// Whether private mount, PID, IPC, and UTS namespaces were requested.
    pub private_process_namespaces: bool,
    /// Whether private networking and Landlock network denial were combined.
    pub network_isolated: bool,
    /// Whether the namespace supervisor kills the complete child tree on exit.
    pub worker_tree_reaped: bool,
    /// Whether process, file, descriptor, address-space, and CPU ceilings apply.
    pub resource_limited: bool,
}

impl ConfinementEvidence {
    /// Validates the minimum Linux confinement contract for maintenance work.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend identity, ABI, or mandatory isolation
    /// properties do not satisfy the version-one contract.
    pub fn validate(&self) -> Result<()> {
        if self.backend != "aos.linux-userns-landlock/v1"
            || self.landlock_abi < 4
            || !self.private_user_namespace
            || !self.private_process_namespaces
            || !self.network_isolated
            || !self.worker_tree_reaped
            || !self.resource_limited
        {
            bail!("gate evidence does not satisfy the required confinement contract");
        }
        Ok(())
    }
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
    /// Candidate attempt receiving these results.
    pub attempt: u32,
    /// Either `quick` or `final`.
    pub phase: String,
    /// Candidate patch identity for pre-commit quick gates.
    pub candidate_digest: Sha256Digest,
    /// Verified local confinement boundary shared by every gate in this set.
    pub confinement: ConfinementEvidence,
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
            || self.attempt > 8
            || self.results.is_empty()
            || self.results.len() > 256
        {
            bail!("gate results header is invalid");
        }
        self.confinement.validate()?;
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
            accepted_candidate: None,
            candidate_commit: None,
            evidence_digest: None,
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

/// Contains the complete verified local evidence for one ready candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdateEvidenceV1 {
    /// Selects the exact closed evidence schema.
    pub schema: String,
    /// Durable run represented by this dossier.
    pub run_id: RunId,
    /// Immutable plan represented by this dossier.
    pub plan_id: PlanId,
    /// Final accepted candidate attempt.
    pub attempt: u32,
    /// Plan digest carried by the run journal.
    pub plan_digest: Sha256Digest,
    /// Exact protected base commit.
    pub base_commit: GitObjectId,
    /// Exact maintainer-authored candidate commit.
    pub candidate_commit: GitObjectId,
    /// Accepted textual candidate patch identity.
    pub patch_digest: Sha256Digest,
    /// Complete deterministic source materialization evidence.
    pub materialization: MaterializationRecordV1,
    /// Successful quick gate execution.
    pub quick_gates: GateResultsV1,
    /// Successful exact-commit final gate execution.
    pub final_gates: GateResultsV1,
    /// Digest of the verified journal tip at evidence construction time.
    pub journal_tip: Sha256Digest,
    /// Observation time in Unix seconds.
    pub completed_at_unix: u64,
}

impl PackageUpdateEvidenceV1 {
    /// Validates cross-object identities and completion claims.
    ///
    /// # Errors
    ///
    /// Returns an error when schemas, run/plan identities, candidate inputs,
    /// or gate outcomes disagree.
    pub fn validate(&self) -> Result<()> {
        if self.schema != crate::PACKAGE_UPDATE_EVIDENCE_V1 {
            bail!("unsupported package update evidence schema");
        }
        self.base_commit.validate()?;
        self.candidate_commit.validate()?;
        self.materialization.validate()?;
        self.quick_gates.validate()?;
        self.final_gates.validate()?;
        if self.materialization.run_id != self.run_id
            || self.quick_gates.run_id != self.run_id
            || self.final_gates.run_id != self.run_id
            || self.materialization.plan_id != self.plan_id
            || self.quick_gates.plan_id != self.plan_id
            || self.final_gates.plan_id != self.plan_id
            || self.quick_gates.attempt != self.attempt
            || self.final_gates.attempt != self.attempt
            || (self.attempt == 0 && self.materialization.patch_digest != self.patch_digest)
            || self.quick_gates.candidate_digest != self.patch_digest
            || self.final_gates.candidate_digest
                != Sha256Digest::separated(
                    "aos.package-update-commit/v1",
                    self.candidate_commit.value.as_bytes(),
                )
            || self.quick_gates.phase != "quick"
            || self.final_gates.phase != "final"
            || !self.quick_gates.all_succeeded()
            || !self.final_gates.all_succeeded()
        {
            bail!("package update evidence objects do not form one completed candidate");
        }
        Ok(())
    }
}
