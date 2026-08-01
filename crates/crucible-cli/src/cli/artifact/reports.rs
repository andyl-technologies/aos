//! Replay and failure artifact report types.

use super::*;

#[derive(Debug)]
pub(crate) struct ReplayArtifactReport {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
    pub(crate) seed: u64,
    pub(crate) scenario_digest: String,
    pub(crate) reduction: Option<ReplayReductionProof>,
    pub(crate) to_savepoint: Option<ReplayToSavepointReport>,
    pub(crate) check: Option<ReplayCheckReport>,
    pub(crate) bisect: Option<ReplayBisectionReport>,
}

#[derive(Debug)]
pub(crate) struct ReplayReductionProof {
    pub(crate) artifact: crucible::ContentHash,
    pub(crate) scenario: crucible::ContentHash,
    pub(crate) schedule: crucible::ContentHash,
    pub(crate) state: crucible::ContentHash,
    pub(crate) reconstructed_decisions: usize,
}

#[derive(Debug)]
pub(crate) struct ReplayToSavepointReport {
    pub(crate) target_label: String,
    pub(crate) checkpoint: crucible::ContentHash,
    pub(crate) frontier_ticks: u64,
    pub(crate) schedule_prefix: ReplaySchedulePrefixProof,
    pub(crate) oracle: SavepointOracleProof,
    pub(crate) materialization: ReplayToSavepointMaterializationProof,
}

#[derive(Debug)]
pub(crate) struct ReplaySchedulePrefixProof {
    pub(crate) target_decisions: usize,
    pub(crate) artifact_decisions: usize,
    pub(crate) matched_decisions: usize,
    pub(crate) typed_prefix_digest: String,
    pub(crate) artifact_prefix_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySchedulePrefixDecisionProof {
    pub(crate) sequence: u64,
    pub(crate) virtual_time_ticks: u64,
    pub(crate) kind: String,
    pub(crate) payload_summary: String,
    pub(crate) payload_digest: String,
}

#[derive(Debug)]
pub(crate) struct ReplayToSavepointMaterializationProof {
    pub(crate) materialization: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) graph: crucible::ContentHash,
    pub(crate) configuration: crucible::ContentHash,
    pub(crate) schedule: crucible::ContentHash,
    pub(crate) checkpoint: crucible::ContentHash,
    pub(crate) reduced_state: crucible::ContentHash,
    pub(crate) runtime_state: crucible::ContentHash,
    pub(crate) single_vm_fingerprint: crucible::ContentHash,
    pub(crate) replay_fat_checkpoint: crucible::ContentHash,
    pub(crate) replay_thin_checkpoint: crucible::ContentHash,
}

#[derive(Debug)]
pub(crate) struct ReplayCheckReport {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
    pub(crate) mismatch: Option<ReplayCheckMismatchReport>,
}

#[derive(Debug)]
pub(crate) struct ReplayCheckMismatchReport {
    pub(crate) original_digest: String,
    pub(crate) replayed_digest: String,
    pub(crate) first_diff_byte: usize,
    pub(crate) original_len: usize,
    pub(crate) replayed_len: usize,
}

#[derive(Debug)]
pub(crate) struct ReplayBisectionReport {
    pub(crate) other_path: PathBuf,
    pub(crate) other_digest: String,
    pub(crate) divergence: Option<VerifyDivergenceReport>,
}

#[derive(Debug)]
pub(crate) struct FailureArtifactReport {
    pub(crate) path: PathBuf,
    pub(crate) digest: String,
    pub(crate) footer: FailureReproductionFooter,
}
