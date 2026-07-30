//! Replay-to-savepoint materialization proof conversion.

use super::*;

impl ReplayToSavepointMaterializationProof {
    pub(crate) fn from_report(report: crucible::UnifiedGraphOperationReport) -> Self {
        Self {
            materialization: "model-temporal-graph",
            operation: "replay",
            graph: report.graph,
            configuration: report.configuration,
            schedule: report.schedule,
            checkpoint: report.checkpoint,
            reduced_state: report.reduced_state,
            runtime_state: report.runtime_state,
            single_vm_fingerprint: report.single_vm_fingerprint.hash,
            replay_fat_checkpoint: report.replay_oracle.fat_checkpoint,
            replay_thin_checkpoint: report.replay_oracle.thin_checkpoint,
        }
    }
}
