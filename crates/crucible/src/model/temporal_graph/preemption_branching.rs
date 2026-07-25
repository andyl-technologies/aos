//! Replay-oracle materialization for reduced preemption frontiers.

use super::*;

impl TemporalGraph {
    /// Materializes every explored child and each unique covered representative.
    pub(in crate::model) fn materialize_preemption_branches(
        &mut self,
        report: &FrontierReductionReport,
    ) -> Result<Vec<Checkpoint>, EngineError> {
        let mut materialized = Vec::new();
        let mut materialized_ids = BTreeSet::new();
        for child in &report.explored {
            let checkpoint = self.materialize_checkpoint(&child.configuration)?;
            if materialized_ids.insert(checkpoint.id) {
                materialized.push(checkpoint);
            }
        }
        for child in &report.covered {
            let representative = self
                .recorded_configurations
                .get(&child.representative)
                .cloned()
                .ok_or(EngineError::CheckpointNotRecorded {
                    checkpoint: child.representative,
                })?;
            let checkpoint = self.materialize_checkpoint(&representative)?;
            if materialized_ids.insert(checkpoint.id) {
                materialized.push(checkpoint);
            }
        }
        Ok(materialized)
    }
}
