//! Aggregate event-staging admission for one QEMU transaction.

use super::*;

impl QemuFaultActionSink<'_> {
    pub(super) fn event_staging_allowance(
        &mut self,
        node: &NodeId,
    ) -> Result<usize, FaultActionCommitError> {
        self.nodes
            .fault_event_staging_allowance(node, self.maximum_event_records)
            .map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
            })
    }
}
