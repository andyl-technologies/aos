//! Aggregate occurrence-event staging across the live QEMU node set.

use super::*;

impl QemuNodeSet {
    /// Reports whether any node has an event awaiting runtime admission.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any event transport is invalid.
    pub fn has_pending_fault_events(&mut self) -> Result<bool, BackendError> {
        for node in self.nodes.values_mut() {
            if node.fault_event_pending().map_err(BackendError::from)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Applies one aggregate event-staging ceiling to every live node.
    pub(crate) fn set_fault_event_staging_limit(
        &mut self,
        maximum_event_records: usize,
    ) -> Result<(), BackendError> {
        let current = self.staged_fault_event_count()?;
        let remaining = maximum_event_records.checked_sub(current).ok_or_else(|| {
            BackendError::Rejected {
                message: format!(
                    "QEMU staged fault events exceed the aggregate ceiling: current {current}, configured {maximum_event_records}"
                ),
            }
        })?;
        for node in self.nodes.values_mut() {
            let node_limit = node
                .staged_fault_event_count()
                .checked_add(remaining)
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from(
                        "QEMU per-node fault-event allowance is not representable",
                    ),
                })?;
            node.set_fault_event_staging_limit(node_limit)
                .map_err(BackendError::from)?;
        }
        Ok(())
    }

    pub(crate) fn fault_event_staging_allowance(
        &mut self,
        node: &NodeId,
        maximum_event_records: usize,
    ) -> Result<usize, BackendError> {
        let aggregate_current = self.staged_fault_event_count()?;
        self.set_fault_event_staging_limit(maximum_event_records)?;
        self.nodes
            .get(node)
            .map(QemuNode::staged_fault_event_count)
            .and_then(|current| {
                current.checked_add(maximum_event_records.checked_sub(aggregate_current)?)
            })
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU node `{}` has no event-staging allowance", node.name),
            })
    }

    fn staged_fault_event_count(&self) -> Result<usize, BackendError> {
        self.nodes
            .values()
            .try_fold(0_usize, |total, node| {
                total.checked_add(node.staged_fault_event_count())
            })
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("QEMU staged fault-event count is not representable"),
            })
    }
}
