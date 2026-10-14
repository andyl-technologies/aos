//! Observes actual original node-owned fields before the administrative callback.
//!
//! Source backing is charged through its original Rc by the daemon owner walk.
//! The node's original plan backing is conservatively charged again per view;
//! this explicit overlap does not grant an allocation-identity refund.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};

impl PreparedHostSchedulingNode {
    pub(in crate::node_contract::host_scheduling_owner) fn retained_requested_storage_excluding_source(
        &self,
    ) -> Result<usize, OperationFailure> {
        self.current()?;
        if self.source.original_ticket.is_some()
            || self.source.archive_ticket.is_some()
            || self.retired
            || self.reclamation.is_some()
            || self.restoration.is_some()
            || self.restoration_installed
            || self.capture_preparation.is_some()
        {
            return Err(failure(
                "complete original Host node storage is not in its stable capture phase",
            ));
        }
        let total = (|| -> Result<usize, RuntimeError> {
            // The original anchor's shared allocation is counted by the source's
            // retained Weak link; this concrete Box owns only the node inline.
            let mut total = std::mem::size_of::<Self>();
            total = total
                .checked_add(NodeRuntime::capture_host_node_metadata_storage(
                    &self.activation,
                    &self.route,
                    self.ready.as_ref(),
                )?)
                .ok_or(RuntimeError::ResourceLimit)?;
            if let Some(plan) = &self.plan {
                total = total
                    .checked_add(
                        plan.retained_allocation_bytes_excluding_authority()
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                    )
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            Ok(total)
        })()
        .map_err(failure)?;
        self.current()?;
        Ok(total)
    }
}
