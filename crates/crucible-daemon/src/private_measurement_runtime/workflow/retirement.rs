//! Retires fixed workflow inputs after their actual dependent services close.
//!
//! Input bytes and descriptors are freed before the original decoder control.
//! A consuming close refusal retains the same owner and becomes terminal;
//! the containing workflow's Drop does not retry it after aliases change.
//! Process-lifetime actor and SQLite custody stay outside this local closure.

use super::{OriginalActorRoleIssuer, OriginalResidentWorkflowOwner};

impl OriginalResidentWorkflowOwner {
    /// Frees fixed input bodies before closing their original decode control.
    ///
    /// # Errors
    /// Refuses retained service/catalog/artifact owners or the saved original.
    /// The first consuming decoder close is terminal: a refusal stores that same
    /// owner here and Drop retains it rather than retrying after alias changes.
    pub(in crate::private_measurement_runtime) fn close_inputs(
        &mut self,
        actor: &OriginalActorRoleIssuer,
    ) -> Result<(), OriginalWorkflowCloseError> {
        if self.input_retirement_attempted
            || self.policy.is_some()
            || self.campaign_policy.is_some()
            || self.catalog.is_some()
            || self.graph.is_some()
            || self.refs.is_some()
            || self.repository.is_some()
            || self.service_state.is_some()
            || self.prepared_state.is_some()
            || self.retention.is_some()
            || self.transfers.is_some()
            || self.prepared_retention.is_some()
            || self.prepared_transfers.is_some()
            || self.prepared_policy.is_some()
            || self.prepared_service.is_some()
            || self.artifacts.is_some()
        {
            return Err(OriginalWorkflowCloseError::Occupied);
        }
        let decoder = self
            .decoder
            .as_ref()
            .ok_or(OriginalWorkflowCloseError::Occupied)?;
        decoder.verify_original_boundary()?;
        self.input_retirement_attempted = true;
        drop(self.components.take());
        self.component_authorities = None;
        drop(self.projection.take());
        drop(self.campaign.take());
        drop(self.bootstrap.take());
        drop(self.input.take());
        let decoder = self
            .decoder
            .take()
            .ok_or(OriginalWorkflowCloseError::Occupied)?;
        let retained = decoder.try_close().err();
        self.decoder = retained;
        let after = actor.verify_original_boundary();
        if self.decoder.is_some() {
            return Err(OriginalWorkflowCloseError::Decoder {
                original_after: after.err(),
            });
        }
        after?;
        Ok(())
    }
}

/// Preserves the actual workflow input or decode retirement refusal.
#[derive(Debug, thiserror::Error)]
pub enum OriginalWorkflowCloseError {
    /// A live dependent owner or earlier retirement prevents input destruction.
    #[error("original workflow retirement retains dependent custody")]
    Occupied,
    /// The same original refused before input destruction.
    #[error("original workflow retirement interval refused: {0}")]
    Original(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
    /// The actual decoder refused; its same owner remains in the workflow.
    #[error("original workflow decoder retained custody; original: {original_after:?}")]
    Decoder {
        /// The same external raw original after consuming decode close.
        original_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    },
}
