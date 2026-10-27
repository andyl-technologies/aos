//! Dispatches an admitted host query while retaining the actual preparation.
//!
//! The SDK writes the completion slot inside the original completed-Admit token
//! before validation and transport postchecks. Refusal and unwind preserve that
//! same process capsule, planned request and partial report owners.

use std::rc::Rc;

use crucible_node_format::Id;
use crucible_node_transport::client::OriginalFreshRestoreQueryStorageData;

use super::CnpSemanticPreparation;
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::{CompleteOriginalFreshRestoreHostWindow, InstalledConformancePlan},
    node_contract::RuntimeError,
};

impl CnpSemanticPreparation {
    pub(crate) fn original_fresh_query_current_storage_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_fresh_query_preparation_data(source)?;
        source.original_fresh_host_current_storage_data(
            self.guard
                .custody
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }

    pub(crate) fn quote_original_fresh_query_storage_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        planned_id: &Id,
    ) -> Result<OriginalFreshRestoreQueryStorageData, RuntimeError> {
        self.authenticate_original_fresh_query_preparation_data(source)?;
        source.quote_original_fresh_host_query_data(
            self.guard
                .custody
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            planned_id,
        )
    }

    /// Dispatches one original readonly query under its already retained host window.
    ///
    /// The holder saves the opaque ticket before this call and retains the
    /// preparation on every failure. This constructs Query data only after
    /// spending that same ticket; no caller-supplied Query or key is accepted.
    /// It grants no Prepare, activation or whole-restoration authority.
    ///
    /// # Errors
    /// Refuses a foreign/spent ticket, changed Source/native/controller or
    /// completed-Admit frontier, unsupported selection, transport uncertainty,
    /// malformed report, invalid keyed proof or revoked holder currency.
    pub fn call_original_fresh_restore_allocation_into(
        &mut self,
        ticket: &mut CompleteOriginalFreshRestoreHostWindow,
        planned_id: &Id,
    ) -> Result<(), RuntimeError> {
        let source = ticket.original_source_data()?;
        let plan: InstalledConformancePlan = ticket.authenticate_preparation(self, &source)?;
        self.authenticate_original_fresh_query_plan_data(&plan)?;
        ticket.authenticate_holder_data(&plan, &source)?;
        ticket.spend()?;
        let quote = ticket.quote_data();
        let native = self
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        source.authenticate_original_fresh_host_query_native_data(native)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let token = native
            .completed_ack_admission
            .get_mut()
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        source.call_original_fresh_host_query_into_data(
            controller,
            quote,
            planned_id,
            &self.realization,
            token.fresh_query_slot_data(),
            || ticket.authenticate_holder_data(&plan, &source),
        )?;
        self.authenticate_original_fresh_query_preparation_data(&source)?;
        ticket.authenticate_holder_data(&plan, &source)
    }
}
