//! Quotes the existing inactive node without extracting its native preparation.
//!
//! The spent Admit and completed Query remain in the same native custody token.
//! This raw owning path does not weaken the separate pre-runtime Query guard.

use super::*;
use crate::{
    node_admission::{OriginalRestorationNodeConstructionData, OriginalRestorationNodeInputs},
    node_contract::RuntimeError,
};

impl CnpSemanticNode {
    pub(crate) fn original_restoration_construction_data(
        &self,
        inputs: &OriginalRestorationNodeInputs<'_>,
    ) -> Result<OriginalRestorationNodeConstructionData, RuntimeError> {
        let preparation = &self.preparation;
        preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        preparation.authenticate_original_fresh_query_plan_data(inputs.plan)?;
        let native = preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native.read_owner.original_fresh_query_custody_data()?;
        let installed = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(
            Rc::as_ptr(installed).cast::<()>(),
            Rc::as_ptr(inputs.source).cast::<()>(),
        ) || !std::ptr::eq(installed.installation(), inputs.source.installation())
            || !native.completed_ack_protocol_started
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let runtime = native
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if runtime.arm_attempt.is_some()
            || runtime.ready.is_some()
            || runtime.prepared_owner.is_some()
            || runtime.activate_response.is_some()
            || runtime.activation_attempt.is_some()
            || runtime.active.is_some()
            || !runtime.inputs.is_empty()
            || !runtime.operations.is_empty()
            || runtime.observation.is_some()
            || runtime.reclaimed.is_some()
            || runtime.quarantined
            || runtime.observe_sequence.get() != 0
            || runtime.watermark.get() != 0
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let token = native
            .completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let token = token.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let query = token.original_restoration_query_data(inputs.source)?;
        let data = inputs.source.original_restoration_node_construction_data(
            native,
            query,
            &preparation.realization,
            inputs,
        )?;
        data.authenticate_original_owner_data(
            inputs.source,
            Rc::as_ptr(&native.read_owner).cast(),
        )?;
        native.read_owner.original_fresh_query_custody_data()?;
        Ok(data)
    }
}

impl CnpSemanticNode {
    pub(crate) fn original_restoration_construction_counter_scratch_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native.controller().ok_or(RuntimeError::OwnerUnavailable)?;
        let terms = [
            std::mem::size_of::<OriginalRestorationNodeInputs<'static>>(),
            std::mem::size_of::<OriginalRestorationNodeConstructionData>(),
            std::mem::size_of_val(&native.read_owner),
            super::super::packet_complete_source::OriginalCompletedCanonicalAckWorldAdmission::original_restoration_query_counter_scratch_data(),
            super::super::PacketCompleteSemanticSource::original_restoration_source_counter_scratch_data(),
            controller.original_complete_restore_upload_before_mapping_counter_scratch_data(),
        ];
        terms.into_iter().try_fold(0usize, |sum, term| {
            sum.checked_add(term).ok_or(RuntimeError::ResourceLimit)
        })
    }
}
