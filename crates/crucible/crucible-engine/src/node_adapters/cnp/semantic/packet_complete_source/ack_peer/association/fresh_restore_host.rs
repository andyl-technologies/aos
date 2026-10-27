//! Uses the same Source-born emitter and private birth for an admitted query.
//!
//! Raw precredit quote guards never read kernel state or format a diagnostic.
//! The ticketed call separately checks actual SourceRead currentness and keeps
//! the SDK completion in its caller-owned process slot through later refusal.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_transport::{
    client::{OriginalFreshRestoreQuery, OriginalFreshRestoreQueryStorageData},
    reference_packet::service::fresh_restore_allocation::*,
};

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_original_fresh_host_query_native_data(
        &self,
        native: &crate::node_adapters::cnp::semantic::CnpSemanticProcessCustody,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_original_fresh_query_invocation_data()?;
        let expected = self
            .fresh_restore_allocation_selection
            .flatten()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let association = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if !association.ready
            || association.failed
            || !association.completed_mechanism.get()
            || !association
                .native
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .same_native_owner(native)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let controller = native.controller().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = association
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if controller
            .original_native5_fresh_restore_allocation_selection()
            .map_err(|_| RuntimeError::UnsupportedFacet)?
            != Some(expected)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_fresh_host_current_storage_data(
        &self,
        native: &crate::node_adapters::cnp::semantic::CnpSemanticProcessCustody,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_fresh_host_query_native_data(native)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        association
            .as_ref()
            .and_then(|value| value.native.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_current_storage_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn quote_original_fresh_host_query_data(
        &self,
        native: &crate::node_adapters::cnp::semantic::CnpSemanticProcessCustody,
        planned_id: &Id,
    ) -> Result<OriginalFreshRestoreQueryStorageData, RuntimeError> {
        self.authenticate_original_fresh_host_query_native_data(native)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let emitter = association
            .as_ref()
            .and_then(|value| value.emitter.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native
            .controller()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .quote_original_fresh_restore_query_storage_data(emitter, planned_id)
            .map_err(|_| RuntimeError::UnsupportedFacet)
    }

    pub(in crate::node_adapters::cnp::semantic) fn call_original_fresh_host_query_into_data(
        &self,
        controller: &mut CnpController,
        quote: &OriginalFreshRestoreQueryStorageData,
        planned_id: &Id,
        realization: &crucible_node_transport::bodies::RealizeResult,
        completed: &mut Option<OriginalFreshRestoreQuery>,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_original_fresh_query_invocation_data()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let association = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let native = association
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = association
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mut current_scratch = native.original_fresh_current_scratch()?;
        native.ensure_original_fresh_current(&mut current_scratch)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let admit = controller
            .original_completed_canonical_ack_admit(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let maximum = usize::try_from(controller.authority().limits().frame_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let request = fresh_restore_allocation_envelope_digest_data(
            admit.original(),
            PacketNativeFreshRestoreOriginalRole::AdmitRequest,
            maximum,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let response = fresh_restore_allocation_envelope_digest_data(
            admit.response(),
            PacketNativeFreshRestoreOriginalRole::AdmitResponse,
            maximum,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let query = PacketNativeFreshRestoreAllocationQuery {
            schema: PACKET_FRESH_RESTORE_ALLOCATION_QUERY.to_owned(),
            nonce: Bytes::new(fresh_restore_allocation_nonce_data(key).to_vec()),
            completed_admit_request: Bytes::new(request.to_vec()),
            completed_admit_response: Bytes::new(response.to_vec()),
        };
        let call = native.begin_original_fresh_query_call_data(&mut current_scratch)?;
        controller
            .call_original_fresh_restore_allocation_into(
                emitter, quote, planned_id, query, completed,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let owner = completed.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let report = owner.report_data().ok_or(RuntimeError::InvalidReceipt)?;
        owner
            .authenticate_original_source_context_data(
                controller,
                emitter,
                &self.installation().owner,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let expected = self.installation();
        let scope = &report.data.scope;
        if scope.native_pid.get() != u64::from(controller.peer_pid())
            || scope.world != expected.world_binding_hash
            || scope.owner_generation != expected.binding.authority.owner_generation
            || scope.admission != expected.admission
            || scope.prepared_token != realization.prepared_token
            || scope.closed_gate_receipt != realization.closed_gate_receipt
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        verify_fresh_restore_allocation_proof_data(key, &report.data, &report.proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        owner
            .authenticate_current(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        call.complete(&mut current_scratch, final_currency)
    }
}
