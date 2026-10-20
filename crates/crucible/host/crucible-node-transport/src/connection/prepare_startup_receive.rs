//! Receives one genuinely admitted Prepare before typed body allocation.
//!
//! Generic receive, negotiated raw R and the original literal bank are unchanged.
//! Only the real boot6 startup scope chooses this read. Every refusal keeps the
//! same literal and hands containment to the existing connection supervisor.

use super::super::complete_restore_projection::{
    content, field, hash, identifier, integer, object, text,
};
use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::ack_emitter::OriginalNativePrepareStartupAllocation;
use crate::reference_packet::service::complete_restore::transfer::*;
use crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING;

pub(crate) fn authenticate_original_native_prepare_header_data(
    selection: &PacketControlSelection,
    fresh_selected: bool,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = selection.realization.owner_bindings.as_slice() else {
        return Err(invalid());
    };
    if original.protocol != "CNP/1"
        || original.message != MessageKind::Request
        || original.method != Method::Begin
        || original.request_id.0.is_none()
        || original.operation_id.0.is_some()
        || original.session_id.0.as_ref() != Some(&binding.authority.session_id)
        || original.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.execution_owner_id.0.as_ref() != Some(&owner.owner.id)
        || original.capture_owner_id.0.is_some()
        || original.body.len() != 7
        || !original.body.contains_key("extensions")
        || original.body["extensions"]
            .as_object()
            .is_none_or(|v| !v.is_empty())
        || !fresh_selected
            && original
                .extensions
                .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
    {
        return Err(invalid());
    }
    let body = &original.body;
    for key in [
        "kind",
        "binding_hash",
        "owner_generation",
        "activation_id",
        "world_generation",
        "arguments",
        "extensions",
    ] {
        field(body, key)?;
    }
    if text(body, "kind")? != "prepare_restore"
        || integer(field(body, "owner_generation")?)? != binding.authority.owner_generation.get()
        || integer(field(body, "world_generation")?)? == 0
    {
        return Err(invalid());
    }
    identifier(text(body, "activation_id")?)?;
    hash(field(body, "binding_hash")?, Some("cnp.owner-binding.v1"))?;
    let args = object(
        field(body, "arguments")?,
        &[
            "transaction_id",
            "capture_manifest",
            "expected_world_binding_hash",
            "expected_owner_binding_hash",
            "destination_owner_ids",
        ],
    )?;
    identifier(text(args, "transaction_id")?)?;
    content(field(args, "capture_manifest")?)?;
    hash(
        field(args, "expected_world_binding_hash")?,
        Some("cnp.world-binding.v1"),
    )?;
    hash(
        field(args, "expected_owner_binding_hash")?,
        Some("cnp.owner-binding.v1"),
    )?;
    let destinations = field(args, "destination_owner_ids")?
        .as_array()
        .ok_or_else(invalid)?;
    if destinations.len() != 1 || destinations[0].as_str() != Some(owner.owner.id.as_str()) {
        return Err(invalid());
    }
    let request = original
        .extensions
        .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
        .ok_or_else(invalid)?;
    let proof = original
        .extensions
        .get(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)
        .ok_or_else(invalid)?;
    crate::connection::serialized_credit(request, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
    crate::connection::serialized_credit(proof, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
    let projection = if fresh_selected {
        CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(original)?
    } else {
        CompleteRestoreTransferProjection::from_envelope(original)?
    };
    if !matches!(
        projection,
        CompleteRestoreTransferProjection::Request {
            phase: PacketCompleteRestoreTransferPhase::Prepare,
            ..
        }
    ) {
        return Err(invalid());
    }
    // Full target identity, Source MAC and genuine completed Fresh query remain
    // separate checks in the actual endpoint/issuer before continuation.
    Ok(())
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn receive_original_native_prepare_startup(
        &mut self,
        startup: &mut OriginalNativePrepareStartupAllocation,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.receive_original_native_prepare_with_header(startup, None)
    }

    pub(crate) fn receive_original_native_prepare_after_fresh(
        &mut self,
        startup: &mut OriginalNativePrepareStartupAllocation,
        completed: &crate::reference_packet::endpoint::OriginalNativeFreshPrepareHeader<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        completed.authenticate_current(self)?;
        self.receive_original_native_prepare_with_header(startup, Some(completed))
    }

    fn receive_original_native_prepare_with_header(
        &mut self,
        startup: &mut OriginalNativePrepareStartupAllocation,
        completed: Option<&crate::reference_packet::endpoint::OriginalNativeFreshPrepareHeader<'_>>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        startup.begin(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(invalid());
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_native_prepare_startup_inner(startup, completed);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_native_prepare_startup_inner(
        &mut self,
        startup: &OriginalNativePrepareStartupAllocation,
        completed: Option<&crate::reference_packet::endpoint::OriginalNativeFreshPrepareHeader<'_>>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        startup.authenticate_header(self, &envelope)?;
        if let Some(completed) = completed {
            completed.authenticate_header(self, &envelope)?;
        }
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        startup.authenticate_active(self)?;
        if let Some(completed) = completed {
            completed.authenticate_current(self)?;
        }
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("native Prepare startup header")
}

#[cfg(test)]
#[path = "prepare_startup_tests.rs"]
mod tests;
