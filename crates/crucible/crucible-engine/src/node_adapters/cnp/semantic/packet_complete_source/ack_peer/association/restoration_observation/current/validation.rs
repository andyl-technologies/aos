//! Authenticates fresh actual pairs and complete model proofs under SourceRead.

use super::*;
use crucible_node_transport::bodies::{MethodResult, OperationState, ResponseShape};
use crucible_node_transport::reference_packet::service::complete_restore::activation::{
    PacketRestorationActivationScope, authenticate_restoration_activation_held_correspondence_data,
};
use std::io::{self, Write};

/// Borrows an actual Source-owned verified attempt after its complete read fence.
///
/// No constructor, Clone, decoder or caller-supplied phase is exposed. Its
/// synchronous fixed authentication advances only the already-spent Core claim.
pub(crate) struct OriginalSourceRestoredObservationCompletion<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    ordinal: u64,
    signature: [u8; 32],
}

impl<'a> OriginalSourceRestoredObservationCompletion<'a> {
    pub(super) fn new_data(
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        ordinal: u64,
        signature: [u8; 32],
    ) -> Self {
        Self {
            source,
            controller,
            ordinal,
            signature,
        }
    }

    pub(crate) fn authenticate_claim_data(
        &self,
        row: &OriginalRestoredSchedulingObservationConstructionData,
        world: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        row.authenticate_owner_data(self.source, self.controller)?;
        let association = self
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        let latest = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let scheduling = latest
            .scheduling
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if history.failed
            || latest.stage != Stage::Verified
            || self.ordinal != row.ordinal
            || latest.row.ordinal != row.ordinal
            || latest.signature != Some(self.signature)
            || scheduling.node != self.source.installation().binding.compatibility.node_id
            || scheduling.owners.len() != 1
            || !scheduling
                .owners
                .iter()
                .all(|owner| world.record().owners.contains(owner))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }
}

pub(super) fn terminal_measurement<'a>(
    response: &'a ResponseBody,
    scope: &PacketRestorationActivationScope,
    original: &crucible_node_transport::envelope::Envelope,
) -> Result<&'a ContentRef, RuntimeError> {
    if !matches!(&response.shape,
        ResponseShape::Completed { operation_state: OperationState::Completed, extensions, .. }
            if extensions.is_empty())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let Some(MethodResult::Observe(result)) = response.result.as_ref() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let [batch] = result.observations.as_slice() else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let target = &scope.target;
    if !result.complete
        || result.next_sequence.get() != 1
        || batch.schema_version != 1
        || batch.execution_owner_id != target.owner
        || batch.owner_binding_hash != target.binding_hash
        || batch.world_binding_hash != target.world
        || batch.activation_id != target.activation
        || batch.world_generation != target.generation
        || batch.owner_generation != target.owner_generation
        || Some(&batch.operation_id) != original.request_id.0.as_ref()
        || batch.grant_id.is_some()
        || batch.first_sequence.get() != 0
        || batch.last_sequence.get() != 0
        || !batch.events.is_empty()
        || batch.visibility != crucible_node_format::Visibility::Staged
        || !batch.extensions.is_empty()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(&batch.measurement_ref)
}

pub(super) fn retain_proof_data(
    attempt: &mut CurrentObservationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    scope: &PacketRestorationActivationScope,
) -> Result<(), RuntimeError> {
    let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    let (original, terminal, typed) = sdk
        .authenticate_current_pair_data(controller, emitter)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !original.extensions.is_empty() || !terminal.extensions.is_empty() {
        return Err(RuntimeError::InvalidReceipt);
    }
    let reference = terminal_measurement(typed, scope, original)?;
    attempt.measurement = Some(reference.clone());
    let raw = controller
        .content(reference)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    reference
        .verify(raw)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let limit = attempt.row.provider.maximum_restored_record_bytes_data();
    if raw.len() > limit {
        return Err(RuntimeError::ResourceLimit);
    }
    let value = canonical::parse_json(raw, limit).map_err(|_| RuntimeError::InvalidReceipt)?;
    let encoded = canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if encoded.as_slice() != raw {
        return Err(RuntimeError::InvalidReceipt);
    }
    attempt.record = Some(serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?);
    let record = attempt
        .record
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let underlying = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if underlying.len() > attempt.row.provider.maximum_underlying_record_bytes_data() {
        return Err(RuntimeError::ResourceLimit);
    }
    record
        .native_receipt
        .native_record
        .verify(underlying)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let observed = controller
        .authenticate_original_restored_suffix_receipt_data(
            emitter, original, terminal, original, record, underlying,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    attempt.underlying = Some(observed);
    Ok(())
}

pub(super) fn authenticate_proof_data(
    attempt: &CurrentObservationAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    scope: &PacketRestorationActivationScope,
    held: &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
) -> Result<(), RuntimeError> {
    let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    let (original, terminal, typed) = sdk
        .authenticate_current_pair_data(controller, emitter)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let measurement = terminal_measurement(typed, scope, original)?;
    if attempt.measurement.as_ref() != Some(measurement) {
        return Err(RuntimeError::InvalidReceipt);
    }
    let record = attempt
        .record
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let bytes = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let observed = controller
        .authenticate_original_restored_suffix_receipt_data(
            emitter, original, terminal, original, record, bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    authenticate_restoration_activation_held_correspondence_data(record, &observed, held)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    super::super::effect::authenticate_terminal_inventory_data(typed, &held.inventory_hash)?;
    // The independently retained native model is part of this Source attempt;
    // recompute its complete inventory/cursor correspondence rather than accept
    // a caller scalar or an old first-Observe reference as the current proof.
    authenticate_restoration_activation_held_correspondence_data(
        record,
        attempt
            .underlying
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        held,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(())
}

struct HashWriter<'a>(&'a mut blake3::Hasher);

impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn signature_data(
    attempt: &CurrentObservationAttempt,
    key: &[u8; 32],
) -> Result<[u8; 32], RuntimeError> {
    let (original, terminal, _) = attempt
        .sdk
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(b"aos.restored-suffix.current-observation.v1\0");
    hash.update(&attempt.row.ordinal.to_le_bytes());
    hash.update(&attempt.previous);
    let mut writer = HashWriter(&mut hash);
    serde_json::to_writer(&mut writer, original).map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(&mut writer, terminal).map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(
        &mut writer,
        attempt
            .record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(
        &mut writer,
        attempt
            .scheduling
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(*hash.finalize().as_bytes())
}

pub(super) fn counter_scratch_data() -> usize {
    use crucible_node_transport::{ProviderError, envelope::Envelope};
    size_of::<OriginalSourceRestoredObservationCompletion<'static>>()
        + size_of::<Result<OriginalSourceRestoredObservationCompletion<'static>, RuntimeError>>()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
        + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
        + size_of::<PacketNativeRestoredRecord>()
        + size_of::<Result<PacketNativeRestoredRecord, serde_json::Error>>()
        + size_of::<PacketNative5UnderlyingRecord>() * 2
        + size_of::<Result<PacketNative5UnderlyingRecord, ProviderError>>()
        + size_of::<Result<&ContentRef, RuntimeError>>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<Result<&ContentRef, ProviderError>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<HashWriter<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<usize, io::Error>>()
        + size_of::<Result<(), io::Error>>()
        + size_of::<Result<[u8; 32], RuntimeError>>()
        + size_of::<[u8; 32]>() * 3
        + size_of::<[u8; 8]>()
        + size_of::<&[u8]>() * 2
        + size_of::<&ContentRef>() * 2
        + size_of::<&CurrentObservationAttempt>()
        + size_of::<&mut CurrentObservationAttempt>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<&ObserveRequest>()
}

impl PacketCompleteSemanticSource {
    pub(crate) fn authenticate_original_current_observation_data(
        &self,
        controller: &CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        row: &OriginalRestoredSchedulingObservationConstructionData,
        world: &crate::node_contract::WorldActivation,
        ordinal: u64,
        actual: &NativeSchedulingObservation,
        final_currency: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        row.authenticate_owner_data(self, controller)?;
        let ancestry =
            self.original_verified_restoration_observation_data(controller, inputs, &row.first)?;
        drop(ancestry);
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .current_observations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        let attempt = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let key = birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let mut scratch = native.original_fresh_current_scratch()?;
        let call = native.begin_original_fresh_query_call_data(&mut scratch)?;
        if history.failed
            || attempt.stage != Stage::Verified
            || attempt.row.ordinal != ordinal
            || ordinal != row.ordinal
            || attempt.signature != Some(signature_data(attempt, key)?)
            || attempt.scheduling.as_ref() != Some(actual)
            || !inputs
                .activation
                .world
                .is_some_and(|old| old.same_authority(world))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        restoration_activation::with_verified_world_under_read_data(
            self,
            controller,
            original,
            inputs.activation,
            &row.first.activation,
            key,
            || call.ensure_original_fresh_current_before_effect_data(&mut scratch),
            |scope, reference, held| {
                authenticate_proof_data(attempt, controller, emitter, scope, held)?;
                inputs.authenticate_original_observation_hold_data(held, reference)
            },
        )?;
        scheduling::authenticate_bound(
            actual,
            row.first.scheduling_observation_requested_bytes_data(),
        )?;
        call.complete(&mut scratch, final_currency)
    }
}
