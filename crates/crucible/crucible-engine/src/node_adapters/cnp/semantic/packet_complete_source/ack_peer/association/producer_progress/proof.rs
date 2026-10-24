//! Verifies actual native receipts and seals only completed owning-read phases.

use super::*;
use crate::node_contract::WorldActivation;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;
use std::io::{self, Write};

/// Borrows a Source-owned phase after its complete native read fence.
///
/// Only this module constructs the token. It is neither a result DTO nor a
/// publication receipt; Core separately checks its real Runtime state before
/// advancing the already-spent exact phase claim.
pub(crate) struct OriginalSourceRestoredProducerPhaseCompletion<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    slot: usize,
    phase: ProducerExecutionPhase,
    signature: [u8; 32],
}

impl<'a> OriginalSourceRestoredProducerPhaseCompletion<'a> {
    pub(super) fn new_data(
        source: &'a PacketCompleteSemanticSource,
        controller: &'a CnpController,
        slot: usize,
        phase: ProducerExecutionPhase,
        signature: [u8; 32],
    ) -> Self {
        Self {
            source,
            controller,
            slot,
            phase,
            signature,
        }
    }

    /// Compares the exact Source-retained phase to the already-spent Core claim.
    ///
    /// # Errors
    /// Refuses another Source/Controller, row, slot, phase, signature or World.
    pub(crate) fn authenticate_claim_data(
        &self,
        row: &OriginalRestoredProducerExecutionConstructionData,
        slot: usize,
        phase: ProducerExecutionPhase,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        row.authenticate_owner_data(self.source, self.controller)?;
        let association = self
            .source
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .producer_progress
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.origin_data()?;
        let attempt = history
            .attempts
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        construction::authenticate_source_row_data(row, &attempt.row)?;
        let expected = match phase {
            ProducerExecutionPhase::Begin => Stage::Begun,
            ProducerExecutionPhase::Poll => Stage::Completed,
            ProducerExecutionPhase::Publication => {
                if attempt.stage.get() == Stage::Durable {
                    Stage::Durable
                } else {
                    Stage::Completed
                }
            }
            ProducerExecutionPhase::Retirement => Stage::Retired,
            ProducerExecutionPhase::Observation => Stage::Verified,
        };
        if history.failed
            || self.slot != slot
            || attempt.slot != slot
            || self.phase != phase
            || attempt.stage.get() != expected
            || attempt.signature != Some(self.signature)
            || !attempt
                .admission
                .as_ref()
                .is_some_and(|admission| admission.activation().same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

pub(super) fn reference_storage_data(maximum: usize) -> Result<usize, RuntimeError> {
    let bytes = "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/octet-stream".len();
    if bytes > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
}

pub(super) fn authenticate_checkpoint_data(
    history: &ProducerProgressHistory,
    original: &OriginalAckPeerAssociation,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    key: &[u8; 32],
) -> Result<(), RuntimeError> {
    history.require_verified_prefix_data()?;
    if let Some(attempt) = history.attempts.last() {
        if attempt.signature != Some(signature_data(attempt, key)?) {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt
            .observe
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_current_pair_data(controller, emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    let (record, producer, measurement) = history.checkpoint_data(original)?;
    let raw = controller
        .content(measurement)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    measurement
        .verify(raw)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let bytes = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    record
        .native_receipt
        .native_record
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let observed = if let Some(attempt) = history.attempts.last() {
        let (request, response, _) = attempt
            .observe
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .completed_pair_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        controller.authenticate_original_restored_suffix_receipt_data(
            emitter, request, response, request, record, bytes,
        )
    } else {
        controller.authenticate_original_installed_restoration_observation_evidence_data(
            emitter, record, bytes,
        )
    }
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !matches!(observed, PacketNative5UnderlyingRecord::Producer(actual) if actual.as_ref() == producer)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

pub(super) fn retain_native_data(
    attempt: &mut ProducerProgressAttempt,
    controller: &CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    checkpoint: bool,
) -> Result<(), RuntimeError> {
    let sdk = if checkpoint {
        attempt.observe.as_ref()
    } else {
        attempt.begin.as_ref()
    }
    .ok_or(RuntimeError::OwnerUnavailable)?;
    let (original, terminal, typed) = sdk
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let measurement = measurement_data(typed)?.clone();
    if checkpoint {
        attempt.checkpoint_measurement = Some(measurement);
    } else {
        attempt.completed_measurement = Some(measurement);
    }
    let measurement = if checkpoint {
        attempt.checkpoint_measurement.as_ref()
    } else {
        attempt.completed_measurement.as_ref()
    }
    .ok_or(RuntimeError::OwnerUnavailable)?;
    let index = if checkpoint { 2 } else { 0 };
    let bytes = controller
        .content(measurement)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    measurement
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let limit = attempt.row.provider.maximum_restored_record_bytes_data();
    if bytes.len() > limit || attempt.record_values[index].is_some() {
        return Err(RuntimeError::ResourceLimit);
    }
    attempt.record_values[index] =
        Some(canonical::parse_json(bytes, limit).map_err(|_| RuntimeError::InvalidReceipt)?);
    let value = attempt.record_values[index]
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    attempt.record_canonical[index] =
        canonical::canonical_json(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if attempt.record_canonical[index].as_slice() != bytes {
        return Err(RuntimeError::InvalidReceipt);
    }
    let record =
        serde::Deserialize::deserialize(value).map_err(|_| RuntimeError::InvalidReceipt)?;
    if checkpoint {
        attempt.checkpoint_record = Some(record);
    } else {
        attempt.completed_record = Some(record);
    }
    let record = if checkpoint {
        attempt.checkpoint_record.as_ref()
    } else {
        attempt.completed_record.as_ref()
    }
    .ok_or(RuntimeError::OwnerUnavailable)?;
    let underlying = controller
        .content(&record.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    record
        .native_receipt
        .native_record
        .verify(underlying)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let limit = attempt.row.provider.maximum_underlying_record_bytes_data();
    if underlying.len() > limit {
        return Err(RuntimeError::ResourceLimit);
    }
    attempt.record_values[index + 1] =
        Some(canonical::parse_json(underlying, limit).map_err(|_| RuntimeError::InvalidReceipt)?);
    attempt.record_canonical[index + 1] = canonical::canonical_json(
        attempt.record_values[index + 1]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    if attempt.record_canonical[index + 1].as_slice() != underlying {
        return Err(RuntimeError::InvalidReceipt);
    }
    let observed = controller
        .authenticate_original_restored_suffix_receipt_data(
            emitter, original, terminal, original, record, underlying,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if checkpoint {
        attempt.checkpoint_producer = Some(observed);
    } else {
        attempt.completed_producer = Some(observed);
    }
    Ok(())
}

pub(super) fn measurement_data(typed: &ResponseBody) -> Result<&ContentRef, RuntimeError> {
    if !matches!(&typed.shape, ResponseShape::Completed { extensions, .. } if extensions.is_empty())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    match typed.result.as_ref() {
        Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => {
            Ok(&result.stop_receipt)
        }
        Some(MethodResult::Observe(result)) => {
            let [batch] = result.observations.as_slice() else {
                return Err(RuntimeError::InvalidReceipt);
            };
            Ok(&batch.measurement_ref)
        }
        _ => Err(RuntimeError::InvalidReceipt),
    }
}

pub(super) fn completed_data<'a>(
    attempt: &'a ProducerProgressAttempt,
    checkpoint: (
        &'a PacketNativeRestoredRecord,
        &'a PacketNativeRecord,
        &'a ContentRef,
    ),
    launch: &'a PacketNative5SourceLaunch,
    held: &'a PacketNativeRestoredCommitHold,
) -> Result<PacketRestoredProducerCompletedData<'a>, RuntimeError> {
    let original = attempt
        .admission
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    Ok(PacketRestoredProducerCompletedData {
        launch,
        held,
        checkpoint: checkpoint.0,
        checkpoint_producer: checkpoint.1,
        restored: attempt
            .completed_record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        producer: attempt.producer_data()?,
        measurement: attempt
            .completed_measurement
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        begin: attempt
            .begin
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        poll: attempt
            .poll
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        operation: construction::operation_data(original.token().operation(), original.request())?,
        arguments: attempt
            .arguments
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    })
}

pub(super) fn signature_data(
    attempt: &ProducerProgressAttempt,
    key: &[u8; 32],
) -> Result<[u8; 32], RuntimeError> {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(b"crucible.source-restored-producer-history/1");
    hash.update(&attempt.slot.to_le_bytes());
    hash.update(&attempt.previous);
    let mut writer = HashWriter(&mut hash);
    for sdk in [
        &attempt.begin,
        &attempt.poll,
        &attempt.retire,
        &attempt.observe,
    ]
    .into_iter()
    .chain(attempt.uploads.iter())
    .flatten()
    {
        let (request, terminal, _) = sdk
            .completed_pair_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        serde_json::to_writer(&mut writer, &(request, terminal))
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    serde_json::to_writer(&mut writer, &attempt.record_values)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(&mut writer, &attempt.outcome)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(&mut writer, &attempt.report_reference)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let root = attempt
        .durable_root
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    serde_json::to_writer(&mut writer, &*root).map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::to_writer(&mut writer, &attempt.scheduling)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(*hash.finalize().as_bytes())
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

pub(super) fn counter_scratch_data() -> usize {
    use crucible_node_transport::{ProviderError, envelope::Envelope};
    size_of::<OriginalSourceRestoredProducerPhaseCompletion<'static>>()
        + size_of::<Result<OriginalSourceRestoredProducerPhaseCompletion<'static>, RuntimeError>>()
        + size_of::<PacketRestoredProducerCompletedData<'static>>()
        + size_of::<Result<PacketRestoredProducerCompletedData<'static>, RuntimeError>>()
        + size_of::<PacketRestoredProducerRetiredData<'static>>()
        + size_of::<(
            &PacketNativeRestoredRecord,
            &PacketNativeRecord,
            &ContentRef,
        )>()
        + size_of::<
            Result<
                (
                    &PacketNativeRestoredRecord,
                    &PacketNativeRecord,
                    &ContentRef,
                ),
                RuntimeError,
            >,
        >()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
        + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
        + size_of::<(&Envelope, &Envelope)>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<Result<&ContentRef, RuntimeError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<PacketNativeRestoredRecord, serde_json::Error>>()
        + size_of::<Result<PacketNative5UnderlyingRecord, crucible_node_transport::ProviderError>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<HashWriter<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<usize, io::Error>>()
        + size_of::<Result<(), io::Error>>()
        + size_of::<Result<[u8; 32], RuntimeError>>()
        + size_of::<[u8; 32]>() * 3
        + size_of::<[u8; size_of::<usize>()]>()
        + original_restored_producer_progress_counter_scratch_data()
}

pub(super) fn authenticate_completed_data(
    attempt: &ProducerProgressAttempt,
    controller: &CnpController,
    association: &OriginalAckPeerAssociation,
    checkpoint: (
        &PacketNativeRestoredRecord,
        &PacketNativeRecord,
        &ContentRef,
    ),
    launch: &PacketNative5SourceLaunch,
    held: &PacketNativeRestoredCommitHold,
) -> Result<(), RuntimeError> {
    let completed = proof::completed_data(attempt, checkpoint, launch, held)?;
    let (request, terminal, _) = completed
        .begin
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let raw = controller
        .content(&completed.restored.native_receipt.native_record)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    completed
        .restored
        .native_receipt
        .native_record
        .verify(raw)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let actual = controller
        .authenticate_original_restored_suffix_receipt_data(
            association
                .emitter
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            request,
            terminal,
            request,
            completed.restored,
            raw,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !matches!(actual, PacketNative5UnderlyingRecord::Producer(record) if record.as_ref() == completed.producer)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    authenticate_restored_producer_completed_data(&completed)
        .map_err(|_| RuntimeError::InvalidReceipt)
}
