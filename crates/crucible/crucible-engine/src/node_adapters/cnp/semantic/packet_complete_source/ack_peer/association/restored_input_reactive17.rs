//! Retains Source Input17 originals independently of legacy Input4 correlation.
//!
//! Every phase is appended only by the owning admitted signer. Historical SDK
//! frontier DATA is compared before any current validator runs. A partial or
//! failed phase blocks older proof reuse, including immutable first Observe.

use super::*;
use crate::node_contract::{NodeRuntime, WorldActivation};
use crucible_node_format::{Bytes, ContentRef, U64};
use crucible_node_transport::{
    bodies::{InputResult, MethodResult, OperationState, ResponseShape},
    client::OriginalRestoredSuffixHostAttempt,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::{
            complete_restore::{
                PacketNativeRestoredRecord,
                activation::{
                    restoration_activation_retained_native_evidence_data,
                    restoration_activation_scope_digest_data,
                },
            },
            restored_input_reactive17::{
                PacketRestoredInputReactive17Artifact, PacketRestoredInputReactive17Context,
                PacketRestoredInputReactive17PostCheckpointData,
                PacketRestoredInputReactive17RetainedData, RESTORED_INPUT_REACTIVE17_FEATURE,
                restored_input_reactive17_assigned_request_digest_data,
                restored_input_reactive17_context_schema_data,
                verify_restored_input_reactive17_proof_data,
            },
        },
    },
};
use std::{
    cell::{Cell, RefCell},
    mem::size_of,
    thread::ThreadId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Assigned,
    Published,
    SourceVerified,
    Complete,
    Failed,
}

struct InputReactive17Attempt {
    row: Option<crate::node_admission::OriginalRestoredInput17ConstructionData>,
    acknowledgement: Option<crate::node_scheduling::NativeInputAcknowledgement>,
    sdk: Option<OriginalRestoredSuffixHostAttempt>,
    artifact: Option<PacketRestoredInputReactive17Artifact>,
    context: Option<PacketRestoredInputReactive17Context>,
    post: Option<PacketRestoredInputReactive17PostCheckpointData>,
    record_value: Option<serde_json::Value>,
    record: Option<PacketNativeRestoredRecord>,
    underlying: Option<PacketNative5UnderlyingRecord>,
    input_result: Option<InputResult>,
    previous: [u8; 32],
    signature: Option<[u8; 32]>,
    stage: Cell<Stage>,
}

pub(super) struct InputReactive17History {
    process: u32,
    thread: ThreadId,
    failed: bool,
    attempts: Vec<InputReactive17Attempt>,
}

impl InputReactive17History {
    pub(super) fn new_data() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            failed: false,
            attempts: Vec::new(),
        }
    }

    pub(super) fn is_used_data(&self) -> bool {
        self.failed || !self.attempts.is_empty() || self.attempts.capacity() != 0
    }

    fn authenticate_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    fn completed_data(&self) -> Result<Option<&InputReactive17Attempt>, RuntimeError> {
        self.authenticate_origin_data()?;
        if self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let Some(attempt) = self.attempts.last() else {
            return Ok(None);
        };
        if attempt.stage.get() != Stage::Complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(Some(attempt))
    }

    pub(super) fn retained_heap_bytes_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
            sum_with_error, value_storage_with_error,
        };
        let mut bytes = self
            .attempts
            .capacity()
            .checked_mul(size_of::<InputReactive17Attempt>())
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| E::limit("Input17 Source history capacity"))?;
        for attempt in &self.attempts {
            if let Some(acknowledgement) = &attempt.acknowledgement {
                bytes = sum_with_error::<E, _>(
                    [
                        bytes,
                        NodeRuntime::original_input_ack_requested_storage_data(
                            acknowledgement,
                            maximum,
                        )
                        .map_err(|_| E::limit("Input17 Source acknowledgement"))?,
                    ],
                    maximum,
                )?;
            }
            if let Some(sdk) = &attempt.sdk {
                let facts = sdk.retained_metadata_data().map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            }
            for retained in [
                attempt
                    .artifact
                    .as_ref()
                    .map(PacketRestoredInputReactive17RetainedData::Artifact),
                attempt
                    .context
                    .as_ref()
                    .map(PacketRestoredInputReactive17RetainedData::Context),
                attempt
                    .post
                    .as_ref()
                    .map(PacketRestoredInputReactive17RetainedData::PostCheckpoint),
            ]
            .into_iter()
            .flatten()
            {
                let facts = retained
                    .original_retained_metadata_data()
                    .map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            }
            if let Some(value) = &attempt.record_value {
                bytes = sum_with_error::<E, _>(
                    [bytes, value_storage_with_error::<E>(value, 0, maximum)?],
                    maximum,
                )?;
            }
            if let Some(record) = &attempt.record {
                let facts = restoration_activation_retained_native_evidence_data(
                    record,
                    attempt.underlying.as_ref(),
                )
                .map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            } else if attempt.underlying.is_some() {
                return Err(E::unknown("Input17 model lacks retained restored owner"));
            }
            if let Some(result) = &attempt.input_result {
                let facts = crucible_node_transport::retained_metadata::RetainedCommonProtocolData::InputResult(result)
                    .observe_retained_metadata().map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            }
        }
        Ok(bytes)
    }
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_input_reactive_checkpoint_frontier17_data(
        &self,
    ) -> Result<Option<U64>, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .restored_inputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let Some(attempt) = history.completed_data()? else {
            return Ok(None);
        };
        Ok(Some(
            attempt
                .sdk
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .completed_frontier_data()
                .ok_or(RuntimeError::InvalidReceipt)?,
        ))
    }

    pub(crate) fn with_original_input_reactive_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_input17_checkpoint_stage_data(
            controller,
            world,
            key,
            frontier,
            Stage::Complete,
            inspect,
        )
    }

    fn with_original_input17_checkpoint_stage_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        stage: Stage,
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_input17_typed_checkpoint_stage_data(
            controller,
            world,
            key,
            frontier,
            stage,
            true,
            |record, _, measurement, frontier| {
                inspect(measurement, &record.native_receipt.native_record, frontier)
            },
        )
    }

    pub(crate) fn with_original_input_reactive_typed_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        current: bool,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_input17_typed_checkpoint_stage_data(
            controller,
            world,
            key,
            frontier,
            Stage::Complete,
            current,
            inspect,
        )
    }

    fn with_original_input17_typed_checkpoint_stage_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        frontier: U64,
        stage: Stage,
        current: bool,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let history = original
            .restored_inputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        let mut candidates = history.attempts.iter().filter(|attempt| {
            attempt
                .sdk
                .as_ref()
                .and_then(OriginalRestoredSuffixHostAttempt::completed_frontier_data)
                == Some(frontier)
        });
        let attempt = candidates.next().ok_or(RuntimeError::OwnerUnavailable)?;
        if candidates.next().is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
        if attempt.stage.get() != stage
            || match stage {
                Stage::Complete => history.failed,
                Stage::SourceVerified => !history.failed,
                _ => true,
            }
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        if attempt.signature != Some(signature_data(attempt, key)?) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if sdk.completed_frontier_data() != Some(frontier) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let (request, terminal, typed) = if current {
            sdk.authenticate_current_pair_data(controller, emitter)
        } else {
            sdk.authenticate_retained_pair_data(controller, emitter)
        }
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let artifact = attempt
            .artifact
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let context = attempt
            .context
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let row = attempt.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_owner_data(self, controller)?;
        if artifact.request.native_allocation != row.native
            || !matches!((row.phase, artifact.request.command.input_context_data()),
                (crate::node_contract::OriginalRuntimeInputPhase::Stage,
                    Some(crucible_node_transport::reference_packet::input::PacketInputContext::Stage { .. }))
                | (crate::node_contract::OriginalRuntimeInputPhase::Commit,
                    Some(crucible_node_transport::reference_packet::input::PacketInputContext::Commit { .. })))
        { return Err(RuntimeError::ForeignAuthority); }
        if request.extensions.len() != 1
            || context.request != artifact.request
            || context.schema != restored_input_reactive17_context_schema_data()
            || request
                .extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .is_none_or(|actual| serde_json::to_value(artifact).ok().as_ref() != Some(actual))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let maximum = controller
            .original_native5_storage_facts()
            .map_err(|_| RuntimeError::ResourceLimit)?
            .maximum_frame_bytes;
        let assigned = restored_input_reactive17_assigned_request_digest_data(request, maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if context.assigned_request.as_slice() != assigned {
            return Err(RuntimeError::InvalidReceipt);
        }
        verify_restored_input_reactive17_proof_data(key, context, &artifact.proof)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let ResponseShape::Completed {
            operation_state: OperationState::Completed,
            extensions,
            ..
        } = &typed.shape
        else {
            return Err(RuntimeError::InvalidReceipt);
        };
        let post = attempt
            .post
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if extensions.len() != 1
            || extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .is_none_or(|actual| serde_json::to_value(post).ok().as_ref() != Some(actual))
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        post.validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let Some(MethodResult::Input(actual)) = typed.result.as_ref() else {
            return Err(RuntimeError::InvalidReceipt);
        };
        if attempt.input_result.as_ref() != Some(actual) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let record = attempt
            .record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        super::restored_checkpoint17::authenticate_world_record_data(self, record, world)?;
        if post.current_model != record.native_receipt.native_record {
            return Err(RuntimeError::InvalidReceipt);
        }
        let raw = controller
            .content(&post.current_record)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        post.current_record
            .verify(raw)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let bytes = controller
            .content(&post.current_model)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let authenticated = controller
            .authenticate_original_restored_suffix_receipt_data(
                emitter, request, terminal, request, record, bytes,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if attempt.underlying.as_ref().is_none_or(|underlying| {
            !super::restored_checkpoint17::same_underlying_data(underlying, &authenticated)
        }) {
            return Err(RuntimeError::InvalidReceipt);
        }
        let result = inspect(
            record,
            attempt
                .underlying
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &post.current_record,
            frontier,
        );
        if current {
            sdk.authenticate_current_pair_data(controller, emitter)
        } else {
            sdk.authenticate_retained_pair_data(controller, emitter)
        }
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        result
    }
}

struct HashWriter<'a>(&'a mut blake3::Hasher);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn signature_data(
    attempt: &InputReactive17Attempt,
    key: &[u8; 32],
) -> Result<[u8; 32], RuntimeError> {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(b"crucible.source-restored-input-reactive-history/17\0");
    hash.update(&attempt.previous);
    let row = attempt.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    hash.update(&row.batch_digest);
    hash.update(&row.source_slot.to_le_bytes());
    hash.update(&[match row.phase {
        crate::node_contract::OriginalRuntimeInputPhase::Stage => 0,
        crate::node_contract::OriginalRuntimeInputPhase::Commit => 1,
    }]);
    let sdk = attempt.sdk.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    let (request, terminal, _) = sdk
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    // The terminal precedes recursive evidence reads. Bind the actual saved
    // completed SDK cut rather than reconstructing it from terminal.sequence.
    let frontier = sdk
        .completed_frontier_data()
        .ok_or(RuntimeError::InvalidReceipt)?;
    hash.update(&frontier.get().to_le_bytes());
    let mut writer = HashWriter(&mut hash);
    serde_json::to_writer(
        &mut writer,
        &(
            request,
            terminal,
            &attempt.artifact,
            &attempt.context,
            &attempt.post,
            &attempt.record,
            &attempt.underlying.as_ref().map(UnderlyingSignatureData),
            &attempt.input_result,
            &attempt.acknowledgement,
            &row.native,
            row.retained,
            row.transient,
            row.scratch,
            row.runtime_work,
            row.maximum,
        ),
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    Ok(*hash.finalize().as_bytes())
}

#[path = "restored_input_reactive17/checkpoint_cache17.rs"]
mod checkpoint_cache17;
pub(super) fn counter_scratch_data() -> usize {
    use crucible_node_transport::{
        ProviderError,
        bodies::ResponseBody,
        envelope::Envelope,
        retained_metadata::{RetainedCommonProtocolData, RetainedProtocolMetadataFacts},
    };
    size_of::<U64>()
        + size_of::<[u8; 8]>()
        + size_of::<UnderlyingSignatureData<'static>>()
        + size_of::<Option<UnderlyingSignatureData<'static>>>()
        + size_of::<InputReactive17History>()
        + size_of::<InputReactive17Attempt>()
        + size_of::<Option<&InputReactive17Attempt>>()
        + size_of::<Result<Option<&InputReactive17Attempt>, RuntimeError>>()
        + size_of::<std::cell::Ref<'static, InputReactive17History>>()
        + size_of::<Result<std::cell::Ref<'static, InputReactive17History>, std::cell::BorrowError>>(
        )
        + size_of::<std::cell::RefMut<'static, InputReactive17History>>()
        + size_of::<
            Result<std::cell::RefMut<'static, InputReactive17History>, std::cell::BorrowMutError>,
        >()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
        + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
        + size_of::<PacketNative5UnderlyingRecord>()
        + size_of::<Result<PacketNative5UnderlyingRecord, ProviderError>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<serde_json::Value>() * 2
        + size_of::<Result<serde_json::Value, serde_json::Error>>() * 2
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<[Option<PacketRestoredInputReactive17RetainedData<'static>>; 3]>()
        + size_of::<
            std::array::IntoIter<Option<PacketRestoredInputReactive17RetainedData<'static>>, 3>,
        >()
        + size_of::<
            std::iter::Flatten<
                std::array::IntoIter<Option<PacketRestoredInputReactive17RetainedData<'static>>, 3>,
            >,
        >()
        + size_of::<RetainedCommonProtocolData<'static>>()
        + size_of::<HashWriter<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<Result<[u8; 32], RuntimeError>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<usize, std::io::Error>>()
        + size_of::<Result<(), std::io::Error>>()
        + size_of::<Result<(), RuntimeError>>()
        + PacketRestoredInputReactive17RetainedData::counter_scratch_data()
        + OriginalRestoredSuffixHostAttempt::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfinished_reserved_bank_blocks_old_checkpoint_reuse_and_keeps_storage() {
        let mut history = InputReactive17History::new_data();
        assert!(history.completed_data().unwrap().is_none());
        history.failed = true;
        history.attempts.try_reserve_exact(1).unwrap();
        assert!(history.is_used_data());
        assert!(matches!(
            history.completed_data(),
            Err(RuntimeError::OutstandingObligations)
        ));
        let actual = history
            .retained_heap_bytes_with_error::<RuntimeError>(usize::MAX)
            .unwrap();
        assert!(actual >= size_of::<InputReactive17Attempt>());
        assert_eq!(
            history.retained_heap_bytes_with_error::<RuntimeError>(actual),
            Ok(actual)
        );
        assert!(
            history
                .retained_heap_bytes_with_error::<RuntimeError>(actual - 1)
                .is_err()
        );
        assert_eq!(history.attempts.len(), 0);
        assert!(history.failed);
    }

    #[test]
    fn a_foreign_history_cannot_expose_even_an_empty_completed_candidate() {
        let mut history = InputReactive17History::new_data();
        history.process = history.process.wrapping_add(1);
        assert!(matches!(
            history.completed_data(),
            Err(RuntimeError::ForeignAuthority)
        ));
    }
}

/// Gives the private history MAC a closed stable model discriminator.
struct UnderlyingSignatureData<'a>(&'a PacketNative5UnderlyingRecord);

impl serde::Serialize for UnderlyingSignatureData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut fields = serializer.serialize_struct("SourceInput17UnderlyingSignature", 2)?;
        match self.0 {
            PacketNative5UnderlyingRecord::Producer(record) => {
                fields.serialize_field("kind", "producer")?;
                fields.serialize_field("value", record)?;
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                fields.serialize_field("kind", "reactive")?;
                fields.serialize_field("value", record)?;
            }
        }
        fields.end()
    }
}

impl PacketCompleteSemanticSource {
    /// Refuses omitted logical Input17 history before a writer or Capture cut.
    ///
    /// # Errors
    /// Refuses another Source, unavailable/busy association, or any failed,
    /// pending, completed or reserved Input history owner.
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_unused_input17_owner_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let history = original
            .restored_inputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        history.authenticate_origin_data()?;
        if history.is_used_data() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}
