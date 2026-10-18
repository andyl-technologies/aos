//! Walks every independent Capture partial without live or completion predicates.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts, aliases::MetadataAliasBank,
    records::MetadataRecordBank,
};

impl AssignedRestoredSettledCapture {
    pub(crate) fn observe_retained_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request_id,
            operation_id,
            body,
            request,
            prefix_frontier: _,
            auxiliary_uploads,
            maximum_auxiliary_originals: _,
            arguments,
            unsigned_request,
            original,
            context,
            artifact,
            canonical,
            cut: _,
            terminal,
            decoded,
            roots,
            capture_frontier: _,
            confirmation,
            stage: _,
        } = self;
        observer.observe(request_id)?;
        observer.observe(operation_id)?;
        observer.observe(body)?;
        observer.observe(request)?;
        for upload in auxiliary_uploads.iter().flatten() {
            upload.observe_metadata_data(observer)?;
        }
        if let Some(arguments) = arguments {
            capture_arguments(arguments, observer)?;
        }
        observer.observe(unsigned_request)?;
        observer.observe(original)?;
        observer.observe(context)?;
        observer.observe(artifact)?;
        observer.observe(canonical)?;
        observer.observe(terminal)?;
        decoded_response(decoded, observer)?;
        observer.observe(roots)?;
        if let Some(confirmation) = confirmation {
            confirmation.observe_metadata_data(observer)?;
        }
        Ok(())
    }
}

fn capture_arguments(
    value: &CaptureArguments,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let CaptureArguments {
        capture_id,
        participant_ids,
        cut_id,
        cut,
        event_ordinal,
        ordering_profile,
        preservation_contract,
    } = value;
    observer.observe(capture_id)?;
    observer.observe(participant_ids)?;
    observer.observe(cut_id)?;
    observer.observe(cut)?;
    observer.observe(event_ordinal)?;
    observer.observe(ordering_profile)?;
    observer.observe(preservation_contract)
}

fn decoded_response(
    value: &Option<Box<ResponseBody>>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    if let Some(value) = value {
        observer.boxed_value(value.as_ref())?;
        crate::retained_metadata::historical_response_body_data(value)?
            .observe_retained_metadata_data(observer)?;
    }
    Ok(())
}

impl upload::AssignedAuxiliaryUpload {
    fn observe_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request,
            context,
            artifact,
            pending,
            completed,
            next_offset: _,
            maximum_chunk: _,
            finished: _,
            maximum_originals: _,
        } = self;
        observer.observe(request)?;
        observer.observe(context)?;
        observer.observe(artifact)?;
        if let Some(pending) = pending {
            pending.observe_metadata_data(observer)?;
        }
        observer.vector::<upload::AuxiliaryOriginal>(completed.capacity())?;
        for original in completed {
            original.observe_metadata_data(observer)?;
        }
        Ok(())
    }
}

impl upload::AuxiliaryOriginal {
    fn observe_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request_id,
            body,
            continuation,
            extension,
            original,
            cut: _,
            terminal,
            decoded,
            frontier: _,
            stage: _,
        } = self;
        observer.observe(request_id)?;
        match body {
            RestoredSettledCaptureAuxiliaryBody::Begin(value) => {
                let BlobBeginRequest {
                    transfer_id,
                    content,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(content)?;
                observer.observe(extensions)?;
            }
            RestoredSettledCaptureAuxiliaryBody::Chunk(value) => {
                let BlobChunkRequest {
                    transfer_id,
                    offset,
                    bytes,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(offset)?;
                observer.observe(bytes)?;
                observer.observe(extensions)?;
            }
            RestoredSettledCaptureAuxiliaryBody::Finish(value) => {
                let BlobFinishRequest {
                    transfer_id,
                    extensions,
                } = value;
                observer.observe(transfer_id)?;
                observer.observe(extensions)?;
            }
        }
        observer.observe(continuation)?;
        observer.observe(extension)?;
        observer.observe(original)?;
        observer.observe(terminal)?;
        decoded_response(decoded, observer)
    }
}

fn confirmation_request(
    value: &PacketRestoredSettledAfterConfirmationRequest,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketRestoredSettledAfterConfirmationRequest {
        schema,
        capture_request_id,
        capture_request_hash,
        capture_operation_id,
        capture_terminal_hash,
        capture_terminal_sequence,
        settled_capture_request,
        native_snapshot_ref,
        native_control_ref,
        native_anchor_ref,
    } = value;
    observer.observe(schema)?;
    observer.observe(capture_request_id)?;
    observer.observe(capture_request_hash)?;
    observer.observe(capture_operation_id)?;
    observer.observe(capture_terminal_hash)?;
    observer.observe(capture_terminal_sequence)?;
    observer.observe(settled_capture_request)?;
    observer.observe(native_snapshot_ref)?;
    observer.observe(native_control_ref)?;
    observer.observe(native_anchor_ref)
}

impl AssignedConfirmation {
    fn observe_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request_id,
            request,
            extension,
            original,
            cut: _,
            terminal,
            decoded,
            receipt,
            roots,
            frontier: _,
            stage: _,
        } = self;
        observer.observe(request_id)?;
        confirmation_request(request, observer)?;
        observer.observe(extension)?;
        observer.observe(original)?;
        observer.observe(terminal)?;
        decoded_response(decoded, observer)?;
        if let Some(receipt) = receipt {
            let PacketRestoredSettledAfterConfirmationReceipt {
                schema,
                capture,
                native_after_ref,
                native_after_capacity,
            } = receipt;
            observer.observe(schema)?;
            confirmation_request(capture, observer)?;
            observer.observe(native_after_ref)?;
            observer.observe(native_after_capacity)?;
        }
        observer.observe(roots)
    }
}

impl CnpController {
    /// Walks every retained Capture child, including rejected raw/typed partials.
    ///
    /// No currentness or completion predicate can hide a failed allocation.
    /// The defining whole Controller walker separately counts its inline root.
    ///
    /// # Errors
    /// Refuses unsupported response families, traversal exhaustion or overflow.
    pub fn original_restored_settled_capture_retained_metadata_data(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(state) = &self.original_restored_settled_capture {
            state.observe_retained_metadata_data(&mut observer)?;
        }
        Ok(observer.finish())
    }

    /// Records actual capacities and aliases into separately precharged banks.
    ///
    /// Both banks are cleared before this owner's walk. On exhaustion their
    /// partial rows remain; this method never grows either bank.
    ///
    /// # Errors
    /// Refuses finite bank/traversal exhaustion, unsupported children or overflow.
    pub fn record_original_restored_settled_capture_metadata_data(
        &self,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        if let Some(state) = &self.original_restored_settled_capture {
            state.observe_retained_metadata_data(&mut observer)?;
        }
        Ok(observer.finish())
    }

    /// Bounds actual Bytes serialization temporary independently of history output.
    ///
    /// Each Bytes temporary dies after serialize_str; the sum of actual vector
    /// backing bounds the largest such encoding. Output/DOM/canonical banks and
    /// serializer recursion are independent caller-admitted owners.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked base64 extent overflow.
    pub fn original_restored_settled_capture_history_transient_bytes_data(
        &self,
    ) -> Result<usize, ProviderError> {
        crate::retained_metadata::historical_serialization_transient_data(
            self.original_restored_settled_capture_retained_metadata_data()?,
        )
    }
}

impl CnpController {
    /// Names the defining Capture transport, history and actual return views.
    ///
    /// The Source conjoins this fixed demand before walking/quoting the future
    /// Capture row. It is DATA only and never authorizes allocation or IO.
    pub fn original_restored_settled_capture_counter_scratch_data() -> usize {
        use crate::reference_packet::service::restored_settled_capture::upload::*;
        use crate::retained_metadata::{HistoricalResponseBodyData, MetadataObserver};
        use crucible_node_contract::{Bytes, ContractError, HashRef};

        super::construction::counter_scratch_data()
            + size_of::<AssignedRestoredSettledCapture>()
            + size_of::<Option<AssignedRestoredSettledCapture>>()
            + size_of::<&AssignedRestoredSettledCapture>()
            + size_of::<&mut AssignedRestoredSettledCapture>()
            + size_of::<Option<&AssignedRestoredSettledCapture>>()
            + size_of::<Option<&mut AssignedRestoredSettledCapture>>()
            + size_of::<Result<&AssignedRestoredSettledCapture, ProviderError>>()
            + size_of::<Result<&mut AssignedRestoredSettledCapture, ProviderError>>()
            + size_of::<PreparedOriginalRestoredSettledCapture<'static>>()
            + size_of::<Result<PreparedOriginalRestoredSettledCapture<'static>, ProviderError>>()
            + size_of::<upload::PreparedRestoredSettledCaptureAuxiliaryOriginal<'static>>()
            + size_of::<Result<upload::PreparedRestoredSettledCaptureAuxiliaryOriginal<'static>, ProviderError>>()
            + size_of::<upload::AssignedAuxiliaryUpload>()
            + size_of::<Option<upload::AssignedAuxiliaryUpload>>()
            + size_of::<[Option<upload::AssignedAuxiliaryUpload>; 2]>()
            + size_of::<upload::AuxiliaryOriginal>()
            + size_of::<Option<upload::AuxiliaryOriginal>>()
            + size_of::<Vec<upload::AuxiliaryOriginal>>()
            + size_of::<RestoredSettledCaptureAuxiliaryBody>()
            + size_of::<AssignedConfirmation>()
            + size_of::<Option<AssignedConfirmation>>()
            + size_of::<&upload::AssignedAuxiliaryUpload>()
            + size_of::<&mut upload::AssignedAuxiliaryUpload>()
            + size_of::<Option<&upload::AssignedAuxiliaryUpload>>()
            + size_of::<Option<&mut upload::AssignedAuxiliaryUpload>>()
            + size_of::<Result<&upload::AssignedAuxiliaryUpload, ProviderError>>()
            + size_of::<Result<&mut upload::AssignedAuxiliaryUpload, ProviderError>>()
            + size_of::<&upload::AuxiliaryOriginal>()
            + size_of::<&mut upload::AuxiliaryOriginal>()
            + size_of::<Option<&upload::AuxiliaryOriginal>>()
            + size_of::<Option<&mut upload::AuxiliaryOriginal>>()
            + size_of::<Result<&upload::AuxiliaryOriginal, ProviderError>>()
            + size_of::<Result<&mut upload::AuxiliaryOriginal, ProviderError>>()
            + size_of::<Result<upload::AuxiliaryOriginal, ProviderError>>()
            + size_of::<&AssignedConfirmation>()
            + size_of::<&mut AssignedConfirmation>()
            + size_of::<Option<&AssignedConfirmation>>()
            + size_of::<Option<&mut AssignedConfirmation>>()
            + size_of::<Result<&AssignedConfirmation, ProviderError>>()
            + size_of::<Result<&mut AssignedConfirmation, ProviderError>>()
            + size_of::<&PacketRestoredSettledCaptureUploadContext>()
            + size_of::<Result<&PacketRestoredSettledCaptureUploadContext, ProviderError>>()
            + size_of::<&PacketRestoredSettledCaptureUploadArtifact>()
            + size_of::<Result<&PacketRestoredSettledCaptureUploadArtifact, ProviderError>>()
            + size_of::<&PacketRestoredSettledCaptureUploadContinuation>()
            + size_of::<Result<&PacketRestoredSettledCaptureUploadContinuation, ProviderError>>()
            + size_of::<&PacketRestoredSettledCaptureContext>()
            + size_of::<Result<&PacketRestoredSettledCaptureContext, ProviderError>>()
            + size_of::<&PacketRestoredSettledCaptureArtifact>()
            + size_of::<Result<&PacketRestoredSettledCaptureArtifact, ProviderError>>()
            + size_of::<&PacketRestoredSettledAfterConfirmationReceipt>()
            + size_of::<Result<&PacketRestoredSettledAfterConfirmationReceipt, ProviderError>>()
            + size_of::<&CaptureArguments>()
            + size_of::<&BeginRequest>()
            + size_of::<&BlobBeginRequest>()
            + size_of::<&BlobChunkRequest>()
            + size_of::<&BlobFinishRequest>()
            + size_of::<&PollRequest>()
            + size_of::<&CaptureResult>()
            + size_of::<&BlobBeginResult>()
            + size_of::<&BlobChunkResult>()
            + size_of::<&BlobFinishResult>()
            + size_of::<&PollResult>()
            + size_of::<&Option<Box<ResponseBody>>>()
            + size_of::<&mut Option<Box<ResponseBody>>>()
            + size_of::<&mut Option<Envelope>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Stage>()
            + size_of::<ConfirmationStage>()
            + size_of::<upload::AuxiliaryStage>()
            + size_of::<BeginArguments>()
            + size_of::<Result<BeginArguments, ContractError>>()
            + size_of::<BeginRequest>()
            + size_of::<CaptureArguments>()
            + size_of::<Option<CaptureArguments>>()
            + size_of::<BlobBeginRequest>()
            + size_of::<BlobChunkRequest>()
            + size_of::<BlobFinishRequest>()
            + size_of::<PollRequest>()
            + size_of::<PacketRestoredSettledCaptureRequest>()
            + size_of::<PacketRestoredSettledCaptureArtifact>()
            + size_of::<PacketRestoredSettledCaptureContext>()
            + size_of::<Option<PacketRestoredSettledCaptureArtifact>>()
            + size_of::<Option<PacketRestoredSettledCaptureContext>>()
            + size_of::<PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<PacketRestoredSettledCaptureUploadContext>()
            + size_of::<PacketRestoredSettledCaptureUploadArtifact>()
            + size_of::<PacketRestoredSettledCaptureUploadContinuation>()
            + size_of::<Option<PacketRestoredSettledCaptureUploadContext>>()
            + size_of::<Option<PacketRestoredSettledCaptureUploadArtifact>>()
            + size_of::<Option<PacketRestoredSettledCaptureUploadContinuation>>()
            + size_of::<PacketRestoredSettledAfterConfirmationRequest>()
            + size_of::<PacketRestoredSettledAfterConfirmationReceipt>()
            + size_of::<Option<PacketRestoredSettledAfterConfirmationReceipt>>()
            + size_of::<Result<PacketRestoredSettledAfterConfirmationReceipt, serde_json::Error>>()
            + size_of::<Result<PacketRestoredSettledAfterConfirmationReceipt, ContractError>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<&mut MetadataRecordBank>()
            + size_of::<&mut MetadataAliasBank>()
            + size_of::<Envelope>()
            + size_of::<Option<Envelope>>()
            + size_of::<ResponseBody>()
            + size_of::<Option<Box<ResponseBody>>>()
            + size_of::<Value>()
            + size_of::<Option<Value>>()
            + size_of::<serde_json::Map<String, Value>>()
            + size_of::<Extensions>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<Value, ContractError>>()
            + size_of::<Bytes>()
            + size_of::<Vec<u8>>()
            + size_of::<Vec<ContentRef>>()
            + size_of::<ContentRef>()
            + size_of::<HashRef>()
            + size_of::<Result<ContentRef, ContractError>>()
            + size_of::<Result<HashRef, ContractError>>()
            + size_of::<Result<HashRef, ProviderError>>()
            + size_of::<Id>()
            + 3 * size_of::<Option<Id>>()
            + size_of::<(U64, OperationalDeadline)>()
            + size_of::<Result<(U64, OperationalDeadline), ProviderError>>()
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<Option<U64>>()
            + size_of::<Result<U64, ContractError>>()
            + size_of::<Result<U64, ProviderError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), ContractError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<[u8; 32]>()
            + size_of::<Result<[u8; 32], ProviderError>>()
            + size_of::<BorrowedEnvelope<'static, BeginRequest>>()
            + size_of::<BorrowedEnvelope<'static, PollRequest>>()
            + size_of::<BorrowedEnvelope<'static, RestoredSettledCaptureAuxiliaryBody>>()
            + size_of::<OriginalRestoredSettledCaptureData<'static>>()
            + size_of::<Result<OriginalRestoredSettledCaptureData<'static>, ProviderError>>()
            + size_of::<HistoricalResponseBodyData<'static>>()
            + size_of::<Result<HistoricalResponseBodyData<'static>, ProviderError>>()
            + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
            + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Option<&mut Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Result<&mut Envelope, ProviderError>>()
            + size_of::<Option<&ResponseBody>>()
            + size_of::<Result<&ResponseBody, ProviderError>>()
            + size_of::<Option<&serde_json::Map<String, Value>>>()
            + size_of::<Option<&mut serde_json::Map<String, Value>>>()
            + size_of::<Result<&mut serde_json::Map<String, Value>, ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<Option<&CaptureResult>>()
            + size_of::<Option<&PacketRestoredSettledAfterConfirmationReceipt>>()
            + size_of::<Option<&PacketRestoredSettledAfterConfirmationRequest>>()
            + size_of::<&[u8]>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<serde_json::map::Values<'static>>()
            + size_of::<std::collections::btree_map::Values<'static, Id, ClientOriginal>>()
            + size_of::<[usize; 2]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>()
            + size_of::<u64>()
            + size_of::<bool>()
            + size_of::<&'static str>()
            + ClientSession::original_restored_suffix_counter_scratch_data()
            + crate::connection::original_serialized_credit_counter_scratch_data()
            + crate::retained_metadata::historical_response_body_counter_scratch_data()
            + size_of::<crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData>()
            + size_of::<Result<crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData, ProviderError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<Result<&usize, ProviderError>>()
            + size_of::<[usize; 2]>()
            + size_of::<&[usize; 2]>()
            + size_of::<bool>()
            + crate::reference_packet::service::native_startup::original_restored_settled_capture_auxiliary_geometry_counter_scratch_data()
            + restored_settled_capture_contract_counter_scratch_data()
            + restored_settled_capture_schema_counter_scratch_data()
            + crate::reference_packet::service::complete_restore::settled_recapture::restored_settled_capture_selection_counter_scratch_data()
            + restored_settled_capture_upload_counter_scratch_data()
            + restored_settled_capture_upload_schema_counter_scratch_data()
            + restored_settled_after_confirmation_counter_scratch_data()
            + restored_settled_after_confirmation_schema_counter_scratch_data()
            + super::history::counter_scratch_data()
            + super::current::counter_scratch_data()
            + field_views_counter()
    }
}

fn capture_field_views<T>(_: impl FnOnce(&'static AssignedRestoredSettledCapture) -> T) -> usize {
    size_of::<T>()
}

fn upload_field_views<T>(_: impl FnOnce(&'static upload::AssignedAuxiliaryUpload) -> T) -> usize {
    size_of::<T>()
}

fn original_field_views<T>(_: impl FnOnce(&'static upload::AuxiliaryOriginal) -> T) -> usize {
    size_of::<T>()
}

fn confirmation_field_views<T>(_: impl FnOnce(&'static AssignedConfirmation) -> T) -> usize {
    size_of::<T>()
}

fn field_views_counter() -> usize {
    capture_field_views(|value| {
        let AssignedRestoredSettledCapture {
            request_id,
            operation_id,
            body,
            request,
            prefix_frontier,
            auxiliary_uploads,
            maximum_auxiliary_originals,
            arguments,
            unsigned_request,
            original,
            context,
            artifact,
            canonical,
            cut,
            terminal,
            decoded,
            roots,
            capture_frontier,
            confirmation,
            stage,
        } = value;
        (
            request_id,
            operation_id,
            body,
            request,
            prefix_frontier,
            auxiliary_uploads,
            maximum_auxiliary_originals,
            arguments,
            unsigned_request,
            original,
            context,
            artifact,
            canonical,
            cut,
            terminal,
            decoded,
            roots,
            capture_frontier,
            confirmation,
            stage,
        )
    }) + upload_field_views(|value| {
        let upload::AssignedAuxiliaryUpload {
            request,
            context,
            artifact,
            pending,
            completed,
            next_offset,
            maximum_chunk,
            finished,
            maximum_originals,
        } = value;
        (
            request,
            context,
            artifact,
            pending,
            completed,
            next_offset,
            maximum_chunk,
            finished,
            maximum_originals,
        )
    }) + original_field_views(|value| {
        let upload::AuxiliaryOriginal {
            request_id,
            body,
            continuation,
            extension,
            original,
            cut,
            terminal,
            decoded,
            frontier,
            stage,
        } = value;
        (
            request_id,
            body,
            continuation,
            extension,
            original,
            cut,
            terminal,
            decoded,
            frontier,
            stage,
        )
    }) + confirmation_field_views(|value| {
        let AssignedConfirmation {
            request_id,
            request,
            extension,
            original,
            cut,
            terminal,
            decoded,
            receipt,
            roots,
            frontier,
            stage,
        } = value;
        (
            request_id, request, extension, original, cut, terminal, decoded, receipt, roots,
            frontier, stage,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_upload_partial_census_counts_actual_bytes_and_box_without_completion() {
        let mut bytes = Vec::with_capacity(137);
        bytes.extend_from_slice(b"not yet acknowledged");
        let bytes = Bytes::new(bytes);
        let byte_capacity = bytes.allocation_capacity();
        let pending = upload::AuxiliaryOriginal {
            request_id: Id::new("capture-census-original").unwrap(),
            body: RestoredSettledCaptureAuxiliaryBody::Chunk(BlobChunkRequest {
                transfer_id: Id::new("capture-census-transfer").unwrap(),
                offset: U64::new(0),
                bytes,
                extensions: Extensions::new(),
            }),
            continuation: None,
            extension: None,
            original: None,
            cut: None,
            terminal: None,
            decoded: Some(Box::new(ResponseBody {
                shape: ResponseShape::Error {
                    operation_state: OperationState::Unknown,
                    error: ErrorRecord {
                        code: "OUTCOME_UNKNOWN".into(),
                        message: "before terminal completion".into(),
                        effect: EffectCertainty::Unknown,
                        retryable: false,
                        details: Default::default(),
                    },
                    extensions: Extensions::new(),
                },
                result: Some(MethodResult::BlobChunk(BlobChunkResult {
                    transfer_id: Id::new("separate-typed-child").unwrap(),
                    next_offset: U64::new(3),
                })),
            })),
            frontier: None,
            stage: upload::AuxiliaryStage::Publishing,
        };

        let mut observer = MetadataObserver::new();
        pending.observe_metadata_data(&mut observer).unwrap();
        let facts = observer.finish();
        assert_eq!(facts.vector_capacity_bytes, byte_capacity);
        assert_eq!(facts.boxed_value_bytes, size_of::<ResponseBody>());
        assert!(facts.string_capacity_bytes >= "separate-typed-child".len());
        assert!(pending.terminal.is_none());
        assert!(pending.frontier.is_none());
    }
}

impl CnpController {
    /// Reports the defining per-original vector element layout for both uploads.
    ///
    /// This is numeric DATA for the independently admitted Source future row.
    /// The actual finite original counts, body/DOM/canonical/reply backing and
    /// whole Controller inline root remain independent obligations.
    pub const fn original_restored_settled_capture_auxiliary_original_header_data() -> usize {
        size_of::<upload::AuxiliaryOriginal>()
    }
}
