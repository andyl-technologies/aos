//! Retains two ordered Capture-owned uploads without unblocking generic traffic.
//!
//! The independent Source/native row is admitted before this code allocates.
//! A pending original is retained inline before vector growth or assignment;
//! completed originals move only into capacity reserved before their first IO.

use super::*;
use crate::reference_packet::service::restored_settled_capture::upload::*;

/// Owns one exact Capture auxiliary transfer body before fallible assignment.
pub enum RestoredSettledCaptureAuxiliaryBody {
    /// Starts the selected history-prefix or Runtime-object transfer.
    Begin(BlobBeginRequest),
    /// Continues that exact retained transfer at its acknowledged offset.
    Chunk(BlobChunkRequest),
    /// Finishes that exact retained transfer after all bytes were acknowledged.
    Finish(BlobFinishRequest),
}

impl RestoredSettledCaptureAuxiliaryBody {
    fn method(&self) -> Method {
        match self {
            Self::Begin(_) => Method::BlobBegin,
            Self::Chunk(_) => Method::BlobChunk,
            Self::Finish(_) => Method::BlobFinish,
        }
    }
}

impl Serialize for RestoredSettledCaptureAuxiliaryBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Begin(body) => body.serialize(serializer),
            Self::Chunk(body) => body.serialize(serializer),
            Self::Finish(body) => body.serialize(serializer),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum AuxiliaryStage {
    Preparing,
    Unsigned,
    Sealing,
    Assigned,
    Publishing,
    Complete,
}

pub(super) struct AuxiliaryOriginal {
    pub(super) request_id: Id,
    pub(super) body: RestoredSettledCaptureAuxiliaryBody,
    pub(super) continuation: Option<PacketRestoredSettledCaptureUploadContinuation>,
    pub(super) extension: Option<Value>,
    pub(super) original: Option<Envelope>,
    pub(super) cut: Option<OperationalDeadline>,
    pub(super) terminal: Option<Envelope>,
    pub(super) decoded: Option<Box<ResponseBody>>,
    pub(super) frontier: Option<U64>,
    pub(super) stage: AuxiliaryStage,
}

pub(super) struct AssignedAuxiliaryUpload {
    pub(super) request: PacketRestoredSettledCaptureUploadRequest,
    pub(super) context: Option<PacketRestoredSettledCaptureUploadContext>,
    pub(super) artifact: Option<PacketRestoredSettledCaptureUploadArtifact>,
    pub(super) pending: Option<AuxiliaryOriginal>,
    pub(super) completed: Vec<AuxiliaryOriginal>,
    pub(super) next_offset: U64,
    pub(super) maximum_chunk: Option<U64>,
    pub(super) finished: bool,
    pub(super) maximum_originals: usize,
}

/// Borrows the same retained pending original, including an unfinished proof.
#[must_use = "retain the same Controller and pending upload through failure"]
pub struct PreparedRestoredSettledCaptureAuxiliaryOriginal<'a> {
    controller: &'a mut CnpController,
    ordinal: usize,
}

fn index(ordinal: PacketRestoredSettledCaptureUploadOrdinal) -> usize {
    match ordinal {
        PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0,
        PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
    }
}

pub(super) fn both_complete(state: &AssignedRestoredSettledCapture) -> bool {
    state.auxiliary_uploads.iter().all(|slot| {
        slot.as_ref()
            .is_some_and(|upload| upload.finished && upload.pending.is_none())
    })
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Retains one ordinal declaration and its first original before allocation.
    ///
    /// The Runtime object follows the completed history-prefix transfer. A
    /// failed ordinal cannot be replaced and generic uploads remain blocked.
    ///
    /// # Errors
    /// Refuses a reused ordinal, changed Capture/content, wrong ordering or any
    /// failed assignment. Every initialized declaration/body remains retained.
    pub fn begin_auxiliary_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: PacketRestoredSettledCaptureUploadRequest,
        body: BlobBeginRequest,
    ) -> Result<PreparedRestoredSettledCaptureAuxiliaryOriginal<'_>, ProviderError> {
        let controller = &mut *self.controller;
        controller.authenticate_restored_settled_capture_data(emitter)?;
        let ordinal = index(request.ordinal);
        if controller.original(&request_id).is_some() {
            return Err(refused());
        }
        let state = controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if super::request_id_reserved(state, &request_id)
            || state.stage != Stage::Reserved
            || state.auxiliary_uploads[ordinal].is_some()
            || ordinal == 1
                && !state.auxiliary_uploads[0]
                    .as_ref()
                    .is_some_and(|u| u.finished && u.pending.is_none())
        {
            return Err(refused());
        }
        state.auxiliary_uploads[ordinal] = Some(AssignedAuxiliaryUpload {
            request,
            context: None,
            artifact: None,
            pending: Some(AuxiliaryOriginal {
                request_id,
                body: RestoredSettledCaptureAuxiliaryBody::Begin(body),
                continuation: None,
                extension: None,
                original: None,
                cut: None,
                terminal: None,
                decoded: None,
                frontier: None,
                stage: AuxiliaryStage::Preparing,
            }),
            completed: Vec::new(),
            maximum_originals: state.maximum_auxiliary_originals[ordinal],
            next_offset: U64::new(0),
            maximum_chunk: None,
            finished: false,
        });
        let upload = state.auxiliary_uploads[ordinal]
            .as_mut()
            .ok_or_else(refused)?;
        upload.request.validate_data()?;
        if upload.request.capture != state.request {
            return Err(refused());
        }
        prepare_pending(controller, ordinal)?;
        Ok(PreparedRestoredSettledCaptureAuxiliaryOriginal {
            controller,
            ordinal,
        })
    }

    /// Retains one exact Chunk or Finish under the acknowledged ordinal context.
    ///
    /// # Errors
    /// Refuses an unfinished prior original, a completed transfer, wrong offset,
    /// changed transfer/context or excessive chunk. Failure retains the body.
    pub fn continue_auxiliary_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        ordinal: PacketRestoredSettledCaptureUploadOrdinal,
        request_id: Id,
        body: RestoredSettledCaptureAuxiliaryBody,
    ) -> Result<PreparedRestoredSettledCaptureAuxiliaryOriginal<'_>, ProviderError> {
        let controller = &mut *self.controller;
        controller.authenticate_restored_settled_capture_data(emitter)?;
        if controller.original(&request_id).is_some() {
            return Err(refused());
        }
        let ordinal = index(ordinal);
        let state = controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if state.stage != Stage::Reserved || super::request_id_reserved(state, &request_id) {
            return Err(refused());
        }
        let upload = state.auxiliary_uploads[ordinal]
            .as_mut()
            .ok_or_else(refused)?;
        if upload.pending.is_some()
            || upload.finished
            || upload.maximum_chunk.is_none()
            || upload.completed.len() >= upload.maximum_originals
        {
            return Err(refused());
        }
        upload.pending = Some(AuxiliaryOriginal {
            request_id,
            body,
            continuation: None,
            extension: None,
            original: None,
            cut: None,
            terminal: None,
            decoded: None,
            frontier: None,
            stage: AuxiliaryStage::Preparing,
        });
        prepare_pending(controller, ordinal)?;
        Ok(PreparedRestoredSettledCaptureAuxiliaryOriginal {
            controller,
            ordinal,
        })
    }
}

fn prepare_pending(controller: &mut CnpController, ordinal: usize) -> Result<(), ProviderError> {
    let maximum = controller.maximum_frame()?;
    let negotiated_limits = controller.session.authority().limits();
    let state = controller
        .original_restored_settled_capture
        .as_mut()
        .ok_or_else(refused)?;
    let geometry = crate::reference_packet::service::native_startup::original_restored_settled_capture_auxiliary_geometry_for_limits_data(
        &negotiated_limits, &state.request.history_prefix, &state.request.runtime_object,
        state.maximum_auxiliary_originals[0].checked_add(state.maximum_auxiliary_originals[1])
            .and_then(|value| value.checked_add(2)).ok_or_else(refused)?,
    )?;
    let upload = state.auxiliary_uploads[ordinal]
        .as_mut()
        .ok_or_else(refused)?;
    // The inline pending owner survives a failed reservation. No later append
    // can allocate after this original's native effects have begun.
    if upload.completed.capacity() == 0 {
        upload
            .completed
            .try_reserve_exact(upload.maximum_originals)
            .map_err(|_| refused())?;
    }
    if upload.completed.len() >= upload.maximum_originals
        || upload.completed.capacity() < upload.maximum_originals
    {
        return Err(refused());
    }
    let pending = upload.pending.as_mut().ok_or_else(refused)?;
    match &pending.body {
        RestoredSettledCaptureAuxiliaryBody::Begin(body)
            if upload.completed.is_empty()
                && body.transfer_id == upload.request.transfer_id
                && body.content == upload.request.content
                && body.extensions.is_empty() =>
        {
            body.validate()?;
            let mut extension = serde_json::Map::new();
            extension.insert(
                "request".into(),
                serde_json::to_value(&upload.request)
                    .map_err(crucible_node_format::ContractError::from)?,
            );
            pending.extension = Some(Value::Object(extension));
        }
        RestoredSettledCaptureAuxiliaryBody::Chunk(body)
            if body.transfer_id == upload.request.transfer_id
                && body.offset == upload.next_offset
                && body.extensions.is_empty() =>
        {
            body.validate()?;
            let length = u64::try_from(body.bytes.as_slice().len()).map_err(|_| refused())?;
            let offset = usize::try_from(body.offset.get()).map_err(|_| refused())?;
            let expected = geometry.expected_chunk_length_data(ordinal, offset)?;
            if usize::try_from(length).map_err(|_| refused())? != expected
                || length > upload.maximum_chunk.ok_or_else(refused)?.get()
                || body.offset.checked_add(U64::new(length))? > upload.request.content.length
            {
                return Err(refused());
            }
            make_continuation(upload)?;
        }
        RestoredSettledCaptureAuxiliaryBody::Finish(body)
            if body.transfer_id == upload.request.transfer_id
                && body.extensions.is_empty()
                && upload.next_offset == upload.request.content.length =>
        {
            body.validate()?;
            make_continuation(upload)?;
        }
        _ => return Err(refused()),
    }
    let pending = upload.pending.as_mut().ok_or_else(refused)?;
    let (sequence, cut) = controller
        .session
        .begin_original_ack_admit(controller.budget)?;
    pending.cut = Some(cut);
    let mut extensions = Extensions::new();
    extensions.insert(
        RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(),
        pending.extension.as_ref().ok_or_else(refused)?.clone(),
    );
    let node = Some(controller.route.node.clone());
    let owner = None;
    let operation = None;
    let session = controller.session.authority().session_id().clone();
    let incarnation = controller.session.authority().incarnation_id().clone();
    count_serialized(
        &BorrowedEnvelope {
            protocol: "CNP/1",
            message: MessageKind::Request,
            session_id: &session,
            incarnation_id: &incarnation,
            node_id: &node,
            execution_owner_id: &owner,
            capture_owner_id: Some(&state.request.capture_owner),
            request_id: &pending.request_id,
            operation_id: &operation,
            sequence: U64::new(u64::MAX),
            method: pending.body.method(),
            body: &pending.body,
            extensions: &extensions,
        },
        maximum,
    )?;
    let Value::Object(body) =
        serde_json::to_value(&pending.body).map_err(crucible_node_format::ContractError::from)?
    else {
        return Err(refused());
    };
    pending.original = Some(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(session)),
        incarnation_id: Nullable(Some(incarnation)),
        node_id: Nullable(node),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(Some(state.request.capture_owner.clone())),
        request_id: Nullable(Some(pending.request_id.clone())),
        operation_id: Nullable(None),
        sequence,
        method: pending.body.method(),
        body,
        extensions,
    });
    let original = pending.original.as_ref().ok_or_else(refused)?;
    if original.method == Method::BlobBegin {
        restored_settled_capture_upload_assigned_request_digest_data(original, maximum)?;
        pending.stage = AuxiliaryStage::Unsigned;
    } else {
        authenticate_restored_settled_capture_upload_continuation_data(
            original,
            upload.context.as_ref().ok_or_else(refused)?,
            pending.continuation.as_ref().ok_or_else(refused)?,
        )?;
        pending.stage = AuxiliaryStage::Assigned;
    }
    controller
        .session
        .authenticate_original_ack_admit_cut(sequence, cut)?;
    Ok(())
}

fn make_continuation(upload: &mut AssignedAuxiliaryUpload) -> Result<(), ProviderError> {
    let digest = restored_settled_capture_upload_context_digest_data(
        upload.context.as_ref().ok_or_else(refused)?,
    )?;
    let pending = upload.pending.as_mut().ok_or_else(refused)?;
    pending.continuation = Some(PacketRestoredSettledCaptureUploadContinuation {
        schema: restored_settled_capture_upload_schema_ids_data().2.into(),
        context_digest: crucible_node_format::Bytes::new(digest.to_vec()),
        capture_operation: upload.request.capture.capture_operation.clone(),
        transfer_id: upload.request.transfer_id.clone(),
    });
    pending.extension = Some(
        serde_json::to_value(pending.continuation.as_ref().ok_or_else(refused)?)
            .map_err(crucible_node_format::ContractError::from)?,
    );
    Ok(())
}

impl PreparedRestoredSettledCaptureAuxiliaryOriginal<'_> {
    /// Borrows the same assigned original for Source context signing.
    ///
    /// # Errors
    /// Refuses absent assignment, revoked custody or an expired original cut.
    pub fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let upload = self
            .controller
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?
            .auxiliary_uploads[self.ordinal]
            .as_ref()
            .ok_or_else(refused)?;
        let pending = upload.pending.as_ref().ok_or_else(refused)?;
        let original = pending.original.as_ref().ok_or_else(refused)?;
        self.controller
            .session
            .authenticate_original_ack_admit_cut(
                original.sequence,
                pending.cut.ok_or_else(refused)?,
            )?;
        Ok(original)
    }

    /// Retains and inserts only the Source-signed proof for the same BlobBegin.
    ///
    /// # Errors
    /// Refuses another request/context, repeated sealing or expired assignment.
    /// Artifact and context partials remain retained after any refusal.
    pub fn seal_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        artifact: PacketRestoredSettledCaptureUploadArtifact,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_restored_settled_capture_data(emitter)?;
        self.original_data()?;
        let maximum = self.controller.maximum_frame()?;
        let upload = self
            .controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?
            .auxiliary_uploads[self.ordinal]
            .as_mut()
            .ok_or_else(refused)?;
        let pending = upload.pending.as_mut().ok_or_else(refused)?;
        if pending.stage != AuxiliaryStage::Unsigned || upload.artifact.is_some() {
            return Err(refused());
        }
        pending.stage = AuxiliaryStage::Sealing;
        upload.artifact = Some(artifact);
        let artifact = upload.artifact.as_ref().ok_or_else(refused)?;
        artifact.validate_data()?;
        if artifact.request != upload.request {
            return Err(refused());
        }
        let digest = restored_settled_capture_upload_assigned_request_digest_data(
            pending.original.as_ref().ok_or_else(refused)?,
            maximum,
        )?;
        upload.context = Some(PacketRestoredSettledCaptureUploadContext {
            schema: restored_settled_capture_upload_schema_ids_data().1.into(),
            request: upload.request.clone(),
            assigned_request: crucible_node_format::Bytes::new(digest.to_vec()),
        });
        if restored_settled_capture_upload_context_digest_data(
            upload.context.as_ref().ok_or_else(refused)?,
        )?
        .as_slice()
            != artifact.proof.context_digest.as_slice()
        {
            return Err(refused());
        }
        let original = pending.original.as_mut().ok_or_else(refused)?;
        let extension = original
            .extensions
            .get_mut(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?;
        if extension.len() != 1 || !extension.contains_key("request") {
            return Err(refused());
        }
        extension.insert(
            "proof".into(),
            serde_json::to_value(&artifact.proof)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        crate::connection::serialized_credit(original, maximum)?;
        pending.stage = AuxiliaryStage::Assigned;
        Ok(())
    }

    /// Publishes one exact original and retains raw/typed custody before checks.
    ///
    /// # Errors
    /// Refuses failed IO or a reply inconsistent with the actual transfer/offset.
    /// No retry, cut renewal, generic upload or content-fetch bypass is provided.
    pub fn publish_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_restored_settled_capture_data(emitter)?;
        self.original_data()?;
        let upload = self
            .controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?
            .auxiliary_uploads[self.ordinal]
            .as_mut()
            .ok_or_else(refused)?;
        let pending = upload.pending.as_mut().ok_or_else(refused)?;
        if pending.stage != AuxiliaryStage::Assigned {
            return Err(refused());
        }
        pending.stage = AuxiliaryStage::Publishing;
        self.controller
            .session
            .publish_original_restored_suffix_into(
                &mut self.controller.custody,
                pending.original.as_ref().ok_or_else(refused)?,
                pending.cut.ok_or_else(refused)?,
                &mut pending.terminal,
                &mut pending.decoded,
            )?;
        let response = pending.decoded.as_deref().ok_or_else(refused)?;
        if !matches!(
            &response.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) {
            return Err(refused());
        }
        match (&pending.body, response.result.as_ref()) {
            (
                RestoredSettledCaptureAuxiliaryBody::Begin(_),
                Some(MethodResult::BlobBegin(result)),
            ) if result.transfer_id == upload.request.transfer_id
                && result.next_offset == U64::new(0) =>
            {
                result.validate()?;
                upload.maximum_chunk = Some(result.maximum_chunk_bytes);
            }
            (
                RestoredSettledCaptureAuxiliaryBody::Chunk(body),
                Some(MethodResult::BlobChunk(result)),
            ) if result.transfer_id == upload.request.transfer_id => {
                let length = u64::try_from(body.bytes.as_slice().len()).map_err(|_| refused())?;
                let expected = body.offset.checked_add(U64::new(length))?;
                if result.next_offset != expected {
                    return Err(refused());
                }
                upload.next_offset = expected;
            }
            (
                RestoredSettledCaptureAuxiliaryBody::Finish(_),
                Some(MethodResult::BlobFinish(result)),
            ) if result.transfer_id == upload.request.transfer_id
                && result.content == upload.request.content =>
            {
                result.validate()?;
                upload.finished = true;
            }
            _ => return Err(refused()),
        }
        pending.frontier = Some(self.controller.session.fresh_restore_query_sequence()?);
        pending.stage = AuxiliaryStage::Complete;
        if upload.completed.len() == upload.completed.capacity() {
            return Err(refused());
        }
        let completed = upload.pending.take().ok_or_else(refused)?;
        upload.completed.push(completed);
        Ok(())
    }
}
