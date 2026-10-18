//! Retains two once-only signed upload originals under one cut per content.
//!
//! Each actual BlobBegin is assigned from the same exclusive Session sequence
//! before signing. Its request, proof and every actual chunk/finish original and
//! response remain in the Controller after refusal or unwind. No generic upload
//! retry, sequence rewrite or shortened progress loop is available here.

use super::*;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::reference_packet::service::complete_restore::activation::upload::*;
use crate::retained_metadata::MetadataObserver;
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Preparing,
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(in crate::client::controller) struct AssignedUpload {
    request: PacketRestorationActivationUploadRequest,
    transfer: Option<Id>,
    pending_content: Option<(ContentRef, Vec<u8>)>,
    frames: Vec<Frame>,
    cut: OperationalDeadline,
    state: State,
}

struct Frame {
    request_id: Id,
    method: Method,
    offset: usize,
    length: usize,
    original: Option<Envelope>,
    received: Option<ReceivedFrame>,
    attempted: bool,
    complete: bool,
}

/// Borrows a real assigned BlobBegin until the complete bounded upload finishes.
#[must_use = "retain the same Controller and every failed partial upload owner"]
pub struct PreparedOriginalInstalledRestorationUpload<'a> {
    controller: &'a mut CnpController,
    role: PacketRestorationActivationUploadRole,
}

/// Borrows the exact completed upload originals without issuing activation rights.
pub struct CompletedOriginalInstalledRestorationUpload<'a> {
    request: &'a PacketRestorationActivationUploadRequest,
    begin: &'a Envelope,
    terminal: &'a Envelope,
    body: &'a ReceivedBody,
}

impl CompletedOriginalInstalledRestorationUpload<'_> {
    /// Borrows the exact signed content/scope/ordinal original.
    pub fn request_data(&self) -> &PacketRestorationActivationUploadRequest {
        self.request
    }

    /// Borrows the exact original signed BlobBegin request.
    pub fn original(&self) -> &Envelope {
        self.begin
    }

    /// Borrows the actual final same-content BlobFinish terminal.
    pub fn response(&self) -> &Envelope {
        self.terminal
    }

    /// Borrows the actual retained typed Finish response without decoding again.
    ///
    /// # Errors
    /// Refuses an unexpected retained request/notification owner.
    pub fn response_body_data(&self) -> Result<&ResponseBody, ProviderError> {
        let ReceivedBody::Response(body) = self.body else {
            return Err(refused());
        };
        Ok(body.as_ref())
    }
}

impl CnpController {
    /// Assigns one genuine separately funded upload Begin before proof creation.
    ///
    /// Core's once World claim and SourceRead fence remain separate required
    /// authorities. This marker binds the same actual Controller and exact
    /// content tuple; it cannot create a Source key, native grant or readiness.
    ///
    /// # Errors
    /// Refuses missing current selection, changed preadmitted DATA/target/ref,
    /// replay or wrong ordinal, unresolved Arm/Commit, capacity or deadline.
    pub fn prepare_original_installed_restoration_upload(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request: PacketRestorationActivationUploadRequest,
        admitted: &OriginalInstalledRestorationActivationConstructionData,
    ) -> Result<PreparedOriginalInstalledRestorationUpload<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_installed_restoration_activation()?;
        self.protocol_owner.ensure_current()?;
        admitted.authenticate_controller_data(Rc::as_ptr(&self.protocol_owner).cast())?;
        request.validate_data()?;
        let role = request.role;
        self.original_installed_restoration_activation_target_binding_data()?
            .authenticate_scope_data(&request.scope)?;
        if self.original_installed_restoration_upload[role.ordinal_data()].is_some()
            || self
                .original_installed_restoration_upload
                .iter()
                .flatten()
                .any(|state| state.state != State::Complete)
            || (role == PacketRestorationActivationUploadRole::Manifest
                && self.original_installed_restoration_upload[0]
                    .as_ref()
                    .is_none_or(|state| state.state != State::Complete))
            || request.native_allocation != admitted.upload_native_allocation_data(role)
            || request.chunk_bytes.get() != admitted.upload_chunk_bytes_data(role) as u64
            || request.maximum_frame_bytes.get() != self.authority().limits().frame_bytes.get()
            || request.maximum_frame_bytes.get()
                != admitted.upload_maximum_frame_bytes_data(role) as u64
            || request.coordinator.length.get()
                > admitted.upload_maximum_content_bytes_data(
                    PacketRestorationActivationUploadRole::Coordinator,
                ) as u64
            || request.manifest.length.get()
                > admitted.upload_maximum_content_bytes_data(
                    PacketRestorationActivationUploadRole::Manifest,
                ) as u64
        {
            return Err(refused());
        }
        self.original_completed_installed_restoration_activation(
            emitter,
            PacketRestorationActivationPhase::Arm,
        )?;
        if role == PacketRestorationActivationUploadRole::Manifest {
            let first = self.original_installed_restoration_upload[0]
                .as_ref()
                .ok_or_else(refused)?;
            if first.request.scope != request.scope
                || first.request.coordinator != request.coordinator
                || first.request.manifest != request.manifest
            {
                return Err(refused());
            }
        }
        admitted.preflight_upload_data(self, role)?;
        let (_, cut) = self.session.begin_original_restore_upload(self.budget)?;
        self.original_installed_restoration_upload[role.ordinal_data()] = Some(AssignedUpload {
            request,
            transfer: None,
            pending_content: None,
            frames: Vec::new(),
            cut,
            state: State::Preparing,
        });
        let state = self.original_installed_restoration_upload[role.ordinal_data()]
            .as_mut()
            .ok_or_else(refused)?;
        let count = usize::try_from(state.request.maximum_requests.get()).map_err(|_| refused())?;
        let length = usize::try_from(state.request.content_ref_data().length.get())
            .map_err(|_| refused())?;
        let chunk = usize::try_from(state.request.chunk_bytes.get()).map_err(|_| refused())?;
        state
            .frames
            .try_reserve_exact(count)
            .map_err(|_| credit())?;
        let prefix = blake3::hash(&canonical::canonical_json(
            &serde_json::to_value(&state.request)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?)
        .to_hex();
        state.transfer = Some(Id::new(format!("cnp-activation-upload-{prefix}"))?);
        for index in 0..count {
            let (method, offset, size) = if index == 0 {
                (Method::BlobBegin, 0, 0)
            } else if index == count - 1 {
                (Method::BlobFinish, length, 0)
            } else {
                let offset = (index - 1).checked_mul(chunk).ok_or_else(credit)?;
                (
                    Method::BlobChunk,
                    offset,
                    length.saturating_sub(offset).min(chunk),
                )
            };
            state.frames.push(Frame {
                request_id: Id::new(format!("cnp-activation-upload-{prefix}-{index}"))?,
                method,
                offset,
                length: size,
                original: None,
                received: None,
                attempted: false,
                complete: false,
            });
        }
        let begin = serde_json::to_value(BlobBeginRequest {
            transfer_id: state.transfer.as_ref().ok_or_else(refused)?.clone(),
            content: state.request.content_ref_data().clone(),
            extensions: Extensions::new(),
        })
        .map_err(crucible_node_contract::ContractError::from)?;
        let Value::Object(body) = begin else {
            return Err(refused());
        };
        let mut extension = serde_json::Map::new();
        extension.insert(
            "request".into(),
            serde_json::to_value(&state.request)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
            Value::Object(extension),
        );
        state.frames[0].original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.session.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.session.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(state.frames[0].request_id.clone())),
            sequence: self.session.original_restore_upload_sequence(cut)?,
            method: Method::BlobBegin,
            body,
            extensions,
        });
        let maximum =
            usize::try_from(state.request.maximum_frame_bytes.get()).map_err(|_| credit())?;
        crate::connection::serialized_credit(
            state.frames[0].original.as_ref().ok_or_else(refused)?,
            maximum,
        )?
        .checked_add(maximum_restoration_activation_upload_proof_encoded_bytes_data()?)
        .and_then(|bytes| bytes.checked_add(9))
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(credit)?;
        state.state = State::Unsigned;
        Ok(PreparedOriginalInstalledRestorationUpload {
            controller: self,
            role,
        })
    }

    /// Borrows a real completed same-scope upload without renewing its once slot.
    ///
    /// # Errors
    /// Refuses another emitter, unfinished/failed upload or missing original pair.
    pub fn original_completed_installed_restoration_upload_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<CompletedOriginalInstalledRestorationUpload<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self.original_installed_restoration_upload[role.ordinal_data()]
            .as_ref()
            .ok_or_else(refused)?;
        if state.state != State::Complete || state.frames.iter().any(|frame| !frame.complete) {
            return Err(refused());
        }
        Ok(CompletedOriginalInstalledRestorationUpload {
            request: &state.request,
            begin: state
                .frames
                .first()
                .and_then(|frame| frame.original.as_ref())
                .ok_or_else(refused)?,
            terminal: &state
                .frames
                .last()
                .and_then(|frame| frame.received.as_ref())
                .ok_or_else(refused)?
                .envelope,
            body: &state
                .frames
                .last()
                .and_then(|frame| frame.received.as_ref())
                .ok_or_else(refused)?
                .body,
        })
    }
}

impl PreparedOriginalInstalledRestorationUpload<'_> {
    /// Borrows the actual assigned Begin, with its unchanged sequence and body.
    ///
    /// # Errors
    /// Refuses absent/failed state, changed actor or the expired original cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self.state()?;
        self.controller
            .session
            .original_restore_upload_sequence(state.cut)?;
        state
            .frames
            .first()
            .and_then(|frame| frame.original.as_ref())
            .ok_or_else(refused)
    }

    /// Inserts only the Source-signed proof without reassigning the Begin.
    ///
    /// # Errors
    /// Refuses another original/role/context, malformed proof or final frame cap.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        artifact: PacketRestorationActivationUploadArtifact,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        artifact.validate_data()?;
        let maximum = self.controller.maximum_frame()?;
        let assigned = restoration_activation_upload_assigned_request_digest(
            self.original()?,
            self.role,
            maximum,
        )?;
        let context = PacketRestorationActivationUploadContext {
            request: artifact.request.clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        if artifact.proof.context_digest.as_slice()
            != restoration_activation_upload_context_digest_data(&context)?
        {
            return Err(refused());
        }
        let state = self.controller.original_installed_restoration_upload[self.role.ordinal_data()]
            .as_mut()
            .ok_or_else(refused)?;
        if state.state != State::Unsigned || state.request != artifact.request {
            return Err(refused());
        }
        state.state = State::Sealing;
        let original = state.frames[0].original.as_mut().ok_or_else(refused)?;
        let value = original
            .extensions
            .get_mut(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?;
        if value.len() != 1 || !value.contains_key("request") {
            return Err(refused());
        }
        value.insert(
            "proof".into(),
            serde_json::to_value(artifact.proof)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        crate::connection::serialized_credit(original, maximum)?;
        state.state = State::Sealed;
        Ok(())
    }

    /// Publishes the real signed Begin once and retains its actual ACK first.
    ///
    /// # Errors
    /// Refuses replay, a foreign/short chunk allowance, invalid ACK or uncertain IO.
    pub fn publish_begin_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        if self.state()?.state != State::Sealed {
            return Err(refused());
        }
        self.exchange_frame(0, None)?;
        Ok(())
    }

    /// Publishes the fixed remaining chunk/finish plan under the same original cut.
    ///
    /// # Errors
    /// Refuses changed exact bytes, unfinished Begin, retries, malformed progress,
    /// deadline, capacity, protocol refusal or uncertain IO. Actual partials remain.
    pub fn publish_remaining_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        let state = self.state()?;
        state.request.content_ref_data().verify(bytes)?;
        if state.state != State::Publishing || !state.frames[0].complete {
            return Err(refused());
        }
        let count = state.frames.len();
        if state.pending_content.is_some() {
            return Err(refused());
        }
        let controller = &mut *self.controller;
        let state = controller.original_installed_restoration_upload[self.role.ordinal_data()]
            .as_mut()
            .ok_or_else(refused)?;
        // Retain the independently admitted cache copy before allocating its
        // body or sending another original. Failed uploads keep this partial.
        state.pending_content = Some((state.request.content_ref_data().clone(), Vec::new()));
        let (_, pending) = state.pending_content.as_mut().ok_or_else(refused)?;
        pending
            .try_reserve_exact(bytes.len())
            .map_err(|_| credit())?;
        pending.extend_from_slice(bytes);
        for index in 1..count {
            self.exchange_frame(index, Some(bytes))?;
            emitter.authenticate_original(self.controller)?;
        }
        let controller = &mut *self.controller;
        let state = controller.original_installed_restoration_upload[self.role.ordinal_data()]
            .as_mut()
            .ok_or_else(refused)?;
        // Completion includes the real Controller content owner used by the
        // later World manifest/coordinator checks. No ref-only cache evidence.
        controller
            .custody
            .content_mut()
            .install_original_host_startup_from_slot(&mut state.pending_content)?;
        state.state = State::Complete;
        Ok(())
    }

    fn state(&self) -> Result<&AssignedUpload, ProviderError> {
        self.controller.original_installed_restoration_upload[self.role.ordinal_data()]
            .as_ref()
            .ok_or_else(refused)
    }

    fn exchange_frame(&mut self, index: usize, bytes: Option<&[u8]>) -> Result<(), ProviderError> {
        let controller = &mut *self.controller;
        let state = controller.original_installed_restoration_upload[self.role.ordinal_data()]
            .as_mut()
            .ok_or_else(refused)?;
        let frame = state.frames.get_mut(index).ok_or_else(refused)?;
        if frame.attempted || frame.complete || (index != 0 && frame.original.is_some()) {
            return Err(refused());
        }
        // Spend before any body clone, allocation or send. An unwind cannot
        // produce an unattempted frame or resume with a fresh deadline.
        frame.attempted = true;
        state.state = State::Publishing;
        if index != 0 {
            let transfer = state.transfer.as_ref().ok_or_else(refused)?;
            let body = match frame.method {
                Method::BlobChunk => {
                    let end = frame.offset.checked_add(frame.length).ok_or_else(credit)?;
                    let bytes = bytes
                        .and_then(|bytes| bytes.get(frame.offset..end))
                        .ok_or_else(refused)?;
                    serde_json::to_value(BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new(frame.offset as u64),
                        bytes: Bytes::new(bytes.to_vec()),
                        extensions: Extensions::new(),
                    })
                }
                Method::BlobFinish => serde_json::to_value(BlobFinishRequest {
                    transfer_id: transfer.clone(),
                    extensions: Extensions::new(),
                }),
                _ => return Err(refused()),
            }
            .map_err(crucible_node_contract::ContractError::from)?;
            let Value::Object(body) = body else {
                return Err(refused());
            };
            frame.original = Some(Envelope {
                protocol: "CNP/1".into(),
                message: MessageKind::Request,
                session_id: Nullable(Some(controller.session.authority().session_id().clone())),
                incarnation_id: Nullable(Some(
                    controller.session.authority().incarnation_id().clone(),
                )),
                node_id: Nullable(None),
                execution_owner_id: Nullable(None),
                capture_owner_id: Nullable(None),
                operation_id: Nullable(None),
                request_id: Nullable(Some(frame.request_id.clone())),
                sequence: controller
                    .session
                    .original_restore_upload_sequence(state.cut)?,
                method: frame.method,
                body,
                extensions: Extensions::new(),
            });
        }
        let original = frame.original.as_ref().ok_or_else(refused)?;
        controller.session.exchange_original_restore_upload_into(
            &mut controller.custody,
            original,
            state.cut,
            &mut frame.received,
        )?;
        let ReceivedBody::Response(body) = &frame.received.as_ref().ok_or_else(refused)?.body
        else {
            return Err(refused());
        };
        let transfer = state.transfer.as_ref().ok_or_else(refused)?;
        let matches = match &body.result {
            Some(MethodResult::BlobBegin(progress)) if frame.method == Method::BlobBegin => {
                &progress.transfer_id == transfer
                    && progress.next_offset.get() == 0
                    && progress.maximum_chunk_bytes >= state.request.chunk_bytes
            }
            Some(MethodResult::BlobChunk(progress)) if frame.method == Method::BlobChunk => {
                &progress.transfer_id == transfer
                    && progress.next_offset.get()
                        == frame.offset.checked_add(frame.length).ok_or_else(credit)? as u64
            }
            Some(MethodResult::BlobFinish(progress)) if frame.method == Method::BlobFinish => {
                &progress.transfer_id == transfer
                    && &progress.content == state.request.content_ref_data()
            }
            _ => false,
        };
        if !matches
            || !frame
                .received
                .as_ref()
                .ok_or_else(refused)?
                .envelope
                .extensions
                .is_empty()
            || !matches!(&body.shape, ResponseShape::Completed { operation_state: OperationState::Completed, extensions, .. } if extensions.is_empty())
        {
            return Err(refused());
        }
        frame.complete = true;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("selected restoration upload original differs")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("selected restoration upload construction")
}

impl AssignedUpload {
    pub(super) fn authenticate_completed_world_data(
        &self,
        scope: &PacketRestorationActivationScope,
        manifest: &ContentRef,
    ) -> Result<(), ProviderError> {
        if self.state != State::Complete
            || self.frames.iter().any(|frame| !frame.complete)
            || &self.request.scope != scope
            || &self.request.manifest != manifest
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::client::controller) fn observe_owned_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request,
            transfer,
            pending_content,
            frames,
            cut: _,
            state: _,
        } = self;
        request.observe_owned_metadata_data(observer)?;
        observer.observe(transfer)?;
        if let Some((reference, bytes)) = pending_content {
            observer.observe(reference)?;
            observer.vector::<u8>(bytes.capacity())?;
        }
        observer.vector::<Frame>(frames.capacity())?;
        for frame in frames {
            let Frame {
                request_id,
                method: _,
                offset: _,
                length: _,
                original,
                received,
                attempted: _,
                complete: _,
            } = frame;
            observer.observe(request_id)?;
            observer.observe(original)?;
            if let Some(frame) = received {
                observer.observe(&frame.envelope)?;
                let ReceivedBody::Response(body) = &frame.body else {
                    return Err(refused());
                };
                observer.boxed_value(body.as_ref())?;
                observe_response(body, observer)?;
            }
        }
        Ok(())
    }
}

fn observe_response(
    body: &ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match &body.shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    match &body.result {
        None => Ok(()),
        Some(MethodResult::BlobBegin(body)) => {
            let BlobBeginResult {
                transfer_id,
                next_offset,
                maximum_chunk_bytes,
            } = body;
            observer.observe(transfer_id)?;
            observer.observe(next_offset)?;
            observer.observe(maximum_chunk_bytes)
        }
        Some(MethodResult::BlobChunk(body)) => {
            let BlobChunkResult {
                transfer_id,
                next_offset,
            } = body;
            observer.observe(transfer_id)?;
            observer.observe(next_offset)
        }
        Some(MethodResult::BlobFinish(body)) => {
            let BlobFinishResult {
                transfer_id,
                content,
            } = body;
            observer.observe(transfer_id)?;
            observer.observe(content)
        }
        _ => Err(refused()),
    }
}

impl State {
    fn ensure_complete_data(self) -> Result<(), ProviderError> {
        if self != Self::Complete {
            return Err(refused());
        }
        Ok(())
    }
}

impl AssignedUpload {
    pub(super) fn ensure_complete_data(&self) -> Result<(), ProviderError> {
        self.state.ensure_complete_data()
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;

    #[test]
    fn partial_upload_blocks_real_controller_barrier_and_call_before_frontier_change() {
        use crate::client::{ClientContent, ClientCustody, ClientSession, ControllerRoute};
        use std::time::Duration;
        let (_handshake, session, _owner, _witness, _peer) =
            ClientSession::restoration_retained_fixture();
        let content = ClientContent::new(1024 * 1024, 16, 4096).unwrap();
        let custody = ClientCustody::new(16, content).unwrap();
        let mut controller = CnpController::new(
            session,
            custody,
            ControllerRoute {
                node: Id::new("raw-census-node").unwrap(),
                execution_owner: Id::new("raw-census-owner").unwrap(),
            },
            Duration::from_secs(30),
        )
        .unwrap();
        // Portable data supplies no phase/Source/native grant. This exercises
        // the real SDK partial owner barrier before any codec/transport action.
        let request = PacketRestorationActivationUploadRequest {
            schema: PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
            scope: crate::reference_packet::service::complete_restore::activation::tests::request()
                .unwrap()
                .scope,
            role: PacketRestorationActivationUploadRole::Coordinator,
            coordinator: canonical::content_ref(b"actual-coordinator-data", "application/json")
                .unwrap(),
            manifest: canonical::content_ref(b"actual-manifest-data", "application/json").unwrap(),
            maximum_frame_bytes: U64::new(65_536),
            chunk_bytes: U64::new(4096),
            maximum_requests: U64::new(3),
            native_allocation: PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(1),
                maximum_simultaneous_transient_bytes: U64::new(2),
                declared_counter_scratch_bytes: U64::new(3),
            },
        };
        let sequence = controller.session.fresh_restore_query_sequence().unwrap();
        let originals = controller.originals().count();
        for state in [
            State::Preparing,
            State::Unsigned,
            State::Sealing,
            State::Sealed,
            State::Publishing,
        ] {
            controller.original_installed_restoration_upload[0] = Some(AssignedUpload {
                request: request.clone(),
                transfer: None,
                pending_content: None,
                frames: Vec::new(),
                cut: OperationalDeadline::after(Duration::from_secs(30)).unwrap(),
                state,
            });
            assert!(
                controller
                    .ensure_no_pending_original_complete_restore()
                    .is_err()
            );
            let id = Id::new("blocked-ordinary-request").unwrap();
            assert!(
                controller
                    .call(id.clone(), None, Method::Observe, false, Value::Null)
                    .is_err()
            );
            assert_eq!(
                controller.session.fresh_restore_query_sequence().unwrap(),
                sequence
            );
            assert_eq!(controller.originals().count(), originals);
            assert!(controller.original(&id).is_none());
        }
        controller.original_installed_restoration_upload[0]
            .as_mut()
            .unwrap()
            .state = State::Complete;
        // Only the pending barrier permits ordinary processing; native/Source
        // evidence and actual completed-upload validation are still separate.
        assert!(
            controller
                .ensure_no_pending_original_complete_restore()
                .is_ok()
        );
        assert_eq!(
            controller.session.fresh_restore_query_sequence().unwrap(),
            sequence
        );
        assert_eq!(controller.originals().count(), originals);
    }

    #[test]
    fn every_partial_upload_state_refuses_generic_sequence_advance() {
        for state in [
            State::Preparing,
            State::Unsigned,
            State::Sealing,
            State::Sealed,
            State::Publishing,
        ] {
            assert!(state.ensure_complete_data().is_err());
        }
        assert!(State::Complete.ensure_complete_data().is_ok());
    }
}

impl CnpController {
    pub(crate) fn original_installed_restoration_upload_owner_header_bytes_data(
        requests: usize,
    ) -> Result<usize, ProviderError> {
        use std::mem::size_of;
        requests
            .checked_mul(size_of::<Frame>())
            .and_then(|bytes| bytes.checked_add(size_of::<AssignedUpload>()))
            .ok_or_else(credit)
    }

    /// Names complete SDK upload owner, loan, conversion and iteration headers.
    pub fn original_installed_restoration_upload_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<AssignedUpload>()
            + size_of::<Frame>()
            + size_of::<PreparedOriginalInstalledRestorationUpload<'static>>()
            + size_of::<Result<PreparedOriginalInstalledRestorationUpload<'static>, ProviderError>>(
            )
            + size_of::<CompletedOriginalInstalledRestorationUpload<'static>>()
            + size_of::<Result<CompletedOriginalInstalledRestorationUpload<'static>, ProviderError>>(
            )
            + size_of::<Option<(ContentRef, Vec<u8>)>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<AssignedUpload>>>>()
            + size_of::<Option<&AssignedUpload>>()
            + size_of::<Option<&mut AssignedUpload>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Result<&ResponseBody, ProviderError>>()
            + size_of::<Result<Envelope, ProviderError>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
            + size_of::<OperationalDeadline>()
            + size_of::<Result<(U64, OperationalDeadline), ProviderError>>()
            + size_of::<std::slice::Iter<'static, Frame>>()
            + size_of::<std::ops::Range<usize>>()
            + size_of::<[u8; 32]>()
            + size_of::<blake3::Hasher>()
            + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
            + size_of::<[usize; 4]>()
    }
}

#[path = "upload/current.rs"]
mod current;
