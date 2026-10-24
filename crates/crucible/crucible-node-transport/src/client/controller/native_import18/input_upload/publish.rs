//! Advances one actual upload frame between independent whole-owner admissions.
//!
//! Each strict raw ACK remains in its frame. The caller releases all Source and
//! capsule loans before quoting/admitting its expanded Envelope/body row.

use super::super::receive::{OriginalNativeImport18ReceiveConstructionData, ReceiveTarget};
use super::*;

pub(super) struct UploadExecution<'a> {
    controller: &'a mut CnpController,
    complete: bool,
}

impl Drop for UploadExecution<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.controller.fenced = true;
        }
    }
}

impl OriginalNativeImport18Assignment {
    /// Installs and spends the seven-bank plan before any allocation or copy.
    ///
    /// This sends no frame. Actual per-reply decoding requires a separate row
    /// after receiving the strict raw Value, beneath the same original escrow.
    ///
    /// # Errors
    /// Retains a spent partial plan and fences the actor on any refusal.
    pub fn start_input_upload_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        prospective: &OriginalNativeImport18InputUploadProspectiveStorageData,
        row: &OriginalNativeImport18InputUploadStorageData,
        bodies: [&[u8]; 7],
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        if self.uploads.is_used() {
            return Err(invalid());
        }
        self.uploads.started = true;
        self.uploads.failed = true;
        let mut execution = UploadExecution {
            controller,
            complete: false,
        };
        let controller = &mut *execution.controller;
        let result = (|| {
            self.uploads
                .owners
                .try_reserve_exact(1)
                .map_err(|_| credit())?;
            self.uploads.owners.push(InputUpload::new(row));
            if self.uploads.owners.capacity() != 1 {
                return Err(credit());
            }
            prospective.authenticate_actual_data(row)?;
            row.authenticate(self, controller, emitter, &bodies)?;
            let inputs = inputs_data(&self.prepare, &self.binding)?;
            let prefix = row.prefix.to_hex();
            let held = self.uploads.owners.first_mut().ok_or_else(invalid)?;
            held.frames
                .try_reserve_exact(row.requests)
                .map_err(|_| credit())?;
            if held.frames.capacity() != row.requests {
                return Err(credit());
            }
            populate_plan(held, &inputs.references, prefix.as_str(), row.chunk)?;
            if held.frames.len() != row.requests {
                return Err(invalid());
            }
            controller
                .session
                .authenticate_native_import18_upload_start_data(inputs.original, held.cut)?;
            held.stage = UploadStage::Publishing;
            Ok(())
        })();
        let result = self.finish_upload_step(controller, emitter, result);
        execution.complete = result.is_ok();
        result
    }

    /// Publishes one original and retains only its strict raw terminal.
    ///
    /// The caller next quotes/admit-decodes that exact terminal before another
    /// frame may be sent. No response DTO or RawValue visitor runs here.
    ///
    /// # Errors
    /// Retains attempted originals/raw partials and fences any failed step.
    pub fn publish_input_upload_raw_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        bodies: [&[u8]; 7],
    ) -> Result<(), ProviderError> {
        self.authenticate(controller, emitter)?;
        if self.uploads.failed {
            return Err(invalid());
        }
        let mut execution = UploadExecution {
            controller,
            complete: false,
        };
        let controller = &mut *execution.controller;
        let result = (|| {
            let inputs = inputs_data(&self.prepare, &self.binding)?;
            inputs.verify_bodies(&self.binding, &bodies)?;
            let held = self.uploads.owners.first_mut().ok_or_else(invalid)?;
            if held.stage != UploadStage::Publishing {
                return Err(invalid());
            }
            let frame = held.frames.get_mut(held.active).ok_or_else(invalid)?;
            let role = frame.role.ordinal_data();
            if frame.attempted || frame.complete || held.offsets[role] != frame.offset {
                return Err(invalid());
            }
            frame.attempted = true;
            let reference = held.references[role].as_ref().ok_or_else(invalid)?;
            let transfer = held.transfers[role].as_ref().ok_or_else(invalid)?;
            let value = match frame.method {
                Method::BlobBegin => serde_json::to_value(BlobBeginRequest {
                    transfer_id: transfer.clone(),
                    content: reference.clone(),
                    extensions: Extensions::new(),
                }),
                Method::BlobChunk => {
                    let end = frame.offset.checked_add(frame.length).ok_or_else(credit)?;
                    serde_json::to_value(BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new(frame.offset as u64),
                        bytes: Bytes::new(
                            bodies[role]
                                .get(frame.offset..end)
                                .ok_or_else(invalid)?
                                .to_vec(),
                        ),
                        extensions: Extensions::new(),
                    })
                }
                Method::BlobFinish => serde_json::to_value(BlobFinishRequest {
                    transfer_id: transfer.clone(),
                    extensions: Extensions::new(),
                }),
                _ => return Err(invalid()),
            }
            .map_err(crucible_node_format::ContractError::from)?;
            let Value::Object(body) = value else {
                return Err(invalid());
            };
            let authority = controller.authority();
            frame.original = Some(Envelope {
                protocol: "CNP/1".into(),
                message: MessageKind::Request,
                session_id: Nullable(Some(authority.session_id().clone())),
                incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
                node_id: Nullable(None),
                execution_owner_id: Nullable(None),
                capture_owner_id: Nullable(None),
                operation_id: Nullable(None),
                request_id: Nullable(Some(frame.request_id.clone())),
                sequence: controller
                    .session
                    .native_import18_upload_sequence_data(held.cut)?,
                method: frame.method,
                body,
                extensions: Extensions::new(),
            });
            controller
                .session
                .exchange_native_import18_upload_raw_into_data(
                    &mut controller.custody,
                    frame.original.as_ref().ok_or_else(invalid)?,
                    held.cut,
                    &mut frame.raw,
                    &mut frame.json_profile,
                )?;
            held.stage = UploadStage::RawReceived;
            Ok(())
        })();
        let result = self.finish_upload_step(controller, emitter, result);
        execution.complete = result.is_ok();
        result
    }

    /// Prices the selected-contract workspace without decoding the active raw ACK.
    ///
    /// The caller admits receive_counter_scratch_data before entry, then this
    /// returned workspace before quote_input_upload_receive_data. No full schema
    /// factory, Envelope visitor, query or new cut is constructed here.
    ///
    /// # Errors
    /// Refuses another actor, a failed/missing active raw reply or overflow.
    pub fn input_upload_receive_prewalk_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(usize, usize), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(invalid());
        }
        let held = self.uploads.owners.first().ok_or_else(invalid)?;
        self.upload_raw_data(held.active)?;
        self.receive_quote_workspace_data()
    }

    /// Quotes this active strict raw ACK's actual expanded decoder demand.
    ///
    /// Static receive S precedes prewalk; the selected-contract prewalk from
    /// input_upload_prewalk_data precedes this full quote. The Source retains
    /// the returned row and ends all loans before independent admission.
    ///
    /// # Errors
    /// Refuses failed, stale or partial custody, another actor or credit overflow.
    pub fn quote_input_upload_receive_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        maximum: usize,
    ) -> Result<OriginalNativeImport18ReceiveConstructionData, ProviderError> {
        let held = self.uploads.owners.first().ok_or_else(invalid)?;
        self.quote_receive_target_data(
            controller,
            emitter,
            maximum,
            ReceiveTarget::Upload(held.active),
        )
    }

    /// Decodes one independently admitted ACK and advances exactly its offset.
    ///
    /// Returns true only after all seven real role ledgers are complete. This
    /// confers no native adoption, Hold, Commit, Arm or World permission.
    ///
    /// # Errors
    /// Retains raw/Envelope/typed/offset partials and blocks failed continuations.
    pub fn decode_input_upload_received_data(
        &mut self,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        row: &OriginalNativeImport18ReceiveConstructionData,
    ) -> Result<bool, ProviderError> {
        row.authenticate(self, controller, emitter)?;
        let mut execution = UploadExecution {
            controller,
            complete: false,
        };
        let controller = &mut *execution.controller;
        let mut completed = false;
        let result = (|| {
            let held = self.uploads.owners.first_mut().ok_or_else(invalid)?;
            if row.target_data() != ReceiveTarget::Upload(held.active) {
                return Err(invalid());
            }
            held.stage = UploadStage::Decoding;
            let frame = held.frames.get_mut(held.active).ok_or_else(invalid)?;
            frame.json_profile = row.metadata_profile_data();
            controller.session.decode_native_import18_upload_into_data(
                &mut controller.custody,
                frame.original.as_ref().ok_or_else(invalid)?,
                held.cut,
                frame.raw.as_ref().ok_or_else(invalid)?,
                &mut frame.response,
                &mut frame.received,
            )?;
            let role = frame.role.ordinal_data();
            authenticate_ack(
                frame,
                frame.received.as_ref().ok_or_else(invalid)?,
                held.transfers[role].as_ref().ok_or_else(invalid)?,
                held.references[role].as_ref().ok_or_else(invalid)?,
                held.chunk,
                held.maximum_chunk,
            )?;
            held.offsets[role] = frame.offset.checked_add(frame.length).ok_or_else(credit)?;
            frame.complete = true;
            held.active = held.active.checked_add(1).ok_or_else(credit)?;
            if held.active == held.frames.len() {
                for role in PacketNativeImport18InputRole::ALL {
                    let index = role.ordinal_data();
                    if held.offsets[index] as u64
                        != held.references[index]
                            .as_ref()
                            .ok_or_else(invalid)?
                            .length
                            .get()
                    {
                        return Err(invalid());
                    }
                }
                held.next_sequence = Some(
                    controller
                        .session
                        .native_import18_upload_sequence_data(held.cut)?,
                );
                held.frontier = Some(controller.original_native5_storage_facts()?);
                held.stage = UploadStage::Complete;
                completed = true;
            } else {
                held.stage = UploadStage::Publishing;
            }
            Ok(())
        })();
        let result = self.finish_upload_step(controller, emitter, result);
        let result = result.and_then(|()| {
            if completed {
                self.authenticate_input_upload_completed_data(controller, emitter)?;
            }
            Ok(completed)
        });
        if result.is_err() {
            self.fail_upload_step();
        }
        execution.complete = result.is_ok();
        result
    }

    pub(in super::super) fn upload_raw_data(
        &self,
        index: usize,
    ) -> Result<(&crate::transport::RetainedFrame, &Envelope), ProviderError> {
        let held = self.uploads.owners.first().ok_or_else(invalid)?;
        if !self.uploads.started
            || self.uploads.failed
            || held.stage != UploadStage::RawReceived
            || held.active != index
        {
            return Err(invalid());
        }
        let frame = held.frames.get(index).ok_or_else(invalid)?;
        if !frame.attempted || frame.complete {
            return Err(invalid());
        }
        Ok((
            frame.raw.as_ref().ok_or_else(invalid)?,
            frame.original.as_ref().ok_or_else(invalid)?,
        ))
    }

    pub(in super::super) fn authenticate_upload_raw_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        index: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate(controller, emitter)?;
        let (raw, original) = self.upload_raw_data(index)?;
        let held = self.uploads.owners.first().ok_or_else(invalid)?;
        controller
            .session
            .authenticate_native_import18_raw_data(original, held.cut, raw)
    }

    fn fail_upload_step(&mut self) {
        self.uploads.failed = true;
        if let Some(held) = self.uploads.owners.first_mut() {
            held.stage = UploadStage::Failed;
        }
    }

    fn finish_upload_step(
        &mut self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        result: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        let result = result.and(emitter.authenticate_original(controller));
        if result.is_err() {
            self.fail_upload_step();
        } else {
            self.uploads.failed = false;
        }
        result
    }
}

fn populate_plan(
    held: &mut InputUpload,
    references: &[&ContentRef; 7],
    prefix: &str,
    chunk: usize,
) -> Result<(), ProviderError> {
    if held.stage != UploadStage::Allocating
        || !held.frames.is_empty()
        || chunk == 0
        || held.references.iter().any(Option::is_some)
        || held.transfers.iter().any(Option::is_some)
    {
        return Err(invalid());
    }
    for role in PacketNativeImport18InputRole::ALL {
        let index = role.ordinal_data();
        held.references[index] = Some(references[index].clone());
        held.transfers[index] = Some(Id::new(format!("cnp-import18-input-{prefix}-{index}"))?);
        append_plan(held, prefix, role, Method::BlobBegin, 0, 0)?;
        let length = usize::try_from(references[index].length.get()).map_err(|_| credit())?;
        let mut offset = 0usize;
        while offset < length {
            let size = chunk.min(length - offset);
            append_plan(held, prefix, role, Method::BlobChunk, offset, size)?;
            offset = offset.checked_add(size).ok_or_else(credit)?;
        }
        append_plan(held, prefix, role, Method::BlobFinish, length, 0)?;
    }
    Ok(())
}

fn append_plan(
    held: &mut InputUpload,
    prefix: &str,
    role: PacketNativeImport18InputRole,
    method: Method,
    offset: usize,
    length: usize,
) -> Result<(), ProviderError> {
    if held.frames.len() == held.frames.capacity() {
        return Err(credit());
    }
    let name = match method {
        Method::BlobBegin => "begin",
        Method::BlobChunk => "chunk",
        Method::BlobFinish => "finish",
        _ => return Err(invalid()),
    };
    let request_id = Id::new(format!(
        "cnp-import18-input-{prefix}-{}-{name}-{offset}",
        role.ordinal_data()
    ))?;
    held.frames.push(UploadFrame {
        role,
        method,
        offset,
        length,
        request_id,
        original: None,
        json_profile: NativeImport18JsonMetadataProfileData::strict_raw_data(),
        raw: None,
        response: None,
        received: None,
        attempted: false,
        complete: false,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held() -> InputUpload {
        InputUpload {
            stage: UploadStage::Allocating,
            references: std::array::from_fn(|_| None),
            transfers: std::array::from_fn(|_| None),
            offsets: [0; 7],
            frames: Vec::new(),
            active: 0,
            chunk: 2,
            maximum_chunk: 4096,
            cut: OperationalDeadline::expired_fixture(),
            prepare_sequence: U64::new(2),
            response_sequence: U64::new(3),
            token: [0; 32],
            frontier: None,
            next_sequence: None,
        }
    }

    #[test]
    fn equal_content_keeps_seven_distinct_role_ledgers_and_ids() {
        let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
        let mut owner = held();
        let requests = 7 * (5usize.div_ceil(2) + 2);
        owner.frames.try_reserve_exact(requests).unwrap();

        populate_plan(&mut owner, &[&reference; 7], "actual-prepare", 2).unwrap();

        assert_eq!(owner.frames.len(), requests);
        let transfers = owner
            .transfers
            .iter()
            .map(|id| id.as_ref().unwrap().as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let ids = owner
            .frames
            .iter()
            .map(|frame| frame.request_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(transfers.len(), 7);
        assert_eq!(ids.len(), requests);
        for role in PacketNativeImport18InputRole::ALL {
            assert_eq!(
                owner
                    .frames
                    .iter()
                    .filter(|frame| frame.role == role)
                    .count(),
                5
            );
        }
        assert!(
            owner
                .frames
                .iter()
                .any(|frame| frame.role == PacketNativeImport18InputRole::SemanticSpend)
        );
        assert!(
            owner
                .frames
                .iter()
                .all(|frame| !frame.attempted && !frame.complete)
        );
        assert!(populate_plan(&mut owner, &[&reference; 7], "actual-prepare", 2).is_err());
        assert_eq!(owner.frames.len(), requests);
    }

    fn original() -> Envelope {
        let id = || Nullable(Some(Id::new("test/scope").unwrap()));
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: id(),
            incarnation_id: id(),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: id(),
            sequence: U64::new(7),
            method: Method::BlobChunk,
            body: Default::default(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn begin_ack_preserves_actual_smaller_negotiated_receiver_maximum() {
        let transfer = Id::new("transfer/smaller-profile").unwrap();
        let reference = canonical::content_ref(b"input", "application/json").unwrap();
        let mut request = original();
        request.method = Method::BlobBegin;
        let mut response = request.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(9);
        let frame = UploadFrame {
            role: PacketNativeImport18InputRole::NativeProtocol,
            method: Method::BlobBegin,
            offset: 0,
            length: 0,
            request_id: Id::new("test/scope").unwrap(),
            original: Some(request),
            json_profile: NativeImport18JsonMetadataProfileData::strict_raw_data(),
            raw: None,
            response: None,
            received: None,
            attempted: true,
            complete: false,
        };
        let mut ack = ReceivedFrame {
            envelope: response,
            body: ReceivedBody::Response(Box::new(ResponseBody {
                shape: ResponseShape::Completed {
                    operation_state: OperationState::Completed,
                    result: Default::default(),
                    extensions: Default::default(),
                },
                result: Some(MethodResult::BlobBegin(BlobBeginResult {
                    transfer_id: transfer.clone(),
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: U64::new(1024),
                })),
            })),
        };

        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 512, 1024).is_ok());
        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2048, 1024).is_err());
        if let ReceivedBody::Response(body) = &mut ack.body {
            if let Some(MethodResult::BlobBegin(result)) = &mut body.result {
                result.maximum_chunk_bytes = U64::new(4096);
            }
        }
        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 512, 1024).is_err());
    }

    #[test]
    fn semantic_bank_ack_requires_exact_transfer_offset_and_correlation() {
        let transfer = Id::new("transfer/semantic").unwrap();
        let reference = canonical::content_ref(b"abcde", "application/json").unwrap();
        let frame = UploadFrame {
            role: PacketNativeImport18InputRole::SemanticSpend,
            method: Method::BlobChunk,
            offset: 3,
            length: 2,
            request_id: Id::new("test/scope").unwrap(),
            original: Some(original()),
            json_profile: NativeImport18JsonMetadataProfileData::strict_raw_data(),
            raw: None,
            response: None,
            received: None,
            attempted: true,
            complete: false,
        };
        let mut envelope = original();
        envelope.message = MessageKind::Response;
        envelope.sequence = U64::new(9);
        let mut ack = ReceivedFrame {
            envelope,
            body: ReceivedBody::Response(Box::new(ResponseBody {
                shape: ResponseShape::Completed {
                    operation_state: OperationState::Completed,
                    result: Default::default(),
                    extensions: Default::default(),
                },
                result: Some(MethodResult::BlobChunk(BlobChunkResult {
                    transfer_id: transfer.clone(),
                    next_offset: U64::new(5),
                })),
            })),
        };

        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2, 4096).is_ok());
        if let ReceivedBody::Response(body) = &mut ack.body {
            if let Some(MethodResult::BlobChunk(result)) = &mut body.result {
                result.next_offset = U64::new(4);
            }
        }
        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2, 4096).is_err());
        if let ReceivedBody::Response(body) = &mut ack.body {
            if let Some(MethodResult::BlobChunk(result)) = &mut body.result {
                result.next_offset = U64::new(5);
            }
        }
        ack.envelope.request_id = Nullable(Some(Id::new("other/request").unwrap()));
        assert!(authenticate_ack(&frame, &ack, &transfer, &reference, 2, 4096).is_err());
        assert!(!frame.complete);
    }
}

impl OriginalNativeImport18Assignment {
    pub(in super::super) fn upload_metadata_profile_data(
        &self,
        index: usize,
    ) -> Result<NativeImport18JsonMetadataProfileData, ProviderError> {
        let owner = self.uploads.owners.first().ok_or_else(invalid)?;
        if owner.active != index {
            return Err(invalid());
        }
        Ok(owner.frames.get(index).ok_or_else(invalid)?.json_profile)
    }
}
