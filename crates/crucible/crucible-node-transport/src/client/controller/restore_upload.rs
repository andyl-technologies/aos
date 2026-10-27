//! Publishes six role-distinct inputs beneath one completed Prepare and cut.
//!
//! This transport owner is not restoration authority. Source must first verify
//! the actual native receipt MAC and consume a genuine installed whole-restoration
//! action covering these DATA terms and all independent native/Source owners.
//! It retains the original ticket and raw bodies through every partial failure.

use super::*;
use crate::{
    connection::{CompleteRestoreTransferProjection, ReceivedBody, ReceivedFrame},
    operational_time::OperationalDeadline,
    protocol_snapshot::{OriginalProtocolStorageFacts, ProtocolCaptureOwner},
    reference_packet::service::complete_restore::{
        PacketNative5CompleteRestoreSelection, transfer::*,
    },
    retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts},
};
use std::rc::{Rc, Weak};

mod committed;
mod inputs;
mod prospective;
mod source_construction;
pub(super) mod storage;
use inputs::PrepareInputs;
pub use prospective::{
    OriginalCompleteRestoreInputUploadProspectiveStorageData,
    OriginalCompleteRestoreUploadBeforeMappingData,
};

/// Quotes this actor's additional six-input publication work as DATA.
///
/// No constructor, decoder, clone, key or resource grant is exposed. Existing
/// Source/raw bodies/controller/native banks and callback construction require
/// separate whole-action admission before this quote is consumed.
pub struct OriginalCompleteRestoreInputUploadStorageData {
    controller: Weak<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    prepare_id: blake3::Hash,
    prepare_sequence: U64,
    response_sequence: U64,
    receipt_token: blake3::Hash,
    chunk: usize,
    requests: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalCompleteRestoreInputUploadStorageData {
    /// Returns additional retained owner/cache/typed-response requested bytes.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns the conservative simultaneous complete protocol work bound.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns explicit fixed observer/quote/assignment headers.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Reports actual shared association backing, excluding this inline quote.
    ///
    /// # Errors
    /// Refuses an expired/foreign actor or metadata traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(owner.as_ref())?;
        Ok(observer.finish())
    }

    fn authenticate(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalRestoreInputEmitter,
        bodies: &[&[u8]; 6],
    ) -> Result<(), ProviderError> {
        let inputs = PrepareInputs::borrow(controller, emitter)?;
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        if !Rc::ptr_eq(&owner, &controller.protocol_owner)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.prepare_id != blake3::hash(inputs.request_id.as_str().as_bytes())
            || self.prepare_sequence != inputs.original.sequence
            || self.response_sequence != inputs.response.sequence
            || self.receipt_token != blake3::hash(inputs.token.as_bytes())
        {
            return Err(refused());
        }
        inputs.verify_bodies(bodies)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UploadPhase {
    Allocating,
    Publishing,
    Complete,
    Failed,
}

/// Retains original planned IDs, partial frames and ACKs without retry authority.
///
/// The caller's slot is populated before the first reserve/clone/frame. Equal
/// references still have six independent role ledgers. There is no serialization,
/// cloning, reset or retransmission API; a failed or unwound attempt remains held.
pub struct OriginalCompleteRestoreInputUpload {
    controller: Weak<ProtocolCaptureOwner>,
    prepare_id: blake3::Hash,
    prepare_sequence: U64,
    response_sequence: U64,
    receipt_token: blake3::Hash,
    references: [Option<ContentRef>; 6],
    transfers: [Option<Id>; 6],
    offsets: [usize; 6],
    frames: Vec<UploadFrame>,
    active: usize,
    phase: UploadPhase,
    cut: Option<OperationalDeadline>,
}

// The actor is irreversibly fenced on error or unwind, including failures
// before the first send. This never invokes an erased callback during Drop.
struct UploadExecution<'a> {
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

struct UploadFrame {
    role: usize,
    method: Method,
    offset: usize,
    length: usize,
    request_id: Id,
    original: Option<Envelope>,
    received: Option<ReceivedFrame>,
    attempted: bool,
    complete: bool,
}

impl OriginalCompleteRestoreInputUpload {
    /// Reports successful ACK completion of the same original six-role upload.
    ///
    /// This is transport data, not a native Commit, installed model or Ready.
    pub fn is_complete_data(&self) -> bool {
        self.phase == UploadPhase::Complete
    }

    /// Authenticates all six ACKs against the same actual completed Prepare.
    ///
    /// Source calls this before assigning Commit. This preserves SDK association
    /// only; its private ticket/window and keyed receipt checks remain required.
    ///
    /// # Errors
    /// Refuses incomplete/failed ownership, another actor/emitter/Prepare/token,
    /// changed role references or any unsettled planned frame.
    pub fn authenticate_completed_original(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalRestoreInputEmitter,
    ) -> Result<(), ProviderError> {
        let inputs = PrepareInputs::borrow(controller, emitter)?;
        self.authenticate_completed_inputs(controller, &inputs)
    }

    fn authenticate_completed_inputs(
        &self,
        controller: &CnpController,
        inputs: &PrepareInputs<'_>,
    ) -> Result<(), ProviderError> {
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        if self.phase != UploadPhase::Complete
            || !Rc::ptr_eq(&owner, &controller.protocol_owner)
            || self.prepare_id != blake3::hash(inputs.request_id.as_str().as_bytes())
            || self.prepare_sequence != inputs.original.sequence
            || self.response_sequence != inputs.response.sequence
            || self.receipt_token != blake3::hash(inputs.token.as_bytes())
            || self.frames.is_empty()
            || self
                .frames
                .iter()
                .any(|f| !f.attempted || !f.complete || f.received.is_none())
        {
            return Err(refused());
        }
        for role in 0..6 {
            let reference = self.references[role].as_ref().ok_or_else(refused)?;
            if !inputs.references[role].matches(reference)
                || self.offsets[role] != inputs.references[role].length
            {
                return Err(refused());
            }
        }
        Ok(())
    }

    /// Reports actual retained owner children, including partial failure owners.
    ///
    /// The containing caller charges this root's inline layout separately.
    ///
    /// # Errors
    /// Refuses a dead/foreign actor, unknown received method owners, busy or
    /// exhausted metadata traversal, or checked layout overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(owner.as_ref())?;
        observer.observe(&self.references)?;
        observer.observe(&self.transfers)?;
        observer.vector::<UploadFrame>(self.frames.capacity())?;
        for frame in &self.frames {
            observer.observe(&frame.request_id)?;
            observer.observe(&frame.original)?;
            if let Some(received) = &frame.received {
                observer.observe(&received.envelope)?;
                let ReceivedBody::Response(body) = &received.body else {
                    return Err(refused());
                };
                observer.boxed_value(body.as_ref())?;
                storage::observe_response(body, &mut observer)?;
            }
        }
        Ok(observer.finish())
    }
}

impl CnpController {
    /// Returns exact fixed publication/assignment/header scratch before quoting.
    ///
    /// Recursive/compiler frames and allocator overhead remain separate.
    pub fn original_complete_restore_input_upload_counter_scratch_data() -> usize {
        storage::counter_scratch_data()
    }

    /// Quotes six exact role bodies against the actual completed Prepare pair.
    ///
    /// This is a post-Prepare requote of independently prefunded work, never
    /// permission to add allocation credit after Prepare. The original whole
    /// Source action must have prospectively funded these owners before its
    /// first effects, and compare this actual demand with that retained bound.
    /// It separately verifies the keyed receipt and funds retained raw bodies,
    /// native reconstruction and callbacks. No IO, frame,
    /// deadline reset, typed reference clone or resource grant occurs here.
    ///
    /// # Errors
    /// Refuses a missing selected/settled Prepare, foreign emitter, changed full
    /// references/bodies, reused planned IDs, insufficient original history,
    /// unsupported frame/chunk geometry, overflow or total above `maximum`.
    pub fn quote_original_complete_restore_input_upload_storage_data(
        &self,
        emitter: &OriginalCanonicalRestoreInputEmitter,
        bodies: [&[u8]; 6],
        maximum: usize,
    ) -> Result<OriginalCompleteRestoreInputUploadStorageData, ProviderError> {
        let inputs = PrepareInputs::borrow(self, emitter)?;
        inputs.verify_bodies(&bodies)?;
        self.session.preflight_original_restore_upload_data()?;
        let parts = storage::quote(self, &inputs, maximum)?;
        let result = OriginalCompleteRestoreInputUploadStorageData {
            controller: Rc::downgrade(&self.protocol_owner),
            frontier: self.original_native5_storage_facts()?,
            prepare_id: blake3::hash(inputs.request_id.as_str().as_bytes()),
            prepare_sequence: inputs.original.sequence,
            response_sequence: inputs.response.sequence,
            receipt_token: blake3::hash(inputs.token.as_bytes()),
            chunk: parts.chunk,
            requests: parts.requests,
            retained: parts.retained,
            transient: parts.transient,
            scratch: storage::counter_scratch_data(),
        };
        result.authenticate(self, emitter, &bodies)?;
        Ok(result)
    }

    /// Publishes the exact six original roles without automatically retrying.
    ///
    /// Source calls this only after consuming its genuine whole-restoration
    /// action and verifying the actual Prepare receipt MAC. The quote authenticates
    /// SDK custody/data correspondence only. The owner enters `output` before
    /// reserve/clone/frame work; each frame becomes spent before write and its
    /// actual received owner reaches the same slot before ACK/post-call checks.
    /// One original cut covers all six roles and is never renewed per frame.
    ///
    /// # Errors
    /// Refuses occupied output, stale/foreign quote/emitter/Prepare, changed input,
    /// failed original credit, invalid ACK, expired cut or uncertain IO. Every
    /// partial owner remains held. An error or unwind irreversibly fences the
    /// same controller; calling again never retransmits a frame.
    pub fn publish_original_complete_restore_inputs_into(
        &mut self,
        emitter: &OriginalCanonicalRestoreInputEmitter,
        quote: &OriginalCompleteRestoreInputUploadStorageData,
        bodies: [&[u8]; 6],
        output: &mut Option<OriginalCompleteRestoreInputUpload>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        quote.authenticate(self, emitter, &bodies)?;
        *output = Some(OriginalCompleteRestoreInputUpload {
            controller: Rc::downgrade(&self.protocol_owner),
            prepare_id: quote.prepare_id,
            prepare_sequence: quote.prepare_sequence,
            response_sequence: quote.response_sequence,
            receipt_token: quote.receipt_token,
            references: std::array::from_fn(|_| None),
            transfers: std::array::from_fn(|_| None),
            offsets: [0; 6],
            frames: Vec::new(),
            active: 0,
            phase: UploadPhase::Allocating,
            cut: None,
        });
        let held = output.as_mut().ok_or_else(refused)?;
        let mut publication = UploadExecution {
            controller: self,
            complete: false,
        };
        let controller = &mut *publication.controller;
        let result = (|| {
            // Populate all role/ID ownership before the first transport effect.
            let inputs = PrepareInputs::borrow(controller, emitter)?;
            held.frames
                .try_reserve_exact(quote.requests)
                .map_err(|_| credit())?;
            if held.frames.capacity() != quote.requests {
                return Err(credit());
            }
            let prefix = inputs.prefix().to_hex();
            populate_plan(held, &inputs.references, prefix.as_str(), quote.chunk)?;
            if held.frames.len() != quote.requests {
                return Err(refused());
            }
            quote.authenticate(controller, emitter, &bodies)?;
            let (_, cut) = controller
                .session
                .begin_original_restore_upload(controller.budget)?;
            held.cut = Some(cut);
            held.phase = UploadPhase::Publishing;
            for index in 0..held.frames.len() {
                held.active = index;
                emitter.authenticate_original(controller)?;
                let frame = held.frames.get_mut(index).ok_or_else(refused)?;
                if frame.attempted || frame.complete || held.offsets[frame.role] != frame.offset {
                    return Err(refused());
                }
                frame.attempted = true;
                let reference = held.references[frame.role].as_ref().ok_or_else(refused)?;
                let transfer = held.transfers[frame.role].as_ref().ok_or_else(refused)?;
                let value = match frame.method {
                    Method::BlobBegin => serde_json::to_value(BlobBeginRequest {
                        transfer_id: transfer.clone(),
                        content: reference.clone(),
                        extensions: Extensions::new(),
                    }),
                    Method::BlobChunk => serde_json::to_value(BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new(frame.offset as u64),
                        bytes: Bytes::new(
                            bodies[frame.role]
                                .get(frame.offset..frame.offset + frame.length)
                                .ok_or_else(refused)?
                                .to_vec(),
                        ),
                        extensions: Extensions::new(),
                    }),
                    Method::BlobFinish => serde_json::to_value(BlobFinishRequest {
                        transfer_id: transfer.clone(),
                        extensions: Extensions::new(),
                    }),
                    _ => return Err(refused()),
                }
                .map_err(crucible_node_format::ContractError::from)?;
                let Value::Object(body) = value else {
                    return Err(refused());
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
                    sequence: controller.session.original_restore_upload_sequence(cut)?,
                    method: frame.method,
                    body,
                    extensions: Extensions::new(),
                });
                let original = frame.original.as_ref().ok_or_else(refused)?;
                controller.session.exchange_original_restore_upload_into(
                    &mut controller.custody,
                    original,
                    cut,
                    &mut frame.received,
                )?;
                let received = frame.received.as_ref().ok_or_else(refused)?;
                authenticate_ack(frame, received, transfer, reference, quote.chunk)?;
                // Progress changes only after this exact matching native ACK.
                held.offsets[frame.role] =
                    frame.offset.checked_add(frame.length).ok_or_else(credit)?;
                frame.complete = true;
                emitter.authenticate_original(controller)?;
            }
            if held
                .offsets
                .iter()
                .zip(&held.references)
                .any(|(n, r)| r.as_ref().is_none_or(|r| *n as u64 != r.length.get()))
            {
                return Err(refused());
            }
            controller.session.original_restore_upload_sequence(cut)?;
            emitter.authenticate_original(controller)?;
            held.phase = UploadPhase::Complete;
            Ok(())
        })();
        if result.is_err() {
            held.phase = UploadPhase::Failed;
        }
        publication.complete = result.is_ok();
        result
    }
}

fn populate_plan(
    held: &mut OriginalCompleteRestoreInputUpload,
    references: &[inputs::Reference<'_>; 6],
    prefix: &str,
    chunk: usize,
) -> Result<(), ProviderError> {
    if held.phase != UploadPhase::Allocating
        || !held.frames.is_empty()
        || chunk == 0
        || held.references.iter().any(Option::is_some)
        || held.transfers.iter().any(Option::is_some)
    {
        return Err(refused());
    }
    for (role, reference) in references.iter().enumerate() {
        held.references[role] = Some(reference.owned());
        held.transfers[role] = Some(Id::new(format!("cnp-restore-input-{prefix}-{role}"))?);
        append_plan(held, prefix, role, Method::BlobBegin, 0, 0)?;
        let mut offset = 0usize;
        while offset < reference.length {
            let length = chunk.min(reference.length - offset);
            append_plan(held, prefix, role, Method::BlobChunk, offset, length)?;
            offset = offset.checked_add(length).ok_or_else(credit)?;
        }
        append_plan(held, prefix, role, Method::BlobFinish, reference.length, 0)?;
    }
    Ok(())
}

fn append_plan(
    held: &mut OriginalCompleteRestoreInputUpload,
    prefix: &str,
    role: usize,
    method: Method,
    offset: usize,
    length: usize,
) -> Result<(), ProviderError> {
    if held.frames.len() == held.frames.capacity() {
        return Err(credit());
    }
    let request_id = Id::new(format!(
        "cnp-restore-input-{prefix}-{role}-{}-{offset}",
        method_name(method)?
    ))?;
    held.frames.push(UploadFrame {
        role,
        method,
        offset,
        length,
        request_id,
        original: None,
        received: None,
        attempted: false,
        complete: false,
    });
    Ok(())
}

fn authenticate_ack(
    frame: &UploadFrame,
    received: &ReceivedFrame,
    transfer: &Id,
    reference: &ContentRef,
    chunk: usize,
) -> Result<(), ProviderError> {
    frame
        .original
        .as_ref()
        .ok_or_else(refused)?
        .matches_response(&received.envelope)?;
    if !received.envelope.extensions.is_empty() {
        return Err(refused());
    }
    let ReceivedBody::Response(body) = &received.body else {
        return Err(refused());
    };
    let ResponseShape::Completed {
        operation_state: OperationState::Completed,
        extensions,
        ..
    } = &body.shape
    else {
        return Err(refused());
    };
    if !extensions.is_empty() {
        return Err(refused());
    }
    match (frame.method, &body.result) {
        (Method::BlobBegin, Some(MethodResult::BlobBegin(result)))
            if &result.transfer_id == transfer
                && result.next_offset.get() == 0
                && result.maximum_chunk_bytes.get() == 4096
                && chunk <= 4096 =>
        {
            Ok(())
        }
        (Method::BlobChunk, Some(MethodResult::BlobChunk(result)))
            if &result.transfer_id == transfer
                && result.next_offset.get() == (frame.offset + frame.length) as u64 =>
        {
            Ok(())
        }
        (Method::BlobFinish, Some(MethodResult::BlobFinish(result)))
            if &result.transfer_id == transfer && &result.content == reference =>
        {
            Ok(())
        }
        _ => Err(refused()),
    }
}

fn method_name(method: Method) -> Result<&'static str, ProviderError> {
    match method {
        Method::BlobBegin => Ok("begin"),
        Method::BlobChunk => Ok("chunk"),
        Method::BlobFinish => Ok("finish"),
        _ => Err(refused()),
    }
}
fn refused() -> ProviderError {
    ProviderError::Correlation("original six-input upload owner or ACK changed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original six-input upload storage")
}

#[cfg(test)]
mod tests;
