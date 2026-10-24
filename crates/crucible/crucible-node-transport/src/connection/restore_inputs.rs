//! Retains the six exact source-selected restore inputs beside their real token.
//!
//! Generic BlobReceiver limits and consuming pins are unchanged. This separate
//! custody accepts only the ordered roster authenticated by the fresh native
//! prepare issuer. The boot attempt retains the same custody Rc before any bank
//! allocation; the banks never point back to their token or boot owner.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::protocol_snapshot::owned11::{
    aliases::HistoricalAliasSummary,
    native::outer::{SealedHistoricalNativeState, ValidatedNativeOwnedProtocol11},
    outer::OwnedProtocol11DataLimits,
};
use crate::reference_packet::service::{
    ack_emitter::VerifiedCompleteRestorePrepare,
    complete_restore::transfer::PacketCompleteRestorePrepareRequest,
};
use crucible_node_format::ContentRef;
use std::cell::{Ref, RefCell};
use std::thread::ThreadId;

#[derive(Clone, Copy)]
pub(super) struct OriginalRestoreInputChunk {
    input: usize,
    offset: usize,
    length: usize,
}

struct InputBank {
    bytes: Vec<u8>,
    transfer: [u8; 128],
    transfer_length: usize,
    begun: bool,
    finished: bool,
}

impl InputBank {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            transfer: [0; 128],
            transfer_length: 0,
            begun: false,
            finished: false,
        }
    }

    fn matches(&self, transfer: &Id) -> bool {
        self.begun && self.transfer[..self.transfer_length] == *transfer.as_str().as_bytes()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CustodyPhase {
    Allocating,
    Receiving,
    Complete,
    Failed,
}

/// Retains partial banks and exact progress without issuing live restoration.
pub(crate) struct OriginalCompleteRestoreInputCustody {
    creator: u32,
    thread: ThreadId,
    quote: NativeRestoreInputAllocationQuote,
    banks: [InputBank; 6],
    chunks: Vec<OriginalRestoreInputChunk>,
    summaries: Vec<HistoricalAliasSummary>,
    native_encoded: Option<Vec<u8>>,
    native_owner: Option<SealedHistoricalNativeState>,
    mapping_attempt: Option<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>,
    held_proof_quote_taken: bool,
    next_input: usize,
    phase: CustodyPhase,
}

pub(super) struct InstalledCompleteRestoreInputs {
    pub(super) token: VerifiedCompleteRestorePrepare,
    pub(super) custody: Rc<RefCell<OriginalCompleteRestoreInputCustody>>,
}

pub(super) fn original_input_custody_layout() -> usize {
    // RefCell and the actual Rc header are independent of all bank backing.
    std::mem::size_of::<RefCell<OriginalCompleteRestoreInputCustody>>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::align_of::<RefCell<OriginalCompleteRestoreInputCustody>>()
        - 1
        + std::mem::size_of::<InstalledCompleteRestoreInputs>()
}

impl OriginalCompleteRestoreInputCustody {
    pub(super) fn authenticate_original_prepare_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        self.quote.authenticate_original_request(request)
    }

    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        self.quote.actor_current()
    }

    fn reserve(&mut self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.phase != CustodyPhase::Allocating {
            return Err(refused());
        }
        let result = (|| {
            for (bank, length) in self.banks.iter_mut().zip(self.quote.input_lengths()) {
                bank.bytes.try_reserve_exact(length).map_err(|_| credit())?;
                if bank.bytes.capacity() != length {
                    return Err(credit());
                }
            }
            let rows = self.quote.maximum_metadata_rows();
            self.summaries
                .try_reserve_exact(rows)
                .map_err(|_| credit())?;
            if self.summaries.capacity() != rows {
                return Err(credit());
            }
            self.summaries
                .resize(rows, HistoricalAliasSummary::default());
            let nodes = self.quote.maximum_nodes();
            self.chunks.try_reserve_exact(nodes).map_err(|_| credit())?;
            if self.chunks.capacity() != nodes {
                return Err(credit());
            }
            let bank = self.native_encoded.as_mut().ok_or_else(refused)?;
            let bytes = self.quote.input_lengths()[0];
            bank.try_reserve_exact(bytes).map_err(|_| credit())?;
            if bank.capacity() != bytes {
                return Err(credit());
            }
            Ok(())
        })();
        self.phase = if result.is_ok() {
            CustodyPhase::Receiving
        } else {
            CustodyPhase::Failed
        };
        result
    }

    fn authenticate_ready(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        self.quote.authenticate_original_request(request)?;
        if !matches!(self.phase, CustodyPhase::Receiving | CustodyPhase::Complete) {
            return Err(refused());
        }
        // A signed limit is not a physical reservation. Recheck every actual
        // retained bank, including the independent sealed native-body copy,
        // before acknowledging input custody or starting reconstruction.
        let (inputs, chunks, summaries, encoded) = self.allocated_capacities()?;
        let expected = self.quote.input_lengths();
        if inputs != expected
            || chunks != self.quote.maximum_nodes()
            || summaries != self.quote.maximum_metadata_rows()
            || encoded != expected[0]
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn allocated_capacities(
        &self,
    ) -> Result<([usize; 6], usize, usize, usize), ProviderError> {
        self.ensure_origin()?;
        let encoded = self.native_encoded.as_ref().map_or_else(
            || {
                self.native_owner
                    .as_ref()
                    .map_or(0, SealedHistoricalNativeState::encoded_capacity)
            },
            Vec::capacity,
        );
        Ok((
            std::array::from_fn(|i| self.banks[i].bytes.capacity()),
            self.chunks.capacity(),
            self.summaries.capacity(),
            encoded,
        ))
    }

    fn begin(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        begin: &BlobBeginRequest,
    ) -> Result<usize, ProviderError> {
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Receiving || !begin.extensions.is_empty() {
            return Err(refused());
        }
        let i = self.next_input;
        let reference = super::restore_input_quote::input_references(request)
            .get(i)
            .copied()
            .ok_or_else(refused)?;
        if &begin.content != reference {
            return Err(refused());
        }
        if self.banks[i].begun {
            if !self.banks[i].matches(&begin.transfer_id) {
                return Err(refused());
            }
            return Ok(self.banks[i].bytes.len());
        }
        let transfer = begin.transfer_id.as_str().as_bytes();
        if transfer.is_empty()
            || transfer.len() > 128
            || self
                .banks
                .iter()
                .any(|bank| bank.matches(&begin.transfer_id))
        {
            return Err(refused());
        }
        let bank = &mut self.banks[i];
        bank.transfer[..transfer.len()].copy_from_slice(transfer);
        bank.transfer_length = transfer.len();
        bank.begun = true;
        Ok(0)
    }

    fn chunk(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        chunk: &BlobChunkRequest,
    ) -> Result<usize, ProviderError> {
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Receiving
            || !chunk.extensions.is_empty()
            || self.chunks.len() == self.chunks.capacity()
        {
            return Err(refused());
        }
        let i = self.next_input;
        let bank = self.banks.get_mut(i).ok_or_else(refused)?;
        if !bank.matches(&chunk.transfer_id) || bank.finished {
            return Err(refused());
        }
        let offset = usize::try_from(chunk.offset.get()).map_err(|_| refused())?;
        let bytes = chunk.bytes.as_slice();
        let end = offset.checked_add(bytes.len()).ok_or_else(credit)?;
        if bytes.is_empty() || bytes.len() > 4096 || end > bank.bytes.capacity() {
            return Err(credit());
        }
        if offset == bank.bytes.len() {
            // Full capacity was charged before any input request; this cannot grow.
            bank.bytes.extend_from_slice(bytes);
        } else {
            let old = self
                .chunks
                .iter()
                .any(|old| old.input == i && old.offset == offset && old.length == bytes.len());
            if !old || bank.bytes.get(offset..end) != Some(bytes) {
                return Err(refused());
            }
        }
        self.chunks.push(OriginalRestoreInputChunk {
            input: i,
            offset,
            length: bytes.len(),
        });
        Ok(bank.bytes.len())
    }

    fn finish(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        finish: &BlobFinishRequest,
    ) -> Result<usize, ProviderError> {
        self.authenticate_ready(request)?;
        if !finish.extensions.is_empty() {
            return Err(refused());
        }
        let i = self
            .banks
            .iter()
            .position(|bank| bank.matches(&finish.transfer_id))
            .ok_or_else(refused)?;
        let bank = &mut self.banks[i];
        let reference = super::restore_input_quote::input_references(request)[i];
        verify_content(reference, &bank.bytes)?;
        if bank.finished {
            return Ok(i);
        }
        if self.phase != CustodyPhase::Receiving || i != self.next_input {
            return Err(refused());
        }
        bank.finished = true;
        self.next_input = self.next_input.checked_add(1).ok_or_else(credit)?;
        if self.next_input == self.banks.len() {
            self.phase = CustodyPhase::Complete;
        }
        Ok(i)
    }

    pub(crate) fn original_input(&self, index: usize) -> Result<&[u8], ProviderError> {
        self.ensure_origin()?;
        if self.phase != CustodyPhase::Complete {
            return Err(refused());
        }
        let bank = self.banks.get(index).ok_or_else(refused)?;
        if !bank.finished {
            return Err(refused());
        }
        Ok(&bank.bytes)
    }

    /// Decodes only after the caller has rechecked the signed full demand.
    ///
    /// Both the input and the independently precharged sealed encoded bank remain
    /// retained here if validation or final reconstruction fails.
    pub(crate) fn reconstruct_native(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        limits: OwnedProtocol11DataLimits,
    ) -> Result<(), ProviderError> {
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Complete || self.native_owner.is_some() {
            return Err(refused());
        }
        super::restore_input_quote::authenticate_decoder_limits(request, limits)?;
        let mut plan = ValidatedNativeOwnedProtocol11::validate(
            &self.banks[0].bytes,
            limits,
            &mut self.summaries,
        )?;
        plan.complete_schema_identity()?;
        self.quote
            .authenticate_native_plan(request, plan.allocation_demand())?;
        plan.reconstruct_sealed_into(
            &request.native_protocol,
            &mut self.native_encoded,
            &mut self.native_owner,
        )
    }

    fn reconstruct_original_selected_native(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        limits: OwnedProtocol11DataLimits,
        class: crate::protocol_snapshot::RestorationMappingClass,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::RestorationMappingClass;
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Complete || self.native_owner.is_some() {
            return Err(refused());
        }
        super::restore_input_quote::authenticate_decoder_limits(request, limits)?;
        let mut plan = ValidatedNativeOwnedProtocol11::validate(
            &self.banks[0].bytes,
            limits,
            &mut self.summaries,
        )?;
        match class {
            RestorationMappingClass::StartupCapture14 => {
                plan.complete_native_startup_capture_allocation_schema_identity()?;
            }
            RestorationMappingClass::InvocationCapture15 => {
                plan.complete_native_invocation_capture_schema_identity()?;
            }
            RestorationMappingClass::Legacy11 => return Err(refused()),
        }
        self.quote
            .authenticate_native_plan(request, plan.allocation_demand())?;
        match class {
            RestorationMappingClass::StartupCapture14 => plan
                .reconstruct_native_startup_capture_allocation_sealed_into(
                    &request.native_protocol,
                    &mut self.native_encoded,
                    &mut self.native_owner,
                ),
            RestorationMappingClass::InvocationCapture15 => plan
                .reconstruct_native_invocation_capture_sealed_into(
                    &request.native_protocol,
                    &mut self.native_encoded,
                    &mut self.native_owner,
                ),
            RestorationMappingClass::Legacy11 => Err(refused()),
        }
    }

    fn prepare_mapping_into(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        authority: &ConnectionAuthority,
        actor: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        codec: &Rc<Native5CodecOwner>,
        completed: &mut Option<
            Rc<RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>>,
        >,
    ) -> Result<(), ProviderError> {
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Complete
            || completed.is_some()
            || self.mapping_attempt.is_some()
            || self.native_owner.is_none()
        {
            return Err(refused());
        }
        let nonce: [u8; 32] = request
            .restoration
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping::prepare_into(
            &mut self.mapping_attempt,
            crate::protocol_snapshot::NativeArchivedMappingInput {
                historical: &mut self.native_owner,
                reference: &request.restoration.mapping,
                normalization: &self.banks[5].bytes,
                nonce,
            },
            authority,
            actor,
            codec,
        )?;
        // A failed preparation leaves the partial mapping and its original
        // decoded/encoded owners in this persistent custody. Only a complete
        // attempt transfers to the endpoint's persistent slot.
        *completed = Some(Rc::new(RefCell::new(
            self.mapping_attempt.take().ok_or_else(refused)?,
        )));
        Ok(())
    }

    fn prepare_original_selected_mapping_into(
        &mut self,
        request: &PacketCompleteRestorePrepareRequest,
        authority: &ConnectionAuthority,
        actor: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        codec: &Rc<Native5CodecOwner>,
        completed: &mut Option<
            Rc<RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>>,
        >,
    ) -> Result<(), ProviderError> {
        self.authenticate_ready(request)?;
        if self.phase != CustodyPhase::Complete
            || completed.is_some()
            || self.mapping_attempt.is_some()
            || self.native_owner.is_none()
        {
            return Err(refused());
        }
        let nonce: [u8; 32] = request
            .restoration
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping::prepare_original_selected_into(
            &mut self.mapping_attempt,
            crate::protocol_snapshot::NativeArchivedMappingInput {
                historical: &mut self.native_owner,
                reference: &request.restoration.mapping,
                normalization: &self.banks[5].bytes,
                nonce,
            },
            authority,
            actor,
            codec,
        )?;
        // A failed preparation leaves the partial mapping and its original
        // decoded/encoded owners in this persistent custody. Only a complete
        // attempt transfers to the endpoint's persistent slot.
        *completed = Some(Rc::new(RefCell::new(
            self.mapping_attempt.take().ok_or_else(refused)?,
        )));
        Ok(())
    }

    pub(crate) fn native_historical(&self) -> Result<&SealedHistoricalNativeState, ProviderError> {
        self.ensure_origin()?;
        let owner = self.native_owner.as_ref().ok_or_else(refused)?;
        owner.historical()?;
        Ok(owner)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn prepare_original_complete_restore_input_mapping_into(
        &self,
        completed: &mut Option<
            Rc<RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>>,
        >,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed.token.authenticate_current(self)?;
        let selected_class = installed.token.original_selected_native_class_data(self)?;
        let selected_limits = match selected_class {
            Some(_) => Some(selected_decoder_limits(&*installed.token.request(self)?)?),
            None => None,
        };
        let request = installed.token.request(self)?;
        let mut custody = installed.custody.try_borrow_mut().map_err(|_| borrowed())?;
        custody.quote.authenticate_connection(self)?;
        if let (Some(class), Some(limits)) = (selected_class, selected_limits) {
            custody.reconstruct_original_selected_native(&request, limits, class)?;
            custody.prepare_original_selected_mapping_into(
                &request,
                &self.authority,
                &self.protocol_owner,
                self.native5_codec.as_ref().ok_or_else(refused)?,
                completed,
            )?;
            custody.quote.authenticate_connection(self)?;
            installed.token.authenticate_current(self)?;
            return Ok(());
        }
        custody.prepare_mapping_into(
            &request,
            &self.authority,
            &self.protocol_owner,
            self.native5_codec.as_ref().ok_or_else(refused)?,
            completed,
        )
    }

    pub(crate) fn install_original_complete_restore_input_custody(
        &mut self,
        token: &mut Option<VerifiedCompleteRestorePrepare>,
        quote: NativeRestoreInputAllocationQuote,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.original_restore_inputs.is_some() {
            return Err(refused());
        }
        quote.authenticate_connection(self)?;
        let verified = token.as_ref().ok_or_else(refused)?;
        verified.authenticate_installation(self)?;
        verified.authenticate_input_allocation(self, &quote)?;
        let custody = Rc::new(RefCell::new(OriginalCompleteRestoreInputCustody {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            quote,
            banks: std::array::from_fn(|_| InputBank::new()),
            chunks: Vec::new(),
            summaries: Vec::new(),
            native_encoded: Some(Vec::new()),
            native_owner: None,
            mapping_attempt: None,
            held_proof_quote_taken: false,
            next_input: 0,
            phase: CustodyPhase::Allocating,
        }));
        // The genuine boot attempt receives the exact owner before the first
        // bank reserve. On any later error, both original owners retain it.
        verified.attach_input_custody(self, &custody)?;
        self.original_restore_inputs = Some(InstalledCompleteRestoreInputs {
            token: token.take().ok_or_else(refused)?,
            custody,
        });
        self.original_restore_inputs
            .as_ref()
            .ok_or_else(refused)?
            .custody
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .reserve()
    }

    pub(crate) fn acknowledge_original_complete_restore_input_custody(
        &self,
    ) -> Result<Rc<RefCell<OriginalCompleteRestoreInputCustody>>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed.token.authenticate_current(self)?;
        let request = installed.token.request(self)?;
        installed
            .custody
            .try_borrow()
            .map_err(|_| borrowed())?
            .authenticate_ready(&request)?;
        Ok(Rc::clone(&installed.custody))
    }

    /// Consumes a validated original Blob body only in the selected input lease.
    ///
    /// The endpoint builds its normal ACK from this result after the mutation.
    /// Errors retain the current literal and all bytes; no consuming pin or
    /// model installation occurs through this input-only path.
    pub(crate) fn receive_original_complete_restore_input(
        &self,
        original: &Envelope,
        body: &RequestBody,
    ) -> Result<Option<OriginalCompleteRestoreInputProgress>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if !matches!(
            body,
            RequestBody::BlobBegin(_) | RequestBody::BlobChunk(_) | RequestBody::BlobFinish(_)
        ) {
            return Ok(None);
        }
        let Some(installed) = self.original_restore_inputs.as_ref() else {
            return Ok(None);
        };
        installed.token.authenticate_current(self)?;
        self.authenticate_native5_source_codec()?;
        if original.message != MessageKind::Request
            || !original.extensions.is_empty()
            || self.guard.incoming_requests().count() != 1
            || self.guard.incoming_requests().next() != Some(original)
        {
            return Err(refused());
        }
        if !matches!(
            body,
            RequestBody::BlobBegin(_) | RequestBody::BlobChunk(_) | RequestBody::BlobFinish(_)
        ) {
            return Ok(None);
        }
        authenticate_blob_body(original, body)?;
        let request = installed.token.request(self)?;
        let mut owner = installed.custody.try_borrow_mut().map_err(|_| borrowed())?;
        match body {
            RequestBody::BlobBegin(begin) => {
                Ok(Some(OriginalCompleteRestoreInputProgress::Begin {
                    next_offset: owner.begin(&request, begin)?,
                    maximum_chunk_bytes: 4096,
                }))
            }
            RequestBody::BlobChunk(chunk) => {
                Ok(Some(OriginalCompleteRestoreInputProgress::Chunk {
                    next_offset: owner.chunk(&request, chunk)?,
                }))
            }
            RequestBody::BlobFinish(finish) => {
                Ok(Some(OriginalCompleteRestoreInputProgress::Finish {
                    input: owner.finish(&request, finish)?,
                }))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn original_complete_restore_input_state(
        &self,
    ) -> Result<Ref<'_, OriginalCompleteRestoreInputCustody>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed.token.authenticate_current(self)?;
        installed.custody.try_borrow().map_err(|_| borrowed())
    }
}

pub(crate) enum OriginalCompleteRestoreInputProgress {
    Begin {
        next_offset: usize,
        maximum_chunk_bytes: usize,
    },
    Chunk {
        next_offset: usize,
    },
    Finish {
        input: usize,
    },
}

fn verify_content(reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
    if reference.length.get() != u64::try_from(bytes.len()).map_err(|_| refused())?
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
    {
        return Err(refused());
    }
    // Same normative CNP/1 content framing as canonical::hash, with stack-only
    // hex output. No owned HashRef or decoded DOM is created at this boundary.
    let domain = b"cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(
        &u32::try_from(domain.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        &u64::try_from(bytes.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    if hasher.finalize().to_hex().as_str() != reference.hash.digest {
        return Err(refused());
    }
    Ok(())
}
fn refused() -> ProviderError {
    ProviderError::Correlation("complete restore input custody")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("complete restore input custody borrowed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("complete restore input banks")
}

fn authenticate_blob_body(original: &Envelope, body: &RequestBody) -> Result<(), ProviderError> {
    let fields = &original.body;
    let transfer = fields
        .get("transfer_id")
        .and_then(serde_json::Value::as_str);
    let empty = fields
        .get("extensions")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|extensions| extensions.is_empty());
    if !empty {
        return Err(refused());
    }
    match body {
        RequestBody::BlobBegin(begin) if original.method == Method::BlobBegin => {
            if fields.len() != 3 || transfer != Some(begin.transfer_id.as_str()) {
                return Err(refused());
            }
            let content = fields
                .get("content")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(refused)?;
            let hash = content
                .get("hash")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(refused)?;
            if content.len() != 3
                || hash.len() != 3
                || content
                    .get("length")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|n| n.parse::<u64>().ok())
                    != Some(begin.content.length.get())
                || content
                    .get("media_type")
                    .and_then(serde_json::Value::as_str)
                    != Some(begin.content.media_type.as_str())
                || hash.get("algorithm").and_then(serde_json::Value::as_str)
                    != Some(begin.content.hash.algorithm.as_str())
                || hash.get("domain").and_then(serde_json::Value::as_str)
                    != Some(begin.content.hash.domain.as_str())
                || hash.get("digest").and_then(serde_json::Value::as_str)
                    != Some(begin.content.hash.digest.as_str())
            {
                return Err(refused());
            }
        }
        RequestBody::BlobChunk(chunk) if original.method == Method::BlobChunk => {
            if fields.len() != 4
                || transfer != Some(chunk.transfer_id.as_str())
                || fields
                    .get("offset")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|n| n.parse::<u64>().ok())
                    != Some(chunk.offset.get())
                || chunk.bytes.as_slice().len() > 4096
            {
                return Err(refused());
            }
            let raw = fields
                .get("bytes")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(refused)?;
            use base64::Engine;
            let mut encoded = [0u8; 5462];
            let length = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode_slice(chunk.bytes.as_slice(), &mut encoded)
                .map_err(|_| refused())?;
            if &encoded[..length] != raw.as_bytes() {
                return Err(refused());
            }
        }
        RequestBody::BlobFinish(finish) if original.method == Method::BlobFinish => {
            if fields.len() != 2 || transfer != Some(finish.transfer_id.as_str()) {
                return Err(refused());
            }
        }
        _ => return Err(refused()),
    }
    Ok(())
}

impl<S: ProviderStream> Connection<S> {
    /// Retains the once-only proof quote already admitted with actual Prepare custody.
    pub(crate) fn retain_original_complete_restore_held_proof_allocation(
        &self,
    ) -> Result<super::restore_proof_quote::OriginalRestoreHeldProofAllocationQuote, ProviderError>
    {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed.token.authenticate_current(self)?;
        let request = installed.token.request(self)?;
        let mut custody = installed.custody.try_borrow_mut().map_err(|_| borrowed())?;
        custody.ensure_origin()?;
        custody.quote.authenticate_original_request(&request)?;
        if custody.held_proof_quote_taken {
            return Err(refused());
        }
        let quote = custody.quote.retain_held_proof_quote(self)?;
        custody.held_proof_quote_taken = true;
        Ok(quote)
    }
}

// Both bounds come from the exact verified Prepare. The shared decoder's own
// compiled combined-row ceiling is an additional restriction, never an increase
// in signed transfer/object counts or Source memory authority.
fn selected_decoder_limits(
    request: &PacketCompleteRestorePrepareRequest,
) -> Result<OwnedProtocol11DataLimits, ProviderError> {
    let a = &request.allocation;
    a.validate_data()?;
    let extent = |value: u64| usize::try_from(value).map_err(|_| refused());
    let limits = OwnedProtocol11DataLimits {
        json: crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits {
            maximum_input_bytes: extent(a.maximum_input_bytes.get())?,
            maximum_nodes: extent(a.maximum_nodes.get())?,
            maximum_depth: extent(a.maximum_depth.get())?,
            maximum_owned_backing_bytes: extent(a.maximum_owned_backing_bytes.get())?,
            maximum_tree_entries: extent(a.maximum_tree_entries.get())?,
        },
        content: crate::client::compact_metadata8::CompactMetadata8Limits {
            content: crate::client::compact_cursor::CompactContentLimits {
                max_input_bytes: extent(a.maximum_input_bytes.get())?,
                max_rows: extent(a.maximum_content_transfers.get())?
                    .checked_add(extent(a.maximum_content_objects.get())?)
                    .ok_or_else(refused)?
                    .min(
                        crate::client::compact_cursor::CompactContentLimits::maximum_supported_combined_rows_data(),
                    ),
                max_groups: extent(a.maximum_content_groups.get())?,
                max_first_group_capacity_bytes: extent(a.maximum_content_bytes.get())?,
            },
            maximum_metadata_capacity_bytes: extent(a.maximum_content_metadata_bytes.get())?,
        },
        maximum_metadata_rows: extent(a.maximum_metadata_rows.get())?,
        maximum_literal_backing_bytes: extent(a.maximum_literal_backing_bytes.get())?,
    };
    super::restore_input_quote::authenticate_decoder_limits(request, limits)?;
    Ok(limits)
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_complete_restore_selected_native_class_data(
        &self,
    ) -> Result<Option<crate::protocol_snapshot::RestorationMappingClass>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.original_restore_inputs
            .as_ref()
            .ok_or_else(refused)?
            .token
            .original_selected_native_class_data(self)
    }
}

#[path = "restore_inputs/current17.rs"]
mod current17;
mod settled;
