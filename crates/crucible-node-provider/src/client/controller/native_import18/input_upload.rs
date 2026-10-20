//! Owns seven distinct input uploads beneath the actual completed Prepare18.
//!
//! The capsule retains every planned original and received typed/raw ACK. This
//! transport continuation grants no Source key, native lease, model or World.
//! The same Prepare deadline and original history allowance cover every frame.
//!
//! ```text
//! unused -> allocating -> publishing -> complete
//!                         \-> failed (never retransmitted)
//! ```

use super::*;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::retained_metadata::ObserveMetadata;
use std::mem::size_of;

#[path = "input_upload/prospective.rs"]
mod prospective;
#[path = "input_upload/publish.rs"]
mod publication;
pub use prospective::OriginalNativeImport18InputUploadProspectiveStorageData;
#[path = "input_upload/storage.rs"]
mod storage;

#[derive(Clone, Copy, Eq, PartialEq)]
enum UploadStage {
    Allocating,
    Publishing,
    RawReceived,
    Decoding,
    Complete,
    Failed,
}

pub(super) struct InputUploadBank {
    owners: Vec<InputUpload>,
    started: bool,
    failed: bool,
}

impl InputUploadBank {
    pub(super) fn empty() -> Self {
        Self {
            owners: Vec::new(),
            started: false,
            failed: false,
        }
    }

    fn is_used(&self) -> bool {
        self.started || self.failed || !self.owners.is_empty() || self.owners.capacity() != 0
    }

    pub(super) fn metadata_profile_for_envelope_data(
        &self,
        envelope: &Envelope,
    ) -> Result<Option<NativeImport18JsonMetadataProfileData>, ProviderError> {
        for owner in &self.owners {
            for frame in &owner.frames {
                if let Some(profile) = super::controller_metadata::matched_metadata_profile_data(
                    frame.json_profile,
                    frame.original.as_ref(),
                    frame.response.as_ref(),
                    envelope,
                )? {
                    return Ok(Some(profile));
                }
            }
        }
        Ok(None)
    }

    pub(super) fn metadata_maximum_depth_data(&self) -> usize {
        let mut depth = 65;
        for owner in &self.owners {
            for frame in &owner.frames {
                depth = depth.max(frame.json_profile.maximum_depth_data());
            }
        }
        depth
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        observer.vector::<InputUpload>(self.owners.capacity())?;
        for owner in &self.owners {
            owner.observe(observer)?;
        }
        Ok(())
    }
}

struct InputUpload {
    stage: UploadStage,
    references: [Option<ContentRef>; 7],
    transfers: [Option<Id>; 7],
    offsets: [usize; 7],
    frames: Vec<UploadFrame>,
    active: usize,
    chunk: usize,
    maximum_chunk: usize,
    cut: OperationalDeadline,
    prepare_sequence: U64,
    response_sequence: U64,
    token: [u8; 32],
    frontier: Option<OriginalProtocolStorageFacts>,
    next_sequence: Option<U64>,
}

struct UploadFrame {
    role: PacketNativeImport18InputRole,
    method: Method,
    offset: usize,
    length: usize,
    request_id: Id,
    original: Option<Envelope>,
    json_profile: NativeImport18JsonMetadataProfileData,
    raw: Option<crate::transport::RetainedFrame>,
    response: Option<Envelope>,
    received: Option<ReceivedFrame>,
    attempted: bool,
    complete: bool,
}

impl InputUpload {
    fn new(row: &OriginalNativeImport18InputUploadStorageData) -> Self {
        Self {
            stage: UploadStage::Allocating,
            references: std::array::from_fn(|_| None),
            transfers: std::array::from_fn(|_| None),
            offsets: [0; 7],
            frames: Vec::new(),
            active: 0,
            chunk: row.chunk,
            maximum_chunk: row.maximum_chunk,
            cut: row.cut,
            prepare_sequence: row.prepare_sequence,
            response_sequence: row.response_sequence,
            token: row.token,
            frontier: None,
            next_sequence: None,
        }
    }

    fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            stage: _,
            references,
            transfers,
            offsets: _,
            frames,
            active: _,
            chunk: _,
            maximum_chunk: _,
            cut: _,
            prepare_sequence: _,
            response_sequence: _,
            token: _,
            frontier: _,
            next_sequence: _,
        } = self;
        observer.observe(references)?;
        observer.observe(transfers)?;
        observer.vector::<UploadFrame>(frames.capacity())?;
        for frame in frames {
            let UploadFrame {
                role: _,
                method: _,
                offset: _,
                length: _,
                request_id,
                original,
                json_profile,
                raw,
                response,
                received,
                attempted: _,
                complete: _,
            } = frame;
            observer.with_native_import18_json_profile_data(*json_profile, |observer| {
                observer.observe(request_id)?;
                observer.observe(original)?;
                if let Some(raw) = raw {
                    observer.observe(&raw.value)?;
                    observer.vector::<u8>(raw.bytes.capacity())?;
                }
                observer.observe(response)?;
                if let Some(received) = received {
                    received.observe_native_import17_upload_data(observer)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}

struct Inputs<'a> {
    original: &'a Envelope,
    response: &'a Envelope,
    receipt: &'a PacketNativeImport17PrepareReceipt,
    references: [&'a ContentRef; 7],
}

impl Inputs<'_> {
    fn verify_bodies(
        &self,
        binding: &PacketNativeImport18Binding,
        bodies: &[&[u8]; 7],
    ) -> Result<(), ProviderError> {
        for role in PacketNativeImport18InputRole::ALL {
            let index = role.ordinal_data();
            let reference = self.references[index];
            if reference.length.get() > role.maximum_bytes_data(binding).get() {
                return Err(invalid());
            }
            verify_reference(reference, bodies[index])?;
        }
        Ok(())
    }

    fn prefix(&self) -> Result<blake3::Hash, ProviderError> {
        let id = self.original.request_id.0.as_ref().ok_or_else(invalid)?;
        Ok(blake3::hash(id.as_str().as_bytes()))
    }
}

fn inputs_data<'a>(
    prepare: &'a AssignedPhase<PacketCompleteRestorePrepareRequest>,
    binding: &'a PacketNativeImport18Binding,
) -> Result<Inputs<'a>, ProviderError> {
    let (original, response) = completed_pair(prepare)?;
    let receipt = prepare.prepare_receipt.as_ref().ok_or_else(invalid)?;
    Ok(Inputs {
        original,
        response,
        receipt,
        references: PacketNativeImport18InputRole::ALL
            .map(|role| role.reference_data(&prepare.request, binding)),
    })
}

/// Binds additional upload storage to the exact completed capsule and frontier.
///
/// The row is DATA. Its full axes must have been independently admitted by the
/// genuine Source before effects; this post-Prepare row cannot renew admission.
pub struct OriginalNativeImport18InputUploadStorageData {
    controller: Rc<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    prefix: blake3::Hash,
    identity: [u8; 32],
    prepare_sequence: U64,
    response_sequence: U64,
    token: [u8; 32],
    cut: OperationalDeadline,
    chunk: usize,
    maximum_chunk: usize,
    requests: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalNativeImport18InputUploadStorageData {
    /// Returns additional actual requested owner/cache storage.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns independently requested simultaneous protocol work.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns defining fixed counters, excluding compiler/recursive stack.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Observes the real retained shared Controller association of this row.
    ///
    /// # Errors
    /// Refuses foreign creator custody or metadata arithmetic exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        Ok(observer.finish())
    }

    fn authenticate(
        &self,
        capsule: &OriginalNativeImport18Assignment,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        bodies: &[&[u8]; 7],
    ) -> Result<(), ProviderError> {
        let inputs = capsule.upload_inputs(controller, emitter)?;
        inputs.verify_bodies(&capsule.binding, bodies)?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.prefix != inputs.prefix()?
            || self.identity
                != input_identity(&capsule.prepare.request, &capsule.binding, inputs.prefix()?)
            || self.prepare_sequence != inputs.original.sequence
            || self.response_sequence != inputs.response.sequence
            || self.token != *blake3::hash(inputs.receipt.transfer_token.as_slice()).as_bytes()
            || self.cut != capsule.prepare.cut.ok_or_else(invalid)?
            || self.maximum_chunk
                != usize::try_from(controller.authority().limits().blob_chunk_bytes.get())
                    .map_err(|_| credit())?
                    .min(4096)
        {
            return Err(invalid());
        }
        controller
            .session
            .authenticate_native_import18_upload_start_data(inputs.original, self.cut)
    }
}

impl OriginalNativeImport18Assignment {
    fn upload_inputs<'a>(
        &'a self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<Inputs<'a>, ProviderError> {
        self.authenticate(controller, emitter)?;
        inputs_data(&self.prepare, &self.binding)
    }

    /// Quotes the actual seven bodies beneath the same completed Prepare18.
    ///
    /// The independent formatter/schema/hash prewalk must be admitted first.
    /// All bodies stay in their actual Source owners. This row creates neither
    /// native input custody nor a Source phase claim and never resets a deadline.
    ///
    /// # Errors
    /// Refuses incomplete Prepare, started uploads/Commit, changed full bodies,
    /// stale frontier/cut, reused IDs or insufficient original cache/history credit.
    pub fn quote_input_upload_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        bodies: [&[u8]; 7],
        maximum: usize,
    ) -> Result<OriginalNativeImport18InputUploadStorageData, ProviderError> {
        if self.uploads.is_used() {
            return Err(invalid());
        }
        let inputs = self.upload_inputs(controller, emitter)?;
        inputs.verify_bodies(&self.binding, &bodies)?;
        let cut = self.prepare.cut.ok_or_else(invalid)?;
        controller
            .session
            .authenticate_native_import18_upload_start_data(inputs.original, cut)?;
        let parts = storage::quote(
            controller,
            &inputs,
            &self.prepare.request.allocation,
            maximum,
        )?;
        let row = OriginalNativeImport18InputUploadStorageData {
            controller: Rc::clone(&controller.protocol_owner),
            frontier: controller.original_native5_storage_facts()?,
            prefix: inputs.prefix()?,
            identity: input_identity(&self.prepare.request, &self.binding, inputs.prefix()?),
            prepare_sequence: inputs.original.sequence,
            response_sequence: inputs.response.sequence,
            token: *blake3::hash(inputs.receipt.transfer_token.as_slice()).as_bytes(),
            cut,
            chunk: parts.chunk,
            maximum_chunk: parts.maximum_chunk,
            requests: parts.requests,
            retained: parts.retained,
            transient: parts.transient,
            scratch: storage::counter_scratch_data(),
        };
        row.authenticate(self, controller, emitter, &bodies)?;
        Ok(row)
    }

    /// Checks the real seven-role ACK ledger at its exact pre-Commit frontier.
    ///
    /// This grants no keyed receipt verification, native model or phase claim.
    ///
    /// # Errors
    /// Refuses partial/failed/replayed uploads, another actor or Prepare/token,
    /// changed full references, missing original responses or later traffic.
    pub fn authenticate_input_upload_completed_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        let inputs = self.upload_inputs(controller, emitter)?;
        let [held] = self.uploads.owners.as_slice() else {
            return Err(invalid());
        };
        if !self.uploads.started
            || self.uploads.failed
            || held.stage != UploadStage::Complete
            || held.prepare_sequence != inputs.original.sequence
            || held.response_sequence != inputs.response.sequence
            || held.token != *blake3::hash(inputs.receipt.transfer_token.as_slice()).as_bytes()
            || held.frontier != Some(controller.original_native5_storage_facts()?)
        {
            return Err(invalid());
        }
        controller
            .session
            .authenticate_native_import18_upload_cut_data(held.cut)?;
        if held.next_sequence
            != Some(
                controller
                    .session
                    .native_import18_upload_sequence_data(held.cut)?,
            )
        {
            return Err(invalid());
        }
        for role in PacketNativeImport18InputRole::ALL {
            let index = role.ordinal_data();
            if held.references[index].as_ref() != Some(inputs.references[index])
                || held.offsets[index] as u64 != inputs.references[index].length.get()
            {
                return Err(invalid());
            }
        }
        if held.frames.is_empty() {
            return Err(invalid());
        }
        for frame in &held.frames {
            if !frame.attempted || !frame.complete {
                return Err(invalid());
            }
            let original = frame.original.as_ref().ok_or_else(invalid)?;
            let received = frame.received.as_ref().ok_or_else(invalid)?;
            controller
                .custody
                .authenticate_native_import18_upload_pair_data(original, &received.envelope)
                .map_err(|_| invalid())?;
            authenticate_ack(
                frame,
                received,
                held.transfers[frame.role.ordinal_data()]
                    .as_ref()
                    .ok_or_else(invalid)?,
                held.references[frame.role.ordinal_data()]
                    .as_ref()
                    .ok_or_else(invalid)?,
                held.chunk,
                held.maximum_chunk,
            )?;
        }
        emitter.authenticate_original(controller)
    }
}

impl CnpController {
    /// Names all defining upload, selected-codec and retained-cache controls.
    pub fn original_native_import18_input_upload_counter_scratch_data() -> usize {
        storage::counter_scratch_data()
    }

    /// Quotes the actual selected-schema/formatter/hash floor without allocating.
    ///
    /// # Errors
    /// Refuses foreign emitter/actor or checked geometry overflow.
    pub fn original_native_import18_input_upload_prewalk_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(usize, usize), ProviderError> {
        emitter.authenticate_original(self)?;
        let (contract, _) = native_import18_contract_storage_data(usize::MAX)?;
        let transient = contract
            .checked_add(20)
            .and_then(|n| n.checked_add(85))
            .ok_or_else(credit)?;
        Ok((transient, storage::counter_scratch_data()))
    }
}

fn authenticate_ack(
    frame: &UploadFrame,
    received: &ReceivedFrame,
    transfer: &Id,
    reference: &ContentRef,
    chunk: usize,
    maximum_chunk: usize,
) -> Result<(), ProviderError> {
    frame
        .original
        .as_ref()
        .ok_or_else(invalid)?
        .matches_response(&received.envelope)?;
    if !received.envelope.extensions.is_empty() {
        return Err(invalid());
    }
    let ReceivedBody::Response(body) = &received.body else {
        return Err(invalid());
    };
    let ResponseShape::Completed {
        operation_state: OperationState::Completed,
        extensions,
        ..
    } = &body.shape
    else {
        return Err(invalid());
    };
    if !extensions.is_empty() {
        return Err(invalid());
    }
    match (frame.method, &body.result) {
        (Method::BlobBegin, Some(MethodResult::BlobBegin(result)))
            if &result.transfer_id == transfer
                && result.next_offset.get() == 0
                && result.maximum_chunk_bytes.get() == maximum_chunk as u64
                && chunk <= maximum_chunk =>
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
        _ => Err(invalid()),
    }
}

pub(super) fn retained_counter_scratch_data() -> usize {
    size_of::<&InputUploadBank>()
        + size_of::<&InputUpload>()
        + size_of::<&UploadFrame>()
        + size_of::<std::slice::Iter<'static, InputUpload>>()
        + size_of::<std::slice::Iter<'static, UploadFrame>>()
        + size_of::<[&ContentRef; 7]>()
        + size_of::<[Option<ContentRef>; 7]>()
        + size_of::<[Option<Id>; 7]>()
        + size_of::<&crate::transport::RetainedFrame>()
        + size_of::<Option<&crate::transport::RetainedFrame>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<(
            &Id,
            &Option<Envelope>,
            &Option<crate::transport::RetainedFrame>,
            &Option<Envelope>,
            &Option<ReceivedFrame>,
        )>()
        + size_of::<&mut Option<Envelope>>()
        + size_of::<&mut Option<ReceivedFrame>>()
        + size_of::<&mut Option<crate::transport::RetainedFrame>>()
        + ReceivedFrame::native_import17_upload_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefunding_identity_binds_seventh_body_order_and_original_chunk_ceiling() {
        let ordinary = canonical::content_ref(b"base", "application/json").unwrap();
        let semantic = canonical::content_ref(
            b"spend",
            PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data(),
        )
        .unwrap();
        let changed = canonical::content_ref(
            b"other-spend",
            PacketNativeImport18SemanticSpendFamily::Complete18.media_type_data(),
        )
        .unwrap();
        let prefix = blake3::hash(b"actual-prepare-id");
        let mut references = [&ordinary; 7];
        references[6] = &semantic;
        let expected = reference_identity(&references, prefix, &[1; 32], U64::new(9));

        references[6] = &changed;
        assert_ne!(
            reference_identity(&references, prefix, &[1; 32], U64::new(9)),
            expected
        );
        references[6] = &semantic;
        references.swap(5, 6);
        assert_ne!(
            reference_identity(&references, prefix, &[1; 32], U64::new(9)),
            expected
        );
        references.swap(5, 6);
        assert_ne!(
            reference_identity(&references, prefix, &[1; 32], U64::new(10)),
            expected
        );
    }

    #[test]
    fn failed_reserved_spine_remains_spent_and_is_actually_counted() {
        let mut bank = InputUploadBank::empty();
        bank.started = true;
        bank.failed = true;
        bank.owners.try_reserve_exact(1).unwrap();
        let capacity = bank.owners.capacity();
        let mut observer = MetadataObserver::new();

        bank.observe(&mut observer).unwrap();
        let facts = observer.finish();

        assert!(bank.is_used());
        assert!(bank.owners.is_empty());
        assert_eq!(
            facts.vector_capacity_bytes,
            capacity * size_of::<InputUpload>()
        );
        assert!(bank.failed);
    }
}

fn input_identity(
    request: &PacketCompleteRestorePrepareRequest,
    binding: &PacketNativeImport18Binding,
    prefix: blake3::Hash,
) -> [u8; 32] {
    let references =
        PacketNativeImport18InputRole::ALL.map(|role| role.reference_data(request, binding));
    reference_identity(
        &references,
        prefix,
        binding.prepare_digest.as_slice(),
        request.allocation.maximum_nodes,
    )
}

fn reference_identity(
    references: &[&ContentRef; 7],
    prefix: blake3::Hash,
    prepare_digest: &[u8],
    maximum_chunks: U64,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"source-owned.packet-native-import-sdk-inputs/18");
    hash.update(prefix.as_bytes());
    hash.update(&(prepare_digest.len() as u64).to_be_bytes());
    hash.update(prepare_digest);
    hash.update(&maximum_chunks.get().to_be_bytes());
    for reference in references {
        for text in [
            &reference.hash.algorithm,
            &reference.hash.domain,
            &reference.hash.digest,
            &reference.media_type,
        ] {
            hash.update(&(text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(&reference.length.get().to_be_bytes());
    }
    *hash.finalize().as_bytes()
}

fn verify_reference(reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.hash.digest.len() != 64
        || !reference
            .hash
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || reference.media_type.is_empty()
        || reference.media_type.len() > 128
        || !reference
            .media_type
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
        || reference.length.get() == 0
    {
        return Err(invalid());
    }
    reference.verify(bytes)?;
    Ok(())
}

#[path = "input_upload/history.rs"]
mod history;

pub(super) use history::counter_scratch_data as history_counter_scratch_data;

pub use history::partials::{
    OriginalNativeImport18UploadBankPartialData,
    OriginalNativeImport18UploadOwnerPartialData,
    OriginalNativeImport18UploadFramePartialData,
    OriginalNativeImport18FrontierPartialData,
};
pub(super) use history::partials::counter_scratch_data as partial_history_counter_scratch_data;
