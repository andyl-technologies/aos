//! Retains the distinct settled-Capture raw and typed ingress union.
//!
//! The genuine preChild17 owner must debit this independent row before receive.
//! These DATA transitions neither create that owner nor authenticate Capture.
//! Current native boot/Connection/Control, the actual administrative ticket and
//! Source proof, the separate action row and a spent original remain mandatory.
//! Failed decode/validation keeps every installed child and permanently closes
//! the attempt. No old startup16 reservation or generic Capture entry is used.

use super::PacketNativeStartupAllocationRow;
use crate::ProviderError;
use crate::bodies::{
    BeginKind, BeginRequest, BlobBeginRequest, BlobChunkRequest, BlobFinishRequest,
    CaptureArguments, PollRequest,
};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::reference_packet::service::restored_settled_capture::{
    PacketRestoredSettledCaptureArtifact, PacketRestoredSettledCaptureContext,
    RESTORED_SETTLED_CAPTURE_FEATURE, restored_settled_capture_assigned_request_digest_data,
    restored_settled_capture_context_schema_data,
    restored_settled_capture_contract_counter_scratch_data,
    upload::{
        PacketRestoredSettledCaptureUploadArtifact, PacketRestoredSettledCaptureUploadContext,
        PacketRestoredSettledCaptureUploadContinuation, RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
        restored_settled_capture_upload_assigned_request_digest_data,
        restored_settled_capture_upload_counter_scratch_data,
        restored_settled_capture_upload_schema_ids_data,
    },
};
use crate::reference_packet::service::restored_settled_confirmation::{
    PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
    PacketRestoredSettledAfterConfirmationRequest,
    restored_settled_after_confirmation_counter_scratch_data,
};
use crate::retained_metadata::MetadataObserver;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_data,
};
use crucible_node_contract::{Bytes, ContentRef, U64, Validate};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::mem::size_of;

/// Retains closed upload counts and exact native Chunk geometry as DATA.
///
/// The native consumer independently recomputes this from the same private
/// frame limit and both Source-signed full references. SDK custody uses these
/// exact counts before reserve. This value issues no upload/Capture permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredSettledCaptureUploadGeometryData {
    frame_bytes: usize,
    content_bytes: [usize; 2],
    chunk_bytes: usize,
    originals: [usize; 2],
}

impl PacketRestoredSettledCaptureUploadGeometryData {
    /// Returns exact BlobBegin/Chunks/BlobFinish maxima for both fixed ordinals.
    pub const fn maximum_auxiliary_originals_data(&self) -> [usize; 2] {
        self.originals
    }

    /// Returns the shared closed payload ceiling under the actual frame bound.
    pub const fn maximum_chunk_bytes_data(&self) -> usize {
        self.chunk_bytes
    }

    /// Returns one exact next Chunk length at the canonical offset grid.
    ///
    /// Native authenticates the same spent upload and its actual next offset
    /// before this check; choosing tiny chunks cannot multiply spent originals.
    ///
    /// # Errors
    /// Refuses a wrong ordinal, duplicate/unaligned or terminal offset.
    pub fn expected_chunk_length_data(
        &self,
        ordinal: usize,
        offset: usize,
    ) -> Result<usize, ProviderError> {
        let length = *self.content_bytes.get(ordinal).ok_or_else(invalid)?;
        if offset >= length || offset % self.chunk_bytes != 0 {
            return Err(invalid());
        }
        Ok((length - offset).min(self.chunk_bytes))
    }
}

/// Counts both real auxiliary transfers under the unchanged 256-original cap.
///
/// The two later Capture/confirmation originals are included in the cap check.
/// Existing spent originals and per-axis remaining credit remain separate
/// native owner checks. Full references are borrowed from the actual Source
/// capture inputs; no recursive history-prefix self-upload is constructed.
///
/// # Errors
/// Refuses malformed, wrong-role media or empty full references, short frames, arithmetic
/// overflow or total demand above the supplied actual finite allowance or 256.
pub fn original_restored_settled_capture_auxiliary_geometry_data(
    maximum_frame: usize,
    history_prefix: &ContentRef,
    runtime_object: &ContentRef,
    maximum_originals: usize,
) -> Result<PacketRestoredSettledCaptureUploadGeometryData, ProviderError> {
    if maximum_originals == 0 || maximum_originals > 256 {
        return Err(invalid());
    }
    // The closed Chunk envelope/continuation contains fewer than 32 fixed
    // 128-byte text/key fields plus 20-byte decimal coordinates. Six-byte JSON
    // escaping is charged for each, independently of the actual payload.
    let header = multiply(32, 128 * 6 + 20 + 8)?;
    let chunk_bytes = maximum_frame
        .checked_sub(header)
        .and_then(|bytes| bytes.checked_div(4))
        .and_then(|groups| groups.checked_mul(3))
        .filter(|bytes| *bytes > 0)
        .ok_or_else(invalid)?
        .min(1_048_576);
    let mut content_bytes = [0usize; 2];
    let mut originals = [0usize; 2];
    let mut total = 2usize;
    for (ordinal, reference) in [history_prefix, runtime_object].into_iter().enumerate() {
        reference.validate()?;
        let length = usize::try_from(reference.length.get()).map_err(|_| invalid())?;
        let media = match ordinal {
            0 => "application/json",
            1 => "application/vnd.crucible.runtime-original-lineage+json;version=7",
            _ => return Err(invalid()),
        };
        if length == 0 || reference.media_type != media {
            return Err(invalid());
        }
        let chunks = length.checked_add(chunk_bytes - 1).ok_or_else(invalid)? / chunk_bytes;
        content_bytes[ordinal] = length;
        originals[ordinal] = sum(&[2, chunks])?;
        total = sum(&[total, originals[ordinal]])?;
    }
    if total > maximum_originals {
        return Err(invalid());
    }
    Ok(PacketRestoredSettledCaptureUploadGeometryData {
        frame_bytes: maximum_frame,
        content_bytes,
        chunk_bytes,
        originals,
    })
}

/// Derives the exact grid from the same actually negotiated transport limits.
///
/// The frame-only helper is a DATA bound, not an actual receiver selection.
/// Genuine selected17 SDK/native consumers use this method so their exact
/// chunks also obey the actual smaller negotiated Blob limit. Tiny-chunk
/// subdivision cannot multiply funded originals.
///
/// # Errors
/// Refuses invalid limits/fullrefs, empty bodies, grid/count overflow or demand
/// beyond the same independently funded nonrenewing original allowance.
pub fn original_restored_settled_capture_auxiliary_geometry_for_limits_data(
    limits: &crate::handshake::Limits,
    history_prefix: &ContentRef,
    runtime_object: &ContentRef,
    maximum_originals: usize,
) -> Result<PacketRestoredSettledCaptureUploadGeometryData, ProviderError> {
    for (ordinal, reference) in [history_prefix, runtime_object].into_iter().enumerate() {
        reference.validate()?;
        let expected_media = match ordinal {
            0 => "application/json",
            1 => "application/vnd.crucible.runtime-original-lineage+json;version=7",
            _ => return Err(invalid()),
        };
        if reference.media_type != expected_media {
            return Err(invalid());
        }
    }
    let lengths = [
        usize::try_from(history_prefix.length.get()).map_err(|_| invalid())?,
        usize::try_from(runtime_object.length.get()).map_err(|_| invalid())?,
    ];
    original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
        limits,
        lengths,
        maximum_originals,
    )
}

/// Bounds both future auxiliary bodies without inventing full references.
///
/// Source/SDK pre-ticket quotation uses actual defining encoded-length ceilings;
/// the later actual-reference helper must dominate the same two bodies. The grid
/// also observes the native receiver's existing `blob_chunk_bytes.min(4096)`
/// selection in both Endpoint constructors. No larger negotiated Blob limit can
/// increase that actual receiver's chunk size or reduce funded originals.
///
/// # Errors
/// Refuses invalid limits, zero lengths, short frames, overflow, or more than
/// the supplied independent original allowance (which itself cannot exceed 256).
pub fn original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
    limits: &crate::handshake::Limits,
    content_bytes: [usize; 2],
    maximum_originals: usize,
) -> Result<PacketRestoredSettledCaptureUploadGeometryData, ProviderError> {
    limits.validate()?;
    if maximum_originals == 0 || maximum_originals > 256 || content_bytes.contains(&0) {
        return Err(invalid());
    }
    let maximum_frame = usize::try_from(limits.frame_bytes.get()).map_err(|_| invalid())?;
    let receiver_chunk = usize::try_from(limits.blob_chunk_bytes.get()).map_err(|_| invalid())?;
    let header = multiply(32, 128 * 6 + 20 + 8)?;
    let chunk_bytes = maximum_frame
        .checked_sub(header)
        .and_then(|bytes| bytes.checked_div(4))
        .and_then(|groups| groups.checked_mul(3))
        .filter(|bytes| *bytes > 0)
        .ok_or_else(invalid)?
        .min(receiver_chunk)
        .min(4096);
    if chunk_bytes == 0 {
        return Err(invalid());
    }
    let mut originals = [0usize; 2];
    let mut total = 2usize;
    for (originals, bytes) in originals.iter_mut().zip(content_bytes) {
        let chunks = bytes.checked_add(chunk_bytes - 1).ok_or_else(invalid)? / chunk_bytes;
        *originals = sum(&[2, chunks])?;
        total = sum(&[total, *originals])?;
    }
    if total > maximum_originals {
        return Err(invalid());
    }
    Ok(PacketRestoredSettledCaptureUploadGeometryData {
        frame_bytes: maximum_frame,
        content_bytes,
        chunk_bytes,
        originals,
    })
}

/// Names the actual negotiated-limit/grid inputs and mapped fixed views.
pub const fn original_restored_settled_capture_negotiated_geometry_counter_scratch_data() -> usize {
    original_restored_settled_capture_auxiliary_geometry_counter_scratch_data()
        + size_of::<&crate::handshake::Limits>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>() * 2
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, usize>, std::array::IntoIter<usize, 2>>,
        >()
        + size_of::<Option<(&mut usize, usize)>>()
        + size_of::<[usize; 2]>() * 2
        + size_of::<std::array::IntoIter<&'static ContentRef, 2>>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&'static ContentRef, 2>>>()
        + size_of::<Option<(usize, &'static ContentRef)>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>() * 2
        + size_of::<Result<PacketRestoredSettledCaptureUploadGeometryData, ProviderError>>()
}

#[derive(Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Receiving,
    Raw,
    Typed,
    Failed,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
enum Body {
    Capture(BeginRequest),
    BlobBegin(BlobBeginRequest),
    BlobChunk(BlobChunkRequest),
    BlobFinish(BlobFinishRequest),
    Confirmation(PollRequest),
}

/// Retains one original's partial parsing without granting native execution.
#[derive(serde::Serialize)]
pub(crate) struct NativeRestoredSettledCaptureAttempt {
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<Body>,
    arguments: Option<CaptureArguments>,
    capture: Option<PacketRestoredSettledCaptureArtifact>,
    capture_context: Option<PacketRestoredSettledCaptureContext>,
    upload: Option<PacketRestoredSettledCaptureUploadArtifact>,
    upload_context: Option<PacketRestoredSettledCaptureUploadContext>,
    continuation: Option<PacketRestoredSettledCaptureUploadContinuation>,
    confirmation: Option<PacketRestoredSettledAfterConfirmationRequest>,
    checkpoint: Option<crate::reference_packet::control::NativeRestoredSettledCheckpointAttempt>,
    outputs: Option<super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs>,
    terminal: Option<Envelope>,
    prepared_reply: Option<Map<String, Value>>,
    stage: Stage,
}

impl NativeRestoredSettledCaptureAttempt {
    /// Initializes custody only after the actual native owner spends its slot.
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            ordinal,
            original: None,
            body: None,
            arguments: None,
            capture: None,
            capture_context: None,
            upload: None,
            upload_context: None,
            continuation: None,
            confirmation: None,
            checkpoint: None,
            outputs: None,
            terminal: None,
            prepared_reply: None,
            stage: Stage::Receiving,
        }
    }

    /// Installs raw custody before any syntax or selected-method check.
    pub(crate) fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Receiving || self.original.is_some() || self.ordinal == 0 {
            return Err(invalid());
        }
        self.original = Some(original);
        let original = self.original.as_ref().ok_or_else(invalid)?;
        original.validate()?;
        if original.message != MessageKind::Request
            || original.sequence.get() == 0
            || original.request_id.0.is_none()
            || original.node_id.0.is_none()
            || original.capture_owner_id.0.is_none()
            || original.execution_owner_id.0.is_some()
            || original.extensions.len() != 1
        {
            return Err(invalid());
        }
        self.stage = Stage::Raw;
        Ok(())
    }

    /// Borrows the same retained raw original without granting dispatch.
    ///
    /// Failed typed validation does not discard this owner. The genuine native
    /// receive scope separately checks the same Boot/index/shared slot.
    ///
    /// # Errors
    /// Refuses an attempt that has not retained its original Envelope.
    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.original.as_ref().ok_or_else(invalid)
    }

    /// Retains each decoded owner before its own fallible validation.
    ///
    /// This checks closed DATA correspondence only. Its success is not a spent
    /// Source-MAC permit and does not enable dispatch, publication or retirement.
    pub(crate) fn decode_body_data(&mut self, maximum_frame: usize) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Raw || self.body.is_some() {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        crate::connection::serialized_credit(original, maximum_frame)?;
        self.body = Some(match original.method {
            Method::Begin => Body::Capture(decode(&original.body)?),
            Method::BlobBegin => Body::BlobBegin(decode(&original.body)?),
            Method::BlobChunk => Body::BlobChunk(decode(&original.body)?),
            Method::BlobFinish => Body::BlobFinish(decode(&original.body)?),
            Method::Poll => Body::Confirmation(decode(&original.body)?),
            _ => return Err(invalid()),
        });
        match self.body.as_ref().ok_or_else(invalid)? {
            Body::Capture(body) => {
                self.capture = Some(extension(original, RESTORED_SETTLED_CAPTURE_FEATURE)?);
                self.arguments = Some(decode(&body.arguments)?);
                body.validate()?;
                if body.kind != BeginKind::Capture || !body.extensions.is_empty() {
                    return Err(invalid());
                }
                self.arguments.as_ref().ok_or_else(invalid)?.validate()?;
                self.capture.as_ref().ok_or_else(invalid)?.validate_data()?;
                restored_settled_capture_assigned_request_digest_data(original, maximum_frame)?;
            }
            Body::BlobBegin(body) => {
                self.upload = Some(extension(
                    original,
                    RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
                )?);
                body.validate()?;
                self.upload.as_ref().ok_or_else(invalid)?.validate_data()?;
                restored_settled_capture_upload_assigned_request_digest_data(
                    original,
                    maximum_frame,
                )?;
            }
            Body::BlobChunk(body) => {
                self.continuation = Some(extension(
                    original,
                    RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
                )?);
                body.validate()?;
                self.continuation
                    .as_ref()
                    .ok_or_else(invalid)?
                    .validate_data()?;
                if original.operation_id.0.is_some() || !body.extensions.is_empty() {
                    return Err(invalid());
                }
            }
            Body::BlobFinish(body) => {
                self.continuation = Some(extension(
                    original,
                    RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
                )?);
                body.validate()?;
                self.continuation
                    .as_ref()
                    .ok_or_else(invalid)?
                    .validate_data()?;
                if original.operation_id.0.is_some() || !body.extensions.is_empty() {
                    return Err(invalid());
                }
            }
            Body::Confirmation(body) => {
                self.confirmation = Some(extension(
                    original,
                    PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
                )?);
                body.validate()?;
                self.confirmation
                    .as_ref()
                    .ok_or_else(invalid)?
                    .validate_data()?;
                if original.operation_id.0.as_ref()
                    != Some(
                        &self
                            .confirmation
                            .as_ref()
                            .ok_or_else(invalid)?
                            .capture_operation_id,
                    )
                    || body.after_observation_sequence.get() != 0
                    || !body.extensions.is_empty()
                {
                    return Err(invalid());
                }
            }
        }
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Derives the actual Capture context only from this retained original.
    ///
    /// The genuine caller prepays this whole receive row before its constructor.
    /// Completed context custody precedes its own syntax validation; no external
    /// owned context can smuggle unquoted capacities into this native attempt.
    pub(crate) fn derive_capture_context_data(
        &mut self,
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Typed || self.capture_context.is_some() {
            return Err(invalid());
        }
        let artifact = self.capture.as_ref().ok_or_else(invalid)?;
        let digest = restored_settled_capture_assigned_request_digest_data(
            self.original.as_ref().ok_or_else(invalid)?,
            maximum_frame,
        )?;
        self.capture_context = Some(PacketRestoredSettledCaptureContext {
            schema: restored_settled_capture_context_schema_data().to_owned(),
            request: artifact.request.clone(),
            assigned_request: Bytes::new(digest.to_vec()),
        });
        self.capture_context
            .as_ref()
            .ok_or_else(invalid)?
            .validate_data()?;
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Derives the actual upload context without issuing an upload lease.
    pub(crate) fn derive_upload_context_data(
        &mut self,
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        let previous = self.stage;
        self.stage = Stage::Failed;
        if previous != Stage::Typed || self.upload_context.is_some() {
            return Err(invalid());
        }
        let artifact = self.upload.as_ref().ok_or_else(invalid)?;
        let digest = restored_settled_capture_upload_assigned_request_digest_data(
            self.original.as_ref().ok_or_else(invalid)?,
            maximum_frame,
        )?;
        self.upload_context = Some(PacketRestoredSettledCaptureUploadContext {
            schema: restored_settled_capture_upload_schema_ids_data()
                .1
                .to_owned(),
            request: artifact.request.clone(),
            assigned_request: Bytes::new(digest.to_vec()),
        });
        self.upload_context
            .as_ref()
            .ok_or_else(invalid)?
            .validate_data()?;
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Checks the same retained assigned Capture against the actual birth key.
    ///
    /// The native consumer supplies this key only from its intrinsically joined
    /// Boot. This method lends correspondence DATA; current-Control eligibility,
    /// whole graph/output admission and an irrevocably spent native action are
    /// independent mandatory checks before any Capture effect.
    ///
    /// # Errors
    /// Refuses a repeated context attempt, wrong assigned scope/body or MAC.
    /// The derived Context remains retained and failure permanently closes it.
    pub(crate) fn authenticate_capture_source_data(
        &mut self,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        self.derive_capture_context_data(maximum_frame)?;
        self.stage = Stage::Failed;
        let artifact = self.capture.as_ref().ok_or_else(invalid)?;
        let context = self.capture_context.as_ref().ok_or_else(invalid)?;
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let request = &artifact.request;
        if original.capture_owner_id.0.as_ref() != Some(&request.capture_owner)
            || original.operation_id.0.as_ref() != Some(&request.capture_operation)
            || original.node_id.0.as_ref() != Some(&request.scope.target.node)
            || self.arguments.as_ref() != Some(&request.capture)
        {
            return Err(invalid());
        }
        crate::reference_packet::service::restored_settled_capture::verify_restored_settled_capture_proof_data(
            key, context, &artifact.proof,
        )?;
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Checks one actual assigned BlobBegin in the distinct upload MAC domain.
    ///
    /// No upload lease, remaining credit or Capture ticket is created here.
    /// Native independently checks the exact same current Capture scope, ordinal,
    /// transfer grid and reserved action before touching its Blob owner.
    ///
    /// # Errors
    /// Refuses a repeated context, wrong raw/typed transfer or body, owner/node
    /// disagreement, or MAC mismatch. All typed/raw Context owners stay retained.
    pub(crate) fn authenticate_upload_source_data(
        &mut self,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        self.derive_upload_context_data(maximum_frame)?;
        self.stage = Stage::Failed;
        let artifact = self.upload.as_ref().ok_or_else(invalid)?;
        let context = self.upload_context.as_ref().ok_or_else(invalid)?;
        let original = self.original.as_ref().ok_or_else(invalid)?;
        let request = &artifact.request;
        let Some(Body::BlobBegin(body)) = &self.body else {
            return Err(invalid());
        };
        if body.transfer_id != request.transfer_id
            || body.content != request.content
            || original.capture_owner_id.0.as_ref() != Some(&request.capture.capture_owner)
            || original.node_id.0.as_ref() != Some(&request.capture.scope.target.node)
            || original.operation_id.0.is_some()
        {
            return Err(invalid());
        }
        crate::reference_packet::service::restored_settled_capture::upload::verify_restored_settled_capture_upload_proof_data(
            key, context, &artifact.proof,
        )?;
        self.stage = Stage::Typed;
        Ok(())
    }

    /// Appends every actual child to the aggregate native graph observer.
    ///
    /// This never clears caller banks or substitutes encoded length for retained
    /// spare capacities. Failed attempts remain observable as complete children.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.current_readonly_data()
            .observe_with_outputs_data(&self.outputs, observer)
    }

    /// Permanently retains a failed attempt; no method reopens this state.
    pub(crate) fn interrupt_data(&mut self) {
        self.stage = Stage::Failed;
    }
}

fn decode<T: DeserializeOwned>(body: &Map<String, Value>) -> Result<T, ProviderError> {
    serde_json::from_value(Value::Object(body.clone()))
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(ProviderError::from)
}

fn extension<T: DeserializeOwned>(original: &Envelope, feature: &str) -> Result<T, ProviderError> {
    serde_json::from_value(
        original
            .extensions
            .get(feature)
            .ok_or_else(invalid)?
            .clone(),
    )
    .map_err(crucible_node_contract::ContractError::from)
    .map_err(ProviderError::from)
}

/// Names only the defining geometry counter and borrowed/result views.
///
/// This fixed census does not call SDK, Source, native receiver or permission
/// counters, so the paired SDK quote can conjoin it without a dependency cycle.
pub const fn original_restored_settled_capture_auxiliary_geometry_counter_scratch_data() -> usize {
    size_of::<PacketRestoredSettledCaptureUploadGeometryData>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadGeometryData, ProviderError>>()
        + size_of::<[&ContentRef; 2]>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&ContentRef, 2>>>()
        + size_of::<Option<(usize, &ContentRef)>>()
        + size_of::<Option<&usize>>()
        + size_of::<Result<&usize, ProviderError>>()
        + size_of::<[usize; 2]>() * 2
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<[usize; 2]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Option<&usize>>()
}

/// Prices the closed Capture/auxiliary upload/confirmation receive owners.
///
/// This row excludes the native graph snapshot and all output/effect owners;
/// those require the complete separately debited action row. It grants no
/// receive permission and must be independently prepaid before the child.
///
/// # Errors
/// Refuses a frame below the closed artifact ceiling, an unrepresentable JSON
/// extent or checked overflow.
pub fn original_restored_settled_capture_ingress_row_data(
    maximum_frame: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    if maximum_frame < 16_384 {
        return Err(invalid());
    }
    let raw = original_json_value_storage_extent_data(maximum_frame)?;
    // One raw Envelope, one cloned body DOM, six independently retained typed
    // extension/context slots and the separate Capture arguments each have at
    // most one frame's dynamic JSON population. Add their defining fixed DTO
    // layouts separately; bytes never stand in for a guessed typed multiplier.
    let fixed = sum(&[
        size_of::<NativeRestoredSettledCaptureAttempt>(),
        size_of::<Body>(),
        size_of::<CaptureArguments>(),
        size_of::<PacketRestoredSettledCaptureArtifact>(),
        size_of::<PacketRestoredSettledCaptureContext>(),
        size_of::<PacketRestoredSettledCaptureUploadArtifact>(),
        size_of::<PacketRestoredSettledCaptureUploadContext>(),
        size_of::<PacketRestoredSettledCaptureUploadContinuation>(),
        size_of::<PacketRestoredSettledAfterConfirmationRequest>(),
    ])?;
    let retained = sum(&[
        fixed,
        multiply(9, raw.value_dom_requested_bytes)?,
        maximum_frame,
        restored_settled_capture_context_schema_data().len(),
        restored_settled_capture_upload_schema_ids_data().1.len(),
        64,
        size_of::<std::cell::RefCell<NativeRestoredSettledCaptureAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<std::cell::RefCell<NativeRestoredSettledCaptureAttempt>>(),
        )?,
    ])?;
    let transient = sum(&[
        raw.value_dom_requested_bytes,
        multiply(2, raw.canonical_pass_requested_bytes()?)?,
        multiply(2, maximum_frame)?,
    ])?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(
            original_restored_settled_capture_ingress_counter_scratch_data(),
        )?,
    })
}

/// Names the defining receiver/parser/DTO/hash and borrowed counter headers.
pub fn original_restored_settled_capture_ingress_counter_scratch_data() -> usize {
    current_view17::counter_scratch_data()
        + size_of::<NativeRestoredSettledCaptureAttempt>()
        + original_restored_settled_capture_auxiliary_geometry_counter_scratch_data()
        + size_of::<Stage>()
        + size_of::<Body>()
        + size_of::<Option<Body>>()
        + size_of::<Envelope>()
        + size_of::<Result<Body, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<BeginRequest, serde_json::Error>>()
        + size_of::<Result<BlobBeginRequest, serde_json::Error>>()
        + size_of::<Result<BlobChunkRequest, serde_json::Error>>()
        + size_of::<Result<BlobFinishRequest, serde_json::Error>>()
        + size_of::<Result<PollRequest, serde_json::Error>>()
        + size_of::<Result<CaptureArguments, serde_json::Error>>()
        + size_of::<Result<PacketRestoredSettledCaptureArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestoredSettledCaptureUploadContinuation, serde_json::Error>>()
        + size_of::<Result<PacketRestoredSettledAfterConfirmationRequest, serde_json::Error>>()
        + size_of::<Option<&NativeRestoredSettledCaptureAttempt>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<Option<&Body>>()
        + size_of::<Result<&Body, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledCaptureArtifact>>()
        + size_of::<Result<&PacketRestoredSettledCaptureArtifact, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledCaptureContext>>()
        + size_of::<Result<&PacketRestoredSettledCaptureContext, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledCaptureUploadArtifact>>()
        + size_of::<Result<&PacketRestoredSettledCaptureUploadArtifact, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledCaptureUploadContext>>()
        + size_of::<Result<&PacketRestoredSettledCaptureUploadContext, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledCaptureUploadContinuation>>()
        + size_of::<Result<&PacketRestoredSettledCaptureUploadContinuation, ProviderError>>()
        + size_of::<Option<&PacketRestoredSettledAfterConfirmationRequest>>()
        + size_of::<Result<&PacketRestoredSettledAfterConfirmationRequest, ProviderError>>()
        + field_view_bytes(|value: &'static NativeRestoredSettledCaptureAttempt| {
            let NativeRestoredSettledCaptureAttempt {
                ordinal,
                original,
                body,
                arguments,
                capture,
                capture_context,
                upload,
                upload_context,
                continuation,
                confirmation,
                checkpoint,
                outputs,
                terminal,
                prepared_reply,
                stage,
            } = value;
            (
                ordinal,
                original,
                body,
                arguments,
                capture,
                capture_context,
                upload,
                upload_context,
                continuation,
                confirmation,
                checkpoint,
                outputs,
                terminal,
                prepared_reply,
                stage,
            )
        })
        + field_view_bytes(
            |value: &'static PacketRestoredSettledAfterConfirmationRequest| {
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
                (
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
                )
            },
        )
        + field_view_bytes(|value: &'static BlobChunkRequest| {
            let BlobChunkRequest {
                transfer_id,
                offset,
                bytes,
                extensions,
            } = value;
            (transfer_id, offset, bytes, extensions)
        })
        + field_view_bytes(|value: &'static BlobBeginRequest| {
            let BlobBeginRequest {
                transfer_id,
                content,
                extensions,
            } = value;
            (transfer_id, content, extensions)
        })
        + field_view_bytes(|value: &'static BlobFinishRequest| {
            let BlobFinishRequest {
                transfer_id,
                extensions,
            } = value;
            (transfer_id, extensions)
        })
        + field_view_bytes(|value: &'static PollRequest| {
            let PollRequest {
                after_observation_sequence,
                extensions,
            } = value;
            (after_observation_sequence, extensions)
        })
        + restored_settled_capture_contract_counter_scratch_data()
        + restored_settled_capture_upload_counter_scratch_data()
        + restored_settled_after_confirmation_counter_scratch_data()
        + decode_counter_scratch_data::<BeginRequest>()
        + decode_counter_scratch_data::<BlobBeginRequest>()
        + decode_counter_scratch_data::<BlobChunkRequest>()
        + decode_counter_scratch_data::<BlobFinishRequest>()
        + decode_counter_scratch_data::<PollRequest>()
        + decode_counter_scratch_data::<CaptureArguments>()
        + decode_counter_scratch_data::<PacketRestoredSettledCaptureArtifact>()
        + decode_counter_scratch_data::<PacketRestoredSettledCaptureUploadArtifact>()
        + decode_counter_scratch_data::<PacketRestoredSettledCaptureUploadContinuation>()
        + decode_counter_scratch_data::<PacketRestoredSettledAfterConfirmationRequest>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<[usize; 9]>()
        + size_of::<[usize; 8]>()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Option<&usize>>()
}

// Both generic deserializers retain these exact mapped return views, including
// the intermediate contract error before conversion to the Provider error.
const fn decode_counter_scratch_data<T>() -> usize {
    size_of::<Result<T, serde_json::Error>>()
        + size_of::<Result<T, crucible_node_contract::ContractError>>()
        + size_of::<Result<T, ProviderError>>()
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    size_of::<U>()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, term| {
        total.checked_add(*term).ok_or_else(invalid)
    })
}

fn multiply(count: usize, bytes: usize) -> Result<usize, ProviderError> {
    count.checked_mul(bytes).ok_or_else(invalid)
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| invalid())?))
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("settled Capture17 ingress differs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_typed_continuation_keeps_real_raw_and_typed_owners() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::BlobChunk;
        original.node_id = crate::envelope::Nullable(Some(
            crucible_node_contract::Id::new("capture-node").unwrap(),
        ));
        original.execution_owner_id = crate::envelope::Nullable(None);
        original.capture_owner_id = crate::envelope::Nullable(Some(
            crucible_node_contract::Id::new("capture-owner").unwrap(),
        ));
        original.operation_id = crate::envelope::Nullable(None);
        original.body = serde_json::json!({
            "transfer_id":"transfer", "offset":"0", "bytes":"eA", "extensions":{}
        })
        .as_object()
        .unwrap()
        .clone();
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.to_owned(),
            serde_json::json!({
                "schema":"source-owned.packet-restored-settled-capture-upload-continuation/17",
                "context_digest":"eA", "capture_operation":"capture", "transfer_id":"transfer"
            }),
        );
        let mut attempt = NativeRestoredSettledCaptureAttempt::new_data(1);
        attempt.retain_original_data(original.clone()).unwrap();
        assert!(attempt.decode_body_data(65536).is_err());
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(matches!(attempt.body, Some(Body::BlobChunk(_))));
        assert!(attempt.continuation.is_some());
        assert!(attempt.retain_original_data(original).is_err());
        assert!(attempt.decode_body_data(65536).is_err());
    }

    #[test]
    fn auxiliary_grid_obeys_the_actual_smaller_negotiated_blob_limit() {
        let bytes = vec![b'x'; 40_000];
        let history =
            crucible_node_contract::canonical::content_ref(&bytes, "application/json").unwrap();
        let runtime = crucible_node_contract::canonical::content_ref(
            &bytes,
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
        )
        .unwrap();
        let limits = crate::handshake::Limits {
            frame_bytes: U64::new(65_536),
            nesting: U64::new(64),
            requests: U64::new(256),
            journal_entries: U64::new(256),
            blob_chunk_bytes: U64::new(4096),
        };
        let actual = original_restored_settled_capture_auxiliary_geometry_for_limits_data(
            &limits, &history, &runtime, 26,
        )
        .unwrap();
        assert_eq!(actual.maximum_chunk_bytes_data(), 4096);
        assert_eq!(actual.maximum_auxiliary_originals_data(), [12, 12]);
        assert_eq!(actual.expected_chunk_length_data(0, 4096).unwrap(), 4096);
        assert!(actual.expected_chunk_length_data(0, 4095).is_err());
        assert!(
            original_restored_settled_capture_auxiliary_geometry_for_limits_data(
                &limits, &history, &runtime, 25
            )
            .is_err()
        );
        let mut larger = limits.clone();
        larger.blob_chunk_bytes = U64::new(8192);
        let capped = original_restored_settled_capture_auxiliary_geometry_for_limits_data(
            &larger, &history, &runtime, 26,
        )
        .unwrap();
        assert_eq!(capped, actual);
        assert_eq!(capped.maximum_chunk_bytes_data(), 4096);
        assert!(
            original_restored_settled_capture_auxiliary_geometry_for_limits_data(
                &larger, &history, &runtime, 16,
            )
            .is_err()
        );
        assert_eq!(
            original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
                &larger,
                [40_000, 40_000],
                26,
            )
            .unwrap(),
            capped,
        );
        assert!(
            original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
                &larger,
                [0, 40_000],
                26,
            )
            .is_err()
        );

        let mut smaller = limits;
        smaller.blob_chunk_bytes = U64::new(2048);
        assert!(
            original_restored_settled_capture_auxiliary_geometry_for_limits_data(
                &smaller, &history, &runtime, 26
            )
            .is_err()
        );
        let actual = original_restored_settled_capture_auxiliary_geometry_for_limits_data(
            &smaller, &history, &runtime, 46,
        )
        .unwrap();
        assert_eq!(actual.maximum_chunk_bytes_data(), 2048);
        assert_eq!(actual.maximum_auxiliary_originals_data(), [22, 22]);
    }

    #[test]
    fn capture_ingress_quote_is_separate_checked_data() {
        let row = original_restored_settled_capture_ingress_row_data(65536).unwrap();
        assert!(row.requested_peak_data().is_ok());
        assert!(original_restored_settled_capture_ingress_row_data(0).is_err());
        assert!(original_restored_settled_capture_ingress_row_data(usize::MAX).is_err());
    }

    #[test]
    fn auxiliary_geometry_fixes_chunk_grid_and_refuses_one_short_original_count() {
        let bytes = vec![b'x'; 40_000];
        let reference =
            crucible_node_contract::canonical::content_ref(&bytes, "application/json").unwrap();
        let runtime = crucible_node_contract::canonical::content_ref(
            &bytes,
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
        )
        .unwrap();
        let geometry = original_restored_settled_capture_auxiliary_geometry_data(
            65_536, &reference, &runtime, 256,
        )
        .unwrap();
        assert!(
            original_restored_settled_capture_auxiliary_geometry_data(
                65_536, &reference, &reference, 256,
            )
            .is_err()
        );
        assert!(
            original_restored_settled_capture_auxiliary_geometry_data(
                65_536, &runtime, &runtime, 256,
            )
            .is_err()
        );
        let counts = geometry.maximum_auxiliary_originals_data();
        assert_eq!(counts, [4, 4]);
        let chunk = geometry.maximum_chunk_bytes_data();
        assert_eq!(geometry.expected_chunk_length_data(0, 0).unwrap(), chunk);
        assert_eq!(
            geometry.expected_chunk_length_data(0, chunk).unwrap(),
            bytes.len() - chunk
        );
        assert!(geometry.expected_chunk_length_data(0, 1).is_err());
        assert!(geometry.expected_chunk_length_data(0, bytes.len()).is_err());
        assert!(
            original_restored_settled_capture_auxiliary_geometry_data(
                65_536, &reference, &runtime, 9,
            )
            .is_err()
        );
        assert!(
            original_restored_settled_capture_auxiliary_geometry_data(
                65_536, &reference, &runtime, 10,
            )
            .is_ok()
        );
    }
}

#[path = "restored_settled_capture_ingress/current_view17.rs"]
mod current_view17;
pub(crate) use current_view17::NativeCaptureAttemptCurrent17;
