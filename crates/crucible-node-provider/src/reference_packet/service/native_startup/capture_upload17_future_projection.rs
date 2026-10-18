//! Bounds the three closed Capture-upload wire shapes before SDK assignment.
//!
//! These visitors create neither an Envelope nor an assigned identity, proof,
//! receiver, reservation or native scope. The actual launch supplies immutable
//! routing; future identifiers and decimal coordinates use their defining
//! grammars. Each retained shape is demand DATA, never remaining native credit.

use crate::ProviderError;
use crate::blob::BlobReceiver;
use crate::envelope::{MessageKind, Method};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::restored_input_reactive17::observation_geometry::{
    hash, object,
};
use crate::reference_packet::service::restored_settled_capture::{
    MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES, RESTORED_SETTLED_CAPTURE_REQUEST,
    upload::{
        RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE, restored_settled_capture_upload_proof_layout_data,
        restored_settled_capture_upload_schema_ids_data,
    },
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    original_serialization_counter_scratch_data,
};
use crucible_node_contract::{NodeBinding, Phase, Validate};
use std::mem::size_of;

type Projection = OriginalSerializationStorageProjection;
type Shape = OriginalSerializationStorageData;

/// Retains three independently projected, closed successful upload phases.
pub(super) struct NativeCapture17UploadFutureProjections {
    begin: NativeCapture17UploadFuturePhaseData,
    chunk: NativeCapture17UploadFuturePhaseData,
    finish: NativeCapture17UploadFuturePhaseData,
}

/// Keeps original, terminal and completed-body ownership distinct.
pub(super) struct NativeCapture17UploadFuturePhaseData {
    original: Shape,
    terminal: Shape,
    reply: Shape,
}

impl NativeCapture17UploadFutureProjections {
    /// Borrows one exact Blob method's prospective geometry.
    ///
    /// # Errors
    /// Refuses every method outside the three auxiliary upload methods.
    pub(super) fn phase_data(
        &self,
        method: Method,
    ) -> Result<&NativeCapture17UploadFuturePhaseData, ProviderError> {
        match method {
            Method::BlobBegin => Ok(&self.begin),
            Method::BlobChunk => Ok(&self.chunk),
            Method::BlobFinish => Ok(&self.finish),
            _ => Err(refused()),
        }
    }
}

impl NativeCapture17UploadFuturePhaseData {
    /// Borrows the complete original Envelope demand.
    pub(super) fn original_data(&self) -> &Shape {
        &self.original
    }

    /// Borrows the complete successful terminal Envelope demand.
    pub(super) fn terminal_data(&self) -> &Shape {
        &self.terminal
    }

    /// Borrows the independently retained completed-body demand.
    pub(super) fn reply_data(&self) -> &Shape {
        &self.reply
    }
}

/// Projects the closed Source upload family without constructing future DTOs.
///
/// This function does not parse the coordinator's installed bytes to invent a
/// participant roster. The fixed artifact-token bound below is independent of
/// the launch's one native binding. Large legal rosters can conservatively
/// exhaust unchanged storage/frame ceilings; this does not raise those caps.
///
/// # Errors
/// Refuses invalid transport limits, a launch without its sole native binding,
/// malformed borrowed routing, checked arithmetic overflow or a short maximum.
pub(super) fn project_capture17_upload_future_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<NativeCapture17UploadFutureProjections, ProviderError> {
    launch.limits.validate()?;
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    binding.authority.session_id.validate()?;
    binding.authority.incarnation_id.validate()?;
    binding.compatibility.node_id.validate()?;
    binding.compatibility.capture_owner.id.validate()?;
    let chunk = usize::try_from(launch.limits.blob_chunk_bytes.get())
        .map_err(|_| refused())?
        .min(4096);
    if chunk == 0 {
        return Err(refused());
    }

    let begin = phase(launch, binding, Method::BlobBegin, chunk, maximum)?;
    let chunk = phase(launch, binding, Method::BlobChunk, chunk, maximum)?;
    let finish = phase(launch, binding, Method::BlobFinish, 0, maximum)?;
    Ok(NativeCapture17UploadFutureProjections {
        begin,
        chunk,
        finish,
    })
}

fn phase(
    launch: &PacketNative5SourceLaunch,
    binding: &NodeBinding,
    method: Method,
    chunk: usize,
    maximum: usize,
) -> Result<NativeCapture17UploadFuturePhaseData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    envelope(&mut out, launch, binding, method, chunk, false)?;
    let original = out.finish(maximum)?;
    let mut out = Projection::new(maximum)?;
    envelope(&mut out, launch, binding, method, chunk, true)?;
    let terminal = out.finish(maximum)?;
    let mut out = Projection::new(maximum)?;
    BlobReceiver::project_capture17_upload_future_reply_data(method, &mut out)?;
    let reply = out.finish(maximum)?;
    Ok(NativeCapture17UploadFuturePhaseData {
        original,
        terminal,
        reply,
    })
}

fn envelope(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    binding: &NodeBinding,
    method: Method,
    chunk: usize,
    terminal: bool,
) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    out.add_string("CNP/1")?;
    out.add_value(&if terminal {
        MessageKind::Response
    } else {
        MessageKind::Request
    })?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    null(out)?;
    out.add_value(&binding.compatibility.capture_owner.id)?;
    identifier(out)?;
    null(out)?;
    decimal(out)?;
    out.add_value(&method)?;
    if terminal {
        BlobReceiver::project_capture17_upload_future_reply_data(method, out)?;
        out.add_object()
    } else {
        body(out, method, chunk)?;
        object(out, &[RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE])?;
        if method == Method::BlobBegin {
            artifact(out, launch, binding)
        } else {
            continuation(out)
        }
    }
}

fn body(out: &mut Projection, method: Method, chunk: usize) -> Result<(), ProviderError> {
    match method {
        Method::BlobBegin => {
            object(out, &["transfer_id", "content", "extensions"])?;
            identifier(out)?;
            reference(out)?;
        }
        Method::BlobChunk => {
            object(out, &["transfer_id", "offset", "bytes", "extensions"])?;
            identifier(out)?;
            decimal(out)?;
            // Bytes uses URL_SAFE_NO_PAD. Only the encoded extent is walked;
            // no Bytes serializer or temporary base64 String is invoked here.
            let encoded = encoded_bytes(chunk)?;
            out.add_unescaped_ascii_extent(encoded)?;
        }
        Method::BlobFinish => {
            object(out, &["transfer_id", "extensions"])?;
            identifier(out)?;
        }
        _ => return Err(refused()),
    }
    out.add_object()
}

fn artifact(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    binding: &NodeBinding,
) -> Result<(), ProviderError> {
    object(out, &["request", "proof"])?;
    object(
        out,
        &[
            "schema",
            "capture",
            "ordinal",
            "transfer_id",
            "content",
            "native_allocation",
        ],
    )?;
    out.add_string(restored_settled_capture_upload_schema_ids_data().0)?;
    capture_request(out, launch, binding)?;
    out.add_string("history_prefix")?; // Both closed ordinal names have fourteen bytes.
    identifier(out)?;
    reference(out)?;
    allocation(out)?;
    object(out, &["schema", "algorithm", "context_digest", "mac"])?;
    let (schema, algorithm, digest_bytes, mac_bytes) =
        restored_settled_capture_upload_proof_layout_data();
    out.add_string(schema)?;
    out.add_string(algorithm)?;
    out.add_unescaped_ascii_extent(encoded_bytes(digest_bytes)?)?;
    out.add_unescaped_ascii_extent(encoded_bytes(mac_bytes)?)
}

fn capture_request(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    binding: &NodeBinding,
) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "schema",
            "scope",
            "capture",
            "capture_owner",
            "capture_operation",
            "runtime_object",
            "coordinator_checkpoint",
            "parent_archive",
            "first_observation",
            "current_record",
            "current_model",
            "history_prefix",
            "history_next_sequence",
            "native_schema",
            "native_allocation",
        ],
    )?;
    out.add_string(RESTORED_SETTLED_CAPTURE_REQUEST)?;
    scope(out, launch, binding)?;
    capture_arguments(out)?;
    // The administrative ticket is supplied later; only the header owner is
    // already required to equal the immutable native binding at transport.
    identifier(out)?;
    identifier(out)?;
    for _ in 0..7 {
        reference(out)?;
    }
    decimal(out)?;
    reference(out)?;
    allocation(out)
}

fn scope(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    binding: &NodeBinding,
) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "source_birth",
            "source_runtime",
            "scope_proof",
            "target",
            "restoration",
        ],
    )?;
    for _ in 0..3 {
        reference(out)?;
    }
    object(
        out,
        &[
            "native_pid",
            "session",
            "incarnation",
            "node",
            "owner",
            "owner_generation",
            "binding_hash",
            "world",
            "activation",
            "generation",
            "prepared_token",
            "gate",
            "admission",
            "transaction",
        ],
    )?;
    decimal(out)?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    identifier(out)?;
    decimal(out)?;
    hash(out, "cnp.owner-binding.v1")?;
    out.add_value(&launch.selection.world)?;
    identifier(out)?;
    decimal(out)?;
    out.add_value(&launch.selection.prepared_token)?;
    out.add_value(&launch.selection.gate)?;
    out.add_value(&launch.selection.admission)?;
    out.add_value(&launch.selection.transaction)?;
    object(
        out,
        &[
            "captured_owner_state",
            "captured_control",
            "captured_journal",
            "mapping",
            "commit_request",
            "commit_response",
            "context_digest",
        ],
    )?;
    for _ in 0..6 {
        reference(out)?;
    }
    out.add_unescaped_ascii_extent(43)
}

fn capture_arguments(out: &mut Projection) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "capture_id",
            "participant_ids",
            "cut_id",
            "cut",
            "event_ordinal",
            "ordering_profile",
            "preservation_contract",
        ],
    )?;
    identifier(out)?;
    participants(out)?;
    identifier(out)?;
    object(out, &["time_ps", "microstep", "phase"])?;
    decimal(out)?;
    decimal(out)?;
    out.add_value(&Phase::Reaction)?;
    decimal(out)?;
    out.add_string("superdense-v1")?;
    identifier(out)
}

fn participants(out: &mut Projection) -> Result<(), ProviderError> {
    // A valid Id has at least one unescaped byte. Its JSON token and separator
    // use at least four bytes, except the final missing comma: n <= (A+1)/4.
    // The enclosing artifact also bounds total decoded participant Id bytes by
    // A. Count one byte per bounded slot, then the aggregate remaining bytes in
    // one extra geometry-only string. This dominates every permitted length
    // distribution linearly in A, without multiplying 128 by an imagined n.
    let artifact = MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES;
    let count = artifact.checked_add(1).ok_or_else(refused)? / 4;
    let remaining = artifact.checked_sub(count).ok_or_else(refused)?;
    out.add_array_extent(count.checked_add(1).ok_or_else(refused)?)?;
    for _ in 0..count {
        out.add_unescaped_ascii_extent(1)?;
    }
    out.add_unescaped_ascii_extent(remaining)
}

fn continuation(out: &mut Projection) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "schema",
            "context_digest",
            "capture_operation",
            "transfer_id",
        ],
    )?;
    out.add_string(restored_settled_capture_upload_schema_ids_data().2)?;
    out.add_unescaped_ascii_extent(43)?;
    identifier(out)?;
    identifier(out)
}

fn allocation(out: &mut Projection) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    decimal(out)?;
    decimal(out)?;
    decimal(out)
}

fn reference(out: &mut Projection) -> Result<(), ProviderError> {
    object(out, &["hash", "length", "media_type"])?;
    hash(out, "cnp.blob.v1")?;
    decimal(out)?;
    // ContentRef permits printable ASCII media strings, including quotes and
    // backslashes. The full128-byte validated field gets escaping credit.
    out.add_string_extent(128)
}

fn encoded_bytes(bytes: usize) -> Result<usize, ProviderError> {
    bytes
        .checked_div(3)
        .and_then(|groups| groups.checked_mul(4))
        .and_then(|encoded| {
            encoded.checked_add(match bytes % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or_else(refused)
}

fn identifier(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(128)
}

fn decimal(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(20)
}

fn null(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_value(&())
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("Capture17 upload future closed geometry")
}

/// Names the complete defining fixed visitors before any prospective walk.
///
/// The three shapes per method, completed/partial phase set and all actual
/// borrowed launch/binding/method views are independent of owning byte banks.
/// Compiler recursion and allocator residency are not inferred from this DATA.
pub(super) fn counter_scratch_data() -> usize {
    original_serialization_counter_scratch_data()
        + BlobReceiver::capture17_upload_future_reply_counter_scratch_data()
        + size_of::<NativeCapture17UploadFutureProjections>()
        + size_of::<Result<NativeCapture17UploadFutureProjections, ProviderError>>()
        + size_of::<NativeCapture17UploadFuturePhaseData>() * 3
        + size_of::<Result<NativeCapture17UploadFuturePhaseData, ProviderError>>()
        + size_of::<Shape>() * 3
        + size_of::<Projection>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&NodeBinding>()
        + size_of::<&mut Projection>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Method>()
        + size_of::<bool>()
        + size_of::<[&str; 15]>()
        + size_of::<[&str; 14]>()
        + size_of::<[&str; 13]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 6]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 4]>()
        + size_of::<[&str; 3]>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<usize>() // Negotiated bounded Chunk length.
        + size_of::<usize>() // Complete base64 groups.
        + size_of::<usize>() // Encoded Chunk extent.
        + size_of::<usize>() // Artifact byte ceiling.
        + size_of::<usize>() // Maximum participant token count.
        + size_of::<usize>() // Remaining aggregate participant text.
        + size_of::<usize>() // Caller maximum.
        + size_of::<Option<usize>>()
        + size_of::<(&'static str, &'static str, usize, usize)>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
#[path = "capture_upload17_future_projection_tests.rs"]
mod tests;

// Every manual closed roster above must be reconsidered if its defining DTO
// grows. These exhaustive borrowed patterns are compile-time coupling only;
// no DTO is built or decoded during quotation.
const _: fn(
    &crate::envelope::Envelope,
    &crate::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureRequest,
    &crate::reference_packet::service::restored_settled_capture::upload::PacketRestoredSettledCaptureUploadArtifact,
    &crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope,
    &crate::reference_packet::service::restored_settled_capture::upload::PacketRestoredSettledCaptureUploadContinuation,
    &crate::bodies::CaptureArguments,
    &crate::bodies::BlobBeginRequest,
    &crate::bodies::BlobChunkRequest,
    &crate::bodies::BlobFinishRequest,
) = |envelope, capture, artifact, scope, continuation, arguments, begin, chunk, finish| {
    use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, CaptureArguments};
    use crate::envelope::Envelope;
    use crate::reference_packet::service::complete_restore::activation::{
        PacketRestorationActivationOriginals, PacketRestorationActivationProof,
        PacketRestorationActivationScope, PacketRestorationActivationTarget,
    };
    use crate::reference_packet::service::restored_settled_capture::{
        PacketRestoredSettledCaptureRequest,
        upload::{
            PacketRestoredSettledCaptureUploadArtifact,
            PacketRestoredSettledCaptureUploadRequest,
            PacketRestoredSettledCaptureUploadContinuation,
        },
    };
    use super::PacketNativeStartupAllocationRow;

    let Envelope {
        protocol: _,
        message: _,
        session_id: _,
        incarnation_id: _,
        node_id: _,
        execution_owner_id: _,
        capture_owner_id: _,
        request_id: _,
        operation_id: _,
        sequence: _,
        method: _,
        body: _,
        extensions: _,
    } = envelope;

    let PacketRestoredSettledCaptureRequest {
        schema: _,
        scope: _,
        capture: _,
        capture_owner: _,
        capture_operation: _,
        runtime_object: _,
        coordinator_checkpoint: _,
        parent_archive: _,
        first_observation: _,
        current_record: _,
        current_model: _,
        history_prefix: _,
        history_next_sequence: _,
        native_schema: _,
        native_allocation,
    } = capture;

    let PacketNativeStartupAllocationRow {
        retained_requested_bytes: _,
        maximum_simultaneous_transient_bytes: _,
        declared_counter_scratch_bytes: _,
    } = native_allocation;

    let PacketRestoredSettledCaptureUploadArtifact {
        request,
        proof,
    } = artifact;

    let PacketRestoredSettledCaptureUploadRequest {
        schema: _,
        capture: _,
        ordinal: _,
        transfer_id: _,
        content: _,
        native_allocation: _,
    } = request;

    let PacketRestorationActivationScope {
        source_birth: _,
        source_runtime: _,
        scope_proof: _,
        target,
        restoration,
    } = scope;

    let PacketRestorationActivationTarget {
        native_pid: _,
        session: _,
        incarnation: _,
        node: _,
        owner: _,
        owner_generation: _,
        binding_hash: _,
        world: _,
        activation: _,
        generation: _,
        prepared_token: _,
        gate: _,
        admission: _,
        transaction: _,
    } = target;

    let PacketRestorationActivationOriginals {
        captured_owner_state: _,
        captured_control: _,
        captured_journal: _,
        mapping: _,
        commit_request: _,
        commit_response: _,
        context_digest: _,
    } = restoration;

    let PacketRestorationActivationProof {
        schema: _,
        algorithm: _,
        context_digest: _,
        mac: _,
    } = proof;

    let PacketRestoredSettledCaptureUploadContinuation {
        schema: _,
        context_digest: _,
        capture_operation: _,
        transfer_id: _,
    } = continuation;

    let CaptureArguments {
        capture_id: _,
        participant_ids: _,
        cut_id: _,
        cut,
        event_ordinal: _,
        ordering_profile: _,
        preservation_contract: _,
    } = arguments;

    let crucible_node_contract::Position {
        time_ps: _,
        microstep: _,
        phase: _,
    } = cut;

    let BlobBeginRequest {
        transfer_id: _,
        content,
        extensions: _,
    } = begin;

    let crucible_node_contract::ContentRef {
        hash,
        length: _,
        media_type: _,
    } = content;

    let crucible_node_contract::HashRef {
        algorithm: _,
        domain: _,
        digest: _,
    } = hash;

    let BlobChunkRequest {
        transfer_id: _,
        offset: _,
        bytes: _,
        extensions: _,
    } = chunk;

    let BlobFinishRequest {
        transfer_id: _,
        extensions: _,
    } = finish;
};
