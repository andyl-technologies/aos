//! Projects closed activation wire owners from actual borrowed pre-Prepare data.
//!
//! Future references use the compiled ContentRef grammar and the largest U64
//! spelling. These are sizing views, never request, hash, proof or scope owners.
//! Strings of the actual session, target, ticket and journal remain borrowed.

use super::*;
use serde::Serialize;

const NUMBER: &str = "18446744073709551615";
const DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
struct HashFields<'a> {
    algorithm: &'a str,
    domain: &'a str,
    digest: &'a str,
}

impl<'a> From<&'a crucible_node_format::HashRef> for HashFields<'a> {
    fn from(value: &'a crucible_node_format::HashRef) -> Self {
        Self {
            algorithm: &value.algorithm,
            domain: &value.domain,
            digest: &value.digest,
        }
    }
}

#[derive(Serialize)]
struct Reference<'a> {
    hash: HashFields<'a>,
    length: &'static str,
    media_type: &'a str,
}

impl<'a> From<&'a ContentRef> for Reference<'a> {
    fn from(value: &'a ContentRef) -> Self {
        Self {
            hash: (&value.hash).into(),
            length: NUMBER,
            media_type: &value.media_type,
        }
    }
}

impl Reference<'static> {
    fn future() -> Self {
        Self {
            hash: HashFields {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: HEX,
            },
            length: NUMBER,
            media_type: "application/json",
        }
    }
}

#[derive(Serialize)]
struct Target<'a> {
    native_pid: &'static str,
    session: &'a Id,
    incarnation: &'a Id,
    node: &'a Id,
    owner: &'a Id,
    owner_generation: &'static str,
    binding_hash: HashFields<'a>,
    world: HashFields<'a>,
    activation: &'a Id,
    generation: &'static str,
    prepared_token: &'a Id,
    gate: &'a Id,
    admission: &'a Id,
    transaction: &'a Id,
}

#[derive(Serialize)]
struct Originals<'a> {
    captured_owner_state: Reference<'a>,
    captured_control: Reference<'a>,
    captured_journal: Reference<'a>,
    mapping: Reference<'static>,
    commit_request: Reference<'static>,
    commit_response: Reference<'static>,
    context_digest: &'static str,
}

#[derive(Serialize)]
struct Scope<'a> {
    source_birth: Reference<'static>,
    source_runtime: Reference<'a>,
    scope_proof: Reference<'static>,
    target: Target<'a>,
    restoration: Originals<'a>,
}

#[derive(Serialize)]
struct Allocation {
    retained_requested_bytes: &'static str,
    maximum_simultaneous_transient_bytes: &'static str,
    declared_counter_scratch_bytes: &'static str,
}

#[derive(Serialize)]
struct Request<'a> {
    schema: &'static str,
    phase: &'static str,
    scope: &'a Scope<'a>,
    native_allocation: Allocation,
}

#[derive(Serialize)]
struct Context<'a> {
    request: &'a Request<'a>,
    assigned_request: &'static str,
}

#[derive(Serialize)]
struct Proof {
    schema: &'static str,
    algorithm: &'static str,
    context_digest: &'static str,
    mac: &'static str,
}

#[derive(Serialize)]
struct Artifact<'a> {
    request: &'a Request<'a>,
    proof: Proof,
}

/// Names complete serialization work and dynamic decoder children separately.
pub(super) struct Shape {
    pub(super) serialization: usize,
    pub(super) backing: usize,
}

impl Shape {
    fn measure(value: &impl Serialize, maximum: usize) -> Result<Self, RuntimeError> {
        Ok(Self {
            serialization: sum(
                [
                    size_of::<serde_json::Value>(),
                    NodeRuntime::original_runtime_constructor_serialization_storage_data(
                        value, maximum,
                    )?,
                ],
                maximum,
            )?,
            backing: typed_backing::measure(value, maximum)?,
        })
    }

    pub(super) fn decode<T>(&self, maximum: usize) -> Result<usize, RuntimeError> {
        sum(
            [
                size_of::<T>(),
                size_of::<Result<T, serde_json::Error>>(),
                size_of::<&serde_json::Value>(),
                self.backing,
            ],
            maximum,
        )
    }
}

pub(super) struct SigningShapes {
    pub(super) request: Shape,
    pub(super) scope: Shape,
    pub(super) context: Shape,
    pub(super) artifact: Shape,
    pub(super) assigned: [Shape; 2],
    pub(super) terminal: [Shape; 2],
    pub(super) upload: UploadShapes,
}

pub(super) fn measure(
    inputs: &OriginalInstalledRestorationActivationSigningConstructionInputs<'_>,
    target: &crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<'_>,
    maximum: usize,
) -> Result<SigningShapes, RuntimeError> {
    let originals = inputs.transfer;
    let report = originals
        .query
        .report_data()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let owner = originals.ticket.owner()?;
    let scope = Scope {
        source_birth: Reference::future(),
        source_runtime: (&originals.journal.runtime).into(),
        scope_proof: Reference::future(),
        target: Target {
            native_pid: NUMBER,
            session: target.session,
            incarnation: target.incarnation,
            node: target.node,
            owner: target.owner,
            owner_generation: NUMBER,
            binding_hash: (&report.data.scope.owner_binding).into(),
            world: target.world.into(),
            activation: &originals.activation.activation_id,
            generation: NUMBER,
            prepared_token: target.prepared_token,
            gate: target.gate,
            admission: target.admission,
            transaction: target.transaction,
        },
        restoration: Originals {
            captured_owner_state: (&owner.state).into(),
            captured_control: (&originals.journal.native_control).into(),
            captured_journal: originals.journal_reference.into(),
            mapping: Reference::future(),
            commit_request: Reference::future(),
            commit_response: Reference::future(),
            context_digest: DIGEST,
        },
    };
    // world_activate is the longer compiled phase spelling. Fixed native rows
    // retain the same three U64 fields; their values cannot enlarge this view.
    let request = Request {
        schema: PACKET_RESTORATION_ACTIVATION_FEATURE,
        phase: "world_activate",
        scope: &scope,
        native_allocation: Allocation {
            retained_requested_bytes: NUMBER,
            maximum_simultaneous_transient_bytes: NUMBER,
            declared_counter_scratch_bytes: NUMBER,
        },
    };
    let context = Context {
        request: &request,
        assigned_request: DIGEST,
    };
    let artifact = Artifact {
        request: &request,
        proof: Proof {
            schema: "source-owned.packet-restoration-activation-proof/1",
            algorithm: "blake3-256-mac",
            context_digest: DIGEST,
            mac: DIGEST,
        },
    };
    Ok(SigningShapes {
        request: Shape::measure(&request, maximum)?,
        scope: Shape::measure(&scope, maximum)?,
        context: Shape::measure(&context, maximum)?,
        artifact: Shape::measure(&artifact, maximum)?,
        assigned: [
            assigned(&artifact, inputs, target, 0, maximum)?,
            assigned(&artifact, inputs, target, 1, maximum)?,
        ],
        terminal: [
            terminal(inputs, target, 0, maximum)?,
            terminal(inputs, target, 1, maximum)?,
        ],
        upload: measure_upload(&scope, inputs, maximum)?,
    })
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<HashFields<'static>>() + size_of::<Reference<'static>>()
        + size_of::<Target<'static>>() + size_of::<Originals<'static>>()
        + size_of::<Scope<'static>>() + size_of::<Allocation>()
        + size_of::<Request<'static>>() + size_of::<Context<'static>>()
        + size_of::<Proof>() + size_of::<Artifact<'static>>()
        + size_of::<Shape>() + size_of::<SigningShapes>()
        + size_of::<Result<SigningShapes, RuntimeError>>()
        + size_of::<Result<Shape, RuntimeError>>()
        + size_of::<Empty>() + size_of::<WorldBody<'static>>()
        + size_of::<ActivationExtensions<'static>>()
        + size_of::<EnvelopeView<'static, WorldBody<'static>, ActivationExtensions<'static>>>()
        + size_of::<TerminalResult<'static>>() + size_of::<TerminalBody<'static>>()
        + size_of::<EnvelopeView<'static, TerminalBody<'static>, Empty>>()
        + size_of::<UploadShapes>() + size_of::<UploadRequest<'static>>()
        + size_of::<UploadContext<'static>>() + size_of::<UploadArtifact<'static>>()
        + size_of::<UploadExtensions<'static>>() + size_of::<UploadBegin>()
        + size_of::<UploadFinish>() + size_of::<UploadTerminal>()
        + size_of::<EnvelopeView<'static, UploadBegin, UploadExtensions<'static>>>()
        + size_of::<EnvelopeView<'static, UploadTerminal, Empty>>()
        + typed_backing::counter_scratch_data()
        // The fixed scalar encoders include the decoded-base64 reserve and
        // U64 decimal formatter temporaries of actual Bytes/U64 serializers.
        + 44 + 20
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct WorldBody<'a> {
    transaction_id: &'a Id,
    admission_id: &'a Id,
    activation_id: &'a Id,
    world_generation: &'static str,
    prepared_token: &'a Id,
    world_binding_hash: HashFields<'a>,
    gate_id: &'a Id,
    activation_manifest: Reference<'static>,
    extensions: Empty,
}

#[derive(Serialize)]
struct ActivationExtensions<'a> {
    #[serde(rename = "source-owned.packet-restoration-activation/1")]
    artifact: &'a Artifact<'a>,
}

#[derive(Serialize)]
struct EnvelopeView<'a, B, E> {
    protocol: &'static str,
    message: &'static str,
    session_id: Option<&'a Id>,
    incarnation_id: Option<&'a Id>,
    node_id: Option<&'a Id>,
    execution_owner_id: Option<&'a Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: Option<&'a str>,
    operation_id: Option<&'a Id>,
    sequence: &'static str,
    method: &'static str,
    body: B,
    extensions: E,
}

fn envelope<'a, B, E>(
    inputs: &'a OriginalInstalledRestorationActivationSigningConstructionInputs<'a>,
    phase: usize,
    message: &'static str,
    body: B,
    extensions: E,
) -> EnvelopeView<'a, B, E> {
    let controller = inputs.transfer.controller;
    EnvelopeView {
        protocol: "CNP/1",
        message,
        session_id: Some(controller.authority().session_id()),
        incarnation_id: Some(controller.authority().incarnation_id()),
        node_id: Some(&controller.route().node),
        execution_owner_id: Some(&controller.route().execution_owner),
        capture_owner_id: None,
        request_id: Some(inputs.request_ids[phase].as_str()),
        operation_id: None,
        sequence: NUMBER,
        method: "world_activate",
        body,
        extensions,
    }
}

fn assigned(
    artifact: &Artifact<'_>,
    inputs: &OriginalInstalledRestorationActivationSigningConstructionInputs<'_>,
    target: &crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<'_>,
    phase: usize,
    maximum: usize,
) -> Result<Shape, RuntimeError> {
    // This union is an accounting view only. Including BOTH disjoint admission
    // and transaction fields plus the World manifest dominates either actual
    // baseline body; no such union is sent or accepted as a protocol request.
    let body = WorldBody {
        transaction_id: target.transaction,
        admission_id: target.admission,
        activation_id: &inputs.transfer.activation.activation_id,
        world_generation: NUMBER,
        prepared_token: target.prepared_token,
        world_binding_hash: target.world.into(),
        gate_id: target.gate,
        activation_manifest: Reference::future(),
        extensions: Empty {},
    };
    Shape::measure(
        &envelope(
            inputs,
            phase,
            "request",
            body,
            ActivationExtensions { artifact },
        ),
        maximum,
    )
}

#[derive(Serialize)]
struct TerminalResult<'a> {
    staged: bool,
    gate_id: &'a Id,
    staged_owner_ids: [&'a Id; 1],
    armed_owner_ids: [&'a Id; 1],
    activation_receipt: Reference<'static>,
}

#[derive(Serialize)]
struct TerminalBody<'a> {
    status: &'static str,
    operation_state: &'static str,
    result: TerminalResult<'a>,
    extensions: Empty,
}

fn terminal(
    inputs: &OriginalInstalledRestorationActivationSigningConstructionInputs<'_>,
    target: &crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<'_>,
    phase: usize,
    maximum: usize,
) -> Result<Shape, RuntimeError> {
    // Source refuses accepted/error, extension-bearing and foreign/multi-owner
    // typed terminals BEFORE its own normalization. SDK/caller terminal owners
    // remain separately retained on those failures. This union prices both
    // genuine one-owner results; it is never used as response authority.
    let body = TerminalBody {
        status: "completed",
        operation_state: "completed",
        result: TerminalResult {
            staged: true,
            gate_id: target.gate,
            staged_owner_ids: [target.owner],
            armed_owner_ids: [target.owner],
            activation_receipt: Reference::future(),
        },
        extensions: Empty {},
    };
    Shape::measure(
        &envelope(inputs, phase, "response", body, Empty {}),
        maximum,
    )
}

// Actual SDK upload IDs are a fixed prefix, 64 hexadecimal bytes and an index
// below4096.128 bytes is the existing validated Id maximum, not a minted Id.
const UPLOAD_ID: &str = "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii";

pub(super) struct UploadShapes {
    pub(super) request: Shape,
    pub(super) context: Shape,
    pub(super) artifact: Shape,
    pub(super) assigned: Shape,
    pub(super) terminal: Shape,
}

#[derive(Serialize)]
struct UploadRequest<'a> {
    schema: &'static str,
    scope: &'a Scope<'a>,
    role: &'static str,
    coordinator: Reference<'static>,
    manifest: Reference<'static>,
    chunk_bytes: &'static str,
    maximum_frame_bytes: &'static str,
    maximum_requests: &'static str,
    native_allocation: Allocation,
}

#[derive(Serialize)]
struct UploadContext<'a> {
    request: &'a UploadRequest<'a>,
    assigned_request: &'static str,
}

#[derive(Serialize)]
struct UploadArtifact<'a> {
    request: &'a UploadRequest<'a>,
    proof: Proof,
}

#[derive(Serialize)]
struct UploadExtensions<'a> {
    #[serde(rename = "source-owned.packet-restoration-activation-upload/1")]
    artifact: &'a UploadArtifact<'a>,
}

#[derive(Serialize)]
struct UploadBegin {
    transfer_id: &'static str,
    content: Reference<'static>,
    extensions: Empty,
}

#[derive(Serialize)]
struct UploadFinish {
    transfer_id: &'static str,
    content: Reference<'static>,
}

#[derive(Serialize)]
struct UploadTerminal {
    status: &'static str,
    operation_state: &'static str,
    result: UploadFinish,
    extensions: Empty,
}

fn measure_upload(
    scope: &Scope<'_>,
    inputs: &OriginalInstalledRestorationActivationSigningConstructionInputs<'_>,
    maximum: usize,
) -> Result<UploadShapes, RuntimeError> {
    let request = UploadRequest {
        schema: PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        scope,
        role: "coordinator",
        coordinator: Reference::future(),
        manifest: Reference::future(),
        chunk_bytes: NUMBER,
        maximum_frame_bytes: NUMBER,
        maximum_requests: NUMBER,
        native_allocation: Allocation {
            retained_requested_bytes: NUMBER,
            maximum_simultaneous_transient_bytes: NUMBER,
            declared_counter_scratch_bytes: NUMBER,
        },
    };
    let context = UploadContext {
        request: &request,
        assigned_request: DIGEST,
    };
    let artifact = UploadArtifact {
        request: &request,
        proof: Proof {
            schema: "source-owned.packet-restoration-activation-upload-proof/1",
            algorithm: "blake3-256-mac",
            context_digest: DIGEST,
            mac: DIGEST,
        },
    };
    let mut assigned = envelope(
        inputs,
        1,
        "request",
        UploadBegin {
            transfer_id: UPLOAD_ID,
            content: Reference::future(),
            extensions: Empty {},
        },
        UploadExtensions {
            artifact: &artifact,
        },
    );
    assigned.method = "blob_begin";
    assigned.request_id = Some(UPLOAD_ID);
    let mut terminal = envelope(
        inputs,
        1,
        "response",
        UploadTerminal {
            status: "completed",
            operation_state: "completed",
            result: UploadFinish {
                transfer_id: UPLOAD_ID,
                content: Reference::future(),
            },
            extensions: Empty {},
        },
        Empty {},
    );
    terminal.method = "blob_finish";
    terminal.request_id = Some(UPLOAD_ID);
    Ok(UploadShapes {
        request: Shape::measure(&request, maximum)?,
        context: Shape::measure(&context, maximum)?,
        artifact: Shape::measure(&artifact, maximum)?,
        assigned: Shape::measure(&assigned, maximum)?,
        terminal: Shape::measure(&terminal, maximum)?,
    })
}

pub(super) fn future_reference_backing_data(maximum: usize) -> Result<usize, RuntimeError> {
    typed_backing::measure(&Reference::future(), maximum)
}
