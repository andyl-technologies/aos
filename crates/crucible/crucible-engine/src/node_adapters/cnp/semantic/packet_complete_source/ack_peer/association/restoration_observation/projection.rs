//! Projects closed observation wire owners from actual borrowed pre-Prepare data.
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
    scope: &'a Scope<'a>,
    world_original: Reference<'static>,
    world_terminal: Reference<'static>,
    maximum_items: &'static str,
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
    pub(super) assigned: Shape,
    pub(super) terminal: Shape,
}

pub(super) fn measure(
    inputs: &OriginalInstalledRestorationObservationSigningConstructionInputs<'_>,
    target: &crucible_node_transport::client::OriginalRestorationActivationTargetBindingData<'_>,
    maximum: usize,
) -> Result<SigningShapes, RuntimeError> {
    let originals = inputs.activation.transfer;
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

    let request = Request {
        schema: PACKET_RESTORATION_OBSERVE_FEATURE,
        scope: &scope,
        world_original: Reference::future(),
        world_terminal: Reference::future(),
        maximum_items: "1",
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
            schema: "source-owned.packet-restoration-observe-proof/1",
            algorithm: "blake3-256-mac",
            context_digest: DIGEST,
            mac: DIGEST,
        },
    };
    let body = Body {
        binding_hash: (&report.data.scope.owner_binding).into(),
        owner_generation: NUMBER,
        after_observation_sequence: "0",
        maximum_items: "1",
        extensions: Empty {},
    };
    let assigned = envelope(
        inputs,
        "request",
        body,
        ObservationExtensions {
            artifact: &artifact,
        },
    );
    let batch = Batch {
        schema_version: 1,
        execution_owner_id: target.owner,
        owner_binding_hash: (&report.data.scope.owner_binding).into(),
        world_binding_hash: target.world.into(),
        activation_id: &originals.activation.activation_id,
        world_generation: NUMBER,
        owner_generation: NUMBER,
        operation_id: inputs.request_id,
        grant_id: None,
        first_sequence: "0",
        last_sequence: "0",
        events: [],
        visibility: "staged",
        measurement_ref: Reference::future(),
        extensions: Empty {},
    };
    // Both real native inventory variants use these exact fixed domains; the
    // connected spelling is longer and bounds the producer spelling too.
    let terminal = envelope(
        inputs,
        "response",
        TerminalBody {
            status: "completed",
            operation_state: "completed",
            result: TerminalResult {
                observations: [batch],
                next_sequence: "1",
                complete: true,
                inventory_hash: HashFields {
                    algorithm: "blake3-256",
                    domain: "source-owned.packet-connected-inventory/4",
                    digest: HEX,
                },
            },
            extensions: Empty {},
        },
        Empty {},
    );
    Ok(SigningShapes {
        request: Shape::measure(&request, maximum)?,
        scope: Shape::measure(&scope, maximum)?,
        context: Shape::measure(&context, maximum)?,
        artifact: Shape::measure(&artifact, maximum)?,
        assigned: Shape::measure(&assigned, maximum)?,
        terminal: Shape::measure(&terminal, maximum)?,
    })
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct Body<'a> {
    binding_hash: HashFields<'a>,
    owner_generation: &'static str,
    after_observation_sequence: &'static str,
    maximum_items: &'static str,
    extensions: Empty,
}

#[derive(Serialize)]
struct ObservationExtensions<'a> {
    #[serde(rename = "source-owned.packet-restoration-observe/1")]
    artifact: &'a Artifact<'a>,
}

#[derive(Serialize)]
struct Batch<'a> {
    schema_version: u8,
    execution_owner_id: &'a Id,
    owner_binding_hash: HashFields<'a>,
    world_binding_hash: HashFields<'a>,
    activation_id: &'a Id,
    world_generation: &'static str,
    owner_generation: &'static str,
    operation_id: &'a Id,
    grant_id: Option<&'a Id>,
    first_sequence: &'static str,
    last_sequence: &'static str,
    events: [(); 0],
    visibility: &'static str,
    measurement_ref: Reference<'static>,
    extensions: Empty,
}

#[derive(Serialize)]
struct TerminalResult<'a> {
    observations: [Batch<'a>; 1],
    next_sequence: &'static str,
    complete: bool,
    inventory_hash: HashFields<'a>,
}

#[derive(Serialize)]
struct TerminalBody<'a> {
    status: &'static str,
    operation_state: &'static str,
    result: TerminalResult<'a>,
    extensions: Empty,
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
    request_id: Option<&'a Id>,
    operation_id: Option<&'a Id>,
    sequence: &'static str,
    method: &'static str,
    body: B,
    extensions: E,
}

fn envelope<'a, B, E>(
    inputs: &'a OriginalInstalledRestorationObservationSigningConstructionInputs<'a>,
    message: &'static str,
    body: B,
    extensions: E,
) -> EnvelopeView<'a, B, E> {
    let controller = inputs.activation.transfer.controller;
    EnvelopeView {
        protocol: "CNP/1",
        message,
        session_id: Some(controller.authority().session_id()),
        incarnation_id: Some(controller.authority().incarnation_id()),
        node_id: Some(&controller.route().node),
        execution_owner_id: Some(&controller.route().execution_owner),
        capture_owner_id: None,
        request_id: Some(inputs.request_id),
        operation_id: None,
        sequence: NUMBER,
        method: "Observe",
        body,
        extensions,
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<HashFields<'static>>()
        + size_of::<Reference<'static>>()
        + size_of::<Target<'static>>()
        + size_of::<Originals<'static>>()
        + size_of::<Scope<'static>>()
        + size_of::<Allocation>()
        + size_of::<Request<'static>>()
        + size_of::<Context<'static>>()
        + size_of::<Proof>()
        + size_of::<Artifact<'static>>()
        + size_of::<Shape>()
        + size_of::<SigningShapes>()
        + size_of::<Result<SigningShapes, RuntimeError>>()
        + size_of::<Result<Shape, RuntimeError>>()
        + size_of::<Empty>()
        + size_of::<Body<'static>>()
        + size_of::<ObservationExtensions<'static>>()
        + size_of::<EnvelopeView<'static, Body<'static>, ObservationExtensions<'static>>>()
        + size_of::<Batch<'static>>()
        + size_of::<TerminalResult<'static>>()
        + size_of::<TerminalBody<'static>>()
        + size_of::<EnvelopeView<'static, TerminalBody<'static>, Empty>>()
        + typed_backing::counter_scratch_data()
        + 44
        + 20
}

pub(super) fn future_reference_backing_data(maximum: usize) -> Result<usize, RuntimeError> {
    Ok(Shape::measure(&Reference::future(), maximum)?.backing)
}
