//! Projects independent Source-owned arguments and upload objects before birth.

use super::*;
use crate::node_contract::{ActivationRecord, OperationRequest, OwnerIdentity};
use crate::node_scheduling::ExecutionAdmission;
use serde::Serialize;

const HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Serialize)]
struct Hash {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}
#[derive(Serialize)]
struct Reference {
    hash: Hash,
    length: U64,
    media_type: &'static str,
}
impl Reference {
    fn new() -> Self {
        Self {
            hash: Hash {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: HEX,
            },
            length: U64::new(u64::MAX),
            media_type: "application/json",
        }
    }
}
#[derive(Serialize)]
struct Arguments<'a> {
    grant_id: &'a Id,
    participant_ids: &'a [Id],
    realization_id: &'a Id,
    activation_id: &'a Id,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: &'a Id,
    mode: crucible_node_format::OperatingMode,
    ordering_profile: &'static str,
    start: Position,
    limit: Position,
    boundary_policy: BoundaryPolicy,
    input_authorization: Reference,
    input_watermark: U64,
}
#[derive(Serialize)]
struct Begin<'a> {
    kind: BeginKind,
    binding_hash: Hash,
    owner_generation: U64,
    activation_id: Option<&'a Id>,
    world_generation: U64,
    arguments: Arguments<'a>,
    extensions: &'a Extensions,
}
#[derive(Serialize)]
struct Activation<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a crucible_node_format::HashRef,
    owners: &'a [OwnerIdentity],
    boundary: Position,
}
#[derive(Serialize)]
struct Route<'a> {
    node: &'a Id,
    owners: [&'a OwnerIdentity; 1],
}
#[derive(Serialize)]
struct Authorization<'a> {
    schema: &'static str,
    operation: &'a Id,
    route: Route<'a>,
    activation: Activation<'a>,
    request: OperationRequest,
    input: Option<()>,
    input_watermark: U64,
}
#[derive(Serialize)]
struct Consumption<'a> {
    schema: &'static str,
    operation: &'a Id,
    outputs: Outputs<'a>,
}
struct Outputs<'a>(&'a crucible_node_transport::reference_packet::PacketProgramDefinition);
impl Serialize for Outputs<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(
            self.0
                .events
                .iter()
                .filter(|event| event.payload.is_some())
                .count(),
        ))?;
        for event in &self.0.events {
            if event.payload.is_some() {
                seq.serialize_element(&event.id)?;
            }
        }
        seq.end()
    }
}

pub(super) fn source_bodies_data(
    source: &PacketCompleteSemanticSource,
    grant: &ExecutionAdmission,
    maximum: usize,
) -> Result<(usize, usize, usize), RuntimeError> {
    let installation = source.installation();
    let world = grant.activation().record();
    let mut owners = world
        .owners
        .iter()
        .filter(|owner| owner.owner == installation.owner.owner.id);
    let owner = owners.next().ok_or(RuntimeError::ForeignAuthority)?;
    if owners.next().is_some() {
        return Err(RuntimeError::ForeignAuthority);
    }
    let CompletePacketOriginal::Producer(original) = &source.original else {
        return Err(RuntimeError::UnsupportedFacet);
    };
    let operation = construction::operation_data(grant.operation(), &grant.request())?;
    let extensions = Extensions::new();
    let arguments = Arguments {
        grant_id: grant.operation(),
        participant_ids: &installation.owner.owner.participant_ids,
        realization_id: &installation.realize.realization_id,
        activation_id: &world.activation_id,
        world_generation: world.generation,
        owner_generation: installation.binding.authority.owner_generation,
        input_epoch: &installation.binding.authority.input_epoch,
        mode: crucible_node_format::OperatingMode::Exact,
        ordering_profile: "superdense-v1",
        start: operation.start,
        limit: operation.limit,
        boundary_policy: BoundaryPolicy::OrdinaryStop,
        input_authorization: Reference::new(),
        input_watermark: U64::new(0),
    };
    let begin = Begin {
        kind: operation.kind,
        binding_hash: Hash {
            algorithm: "blake3-256",
            domain: "cnp.owner-binding.v1",
            digest: HEX,
        },
        owner_generation: arguments.owner_generation,
        activation_id: Some(&world.activation_id),
        world_generation: world.generation,
        arguments,
        extensions: &extensions,
    };
    let authorization = Authorization {
        schema: "source-owned.packet-common-grant.v5",
        operation: grant.operation(),
        route: Route {
            node: grant.node(),
            owners: [owner],
        },
        activation: Activation {
            generation: world.generation,
            activation_id: &world.activation_id,
            world_binding_hash: &world.world_binding_hash,
            owners: &world.owners,
            boundary: world.boundary,
        },
        request: grant.request(),
        input: None,
        input_watermark: U64::new(0),
    };
    let consumption = Consumption {
        schema: "source-owned.packet-consumption.v1",
        operation: grant.operation(),
        outputs: Outputs(original.original_program_data()),
    };
    let (begin_bytes, _) =
        NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
            &begin,
            size_of::<BeginRequest>().max(size_of::<ExactRunArguments>()),
            maximum,
        )?;
    let (authorization_bytes, authorization_encoded) =
        NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
            &authorization,
            size_of::<serde_json::Value>(),
            maximum,
        )?;
    let (consumption_bytes, consumption_encoded) =
        NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
            &consumption,
            size_of::<serde_json::Value>(),
            maximum,
        )?;
    if authorization_encoded > installation.maximum_authorization_bytes.min(8192)
        || consumption_encoded > 8192
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let bytes = construction::sum(
        [begin_bytes, authorization_bytes, consumption_bytes],
        maximum,
    )?;
    Ok((
        bytes,
        counter_scratch_data(),
        authorization_encoded
            .checked_add(consumption_encoded)
            .ok_or(RuntimeError::ResourceLimit)?,
    ))
}

pub(super) fn counter_scratch_data() -> usize {
    NodeRuntime::capture_serialization_counter_scratch_data()
        + size_of::<Arguments<'static>>()
        + size_of::<Begin<'static>>()
        + size_of::<Authorization<'static>>()
        + size_of::<Consumption<'static>>()
        + size_of::<Route<'static>>()
        + size_of::<Activation<'static>>()
        + size_of::<Outputs<'static>>()
        + size_of::<Reference>()
        + size_of::<Hash>()
        + size_of::<[&OwnerIdentity; 1]>()
        + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
        + size_of::<Option<&OwnerIdentity>>()
        + size_of::<Result<&OwnerIdentity, RuntimeError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_transport::reference_packet::PacketEvent>>(
        ) * 2
        + size_of::<Result<(usize, usize), RuntimeError>>() * 4
        + size_of::<(usize, usize, usize)>()
        + size_of::<Result<(usize, usize, usize), RuntimeError>>()
        + size_of::<(usize, usize)>() * 4
        + size_of::<Extensions>()
        + size_of::<&ActivationRecord>()
        + size_of::<OperationRequest>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
}
