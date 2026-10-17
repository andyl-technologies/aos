//! Installed block and 9p descriptors with explicit positive-latency FIFO lanes.

use super::*;
use crate::node_observed_executor::factory::io::{
    InstalledHostIoProfile, InstalledIoArtifact, build_model, read_artifact,
};
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor, SchemaRef};

pub(super) fn io_profile(
    selected: &InstalledNodeSelection,
    profile: &InstalledHostIoProfile,
    artifacts: &BTreeMap<String, InstalledIoArtifact>,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    // Measuring immutable input precedes native model construction and profile
    // issuance. The scenario retains those complete bytes for archive closure.
    let artifact = artifacts
        .get(&profile.artifact().hash.digest)
        .filter(|artifact| &artifact.expected == profile.artifact())
        .ok_or_else(|| refused("I/O profile has no enrolled immutable artifact"))?;
    let bytes = read_artifact(artifact)?;
    contents.insert(
        artifact.expected.hash.digest.clone(),
        ScenarioContent {
            reference: artifact.expected.clone(),
            bytes,
        },
    );
    let native = build_model(selected, profile, artifacts)?;
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new(profile.role())?];
    descriptor.model_ref = put(contents,
        b"crucible installed storage model v1: native ScheduledIoNode with 16 bounded request/response credits, strict original request codec and correlation, fixed seed zero and no faults; picosecond native cursor, positive nanosecond latency, complete original overlay or served tree/session plus FIFO state".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"native_profile":profile,"seed":"0","faults":[],
            "request_credits":"16","response_credits":"16","ticks_per_ns":"1000",
            "target_node":selected.node,"device_id":"native"
        }),
    )?;
    descriptor.initialization_ref = put(
        contents,
        native
            .initialization_bytes(16 * 1024 * 1024)
            .map_err(native_error)?,
        "application/octet-stream",
    )?;
    let role = profile.role();
    let maximum = crucible_shmem::MAX_FRAME_DATA as u64;
    let request = wire_schema(role, "request", contents)?;
    let response = wire_schema(role, "response", contents)?;
    let ordering = ordering(contents)?;
    let domain = Id::new(format!("{}/state", selected.owner))?;
    let lookahead = profile.minimum_latency_ps()?;
    let lanes = [
        ("input", Direction::Input, request.clone()),
        ("output", Direction::Output, response.clone()),
    ]
    .into_iter()
    .map(|(name, direction, payload_schema)| {
        Ok(LaneDescriptor {
            id: Id::new(name)?,
            direction,
            payload_schema,
            maximum_payload_bytes: U64::new(maximum),
            maximum_pending_events: U64::new(16),
            extensions: Extensions::new(),
        })
    })
    .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?;
    let lane_policies = ["input", "output"]
        .into_iter()
        .map(|name| {
            Ok(LanePolicy {
                lane_id: Id::new(name)?,
                ordering_ref: ordering.clone(),
                correlation_ref: ordering.clone(),
                flow_control: FlowControl::Credit,
                maximum_pending_bytes: U64::new(maximum * 16),
                visibility: LaneVisibility::Exact,
                effect_phases: vec![1],
                minimum_lookahead_ps: U64::new(lookahead),
            })
        })
        .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?;
    let port_policy = PortPolicy {
        schema_version: 1,
        lanes: lane_policies,
        maximum_producers: U64::new(1),
        maximum_consumers: U64::new(1),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: vec![domain],
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: Id::new(format!("crucible/{role}-v1"))?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &port_policy)?,
        lanes,
        extensions: Extensions::new(),
    }];

    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new(format!("crucible-host-{role}"))?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding.implementation.formats.extend([request, response]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({
            "mode":"exact","schema_version":1,"execution_proof_ref":qualification,
            "ceiling":{"kind":"input_blocked","proof_ref":qualification},
            "boundary_settlement_ref":qualification
        }),
    )?;
    // The installed signed archive authenticates actual immutable inputs,
    // complete native custody and coordinator transfer state together before
    // fresh owners may activate the preserved continuation.
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.durable_restart = true;
    binding.guarantees_ref = put_json(contents, &guarantees)?;
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    capabilities.devices_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"native_model":role,"complete_ports":descriptor.ports,
            "immutable_input_ref":profile.artifact(),"faults":[]
        }),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,
            "operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees
        }),
    )?;
    Ok((descriptor, binding, owner, true))
}

pub(super) fn wire_schema(
    role: &str,
    direction: &str,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<SchemaRef, NodeObservedError> {
    let specification = match (role, direction) {
        ("block", "request") => {
            "crucible installed block request v1: complete BlockRequest little-endian native framing; strict supported operation, payload length and correlation ID decoding; at most MAX_FRAME_DATA bytes; read count plus response header must fit the immutable response lane; no partial frames or reinterpretation"
        }
        ("block", "response") => {
            "crucible installed block response v1: complete BlockResponse little-endian native framing with original request ID, status and exact payload length; read or get-length payload follows native codec; at most MAX_FRAME_DATA bytes; original raw bytes retained"
        }
        ("filesystem", "request") => {
            "crucible installed 9p request v1: one complete bounded 9P2000.L Message frame with strict native codec length, message type and tag; read/readdir count plus response framing must fit output lane; unsupported requests retain actual native error semantics; no concatenated or partial frames"
        }
        ("filesystem", "response") => {
            "crucible installed 9p response v1: one complete native 9P2000.L response frame with original tag and exact little-endian declared length; session negotiation/fid state retained in native model; at most MAX_FRAME_DATA bytes; original raw bytes retained"
        }
        _ => return Err(refused("unsupported installed storage wire codec")),
    };
    Ok(SchemaRef {
        id: Id::new(format!("crucible/{role}-{direction}-v1"))?,
        version: 1,
        definition: put(contents, specification.as_bytes().to_vec(), "text/plain")?,
        extensions: Extensions::new(),
    })
}

pub(super) fn ordering(
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<ContentRef, NodeObservedError> {
    put(contents,
        b"installed storage FIFO v1: original superdense order; one response per consumed request with immutable native correlation ID or 9p tag; exact once-only staged input prefix; no host arrival order, implicit cancellation or response invention; exhaustion retains original custody under finite credits".to_vec(), "text/plain")
}

fn native_error(error: crucible::node_contract::OperationFailure) -> NodeObservedError {
    refused(&error.reason)
}
