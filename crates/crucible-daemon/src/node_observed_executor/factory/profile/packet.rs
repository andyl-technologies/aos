//! Explicit opaque packet echo profile with complete original native history.

use super::*;
use crucible::node_adapters::{HostModel, PacketReceiver};
use crucible::node_admission::{FlowControl, LanePolicy, LaneVisibility, PortPolicy};
use crucible_node_contract::{Direction, LaneDescriptor, PortDescriptor, SchemaRef};

pub(super) fn profile(
    selected: &InstalledNodeSelection,
    source: u32,
    latency: U64,
    host: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let receiver =
        PacketReceiver::new(source, latency.get()).map_err(|error| refused(&error.reason))?;
    let (mut descriptor, mut binding, owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("packet_receiver")?];
    descriptor.model_ref = put(contents, b"crucible opaque packet receiver v1: bounded 32-input original FIFO with complete post-fault packet bytes; one unchanged echo response per original consumed input after positive fixed latency; complete native input history/pending replies/clock/sequence plus original runtime/input/ACK and coordinator custody; no Block/Ethernet/guest protocol interpretation, autonomous producer or mutable fault/debug/control".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({"version":1,"source_node":source,"latency_ps":latency,"maximum_original_inputs":"32"}),
    )?;
    descriptor.initialization_ref = put(
        contents,
        HostModel::PacketReceiver(Box::new(receiver))
            .initialization_bytes(4 * 1024 * 1024)
            .map_err(|error| refused(&error.reason))?,
        "application/octet-stream",
    )?;
    let schema = schema(contents)?;
    let ordering = ordering(contents)?;
    let policy = PortPolicy {
        schema_version: 1,
        lanes: vec![Direction::Input, Direction::Output]
            .into_iter()
            .map(|direction| {
                Ok(LanePolicy {
                    lane_id: Id::new(if direction == Direction::Input {
                        "input"
                    } else {
                        "output"
                    })?,
                    ordering_ref: ordering.clone(),
                    correlation_ref: ordering.clone(),
                    flow_control: FlowControl::Credit,
                    maximum_pending_bytes: ((crucible_shmem::MAX_FRAME_DATA * 32) as u64).into(),
                    visibility: LaneVisibility::Exact,
                    effect_phases: vec![1],
                    minimum_lookahead_ps: latency,
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?,
        maximum_producers: 1.into(),
        maximum_consumers: 1.into(),
        arbitration_ref: ordering,
        execution_owner_id: selected.owner.clone(),
        state_domain_ids: vec![Id::new(format!("{}/state", selected.owner))?],
        internal: false,
    };
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: Id::new("crucible/packet-v1")?,
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes: vec![Direction::Input, Direction::Output]
            .into_iter()
            .map(|direction| {
                Ok(LaneDescriptor {
                    id: Id::new(if direction == Direction::Input {
                        "input"
                    } else {
                        "output"
                    })?,
                    direction,
                    payload_schema: schema.clone(),
                    maximum_payload_bytes: (crucible_shmem::MAX_FRAME_DATA as u64).into(),
                    maximum_pending_events: 32.into(),
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?,
        extensions: Extensions::new(),
    }];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.implementation.implementation_id = Id::new("crucible-host-opaque-packet-receiver")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding
        .implementation
        .formats
        .retain(|format| format.id.as_str() != "host/native-continuation-v1");
    binding.implementation.formats.extend([schema, SchemaRef {id:Id::new("host/native-packet-receiver-v1")?,version:1,definition:put(contents,b"crucible packet receiver native v1: closed canonical original input history, delivered prefix, pending replies, source identity, fixed latency and native clock; no request resubmission or payload reinterpretation".to_vec(),"text/plain")?,extensions:Extensions::new()}]);
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({"mode":"exact","schema_version":1,"execution_proof_ref":qualification,"ceiling":{"kind":"input_blocked","proof_ref":qualification},"boundary_settlement_ref":qualification}),
    )?;
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
        &serde_json::json!({"version":1,"native_model":"opaque_packet_receiver","complete_ports":descriptor.ports,"faults":[],"debug":[],"controllers":[]}),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,"operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantees}),
    )?;
    Ok((descriptor, binding, owner, true))
}

pub(super) fn schema(
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<SchemaRef, NodeObservedError> {
    Ok(SchemaRef {id:Id::new("crucible/opaque-packet-v1")?,version:1,definition:put(contents,b"crucible opaque packet bytes v1: one nonempty bounded byte vector of at most 65536 bytes; bytes may be mutated by an explicitly selected upstream faulted link; no protocol framing/correlation/validity claim".to_vec(),"text/plain")?,extensions:Extensions::new()})
}

pub(super) fn ordering(
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<ContentRef, NodeObservedError> {
    put(contents, b"crucible opaque packet FIFO v1: original superdense input order, no protocol correlation claim; one original unchanged delayed echo per consumed input; complete once-only input custody and output sequence retained".to_vec(), "text/plain")
}
