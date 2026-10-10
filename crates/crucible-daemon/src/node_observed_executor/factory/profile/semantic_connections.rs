//! Native response transfers into the installed assertion participant.
//!
//! These routes preserve original response bytes, publication lineage and
//! coordinator-owned FIFO/input custody. A transfer declaration does not
//! authenticate a payload; actual native execution and capture retain its
//! original producer evidence independently.

use super::*;
use crucible::node_admission::{ConnectionDelivery, ConnectionPolicy, VisibilityConversion};
use crucible_node_contract::{ConnectionDescriptor, Direction, Endpoint};

pub(super) fn connections(
    selections: &[InstalledNodeSelection],
    descriptors: &[NodeDescriptor],
    bindings: &mut [BindingCompatibility],
    owners: &mut [OwnerBinding],
    inventory: (
        &mut Vec<StateDomain>,
        &mut Vec<StateObject>,
        &mut [OwnerCapturePolicy],
    ),
    contents: &mut BTreeMap<String, ScenarioContent>,
    qualification: &ContentRef,
) -> Result<Vec<ConnectionDescriptor>, NodeObservedError> {
    let (domains, objects, captures) = inventory;
    let mut connections = Vec::new();
    for selected in selections {
        let (program_ref, condition) = match &selected.kind {
            InstalledNodeKind::HostSemantics { profile } => (&profile.program, false),
            InstalledNodeKind::HostConditionDebug { profile } => (&profile.program, true),
            _ => continue,
        };
        // Profile construction already measured the independently enrolled
        // program. Route construction reads that exact owned immutable object.
        let program = contents
            .get(&program_ref.hash.digest)
            .filter(|content| content.reference == *program_ref)
            .ok_or_else(|| refused("semantic original program content absent"))?;
        program_ref.verify(&program.bytes)?;
        let definition = if condition {
            let definition: crucible::node_adapters::ConditionDebugDefinition =
                serde_json::from_value(canonical::parse_json(
                    &program.bytes,
                    super::super::condition_debug::MAXIMUM_PROGRAM_BYTES,
                )?)?;
            definition.evaluation
        } else {
            serde_json::from_value::<crucible::node_adapters::HostSemanticDefinition>(
                canonical::parse_json(
                    &program.bytes,
                    super::super::semantics::MAXIMUM_SEMANTIC_PROGRAM_BYTES,
                )?,
            )?
        };
        for input in &definition.inputs {
            let source = selections
                .iter()
                .find(|entry| entry.node == input.source.node_id)
                .ok_or_else(|| refused("semantic response producer is absent"))?;
            let producer = descriptors
                .iter()
                .find(|descriptor| descriptor.id == source.node)
                .ok_or_else(|| refused("semantic response producer descriptor absent"))?;
            let consumer = descriptors
                .iter()
                .find(|descriptor| descriptor.id == selected.node)
                .ok_or_else(|| refused("semantic consumer descriptor absent"))?;
            let producer_port = producer
                .ports
                .iter()
                .find(|port| port.id == input.source.port_id)
                .ok_or_else(|| refused("semantic original producer port absent"))?;
            let producer_lane = producer_port
                .lanes
                .iter()
                .find(|lane| lane.id == input.source.lane_id && lane.direction == Direction::Output)
                .ok_or_else(|| refused("semantic original producer output absent"))?;
            let consumer_port = consumer
                .ports
                .iter()
                .find(|port| port.id.as_str() == "data")
                .ok_or_else(|| refused("semantic input port absent"))?;
            let consumer_lane = consumer_port
                .lanes
                .iter()
                .find(|lane| lane.id.as_str() == "input" && lane.direction == Direction::Input)
                .ok_or_else(|| refused("semantic input lane absent"))?;
            if producer_port.interface_id != consumer_port.interface_id
                || producer_lane.payload_schema != consumer_lane.payload_schema
                || producer_lane.maximum_payload_bytes != consumer_lane.maximum_payload_bytes
            {
                return Err(refused(
                    "semantic projection differs from actual original response codec",
                ));
            }
            let id = Id::new(format!("connection/{}/{}", source.node, selected.node))?;
            let domain = Id::new(format!("{id}/custody"))?;
            let mut writers = vec![source.owner.clone(), selected.owner.clone()];
            writers.sort();
            let transfer = put(
                contents,
                b"installed native assertion response transfer v1: unchanged original response octets, evaluation/publication/delivery positions, producer sequence and causal parents; zero physical latency with strict superdense successor; original native receipt/output/input ACK and complete bounded transfer FIFO/credits are retained jointly; no injected observation, read/write classification, result reevaluation or new source receipt".to_vec(),
                "text/plain",
            )?;
            let maximum = producer_lane.maximum_payload_bytes.get();
            let policy = ConnectionPolicy {
                schema_version: 1,
                maximum_payload_bytes: maximum.into(),
                maximum_pending_events: 16.into(),
                maximum_pending_bytes: (maximum * 16).into(),
                visibility: VisibilityConversion::Direct,
                delivery: ConnectionDelivery::Fixed {
                    latency_ps: 0.into(),
                },
                causal_proof_ref: transfer,
                state_domain_ids: vec![domain.clone()],
            };
            connections.push(ConnectionDescriptor {
                schema_version: 1,
                id: id.clone(),
                producer: input.source.clone(),
                consumer: Endpoint {
                    node_id: selected.node.clone(),
                    port_id: consumer_port.id.clone(),
                    lane_id: consumer_lane.id.clone(),
                },
                interface_id: producer_port.interface_id.clone(),
                features: Vec::new(),
                payload_schema: producer_lane.payload_schema.clone(),
                minimum_latency_ps: 0.into(),
                policy_ref: put_json(contents, &policy)?,
                capture_owner_id: selected.owner.clone(),
                extensions: Extensions::new(),
            });
            domains.push(StateDomain {
                id: domain.clone(),
                capture_owner_id: selected.owner.clone(),
                execution_owner_ids: writers.clone(),
                future_affecting: true,
            });
            let mut participants = vec![source.node.clone(), selected.node.clone()];
            participants.sort();
            objects.push(StateObject {
                id,
                node_ids: participants,
                future_affecting: true,
                state: ObjectState::Mutable {
                    domain_id: domain.clone(),
                },
            });
            for binding in bindings.iter_mut() {
                for owner in [&mut binding.execution_owner, &mut binding.capture_owner] {
                    if writers.contains(&owner.id) {
                        owner.state_domain_ids.push(domain.clone());
                        owner.state_domain_ids.sort();
                        owner.state_domain_ids.dedup();
                    }
                }
            }
            for owner in owners
                .iter_mut()
                .filter(|owner| writers.contains(&owner.owner.id))
            {
                owner.owner.state_domain_ids.push(domain.clone());
                owner.owner.state_domain_ids.sort();
                owner.owner.state_domain_ids.dedup();
                owner.ownership_ref = put_json(contents, &owner.owner)?;
            }
            let capture = captures
                .iter_mut()
                .find(|capture| capture.owner_id == selected.owner)
                .ok_or_else(|| refused("semantic transfer has no actual capture owner"))?;
            capture.complete_model = true;
            capture.unchanged_cut = true;
            capture.exact_continuation = true;
            capture.durable_restart = false;
            capture.cut_procedure_ref = qualification.clone();
        }
    }
    for owner in owners {
        owner.node_bindings = bindings
            .iter()
            .filter(|binding| {
                binding.capture_owner.id == owner.owner.id
                    || binding.execution_owner.id == owner.owner.id
            })
            .map(|binding| {
                Ok(NodeBindingRef {
                    node_id: binding.node_id.clone(),
                    binding_hash: binding.identity()?,
                    extensions: Extensions::new(),
                })
            })
            .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?;
    }
    Ok(connections)
}
