//! Ordinary exact public request transfers from enrolled finite source nodes.

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
    let mut consumers = BTreeSet::new();
    for selected in selections {
        let consumer = match &selected.kind {
            InstalledNodeKind::HostScripted { profile } => &profile.consumer,
            InstalledNodeKind::HostSeededLink { profile } => &profile.consumer,
            _ => continue,
        };
        if !consumers.insert(consumer.clone()) {
            return Err(refused(
                "installed storage input permits exactly one original source",
            ));
        }
        let sink = selections
            .iter()
            .find(|entry| entry.node == *consumer)
            .ok_or_else(|| {
                refused("scripted request consumer is absent from complete selection")
            })?;
        if !matches!(&sink.kind, InstalledNodeKind::HostIo { .. })
            && !matches!(&sink.kind, InstalledNodeKind::HostSeededLink {profile} if profile.producer == selected.node)
        {
            return Err(refused(
                "installed request source requires an actual storage consumer",
            ));
        }
        let source_descriptor = descriptors
            .iter()
            .find(|entry| entry.id == selected.node)
            .ok_or_else(|| refused("installed request source descriptor missing"))?;
        let sink_descriptor = descriptors
            .iter()
            .find(|entry| entry.id == sink.node)
            .ok_or_else(|| refused("installed storage descriptor missing"))?;
        let source_port = source_descriptor
            .ports
            .first()
            .ok_or_else(|| refused("source output missing"))?;
        let sink_port = sink_descriptor
            .ports
            .first()
            .ok_or_else(|| refused("storage input missing"))?;
        let source_lane = source_port
            .lanes
            .iter()
            .find(|lane| lane.direction == Direction::Output)
            .ok_or_else(|| refused("source output lane missing"))?;
        let sink_lane = sink_port
            .lanes
            .iter()
            .find(|lane| lane.direction == Direction::Input)
            .ok_or_else(|| refused("storage input lane missing"))?;
        if source_port.interface_id != sink_port.interface_id
            || source_lane.payload_schema != sink_lane.payload_schema
            || source_lane.maximum_payload_bytes != sink_lane.maximum_payload_bytes
        {
            return Err(refused(
                "original script request codec differs from native storage input",
            ));
        }
        let id = Id::new(format!("connection/{}/{}", selected.node, sink.node))?;
        let domain = Id::new(format!("{id}/custody"))?;
        let mut writers = vec![selected.owner.clone(), sink.owner.clone()];
        writers.sort();
        let transfer = put(contents,
            b"installed storage request transfer v1: retain original exact source publication, request octets, causal parents and correlation; zero physical transport latency with strict superdense delivery successor; complete bounded FIFO/credit/input ACK custody is owned by original endpoints; no external input injection or reinterpretation".to_vec(),
            "text/plain")?;
        let maximum = source_lane.maximum_payload_bytes.get();
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
            producer: Endpoint {
                node_id: selected.node.clone(),
                port_id: source_port.id.clone(),
                lane_id: source_lane.id.clone(),
            },
            consumer: Endpoint {
                node_id: sink.node.clone(),
                port_id: sink_port.id.clone(),
                lane_id: sink_lane.id.clone(),
            },
            interface_id: source_port.interface_id.clone(),
            features: Vec::new(),
            payload_schema: source_lane.payload_schema.clone(),
            minimum_latency_ps: 0.into(),
            policy_ref: put_json(contents, &policy)?,
            capture_owner_id: sink.owner.clone(),
            extensions: Extensions::new(),
        });
        domains.push(StateDomain {
            id: domain.clone(),
            capture_owner_id: sink.owner.clone(),
            execution_owner_ids: writers.clone(),
            future_affecting: true,
        });
        let mut participants = vec![selected.node.clone(), sink.node.clone()];
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
            .find(|entry| entry.owner_id == sink.owner)
            .ok_or_else(|| refused("storage transfer owner has no original capture policy"))?;
        // Complete native envelopes and the whole runtime/scheduler ledger
        // preserve the original transfer FIFO, staged bytes, credits and ACKs.
        // The installed signed archive authenticates both actual endpoints and
        // this coordinator-owned domain before fresh owners may resume it.
        capture.complete_model = true;
        capture.unchanged_cut = true;
        capture.exact_continuation = true;
        capture.durable_restart = true;
        capture.cut_procedure_ref = qualification.clone();
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
    connections.sort_by(|left, right| left.id.cmp(&right.id));
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(connections)
}
