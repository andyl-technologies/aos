//! Installed opaque-byte links and explicit public transfer ownership.

use super::*;
use crucible::node_adapters::HostModel;
use crucible::node_admission::{ConnectionDelivery, ConnectionPolicy, VisibilityConversion};
use crucible_device::netlink::{LinkFaults, NetLink};
use crucible_node_contract::{
    ConnectionDescriptor, Direction, Endpoint, LaneDescriptor, PortDescriptor,
};

pub(super) fn link_profile(
    selected: &InstalledNodeSelection,
    selections: &[InstalledNodeSelection],
    host: &ContentRef,
    device: &ContentRef,
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(NodeDescriptor, BindingCompatibility, OwnerBinding, bool), NodeObservedError> {
    let InstalledNodeKind::HostNetLink {
        producer,
        consumer,
        source_node,
        latency_ps,
        floor_ps,
    } = &selected.kind
    else {
        return Err(refused("link profile requires a native link selection"));
    };
    let source = selections
        .iter()
        .find(|entry| &entry.node == producer)
        .ok_or_else(|| refused("link producer is absent from complete selection"))?;
    let sink = selections
        .iter()
        .find(|entry| &entry.node == consumer)
        .ok_or_else(|| refused("link consumer is absent from complete selection"))?;
    let InstalledNodeKind::ReferenceNativeLinked {
        quantum_ps,
        host_budget_ns,
        closed_ingress: true,
    } = &source.kind
    else {
        return Err(refused(
            "installed link source requires the closed native octet producer",
        ));
    };
    if !matches!(
        sink.kind,
        InstalledNodeKind::ReferenceNativeLinked {
            closed_ingress: false,
            ..
        }
    ) {
        return Err(refused(
            "installed link sink requires a causal native octet consumer",
        ));
    }
    let template = ReferenceProfile::build_native_linked(
        source.node.clone(),
        source.owner.clone(),
        host.clone(),
        device.clone(),
        *quantum_ps,
        *host_budget_ns,
        true,
    )
    .map_err(native)?;
    for object in template.content_objects() {
        contents.insert(
            object.reference.hash.digest.clone(),
            ScenarioContent {
                reference: object.reference.clone(),
                bytes: object.bytes.clone(),
            },
        );
    }
    let template_port = template
        .descriptor
        .ports
        .first()
        .ok_or_else(|| refused("source port absent"))?;
    let template_lane = template_port
        .lanes
        .first()
        .ok_or_else(|| refused("source lane absent"))?;
    let object = contents
        .get(&template_port.configuration_ref.hash.digest)
        .ok_or_else(|| refused("installed source lacks its original lane policy"))?;
    let mut policy: serde_json::Value = serde_json::from_slice(&object.bytes)?;
    let mut input = policy["lanes"][0].clone();
    input["lane_id"] = serde_json::json!("input");
    input["visibility"] = serde_json::json!({"kind":"exact"});
    let mut output = input.clone();
    output["lane_id"] = serde_json::json!("output");
    policy["lanes"] = serde_json::json!([input, output]);
    policy["execution_owner_id"] = serde_json::to_value(&selected.owner)?;
    policy["state_domain_ids"] = serde_json::json!([format!("{}/state", selected.owner)]);

    let (mut descriptor, mut binding, mut owner, _) =
        clock_profile(selected, host, qualification, contents)?;
    descriptor.roles = vec![Id::new("network_link")?];
    descriptor.model_ref = put(contents, b"crucible native exact link v1: fault-free picosecond NetLink preserves original octets; positive installed latency/floor; native source sequence and FIFO state are complete; no Ethernet interpretation".to_vec(), "text/plain")?;
    descriptor.configuration_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"source_node":source_node,"latency_ps":latency_ps,"floor_ps":floor_ps,"ticks_per_ns":"1000","faults":"none"}),
    )?;
    let model = HostModel::Link(Box::new(
        NetLink::new(
            *source_node,
            latency_ps.get(),
            floor_ps.get(),
            LinkFaults::none(),
        )
        .map_err(native)?,
    ));
    descriptor.initialization_ref = put(
        contents,
        model
            .initialization_bytes(4 * 1024 * 1024)
            .map_err(native)?,
        "application/octet-stream",
    )?;
    let lanes = [Direction::Input, Direction::Output]
        .into_iter()
        .zip(["input", "output"])
        .map(|(direction, name)| {
            Ok(LaneDescriptor {
                id: Id::new(name)?,
                direction,
                payload_schema: template_lane.payload_schema.clone(),
                maximum_payload_bytes: template_lane.maximum_payload_bytes,
                maximum_pending_events: template_lane.maximum_pending_events,
                extensions: Extensions::new(),
            })
        })
        .collect::<Result<Vec<_>, crucible_node_contract::ContractError>>()?;
    descriptor.ports = vec![PortDescriptor {
        id: Id::new("data")?,
        interface_id: template_port.interface_id.clone(),
        features: Vec::new(),
        configuration_ref: put_json(contents, &policy)?,
        lanes,
        extensions: Extensions::new(),
    }];
    binding.descriptor_hash = descriptor.identity()?;
    binding.configuration_ref = descriptor.configuration_ref.clone();
    binding.operating_contract.policy_ref = put_json(
        contents,
        &serde_json::json!({"mode":"exact","schema_version":1,"execution_proof_ref":qualification,"ceiling":{"kind":"input_blocked","proof_ref":qualification},"boundary_settlement_ref":qualification}),
    )?;
    binding.implementation.implementation_id = Id::new("crucible-host-netlink")?;
    binding.implementation.model_definitions = vec![descriptor.model_ref.clone()];
    binding.implementation.formats = vec![template_lane.payload_schema.clone()];
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    capabilities.devices_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"model":"native-opaque-netlink","latency_ps":latency_ps,"floor_ps":floor_ps,"faults":"none","complete_ports":descriptor.ports}),
    )?;
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,"operating_contract":binding.operating_contract,"capabilities":capabilities}),
    )?;
    let mut guarantee: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantee.capture_scope = CaptureScope::None;
    guarantee.continuation = Continuation::Unsupported;
    guarantee.durable_restart = false;
    binding.guarantees_ref = put_json(contents, &guarantee)?;
    for facet in &mut binding.operating_contract.facets {
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    capabilities.facets = binding.operating_contract.facets.clone();
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({"schema_version":1,"descriptor":descriptor,"implementation":binding.implementation,"operating_contract":binding.operating_contract,"capabilities":capabilities,"guarantees":guarantee}),
    )?;
    owner.node_bindings = Vec::new();
    Ok((descriptor, binding, owner, false))
}

pub(super) fn connections(
    selections: &[InstalledNodeSelection],
    bindings: &mut [BindingCompatibility],
    owners: &mut [OwnerBinding],
    inventory: (
        &mut Vec<StateDomain>,
        &mut Vec<StateObject>,
        &mut [OwnerCapturePolicy],
    ),
    qualification: &ContentRef,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<Vec<ConnectionDescriptor>, NodeObservedError> {
    let (domains, objects, captures) = inventory;
    let mut connections = Vec::new();
    for selected in selections {
        let InstalledNodeKind::HostNetLink {
            producer, consumer, ..
        } = &selected.kind
        else {
            continue;
        };
        for (source, sink, sampled) in [
            (producer, &selected.node, false),
            (&selected.node, consumer, true),
        ] {
            let source_binding = bindings
                .iter()
                .find(|entry| &entry.node_id == source)
                .ok_or_else(|| refused("connection producer missing"))?;
            let sink_binding = bindings
                .iter()
                .find(|entry| &entry.node_id == sink)
                .ok_or_else(|| refused("connection consumer missing"))?;
            let capture = sink_binding.capture_owner.id.clone();
            let mut writers = vec![
                source_binding.execution_owner.id.clone(),
                sink_binding.execution_owner.id.clone(),
            ];
            writers.sort();
            writers.dedup();
            let id = Id::new(format!("connection/{source}/{sink}"))?;
            let domain = Id::new(format!("{id}/custody"))?;
            let schema = source_binding
                .implementation
                .formats
                .iter()
                .find(|schema| schema.id.as_str() == "crucible/octet-stream-v1")
                .cloned()
                .ok_or_else(|| refused("link endpoint lacks installed byte schema"))?;
            let transfer = put_json(
                contents,
                &serde_json::json!({"schema_version":1,"semantics":"original octets and causal parents retained; exact public FIFO and bounded credit; zero transport latency; destination boundary sampling only when explicitly selected","sampled":sampled}),
            )?;
            let policy = ConnectionPolicy {
                schema_version: 1,
                maximum_payload_bytes: U64::new(4096),
                maximum_pending_events: U64::new(1),
                maximum_pending_bytes: U64::new(4096),
                visibility: if sampled {
                    VisibilityConversion::BoundarySampling {
                        contract_ref: transfer.clone(),
                    }
                } else {
                    VisibilityConversion::PublicationPreserving {
                        contract_ref: transfer.clone(),
                    }
                },
                delivery: ConnectionDelivery::Fixed {
                    latency_ps: U64::new(0),
                },
                causal_proof_ref: transfer,
                state_domain_ids: vec![domain.clone()],
            };
            connections.push(ConnectionDescriptor {
                schema_version: 1,
                id: id.clone(),
                producer: Endpoint {
                    node_id: source.clone(),
                    port_id: Id::new("data")?,
                    lane_id: Id::new("output")?,
                },
                consumer: Endpoint {
                    node_id: sink.clone(),
                    port_id: Id::new("data")?,
                    lane_id: Id::new("input")?,
                },
                interface_id: Id::new("crucible/octet-stream-v1")?,
                features: Vec::new(),
                payload_schema: schema,
                minimum_latency_ps: U64::new(0),
                policy_ref: put_json(contents, &policy)?,
                capture_owner_id: capture.clone(),
                extensions: Extensions::new(),
            });
            domains.push(StateDomain {
                id: domain.clone(),
                capture_owner_id: capture.clone(),
                execution_owner_ids: writers.clone(),
                future_affecting: true,
            });
            let mut participants = vec![source.clone(), sink.clone()];
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
                    if writers.contains(&owner.id) || owner.id == capture {
                        owner.state_domain_ids.push(domain.clone());
                        owner.state_domain_ids.sort();
                        owner.state_domain_ids.dedup();
                    }
                }
            }
            for owner in owners
                .iter_mut()
                .filter(|owner| writers.contains(&owner.owner.id) || owner.owner.id == capture)
            {
                owner.owner.state_domain_ids.push(domain.clone());
                owner.owner.state_domain_ids.sort();
                owner.owner.state_domain_ids.dedup();
                owner.ownership_ref = put_json(contents, &owner.owner)?;
            }
            // Transfer custody is owned, but this observed edition does not yet
            // install a combined native/coordinator durable state procedure.
            let capture_policy = captures
                .iter_mut()
                .find(|entry| entry.owner_id == capture)
                .ok_or_else(|| refused("connection capture procedure missing"))?;
            capture_policy.complete_model = false;
            capture_policy.unchanged_cut = false;
            capture_policy.exact_continuation = false;
            capture_policy.cut_procedure_ref = qualification.clone();
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
    connections.sort_by(|a, b| a.id.cmp(&b.id));
    objects.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(connections)
}
