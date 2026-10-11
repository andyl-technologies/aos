//! Private installed recording fixture with a genuine direct native source edge.
//!
//! Both reference implementations remain their actually measured native profiles.
//! This fixture installs explicit bounded coordinator transfer custody in the
//! consumer's existing domain; it advertises no native capture or restoration.

use super::*;
use crucible::node_admission::{ConnectionDelivery, ConnectionPolicy, VisibilityConversion};
use crucible_node_contract::{ConnectionDescriptor, Endpoint};

pub(super) fn connections(
    selections: &[InstalledNodeSelection],
    bindings: &[BindingCompatibility],
    objects: &mut Vec<StateObject>,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<Vec<ConnectionDescriptor>, NodeObservedError> {
    // This closed fixture is separate from the production selected topology.
    // Unexpected peer kinds do not implicitly become linked native devices.
    if selections.len() != 2
        || !selections.iter().all(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::ReferenceNativeLinked { .. }
            )
        })
    {
        return Ok(Vec::new());
    }
    let producers = selections
        .iter()
        .filter(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::ReferenceNativeLinked {
                    closed_ingress: true,
                    ..
                }
            )
        })
        .collect::<Vec<_>>();
    let consumers = selections
        .iter()
        .filter(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::ReferenceNativeLinked {
                    closed_ingress: false,
                    ..
                }
            )
        })
        .collect::<Vec<_>>();
    if producers.len() != 1 || consumers.len() != 1 {
        return Err(refused(
            "private recording pair requires one closed source and one input consumer",
        ));
    }
    let source = producers[0];
    let sink = consumers[0];
    let producer = bindings
        .iter()
        .find(|binding| binding.node_id == source.node)
        .ok_or_else(|| refused("private recording source binding absent"))?;
    let consumer = bindings
        .iter()
        .find(|binding| binding.node_id == sink.node)
        .ok_or_else(|| refused("private recording consumer binding absent"))?;
    if producer.operating_contract.resolution_ps != consumer.operating_contract.resolution_ps
        || producer.operating_contract.phase_ps != consumer.operating_contract.phase_ps
    {
        return Err(refused(
            "private recording pair requires the same original sampling grid",
        ));
    }
    let schema = producer
        .implementation
        .formats
        .iter()
        .find(|schema| schema.id.as_str() == "crucible/octet-stream-v1")
        .filter(|schema| consumer.implementation.formats.contains(schema))
        .cloned()
        .ok_or_else(|| refused("private recording byte codec differs between actual peers"))?;
    let custody = consumer
        .capture_owner
        .state_domain_ids
        .first()
        .cloned()
        .ok_or_else(|| refused("private consumer transfer custody domain absent"))?;
    let semantics = put(contents,
        b"crucible private direct native recording pair v1: original producer octets, public FIFO identity, causal provenance and retained proof bytes are sampled losslessly at the first consumer quantum boundary; fixed transport latency zero; maximum one pending 4096-byte event; original native source and coordinator transfer custody have no preservation procedure".to_vec(),
        "text/plain")?;
    let policy = ConnectionPolicy {
        schema_version: 1,
        maximum_payload_bytes: U64::new(4096),
        maximum_pending_events: U64::new(1),
        maximum_pending_bytes: U64::new(4096),
        visibility: VisibilityConversion::BoundarySampling {
            contract_ref: semantics.clone(),
        },
        delivery: ConnectionDelivery::Fixed {
            latency_ps: U64::new(0),
        },
        causal_proof_ref: semantics,
        state_domain_ids: vec![custody.clone()],
    };
    let connection = ConnectionDescriptor {
        schema_version: 1,
        id: Id::new(format!("connection/{}/{}", source.node, sink.node))?,
        producer: Endpoint {
            node_id: source.node.clone(),
            port_id: Id::new("data")?,
            lane_id: Id::new("output")?,
        },
        consumer: Endpoint {
            node_id: sink.node.clone(),
            port_id: Id::new("data")?,
            lane_id: Id::new("input")?,
        },
        interface_id: Id::new("crucible/octet-stream-v1")?,
        features: Vec::new(),
        payload_schema: schema,
        minimum_latency_ps: U64::new(0),
        policy_ref: put_json(contents, &policy)?,
        capture_owner_id: consumer.capture_owner.id.clone(),
        extensions: Extensions::new(),
    };
    let mut participants = vec![source.node.clone(), sink.node.clone()];
    participants.sort();
    objects.push(StateObject {
        id: connection.id.clone(),
        node_ids: participants,
        future_affecting: true,
        state: ObjectState::Mutable { domain_id: custody },
    });
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(vec![connection])
}
