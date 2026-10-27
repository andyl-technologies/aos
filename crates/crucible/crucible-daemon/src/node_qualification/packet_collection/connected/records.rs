//! Independently interprets the exact connected graph's bounded public policies.
//!
//! Native programs and concrete source registration are authenticated separately
//! by the original source roster. A parsed coordinator or policy is never an
//! accepted class, physical ownership proof or a substitute for current custody.

use std::collections::{BTreeMap, BTreeSet};

use crucible_engine::node_admission::{
    ConnectionDelivery, ConnectionPolicy, CoordinatorPolicy, FlowControl, LaneVisibility,
    ObjectState, OwnershipPolicy, PortPolicy, ScenarioRequirements, VisibilityConversion,
};
use crucible_node_format::{ContentRef, Direction, HashRef, Id, SchemaRef, Validate, canonical};
use serde::de::DeserializeOwned;

use super::{PacketConnectedGraphRequest, QualificationError, refused};

pub(super) struct Validated {
    pub(super) requirements: HashRef,
    pub(super) schemas: Vec<SchemaRef>,
    pub(super) proof: ContentRef,
    pub(super) connections: Vec<(Id, ContentRef)>,
    pub(super) closures: Vec<Id>,
}

/// Encodes the independent connected interpretation without issuing authority.
///
/// # Errors
/// Reports canonical serialization failure for the fixed collecting contract.
pub fn packet_connected_independent_graph_contract() -> Result<Vec<u8>, QualificationError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-connected-independent-graph/4",
        "purpose":"complete original producer/relay/sink collection only; all original normative obligations remain required",
        "native":"one unchanged output-only producer and two concrete connected original sources; actual native current custody is a separate terminal conjunction",
        "connections":"declared producer-to-relay-to-sink chain; direct exact bytes; fixed zero or one picosecond latency; bounded transfer credits and original staged delivery history",
        "closure":"at most16 complete microsteps; each actual owner has its own closure row; Delivery then Reaction then next-microstep Publication; no empty-queue inference past authentic producer frontier",
        "inventory":"native gate/input journals/staged bytes/delivered history/pending reactions/publications/output FIFO/grants/retirement and effects remain in native objects; each host-managed connection history has a separate explicit domain and object",
        "coordinator":"original scheduler reservations/source sequences/delivery heap/payloads/input batches/consumed commits/frontiers/operations/durable placements/owner lifecycle are host state, never represented as native process bytes",
        "capture":"all-false limitation only; no checkpoint, restart, isolated fork, replay or accepted capture procedure",
        "current":"same original concrete source roster, source-installed issuer revision and measured descriptor/path/read-lease guards; revocation is permanent"
    }))?)
}

/// Encodes the complete measured fixture binding beneath the compiled interpretation.
///
/// These data authenticate no native readiness or behavioral class. The installer
/// independently measures the same original files and verifies all full tuples.
///
/// # Errors
/// Refuses missing or different original build-closure roles or oversized records.
pub fn packet_connected_measured_graph_proof(
    measurements: &[super::super::PacketFixtureMeasurements; 3],
) -> Result<Vec<u8>, QualificationError> {
    super::super::scope::encoded_size(measurements, 3 * 65_536)?;
    let receipt = measurements[0]
        .sources
        .iter()
        .find(|source| source.role == "build_closure")
        .ok_or_else(refused)?
        .content
        .clone();
    if measurements.iter().any(|measurement| {
        measurement
            .sources
            .iter()
            .find(|source| source.role == "build_closure")
            .is_none_or(|source| source.content != receipt)
    }) {
        return Err(refused());
    }
    let interpretation = canonical::content_ref(
        &packet_connected_independent_graph_contract()?,
        "application/json",
    )?;
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-connected-independent-graph/4",
        "interpretation_ref":interpretation,
        "native_source_receipt":receipt,
        "measurements":measurements
    }))?)
}

pub(super) fn decode<T: DeserializeOwned>(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<T, QualificationError> {
    let bytes = content.get(reference).ok_or_else(refused)?;
    reference.verify(bytes)?;
    Ok(
        serde_json::from_value(canonical::parse_json(bytes, 1024 * 1024)?)
            .map_err(crucible_node_format::ContractError::from)?,
    )
}

pub(super) fn validate(
    request: &PacketConnectedGraphRequest<'_>,
) -> Result<Validated, QualificationError> {
    if request.content.len() > 128 {
        return Err(refused());
    }
    let extent = request.content.values().try_fold(0usize, |sum, bytes| {
        if bytes.len() > 1024 * 1024 {
            return Err(refused());
        }
        sum.checked_add(bytes.len()).ok_or_else(refused)
    })?;
    if extent > 2 * 1024 * 1024 {
        return Err(refused());
    }
    for (reference, bytes) in request.content {
        reference.verify(bytes)?;
    }
    super::super::scope::encoded_size(
        &(request.world, request.requirements, &request.measurements),
        2 * 1024 * 1024,
    )?;
    request.roster.current_scope()?;
    if request.coordinator != &request.roster.coordinator {
        return Err(refused());
    }
    request
        .host
        .authenticate_preparation_source(&request.world.identity()?)
        .map_err(|error| QualificationError::Evidence(error.reason))?;
    request.world.validate()?;
    let world_hash = request.world.identity()?;
    let sources = &request.roster.sources;
    let selected: Vec<_> = sources.iter().map(|source| source.installation()).collect();
    if request.world.node_bindings.len() != 4
        || request.world.connections.len() != 2
        || !request.world.extensions.is_empty()
        || request.world.ordering_profile != "superdense-v1"
        || selected
            .iter()
            .any(|one| one.world_binding_hash != world_hash)
    {
        return Err(refused());
    }
    let requirements = canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
    let original: ScenarioRequirements = decode(request.content, &request.world.scenario_ref)?;
    let host = request.host.selection();
    let mut nodes: Vec<_> = selected
        .iter()
        .map(|one| one.descriptor.id.clone())
        .collect();
    nodes.push(host.descriptor.id.clone());
    if nodes.iter().collect::<BTreeSet<_>>().len() != 4
        || canonical::json_hash("cnp.admission-requirements.v1", &original)? != requirements
        || original.deterministic
        || original.exact_capture
        || original.exact_continuation
        || original.durable_restart
        || original.isolated_fork
        || !original.accepted_quantized_nodes.is_empty()
        || !original.accepted_visibility_conversions.is_empty()
        || original.accepted_nondeterministic_nodes != nodes
        || original.accepted_limited_state_nodes != nodes
    {
        return Err(refused());
    }
    let interpretation = packet_connected_independent_graph_contract()?;
    let interpretation_ref = canonical::content_ref(&interpretation, "application/json")?;
    let measurements = request.measurements.map(Clone::clone);
    let bytes = packet_connected_measured_graph_proof(&measurements)?;
    let proof = canonical::content_ref(&bytes, "application/json")?;
    if request.content.get(&proof) != Some(&bytes)
        || request.content.get(&interpretation_ref) != Some(&interpretation)
    {
        return Err(refused());
    }
    let inventory: OwnershipPolicy = decode(request.content, &request.world.ownership_ref)?;
    let coordinator: CoordinatorPolicy =
        decode(request.content, &request.world.coordinator_contract_ref)?;
    if inventory.schema_version != 1
        || inventory.domains.len() != 6
        || inventory.objects.len() != 8
        || inventory.capture_owners.len() != 4
        || !inventory.internal_dependencies.is_empty()
        || inventory.inventory_proof_ref != proof
        || coordinator.schema_version != 1
        || coordinator.state_closure_ref != proof
        || coordinator.operational_policy_ref != proof
        || coordinator.maximum_microsteps_per_instant.get() != 16
        || coordinator.same_time_closure.len() != 4
        || !coordinator.external_inputs.is_empty()
    {
        return Err(refused());
    }
    let mut owners = BTreeSet::new();
    let mut schemas = Vec::new();
    let mut native_domains = BTreeSet::new();
    for (index, one) in selected.iter().enumerate() {
        validate_native_definitions(request, index)?;
        one.provider.validate()?;
        one.descriptor.validate()?;
        one.binding.validate()?;
        one.owner.validate()?;
        let owner = &one.owner.owner;
        if !owners.insert(owner.id.clone())
            || one.owner.node_bindings != [request.world.node_bindings[index].clone()]
            || owner.participant_ids != [one.descriptor.id.clone()]
            || one.provider.implementation.artifacts.len() != 1
            || one.provider.implementation.artifacts[0].role.as_str() != "executable"
            || one.provider.implementation.artifacts[0].content
                != request.measurements[index].peer.content
            || request.measurements[index].host != request.measurements[0].host
            || one.descriptor.ports.is_empty()
            || one.descriptor.ports.len() > 2
        {
            return Err(refused());
        }
        let object = inventory
            .objects
            .iter()
            .find(|row| row.id == one.descriptor.id)
            .ok_or_else(refused)?;
        let ObjectState::Mutable { domain_id } = &object.state else {
            return Err(refused());
        };
        if !object.future_affecting
            || object.node_ids != [one.descriptor.id.clone()]
            || !owner.state_domain_ids.contains(domain_id)
            || !native_domains.insert(domain_id.clone())
        {
            return Err(refused());
        }
        for port in &one.descriptor.ports {
            let policy: PortPolicy = decode(request.content, &port.configuration_ref)?;
            if policy.schema_version != 1
                || policy.internal
                || policy.execution_owner_id != owner.id
                || policy.lanes.len() != port.lanes.len()
                || policy.state_domain_ids.is_empty()
                || policy
                    .state_domain_ids
                    .iter()
                    .any(|id| !owner.state_domain_ids.contains(id))
                || policy.maximum_producers.get() > 1
                || policy.maximum_consumers.get() > 1
                || policy.arbitration_ref != proof
            {
                return Err(refused());
            }
            for (lane, semantics) in port.lanes.iter().zip(&policy.lanes) {
                if lane.id != semantics.lane_id
                    || semantics.ordering_ref != proof
                    || semantics.correlation_ref != proof
                    || semantics.flow_control != FlowControl::Credit
                    || semantics.visibility != LaneVisibility::Exact
                    || semantics.maximum_pending_bytes.get() == 0
                    || semantics.maximum_pending_bytes.get() > 32 * 1024
                    || semantics.minimum_lookahead_ps.get() != 0
                    // The shared lane contract covers publication and delivery;
                    // native directional emissions are validated independently.
                    || semantics.effect_phases.as_slice() != [1, 2]
                {
                    return Err(refused());
                }
                lane.payload_schema.validate()?;
                if !schemas.contains(&lane.payload_schema) {
                    schemas.push(lane.payload_schema.clone());
                }
            }
        }
        for format in &one.provider.implementation.formats {
            format.validate()?;
            if !schemas.contains(format) {
                schemas.push(format.clone());
            }
        }
    }
    validate_host_definition(request)?;
    host.descriptor.validate()?;
    host.binding.validate()?;
    host.owner.validate()?;
    if request.host.world() != &world_hash
        || request.roster.coordinator.host.descriptor != host.descriptor
        || request.roster.coordinator.host.binding != host.binding
        || request.roster.coordinator.host.owner != host.owner
        || request.roster.coordinator.host.prepared_token != *request.host.prepared_token()
        || request.roster.coordinator.host.initial_node
            != request
                .host
                .initial_node_record()
                .map_err(|error| QualificationError::Evidence(error.reason))?
        || host.owner.node_bindings != [request.world.node_bindings[3].clone()]
        || host.owner.owner.participant_ids != [host.descriptor.id.clone()]
        || !host.descriptor.ports.is_empty()
        || host.binding.compatibility.implementation.formats.as_slice()
            != [
                crucible_engine::node_contract::host_scheduling_owner_preparation_schema()
                    .map_err(|error| QualificationError::Evidence(error.reason))?,
            ]
        || !owners.insert(host.owner.owner.id.clone())
    {
        return Err(refused());
    }
    for format in &host.binding.compatibility.implementation.formats {
        format.validate()?;
        if !schemas.contains(format) {
            schemas.push(format.clone());
        }
    }
    validate_ownership(&inventory, &selected, &host.owner.owner, &proof)?;
    validate_host_core_objects(
        &inventory,
        &native_domains,
        &host.descriptor.id,
        &host.owner.owner,
    )?;
    let mut connections = Vec::new();
    let mut transfer_domains = BTreeSet::new();
    for (index, connection) in request.world.connections.iter().enumerate() {
        let policy: ConnectionPolicy = decode(request.content, &connection.policy_ref)?;
        let producer = &selected[index].descriptor;
        let consumer = &selected[index + 1].descriptor;
        if connection.producer.node_id != producer.id
            || connection.consumer.node_id != consumer.id
            || !connection.features.is_empty()
            || !connection.extensions.is_empty()
            || connection.minimum_latency_ps.get() != u64::from(index == 0)
            || policy.schema_version != 1
            || policy.visibility != VisibilityConversion::Direct
            || policy.delivery
                != (ConnectionDelivery::Fixed {
                    latency_ps: connection.minimum_latency_ps,
                })
            || policy.causal_proof_ref != proof
            || policy.maximum_payload_bytes.get() == 0
            || policy.maximum_payload_bytes.get() > 32
            || policy.maximum_pending_events.get() == 0
            || policy.maximum_pending_events.get() > 32
            || policy.maximum_pending_bytes.get() == 0
            || policy.maximum_pending_bytes.get() > 32 * 1024
            || policy.state_domain_ids.len() != 1
        {
            return Err(refused());
        }
        for (descriptor, endpoint, direction) in [
            (producer, &connection.producer, Direction::Output),
            (consumer, &connection.consumer, Direction::Input),
        ] {
            let port = descriptor
                .ports
                .iter()
                .find(|port| port.id == endpoint.port_id)
                .ok_or_else(refused)?;
            let lane = port
                .lanes
                .iter()
                .find(|lane| lane.id == endpoint.lane_id)
                .ok_or_else(refused)?;
            if port.interface_id != connection.interface_id
                || lane.direction != direction
                || lane.payload_schema != connection.payload_schema
            {
                return Err(refused());
            }
        }
        let domain_id = &policy.state_domain_ids[0];
        let domain = inventory
            .domains
            .iter()
            .find(|row| &row.id == domain_id)
            .ok_or_else(refused)?;
        let object = inventory
            .objects
            .iter()
            .find(|row| row.id == connection.id)
            .ok_or_else(refused)?;
        let mut members = vec![
            producer.id.clone(),
            consumer.id.clone(),
            host.descriptor.id.clone(),
        ];
        members.sort();
        if native_domains.contains(domain_id)
            || !transfer_domains.insert(domain_id.clone())
            || domain.capture_owner_id != connection.capture_owner_id
            || connection.capture_owner_id != host.owner.owner.id
            || domain.execution_owner_ids != [host.owner.owner.id.clone()]
            || request
                .host
                .domains()
                .connections
                .iter()
                .find(|mapping| mapping.connection == connection.id)
                .is_none_or(|mapping| &mapping.domain != domain_id)
            || !object.future_affecting
            || object.node_ids != members
            || object.state
                != (ObjectState::Mutable {
                    domain_id: domain_id.clone(),
                })
        {
            return Err(refused());
        }
        connections.push((connection.id.clone(), policy.causal_proof_ref));
    }
    let mut closures = Vec::new();
    for closure in &coordinator.same_time_closure {
        if !owners.contains(&closure.execution_owner_id) || closure.proof_ref != proof {
            return Err(refused());
        }
        closures.push(closure.execution_owner_id.clone());
    }
    if closures.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(refused());
    }
    if transfer_domains.len() != request.host.domains().connections.len()
        || request.host.domains().connections.len() != request.world.connections.len()
        || transfer_domains.contains(&request.host.domains().coordinator)
    {
        return Err(refused());
    }
    let initialization: Vec<ContentRef> =
        decode(request.content, &request.world.initialization_ref)?;
    let mut initializers = selected
        .iter()
        .map(|one| one.descriptor.initialization_ref.clone())
        .collect::<Vec<_>>();
    initializers.push(host.descriptor.initialization_ref.clone());
    if initialization != initializers {
        return Err(refused());
    }
    Ok(Validated {
        requirements,
        schemas,
        proof,
        connections,
        closures,
    })
}

fn validate_ownership(
    inventory: &OwnershipPolicy,
    selected: &[&crucible_engine::node_adapters::cnp::CnpSemanticInstallation],
    host_owner: &crucible_node_format::OwnerRef,
    proof: &ContentRef,
) -> Result<(), QualificationError> {
    if inventory
        .domains
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
        || inventory
            .objects
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || inventory
            .capture_owners
            .windows(2)
            .any(|pair| pair[0].owner_id >= pair[1].owner_id)
    {
        return Err(refused());
    }
    let mut owners = selected
        .iter()
        .map(|one| &one.owner.owner)
        .collect::<Vec<_>>();
    owners.push(host_owner);
    for owner in &owners {
        let capture = inventory
            .capture_owners
            .iter()
            .find(|row| row.owner_id == owner.id)
            .ok_or_else(refused)?;
        let actual: BTreeSet<_> = inventory
            .domains
            .iter()
            .filter(|row| {
                row.capture_owner_id == owner.id || row.execution_owner_ids.contains(&owner.id)
            })
            .map(|row| row.id.clone())
            .collect();
        if owner
            .state_domain_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != actual
            || capture.complete_model
            || capture.unchanged_cut
            || capture.exact_continuation
            || capture.durable_restart
            || capture.isolated_fork
            || !capture.dependencies.is_empty()
            || &capture.cut_procedure_ref != proof
        {
            return Err(refused());
        }
    }
    for domain in &inventory.domains {
        if !domain.future_affecting
            || !owners
                .iter()
                .any(|owner| owner.id == domain.capture_owner_id)
            || domain.execution_owner_ids.is_empty()
            || domain
                .execution_owner_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || domain
                .execution_owner_ids
                .iter()
                .any(|writer| !owners.iter().any(|owner| &owner.id == writer))
        {
            return Err(refused());
        }
    }
    Ok(())
}

pub(super) fn validate_host_core_objects(
    inventory: &OwnershipPolicy,
    native_domains: &BTreeSet<Id>,
    host_node: &Id,
    host_owner: &crucible_node_format::OwnerRef,
) -> Result<(), QualificationError> {
    let mut core = BTreeSet::new();
    for object in &inventory.objects {
        if object.node_ids != [host_node.clone()] {
            continue;
        }
        let ObjectState::Mutable { domain_id } = &object.state else {
            return Err(refused());
        };
        let domain = inventory
            .domains
            .iter()
            .find(|domain| &domain.id == domain_id)
            .ok_or_else(refused)?;
        if !object.future_affecting
            || native_domains.contains(domain_id)
            || domain.capture_owner_id != host_owner.id
            || domain.execution_owner_ids != [host_owner.id.clone()]
            || !host_owner.state_domain_ids.contains(domain_id)
            || !core.insert(domain_id.clone())
        {
            return Err(refused());
        }
    }
    if core
        != host_owner
            .state_domain_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    {
        return Err(refused());
    }
    Ok(())
}

fn validate_host_definition(
    request: &PacketConnectedGraphRequest<'_>,
) -> Result<(), QualificationError> {
    use crucible_engine::node_contract::{
        host_scheduling_owner_configuration, host_scheduling_owner_definition,
    };

    let host = request.host.selection();
    for (reference, bytes) in [
        (
            &host.descriptor.model_ref,
            host_scheduling_owner_definition()
                .map_err(|error| QualificationError::Evidence(error.reason))?,
        ),
        (
            &host.descriptor.configuration_ref,
            host_scheduling_owner_configuration(request.host.domains())
                .map_err(|error| QualificationError::Evidence(error.reason))?,
        ),
        (
            &host.binding.compatibility.operating_contract.policy_ref,
            canonical::canonical_json(
                &serde_json::to_value(&host.operating_policy)
                    .map_err(crucible_node_format::ContractError::from)?,
            )?,
        ),
        (
            &host.binding.compatibility.guarantees_ref,
            canonical::canonical_json(
                &serde_json::to_value(&host.guarantees)
                    .map_err(crucible_node_format::ContractError::from)?,
            )?,
        ),
    ] {
        if request.content.get(reference) != Some(&bytes) {
            return Err(refused());
        }
        reference.verify(&bytes)?;
    }
    Ok(())
}

fn validate_native_definitions(
    request: &PacketConnectedGraphRequest<'_>,
    member: usize,
) -> Result<(), QualificationError> {
    use crucible_node_transport::reference_packet::contracts;

    let selected = request.roster.sources[member].installation();
    let octets = contracts::immediate_packet_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let connected = contracts::connected_packet_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let ingress = contracts::connected_ingress_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let octets_ref = canonical::content_ref(&octets, "application/json")?;
    let connected_ref = canonical::content_ref(&connected, "application/json")?;
    let ingress_ref = canonical::content_ref(&ingress, "application/json")?;
    for (reference, bytes) in [
        (&octets_ref, &octets),
        (&connected_ref, &connected),
        (&ingress_ref, &ingress),
    ] {
        if request.content.get(reference) != Some(bytes) {
            return Err(refused());
        }
    }
    let mut expected = if member == 0 {
        vec![
            ("source-owned.packet-program/1", 1, &octets_ref),
            ("source-owned.packet-receipt/2", 2, &octets_ref),
        ]
    } else {
        vec![
            ("source-owned.packet-connected-program/4", 4, &connected_ref),
            ("source-owned.packet-receipt/4", 4, &connected_ref),
        ]
    };
    expected.extend([
        ("source-owned.packet-ingress/4", 4, &ingress_ref),
        ("source-owned.packet-octets/1", 1, &octets_ref),
    ]);
    expected.sort_by_key(|(id, _, _)| *id);
    let formats = &selected.provider.implementation.formats;
    if formats.len() != expected.len()
        || formats
            .iter()
            .zip(expected)
            .any(|(actual, (id, version, reference))| {
                actual.id.as_str() != id
                    || actual.version != version
                    || &actual.definition != reference
                    || !actual.extensions.is_empty()
            })
        || selected.descriptor.ports.iter().any(|port| {
            !port.extensions.is_empty()
                || port.lanes.iter().any(|lane| {
                    !lane.extensions.is_empty()
                        || lane.payload_schema.id.as_str() != "source-owned.packet-octets/1"
                        || lane.payload_schema.version != 1
                        || lane.payload_schema.definition != octets_ref
                        || !lane.payload_schema.extensions.is_empty()
                })
        })
    {
        return Err(refused());
    }
    Ok(())
}
