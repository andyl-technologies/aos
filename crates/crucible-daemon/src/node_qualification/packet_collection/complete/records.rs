//! Independently interprets the exact connected graph's bounded public policies.
//!
//! Native programs and concrete source registration are authenticated separately
//! by the original source roster. A parsed coordinator or policy is never an
//! accepted class, physical ownership proof or a substitute for current custody.

use std::collections::{BTreeMap, BTreeSet};

use crucible::node_adapters::cnp::CnpSemanticSource;

use crucible::node_admission::{
    ConnectionDelivery, ConnectionPolicy, CoordinatorPolicy, FlowControl, LaneVisibility,
    ObjectState, OwnershipPolicy, PortPolicy, ScenarioRequirements, VisibilityConversion,
};
use crucible_node_contract::{ContentRef, Direction, HashRef, Id, SchemaRef, Validate, canonical};
use serde::de::DeserializeOwned;

use super::{PacketCompleteGraphRequest, QualificationError, refused};

#[path = "records/host_capture17.rs"]
mod host_capture17;

pub(super) fn host_capture17_counter_scratch_data() -> usize {
    host_capture17::counter_scratch_data()
}

pub(super) struct Validated {
    pub(super) requirements: HashRef,
    pub(super) schemas: Vec<SchemaRef>,
    pub(super) proof: ContentRef,
    pub(super) interpretation: ContentRef,
    pub(super) connections: Vec<(Id, ContentRef)>,
    pub(super) closures: Vec<Id>,
}

/// Encodes the independent connected interpretation without issuing authority.
///
/// # Errors
/// Reports canonical serialization failure for the fixed collecting contract.
pub fn packet_complete_independent_graph_contract() -> Result<Vec<u8>, QualificationError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-complete-independent-graph/5",
        "purpose":"complete original producer/relay/sink collection only; all original normative obligations remain required",
        "native":"one unchanged output-only producer and two concrete connected original sources; actual native current custody is a separate terminal conjunction",
        "connections":"declared producer-to-relay-to-sink chain; direct exact bytes; fixed zero or one picosecond latency; bounded transfer credits and original staged delivery history",
        "closure":"at most16 complete microsteps; each actual owner has its own closure row; Delivery then Reaction then next-microstep Publication; no empty-queue inference past authentic producer frontier",
        "inventory":"native gate/input journals/staged bytes/delivered history/pending reactions/publications/output FIFO/grants/retirement and effects remain in native objects; each host-managed connection history has a separate explicit domain and object",
        "coordinator":"original scheduler reservations/source sequences/delivery heap/payloads/input batches/consumed commits/frontiers/operations/durable placements/owner lifecycle are host state, never represented as native process bytes",
        "capture":"declarations only; bootstrap refuses Capture qualification; actual live factory, selected geometry and original Host2 association are independently mandatory before administrative ticket dispatch",
        "current":"same original concrete source roster and source-installed issuer revision; complete-byte validation selected before acquisition, no notification worker; hash all retained descriptor bytes and check original path/process/metadata at every current read; observed revocation is permanent"
    }))?)
}

/// Encodes the complete measured fixture binding beneath the compiled interpretation.
///
/// These data authenticate no native readiness or behavioral class. The installer
/// independently measures the same original files and verifies all full tuples.
///
/// # Errors
/// Refuses missing or different original build-closure roles or oversized records.
pub fn packet_complete_measured_graph_proof(
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
        &packet_complete_independent_graph_contract()?,
        "application/json",
    )?;
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-complete-independent-graph/5",
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
            .map_err(crucible_node_contract::ContractError::from)?,
    )
}

pub(super) fn validate(
    request: &PacketCompleteGraphRequest<'_>,
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
        .authenticate_complete_preparation_source(&request.world.identity()?)
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
    if !exact_collecting_nondeterminism_roster(&nodes, &original.accepted_nondeterministic_nodes)
        || canonical::json_hash("cnp.admission-requirements.v1", &original)? != requirements
        || original.deterministic
        || original.exact_capture
        || original.exact_continuation
        || original.durable_restart
        || original.isolated_fork
        || !original.accepted_quantized_nodes.is_empty()
        || !original.accepted_visibility_conversions.is_empty()
        || !original.accepted_limited_state_nodes.is_empty()
    {
        return Err(refused());
    }
    let interpretation = packet_complete_independent_graph_contract()?;
    let interpretation_ref = canonical::content_ref(&interpretation, "application/json")?;
    let measurements = request.measurements.map(Clone::clone);
    let bytes = packet_complete_measured_graph_proof(&measurements)?;
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
        || !host_capture17::authenticate_formats_data(request)?
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
        interpretation: interpretation_ref,
        connections,
        closures,
    })
}

fn validate_ownership(
    inventory: &OwnershipPolicy,
    selected: &[&crucible::node_adapters::cnp::CnpSemanticInstallation],
    host_owner: &crucible_node_contract::OwnerRef,
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
            || !capture.complete_model
            || !capture.unchanged_cut
            || !capture.exact_continuation
            || !capture.durable_restart
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
    host_owner: &crucible_node_contract::OwnerRef,
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

/// Requires explicit acceptance of every actual unqualified collecting participant.
///
/// The caller supplies the three native descriptors and the actual selected Host.
/// Only that exact four-owner set, in canonical order without extras, is accepted.
/// This predicate performs no original file read or qualification callback.
pub(super) fn exact_collecting_nondeterminism_roster(nodes: &[Id], accepted: &[Id]) -> bool {
    let expected: BTreeSet<_> = nodes.iter().collect();
    nodes.len() == 4
        && expected.len() == 4
        && accepted.len() == 4
        && expected.into_iter().eq(accepted.iter())
}

fn validate_host_definition(
    request: &PacketCompleteGraphRequest<'_>,
) -> Result<(), QualificationError> {
    use crucible::node_contract::{
        host_scheduling_complete_owner_configuration, host_scheduling_complete_owner_definition,
    };

    let host = request.host.selection();
    for (reference, bytes) in [
        (
            &host.descriptor.model_ref,
            host_scheduling_complete_owner_definition()
                .map_err(|error| QualificationError::Evidence(error.reason))?,
        ),
        (
            &host.descriptor.configuration_ref,
            host_scheduling_complete_owner_configuration(request.host.domains())
                .map_err(|error| QualificationError::Evidence(error.reason))?,
        ),
        (
            &host.binding.compatibility.operating_contract.policy_ref,
            canonical::canonical_json(
                &serde_json::to_value(&host.operating_policy)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?,
        ),
        (
            &host.binding.compatibility.guarantees_ref,
            canonical::canonical_json(
                &serde_json::to_value(&host.guarantees)
                    .map_err(crucible_node_contract::ContractError::from)?,
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
    request: &PacketCompleteGraphRequest<'_>,
    member: usize,
) -> Result<(), QualificationError> {
    validate_original_native_definition_data(
        &request.roster.sources[member],
        request.content,
        member,
    )
}

/// Authenticates the same concrete Source's immutable native grammar and content.
///
/// Installation edition three invokes this DATA check before capture banks or
/// namespace acquisition. This issues no startup, graph or execution permission.
///
/// # Errors
/// Refuses incomplete, foreign, extended, duplicate or extra native definitions.
pub(super) fn validate_original_native_definition_data(
    source: &crucible::node_adapters::cnp::PacketCompleteSemanticSource,
    content: &BTreeMap<ContentRef, Vec<u8>>,
    member: usize,
) -> Result<(), QualificationError> {
    use crucible_node_provider::reference_packet::contracts;

    let selected = source.installation();
    let octets = contracts::immediate_packet_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let connected = contracts::connected_packet_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let complete =
        crucible_node_provider::reference_packet::continuation_contracts::complete_packet_contract(
        )
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let complete_ref = canonical::content_ref(&complete, "application/json")?;
    let ingress = crucible_node_provider::reference_packet::continuation_contracts::complete_ingress_contract()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let octets_ref = canonical::content_ref(&octets, "application/json")?;
    let connected_ref = canonical::content_ref(&connected, "application/json")?;
    let ingress_ref = canonical::content_ref(&ingress, "application/json")?;
    for (reference, bytes) in [
        (&octets_ref, &octets),
        (&connected_ref, &connected),
        (&ingress_ref, &ingress),
        (&complete_ref, &complete),
    ] {
        if content.get(reference) != Some(bytes) {
            return Err(refused());
        }
    }
    let mut expected = if member == 0 {
        vec![
            ("source-owned.packet-program/1", 1, &complete_ref),
            ("source-owned.packet-receipt/5", 5, &complete_ref),
        ]
    } else {
        vec![
            ("source-owned.packet-connected-program/4", 4, &complete_ref),
            ("source-owned.packet-receipt/5", 5, &complete_ref),
        ]
    };
    let continuation = crucible_node_provider::reference_packet::continuation_contracts::complete_packet_continuation_schema()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    expected.push((
        "source-owned.packet-native-continuation/5",
        5,
        &continuation.definition,
    ));
    expected.extend([
        ("source-owned.packet-ingress/5", 5, &ingress_ref),
        ("source-owned.packet-octets/1", 1, &octets_ref),
    ]);
    // The same concrete Source fixes selected additional grammar before any
    // binding hashes or native preparation. Declarations grant no collection,
    // currentness, graph admission or Capture authority here.
    let additional = selected_native_definition_bodies(source)?;
    for (schema, bytes) in &additional {
        schema.definition.verify(bytes)?;
        if content.get(&schema.definition) != Some(bytes) {
            return Err(refused());
        }
        expected.push((schema.id.as_str(), schema.version, &schema.definition));
    }
    expected.sort_by_key(|(id, _, _)| *id);
    let formats = &selected.provider.implementation.formats;
    if !exact_native_format_roster(formats, &expected)
        || (source
            .is_original_invocation_snapshot_declaration_data()
            .map_err(|_| refused())?
            && !exact_native_format_roster(
                &selected.binding.compatibility.implementation.formats,
                &expected,
            ))
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

/// Derives only the closed extra grammar selected by the same concrete Source.
fn selected_native_definition_bodies(
    source: &crucible::node_adapters::cnp::PacketCompleteSemanticSource,
) -> Result<Vec<(SchemaRef, Vec<u8>)>, QualificationError> {
    use crucible_node_provider::reference_packet::service::{
        PacketNative5ConfirmationSelection,
        ack_emitter::{
            PacketNative5AckEmitterSelection, native_canonical_ack_admission_contract,
            native_canonical_ack_admission_schema, native_canonical_blob_ack_contract,
            native_canonical_blob_ack_schema,
        },
        confirmation::{native_after_confirmation_contract, native_after_confirmation_schema},
    };

    let confirmation = source
        .selected_confirmation_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?;
    let ack = source
        .selected_ack_emitter_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?;
    let mut definitions = Vec::new();
    if let Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5) = confirmation {
        definitions.push((
            native_after_confirmation_schema()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?,
            native_after_confirmation_contract()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?,
        ));
    }
    if let Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5) = ack {
        if confirmation != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5) {
            return Err(refused());
        }
        definitions.extend([
            (
                native_canonical_blob_ack_schema()
                    .map_err(|error| QualificationError::Evidence(error.to_string()))?,
                native_canonical_blob_ack_contract()
                    .map_err(|error| QualificationError::Evidence(error.to_string()))?,
            ),
            (
                native_canonical_ack_admission_schema()
                    .map_err(|error| QualificationError::Evidence(error.to_string()))?,
                native_canonical_ack_admission_contract()
                    .map_err(|error| QualificationError::Evidence(error.to_string()))?,
            ),
        ]);
    }
    if let Some(selection) = source
        .selected_complete_restore_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?
    {
        if ack.is_none() || confirmation.is_none() {
            return Err(refused());
        }
        // The same source selection fixes all ten transfer12 schemas or the
        // original three Owned11 schemas. Features are not envelope extensions.
        definitions.extend(
            crucible_node_provider::reference_packet::service::complete_restore::complete_restore_selected_contracts(selection)
                .map_err(|error| QualificationError::Evidence(error.to_string()))?
        );
    }
    if source
        .selected_restore_input_emitter_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?
        .is_some()
    {
        use crucible_node_provider::reference_packet::service::complete_restore::{
            canonical_restore_inputs_contract, canonical_restore_inputs_schema,
        };
        definitions.push((
            canonical_restore_inputs_schema()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?,
            canonical_restore_inputs_contract()
                .map_err(|error| QualificationError::Evidence(error.to_string()))?,
        ));
    }
    if source
        .selected_capture_allocation_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?
        .is_some()
    {
        if ack != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || confirmation != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        {
            return Err(refused());
        }
        use crucible_node_provider::reference_packet::service::capture_allocation::{
            capture_allocation_contract, capture_allocation_record_schema,
            capture_allocation_schema,
        };
        let body = capture_allocation_contract()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        for schema in [
            capture_allocation_schema(),
            capture_allocation_record_schema(),
        ] {
            definitions.push((
                schema.map_err(|error| QualificationError::Evidence(error.to_string()))?,
                body.clone(),
            ));
        }
    }
    if source
        .selected_fresh_restore_allocation_selection()
        .map_err(|error| QualificationError::Evidence(error.reason))?
        .is_some()
    {
        use crucible_node_provider::reference_packet::service::{
            complete_restore::{
                PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            },
            fresh_restore_allocation::{
                PacketNativeFreshRestoreAllocationSchema, fresh_restore_allocation_contract,
                fresh_restore_allocation_schema,
            },
        };
        if source
            .selected_complete_restore_selection()
            .map_err(|error| QualificationError::Evidence(error.reason))?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || source
                .selected_restore_input_emitter_selection()
                .map_err(|error| QualificationError::Evidence(error.reason))?
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        {
            return Err(refused());
        }
        let body = fresh_restore_allocation_contract()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        for kind in [
            PacketNativeFreshRestoreAllocationSchema::Query,
            PacketNativeFreshRestoreAllocationSchema::Report,
            PacketNativeFreshRestoreAllocationSchema::Proof,
            PacketNativeFreshRestoreAllocationSchema::Receipt,
            PacketNativeFreshRestoreAllocationSchema::PrepareBinding,
        ] {
            definitions.push((
                fresh_restore_allocation_schema(kind)
                    .map_err(|error| QualificationError::Evidence(error.to_string()))?,
                body.clone(),
            ));
        }
    }
    if source
        .is_original_invocation_snapshot_declaration_data()
        .map_err(|_| refused())?
    {
        use crucible_node_provider::{
            client::CanonicalAckCodecMetadataExtent,
            reference_packet::service::{
                PacketNative5CaptureProfile,
                capture_allocation::PacketNative5CaptureAllocationSelection,
                complete_restore::{
                    PacketNative5CompleteRestoreSelection,
                    PacketNative5RestoreInputEmitterSelection,
                },
                fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
                native_snapshot::{
                    native_owned14_snapshot_contract, native_owned14_snapshot_schema,
                },
            },
        };
        // The actual Source-retained declaration is independent of invocation
        // purpose. The full original/target roster is identical; live private
        // purpose/currentness and full class15 reconstruction remain required.
        if confirmation != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
            || ack != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || source
                .selected_complete_restore_selection()
                .map_err(|_| refused())?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || source
                .selected_restore_input_emitter_selection()
                .map_err(|_| refused())?
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
            || source
                .selected_fresh_restore_allocation_selection()
                .map_err(|_| refused())?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || source
                .selected_capture_allocation_selection()
                .map_err(|_| refused())?
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || !matches!(
                source.selected_capture_profile().map_err(|_| refused())?,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || source
                .selected_protocol_metadata_limits()
                .map_err(|_| refused())?
                .is_none()
            || source
                .selected_ack_codec_metadata_extent()
                .map_err(|_| refused())?
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || source
                .selected_native_ack_codec_metadata_extent()
                .map_err(|_| refused())?
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        {
            return Err(refused());
        }
        // Append: the independent Transfer12 roster still requires snapshot11.
        definitions.push((
            native_owned14_snapshot_schema().map_err(|_| refused())?,
            native_owned14_snapshot_contract().map_err(|_| refused())?,
        ));
    }
    if source
        .is_original_restoration_activation_declaration_data()
        .map_err(|_| refused())?
    {
        use crucible_node_provider::reference_packet::service::complete_restore::activation::{
            restoration_activation_contract_data, restoration_activation_schema,
            upload::{
                restoration_activation_upload_contract_data, restoration_activation_upload_schema,
            },
        };
        definitions.extend([
            (
                restoration_activation_schema().map_err(|_| refused())?,
                restoration_activation_contract_data().to_vec(),
            ),
            (
                restoration_activation_upload_schema().map_err(|_| refused())?,
                restoration_activation_upload_contract_data().to_vec(),
            ),
        ]);
    }
    if source
        .is_original_restoration_observation_declaration_data()
        .map_err(|_| refused())?
    {
        use crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::{
            restoration_observe_schema, restoration_observe_contract_data,
        };
        definitions.push((
            restoration_observe_schema().map_err(|_| refused())?,
            restoration_observe_contract_data().to_vec(),
        ));
        // Original execution may declare the exact grammar needed by its fresh
        // target without selecting that target's distinct startup carrier.
        if let Some(definition) = restored_suffix::declared_definition_data(source.installation())?
        {
            definitions.push(definition);
        }
    }
    Ok(definitions)
}

fn exact_native_format_roster(
    formats: &[SchemaRef],
    expected: &[(&str, crucible_node_contract::Version, &ContentRef)],
) -> bool {
    formats.len() == expected.len()
        && formats
            .iter()
            .zip(expected)
            .all(|(actual, (id, version, reference))| {
                actual.id.as_str() == *id
                    && actual.version == *version
                    && &actual.definition == *reference
                    && actual.extensions.is_empty()
            })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "closed structural roster fixture assertions"
)]
mod selected_roster_tests {
    use super::*;

    #[test]
    fn closed_native_format_roster_rejects_unknown_extra_foreign_and_extended_formats() {
        let actual = crucible_node_provider::reference_packet::service::confirmation::
            native_after_confirmation_schema().unwrap();
        let expected = [(actual.id.as_str(), actual.version, &actual.definition)];
        assert!(exact_native_format_roster(
            std::slice::from_ref(&actual),
            &expected
        ));

        assert!(!exact_native_format_roster(&[], &expected));
        assert!(!exact_native_format_roster(
            &[actual.clone(), actual.clone()],
            &expected
        ));
        let mut unknown = actual.clone();
        unknown.id = Id::new("unknown.native-format/1").unwrap();
        assert!(!exact_native_format_roster(&[unknown], &expected));
        let mut foreign = actual.clone();
        foreign.definition = canonical::content_ref(b"foreign", "application/json").unwrap();
        assert!(!exact_native_format_roster(&[foreign], &expected));
        let mut extended = actual.clone();
        extended
            .extensions
            .insert("unexpected".into(), serde_json::Value::Null);
        assert!(!exact_native_format_roster(&[extended], &expected));
    }

    #[test]
    fn invocation_snapshot_is_additive_to_actual_transfer_snapshot_roster() {
        use crucible_node_provider::reference_packet::service::{
            complete_restore::{
                PacketNative5CompleteRestoreSelection, complete_restore_selected_contracts,
            },
            native_owned11_snapshot_schema,
            native_snapshot::{native_owned14_snapshot_contract, native_owned14_snapshot_schema},
        };
        let mut definitions = complete_restore_selected_contracts(
            PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        )
        .unwrap();
        let old = native_owned11_snapshot_schema().unwrap();
        let invocation = native_owned14_snapshot_schema().unwrap();
        assert!(definitions.iter().any(|(schema, _)| schema == &old));
        definitions.push((
            invocation.clone(),
            native_owned14_snapshot_contract().unwrap(),
        ));
        definitions.sort_by(|(left, _), (right, _)| left.id.cmp(&right.id));
        let formats: Vec<_> = definitions
            .iter()
            .map(|(schema, _)| schema.clone())
            .collect();
        let expected: Vec<_> = definitions
            .iter()
            .map(|(schema, _)| (schema.id.as_str(), schema.version, &schema.definition))
            .collect();

        assert!(exact_native_format_roster(&formats, &expected));
        for removed in [&old, &invocation] {
            let missing: Vec<_> = formats
                .iter()
                .filter(|schema| *schema != removed)
                .cloned()
                .collect();
            assert!(!exact_native_format_roster(&missing, &expected));
        }
        for (schema, body) in &definitions {
            schema.definition.verify(body).unwrap();
        }
        let mut extra = formats.clone();
        extra.push(invocation);
        assert!(!exact_native_format_roster(&extra, &expected));
    }
}

#[path = "records/restored_suffix.rs"]
mod restored_suffix;
