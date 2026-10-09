//! Validates full directed endpoint contracts and finite transfer reservations.

use std::collections::BTreeMap;

use crucible_node_contract::{
    Direction, Endpoint, HashRef, Id, LaneDescriptor, NodeDescriptor, OperatingMode, PortDescriptor,
};

use super::error::refuse;
use super::evidence::VerifiedContent;
use super::nodes::ordered_ids;
use super::{
    AdmissionCode, AdmissionError, AdmissionRequest, AdmissionStage, AdmissionSubject,
    ConnectionDelivery, ConnectionPolicy, LanePolicy, LaneVisibility, OwnershipPolicy, PortPolicy,
    QualificationClaim, VisibilityConversion,
};

pub(super) type PortPolicies = BTreeMap<(Id, Id), PortPolicy>;
pub(super) type CausalEdges = Vec<(Id, Id, u64)>;

pub(super) struct ConnectionSelections {
    pub edges: CausalEdges,
    pub policies: BTreeMap<Id, ConnectionPolicy>,
}

pub(super) fn validate_ports(
    request: &AdmissionRequest<'_>,
    ownership: &OwnershipPolicy,
    operating_policies: &BTreeMap<Id, crate::node_scheduling::ExecutionPolicy>,
    content: &mut VerifiedContent<'_>,
) -> Result<PortPolicies, AdmissionError> {
    let mut policies = BTreeMap::new();
    for (node, binding) in request.descriptors.iter().zip(request.bindings) {
        let expected_hash = binding.identity().map_err(super::nodes::schema_error)?;
        for port in &node.ports {
            let subject = AdmissionSubject::Node(node.id.clone());
            let fail = |code, required, observed| {
                refuse(
                    AdmissionStage::Edges,
                    subject.clone(),
                    code,
                    required,
                    observed,
                )
            };
            let policy: PortPolicy = content.policy(&port.configuration_ref)?;
            ordered_ids(
                policy.lanes.iter().map(|lane| &lane.lane_id),
                content.limits.maximum_ports_or_lanes,
            )?;
            ordered_ids(
                policy.state_domain_ids.iter(),
                content.limits.maximum_state_objects,
            )?;
            if policy.schema_version != 1
                || policy.lanes.len() != port.lanes.len()
                || policy
                    .lanes
                    .iter()
                    .zip(&port.lanes)
                    .any(|(policy, lane)| policy.lane_id != lane.id)
            {
                return Err(fail(
                    AdmissionCode::InvalidSchema,
                    "supported policy enumerating every selected lane once",
                    "edition or lane roster differs",
                ));
            }
            if !port.extensions.is_empty()
                || port.lanes.iter().any(|lane| {
                    !lane.extensions.is_empty() || !lane.payload_schema.extensions.is_empty()
                })
            {
                return Err(fail(
                    AdmissionCode::UnknownInterface,
                    "registered exact port and schema semantics",
                    "unregistered extension",
                ));
            }
            if policy.execution_owner_id != binding.compatibility.execution_owner.id {
                return Err(fail(
                    AdmissionCode::OwnerConflict,
                    "port effects route through selected unique execution owner",
                    "foreign port execution owner",
                ));
            }
            content.verify(&policy.arbitration_ref)?;
            for domain_id in &policy.state_domain_ids {
                let domain = ownership
                    .domains
                    .iter()
                    .find(|domain| &domain.id == domain_id)
                    .ok_or_else(|| {
                        fail(
                            AdmissionCode::OwnerConflict,
                            "every port domain included in complete ownership inventory",
                            "undeclared port state domain",
                        )
                    })?;
                if !domain
                    .execution_owner_ids
                    .contains(&policy.execution_owner_id)
                {
                    return Err(fail(
                        AdmissionCode::OwnerConflict,
                        "port writer included in domain execution ownership",
                        "port mutates foreign domain",
                    ));
                }
            }
            for (lane_policy, lane) in policy.lanes.iter().zip(&port.lanes) {
                content.verify(&lane.payload_schema.definition)?;
                content
                    .source
                    .authenticate_schema(&lane.payload_schema)
                    .map_err(|error| {
                        refuse(
                            AdmissionStage::Authenticate,
                            subject.clone(),
                            AdmissionCode::UnknownInterface,
                            "installed validator for actual versioned payload schema",
                            error.to_string(),
                        )
                    })?;
                content.verify(&lane_policy.ordering_ref)?;
                content.verify(&lane_policy.correlation_ref)?;
                if lane_policy.effect_phases.is_empty()
                    || lane_policy.effect_phases.iter().any(|phase| *phase > 3)
                    || lane_policy
                        .effect_phases
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                {
                    return Err(fail(
                        AdmissionCode::InvalidSchema,
                        "nonempty strictly sorted baseline effect phases",
                        "unknown, repeated, or missing phase",
                    ));
                }
                validate_visibility(&lane_policy.visibility, content)?;
                let exact = matches!(lane_policy.visibility, LaneVisibility::Exact);
                if exact != (binding.compatibility.operating_contract.mode == OperatingMode::Exact)
                {
                    return Err(fail(
                        AdmissionCode::VisibilityMismatch,
                        "lane visibility matches selected node operating contract",
                        "lane silently changes operating mode",
                    ));
                }
                if let LaneVisibility::Quantized {
                    quantum_ps,
                    phase_ps,
                    ..
                } = &lane_policy.visibility
                {
                    let matches_grid = operating_policies.get(&node.id).is_some_and(|policy| matches!(
                        policy,
                        crate::node_scheduling::ExecutionPolicy::Quantized { quantum_ps: selected_quantum, phase_ps: selected_phase, .. }
                            if quantum_ps == selected_quantum && phase_ps == selected_phase
                    ));
                    if !matches_grid {
                        return Err(fail(
                            AdmissionCode::VisibilityMismatch,
                            "quantized lane uses selected node window grid and phase",
                            "lane and operating-policy grids differ",
                        ));
                    }
                }
                if lane.maximum_payload_bytes.get() > content.limits.maximum_payload_bytes
                    || lane.maximum_pending_events.get() > content.limits.maximum_pending_events
                {
                    return Err(fail(
                        AdmissionCode::BoundMismatch,
                        "lane payload and event ceilings within host admission limits",
                        "lane exceeds finite host limits",
                    ));
                }
            }
            content.qualify(
                subject,
                QualificationClaim::Port {
                    node_id: &node.id,
                    binding_hash: &expected_hash,
                    port_id: &port.id,
                    policy_ref: &port.configuration_ref,
                },
            )?;
            policies.insert((node.id.clone(), port.id.clone()), policy);
        }
    }
    Ok(policies)
}

fn validate_visibility(
    visibility: &LaneVisibility,
    content: &mut VerifiedContent<'_>,
) -> Result<(), AdmissionError> {
    if let LaneVisibility::Quantized {
        quantum_ps,
        phase_ps,
        contract_ref,
    } = visibility
    {
        if quantum_ps.get() == 0 || phase_ps.get() >= quantum_ps.get() {
            return Err(refuse(
                AdmissionStage::Edges,
                AdmissionSubject::World,
                AdmissionCode::VisibilityMismatch,
                "positive quantized grid with phase smaller than quantum",
                "invalid quantized visibility grid",
            ));
        }
        content.verify(contract_ref)?;
    }
    Ok(())
}

fn endpoint<'a>(
    request: &'a AdmissionRequest<'_>,
    endpoint: &Endpoint,
) -> Result<(&'a NodeDescriptor, &'a PortDescriptor, &'a LaneDescriptor), AdmissionError> {
    let node = request
        .descriptors
        .binary_search_by(|node| node.id.cmp(&endpoint.node_id))
        .ok()
        .map(|index| &request.descriptors[index]);
    let port = node.and_then(|node| {
        node.ports
            .binary_search_by(|port| port.id.cmp(&endpoint.port_id))
            .ok()
            .map(|index| &node.ports[index])
    });
    let lane = port.and_then(|port| {
        port.lanes
            .binary_search_by(|lane| lane.id.cmp(&endpoint.lane_id))
            .ok()
            .map(|index| &port.lanes[index])
    });
    match (node, port, lane) {
        (Some(node), Some(port), Some(lane)) => Ok((node, port, lane)),
        _ => Err(refuse(
            AdmissionStage::Edges,
            AdmissionSubject::Node(endpoint.node_id.clone()),
            AdmissionCode::UnknownInterface,
            "declared node, port, and directed lane",
            "connection selects an undeclared endpoint",
        )),
    }
}

pub(super) fn validate_connections(
    request: &AdmissionRequest<'_>,
    ownership: &OwnershipPolicy,
    policies: &PortPolicies,
    world_hash: &HashRef,
    content: &mut VerifiedContent<'_>,
) -> Result<ConnectionSelections, AdmissionError> {
    let mut edges = Vec::new();
    let mut selected_policies = BTreeMap::new();
    let mut counts: BTreeMap<(Id, Id), (u64, u64)> = BTreeMap::new();
    let mut pending_bytes = 0u64;
    for connection in &request.world.connections {
        let subject = AdmissionSubject::Connection(connection.id.clone());
        let fail = |code, required, observed| {
            refuse(
                AdmissionStage::Edges,
                subject.clone(),
                code,
                required,
                observed,
            )
        };
        let (_, producer_port, producer_lane) = endpoint(request, &connection.producer)?;
        let (_, consumer_port, consumer_lane) = endpoint(request, &connection.consumer)?;
        let producer_policy = policies
            .get(&(
                connection.producer.node_id.clone(),
                producer_port.id.clone(),
            ))
            .ok_or_else(|| {
                fail(
                    AdmissionCode::UnknownInterface,
                    "resolved producer policy",
                    "missing producer policy",
                )
            })?;
        let consumer_policy = policies
            .get(&(
                connection.consumer.node_id.clone(),
                consumer_port.id.clone(),
            ))
            .ok_or_else(|| {
                fail(
                    AdmissionCode::UnknownInterface,
                    "resolved consumer policy",
                    "missing consumer policy",
                )
            })?;
        let producer_semantics = producer_policy
            .lanes
            .iter()
            .find(|lane| lane.lane_id == producer_lane.id)
            .ok_or_else(|| {
                fail(
                    AdmissionCode::UnknownInterface,
                    "selected producer lane policy",
                    "missing producer lane policy",
                )
            })?;
        let consumer_semantics = consumer_policy
            .lanes
            .iter()
            .find(|lane| lane.lane_id == consumer_lane.id)
            .ok_or_else(|| {
                fail(
                    AdmissionCode::UnknownInterface,
                    "selected consumer lane policy",
                    "missing consumer lane policy",
                )
            })?;
        if producer_lane.direction != Direction::Output
            || consumer_lane.direction != Direction::Input
        {
            return Err(fail(
                AdmissionCode::DirectionMismatch,
                "output lane connected to input lane",
                "lane direction differs",
            ));
        }
        if connection.interface_id != producer_port.interface_id
            || connection.interface_id != consumer_port.interface_id
            || connection.features != producer_port.features
            || connection.features != consumer_port.features
            || connection.payload_schema != producer_lane.payload_schema
            || connection.payload_schema != consumer_lane.payload_schema
        {
            return Err(fail(
                AdmissionCode::FeatureMismatch,
                "exact selected interface, feature set, and complete versioned payload schema",
                "endpoint or connection selection differs; no implicit subset or conversion",
            ));
        }
        if !connection.extensions.is_empty() || !connection.payload_schema.extensions.is_empty() {
            return Err(fail(
                AdmissionCode::UnknownInterface,
                "registered connection semantics",
                "unregistered extension",
            ));
        }
        if !same_ordering(producer_semantics, consumer_semantics) {
            return Err(fail(
                AdmissionCode::OrderingMismatch,
                "identical ordering, correlation, flow-control, and effect-phase contracts",
                "endpoint ordering or completion semantics differ",
            ));
        }
        let policy: ConnectionPolicy = content.policy(&connection.policy_ref)?;
        if policy.schema_version != 1 {
            return Err(fail(
                AdmissionCode::InvalidSchema,
                "supported connection policy edition",
                "unknown edition",
            ));
        }
        ordered_ids(
            policy.state_domain_ids.iter(),
            content.limits.maximum_state_objects,
        )?;
        let ConnectionDelivery::Fixed { latency_ps } = &policy.delivery;
        if *latency_ps < connection.minimum_latency_ps {
            return Err(fail(
                AdmissionCode::LookaheadUnproven,
                "actual selected delivery latency satisfies complete-path causal lower bound",
                "fixed delivery rule contradicts advertised minimum latency",
            ));
        }
        match &policy.visibility {
            VisibilityConversion::Direct
                if producer_semantics.visibility != consumer_semantics.visibility =>
            {
                return Err(fail(
                    AdmissionCode::VisibilityMismatch,
                    "identical direct visibility or explicitly accepted conversion",
                    "direct endpoint visibility differs",
                ));
            }
            VisibilityConversion::BoundarySampling { contract_ref }
            | VisibilityConversion::PublicationPreserving { contract_ref }
            | VisibilityConversion::Adapter { contract_ref } => {
                if matches!(
                    policy.visibility,
                    VisibilityConversion::BoundarySampling { .. }
                ) && !matches!(
                    consumer_semantics.visibility,
                    LaneVisibility::Quantized { .. }
                ) {
                    return Err(fail(
                        AdmissionCode::VisibilityMismatch,
                        "boundary sampling requires a quantized destination lane",
                        "destination lane is exact",
                    ));
                }
                if request
                    .requirements
                    .accepted_visibility_conversions
                    .binary_search(&connection.id)
                    .is_err()
                {
                    return Err(fail(
                        AdmissionCode::VisibilityMismatch,
                        "scenario acceptance of actual explicit visibility conversion",
                        "conversion unaccepted",
                    ));
                }
                content.verify(contract_ref)?;
            }
            VisibilityConversion::Direct => {}
        }
        let maximum_payload = policy.maximum_payload_bytes.get();
        let maximum_events = policy.maximum_pending_events.get();
        let maximum_bytes = policy.maximum_pending_bytes.get();
        let product = maximum_payload.checked_mul(maximum_events).ok_or_else(|| {
            fail(
                AdmissionCode::BoundMismatch,
                "representable payload capacity arithmetic",
                "queue size multiplication overflows",
            )
        })?;
        if maximum_payload > producer_lane.maximum_payload_bytes.get()
            || maximum_payload > consumer_lane.maximum_payload_bytes.get()
            || maximum_payload > content.limits.maximum_payload_bytes
            || maximum_events > producer_lane.maximum_pending_events.get()
            || maximum_events > consumer_lane.maximum_pending_events.get()
            || maximum_events > content.limits.maximum_pending_events
            || maximum_bytes > producer_semantics.maximum_pending_bytes.get()
            || maximum_bytes > consumer_semantics.maximum_pending_bytes.get()
            || maximum_bytes < maximum_payload
            || maximum_bytes > product
        {
            return Err(fail(
                AdmissionCode::BoundMismatch,
                "finite payload/event/byte reservation supported by both endpoints",
                "connection capacity exceeds endpoint support or is internally inconsistent",
            ));
        }
        pending_bytes = pending_bytes
            .checked_add(maximum_bytes)
            .filter(|bytes| *bytes <= content.limits.maximum_total_pending_bytes)
            .ok_or_else(|| {
                fail(
                    AdmissionCode::BoundMismatch,
                    "whole-world outstanding payload reservation within host ceiling",
                    "total pending byte ceiling exceeded",
                )
            })?;
        if policy.state_domain_ids.is_empty() {
            return Err(fail(
                AdmissionCode::OwnerConflict,
                "connection transfer and credit state owned by an explicit domain",
                "missing connection custody domain",
            ));
        }
        for domain_id in &policy.state_domain_ids {
            let domain = ownership
                .domains
                .iter()
                .find(|domain| &domain.id == domain_id)
                .ok_or_else(|| {
                    fail(
                        AdmissionCode::OwnerConflict,
                        "declared connection custody domain",
                        "missing connection state domain",
                    )
                })?;
            if domain.capture_owner_id != connection.capture_owner_id {
                return Err(fail(
                    AdmissionCode::OwnerConflict,
                    "connection domain captured by selected authoritative owner",
                    "foreign connection capture owner",
                ));
            }
        }
        content.verify(&policy.causal_proof_ref)?;
        content.qualify(
            subject.clone(),
            QualificationClaim::Connection {
                world_binding_hash: world_hash,
                connection_id: &connection.id,
                proof_ref: &policy.causal_proof_ref,
            },
        )?;
        let latency = producer_semantics
            .minimum_lookahead_ps
            .get()
            .checked_add(connection.minimum_latency_ps.get())
            .ok_or_else(|| {
                fail(
                    AdmissionCode::LookaheadUnproven,
                    "representable complete-path minimum latency",
                    "causal latency addition overflows",
                )
            })?;
        edges.push((
            connection.producer.node_id.clone(),
            connection.consumer.node_id.clone(),
            latency,
        ));

        let producer_count = counts
            .entry((
                connection.producer.node_id.clone(),
                producer_port.id.clone(),
            ))
            .or_default();
        producer_count.1 = producer_count.1.checked_add(1).ok_or_else(|| {
            fail(
                AdmissionCode::BoundMismatch,
                "representable consumer count",
                "count overflow",
            )
        })?;
        if producer_count.1 > producer_policy.maximum_consumers.get() {
            return Err(fail(
                AdmissionCode::BoundMismatch,
                "port consumer count within admitted arbitration limit",
                "too many consumers",
            ));
        }
        let consumer_count = counts
            .entry((
                connection.consumer.node_id.clone(),
                consumer_port.id.clone(),
            ))
            .or_default();
        consumer_count.0 = consumer_count.0.checked_add(1).ok_or_else(|| {
            fail(
                AdmissionCode::BoundMismatch,
                "representable producer count",
                "count overflow",
            )
        })?;
        if consumer_count.0 > consumer_policy.maximum_producers.get() {
            return Err(fail(
                AdmissionCode::BoundMismatch,
                "port producer count within admitted arbitration limit",
                "too many producers",
            ));
        }
        selected_policies.insert(connection.id.clone(), policy);
    }
    Ok(ConnectionSelections {
        edges,
        policies: selected_policies,
    })
}

fn same_ordering(producer: &LanePolicy, consumer: &LanePolicy) -> bool {
    producer.ordering_ref == consumer.ordering_ref
        && producer.correlation_ref == consumer.correlation_ref
        && producer.flow_control == consumer.flow_control
        && producer.effect_phases == consumer.effect_phases
}

pub(super) fn validate_input_roster(
    request: &AdmissionRequest<'_>,
    policies: &PortPolicies,
    external_inputs: &[Endpoint],
) -> Result<(), AdmissionError> {
    for endpoint_id in external_inputs {
        let (_, _, lane) = endpoint(request, endpoint_id)?;
        if lane.direction != Direction::Input {
            return Err(refuse(
                AdmissionStage::Graph,
                AdmissionSubject::Node(endpoint_id.node_id.clone()),
                AdmissionCode::DirectionMismatch,
                "external root source selects declared input lane",
                "external input selects output lane",
            ));
        }
    }
    for node in request.descriptors {
        for port in &node.ports {
            let internal = policies
                .get(&(node.id.clone(), port.id.clone()))
                .is_some_and(|policy| policy.internal);
            for lane in &port.lanes {
                if lane.direction == Direction::Input && !internal {
                    let selected = Endpoint {
                        node_id: node.id.clone(),
                        port_id: port.id.clone(),
                        lane_id: lane.id.clone(),
                    };
                    if !request
                        .world
                        .connections
                        .iter()
                        .any(|connection| connection.consumer == selected)
                        && !external_inputs.contains(&selected)
                    {
                        return Err(refuse(
                            AdmissionStage::Graph,
                            AdmissionSubject::Node(node.id.clone()),
                            AdmissionCode::LookaheadUnproven,
                            "every effective input has a declared causal source or admitted external root policy",
                            "unconnected input lane has unknown future production",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
