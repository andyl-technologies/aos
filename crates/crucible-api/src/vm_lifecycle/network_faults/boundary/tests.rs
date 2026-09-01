//! Boundary-network state and canonical evidence tests.

use std::sync::Arc;

use super::*;
use crucible::model::{
    BindingActionCause, EffectLifetime, EffectRequest, NetworkEffectSpecification,
    OpportunityPayload, ResolvedMappingOutput,
};

fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

fn positive(value: u64) -> crucible::model::PositiveU64 {
    crucible::model::PositiveU64::new("test", value)
        .unwrap_or_else(|error| panic!("test duration should be valid: {error}"))
}

fn bounded(value: u32) -> crucible::model::BoundedCount {
    crucible::model::BoundedCount::new(crucible::model::CountLimit::QueueEntries, value)
        .unwrap_or_else(|error| panic!("test bound should be valid: {error}"))
}

fn target() -> crucible::model::ResolvedFaultTarget {
    crucible::model::ResolvedFaultTarget::NetworkSegment {
        segment: id("segment-a"),
        direction: crucible::model::FaultDirection::AToB,
    }
}

fn flap_action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Network(NetworkEffectSpecification::Flap {
            down_nanos: positive(10),
            training_nanos: positive(20),
            recovery_nanos: positive(30),
        }),
    )
    .unwrap_or_else(|error| panic!("test flap should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("flap-binding"),
        target: target(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"flap-mapping"),
        transition_sequence: 7,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 100,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn negotiated_mode_action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Network(NetworkEffectSpecification::NegotiatedMode {
            rate_bps: positive(123),
            duplex: crucible::model::NetworkDuplex::Half,
            lanes: crucible::model::BoundedCount::new(crucible::model::CountLimit::LanesOrVcpus, 2)
                .unwrap_or_else(|error| panic!("test negotiated lanes: {error}")),
            fec: crucible::model::NetworkFecMode::Ldpc,
            training_nanos: positive(25),
        }),
    )
    .unwrap_or_else(|error| panic!("test negotiated mode should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("negotiated-mode-binding"),
        target: target(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"negotiated-mode-mapping"),
        transition_sequence: 8,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 100,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn forwarder_topology() -> crucible::model::WorldFaultTopology {
    crucible::model::WorldFaultTopology {
        network_forwarders: vec![crucible::model::WorldNetworkForwarder {
            id: crucible::model::SignalId::parse("forwarder-a")
                .unwrap_or_else(|error| panic!("test forwarder ID: {error}")),
            kind: crucible::model::WorldNetworkForwarderKind::Router,
            ports: Vec::new(),
            table_capacity: 128,
            fault_domains: Vec::new(),
        }],
        network_queues: vec![crucible::model::WorldNetworkQueue {
            id: crucible::model::SignalId::parse("forwarder-a-egress")
                .unwrap_or_else(|error| panic!("test queue ID: {error}")),
            owner: crucible::model::SignalId::parse("forwarder-a")
                .unwrap_or_else(|error| panic!("test owner ID: {error}")),
            capacity_packets: 64,
            capacity_bytes: 65_536,
            discipline: crucible::model::WorldNetworkQueueDiscipline::Fifo,
            overflow: crucible::model::WorldNetworkQueueOverflow::DropTail,
            fault_domains: Vec::new(),
        }],
        ..crucible::model::WorldFaultTopology::default()
    }
}

fn forwarder_action(
    queue_policy: crucible::model::NetworkStatePolicy,
    table_policy: crucible::model::NetworkStatePolicy,
) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition: crucible::model::NetworkForwarderTransition::PowerLoss,
            downtime_nanos: positive(10),
            queue_policy,
            table_policy,
        }),
    )
    .unwrap_or_else(|error| panic!("test lifecycle should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("forwarder-lifecycle"),
        target: crucible::model::ResolvedFaultTarget::NetworkForwarder {
            forwarder: id("forwarder-a"),
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"forwarder-lifecycle"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 100,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn association_action(policy: FaultObjectId, scores: [i64; 2]) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Network(NetworkEffectSpecification::Association {
            policy: policy.clone(),
        }),
    )
    .unwrap_or_else(|error| panic!("test association should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: id("association-binding"),
        target: crucible::model::ResolvedFaultTarget::NetworkAttachment {
            endpoint: id("vm-a"),
            interface: id("interface-a"),
            attachment: id("attachment-a"),
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::ServiceProfile {
            service_profile: policy,
            input_contracts: Vec::new(),
            inputs: scores
                .into_iter()
                .map(crucible::model::SignalValue::I64)
                .collect(),
        }),
        mapped_digest: ContentHash::from_bytes(b"association-mapping"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn association_topology(policy: FaultObjectId) -> crucible::model::WorldFaultTopology {
    let score = |candidate: &str| crucible::model::NetworkPolicyAssociationCandidate {
        candidate: id(candidate),
        score: crucible::model::NetworkPolicyIntegerTable {
            input_unit: id("quality"),
            output_unit: id("score"),
            interpolation: crucible::model::NetworkPolicyInterpolation::LinearTiesToEven,
            outside: crucible::model::NetworkPolicyOutsideRange::Clamp,
            points: vec![
                crucible::model::NetworkPolicyIntegerPoint {
                    input: -1_000,
                    output: -1_000,
                },
                crucible::model::NetworkPolicyIntegerPoint {
                    input: 1_000,
                    output: 1_000,
                },
            ],
        },
    };
    crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![crucible::model::WorldNetworkPolicyArtifact {
            id: policy,
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::Association(
                crucible::model::NetworkPolicyAssociation {
                    hysteresis: 5,
                    time_to_trigger_nanos: 10,
                    scan_interval_nanos: positive(2),
                    authentication_nanos: 2,
                    interruption_nanos: 3,
                    preserve_queued: false,
                    preserve_address: false,
                    candidates: vec![score("segment-a"), score("segment-b")],
                },
            ),
        }],
        ..crucible::model::WorldFaultTopology::default()
    }
}

fn control_service_action() -> ResolvedBindingAction {
    control_service_action_with("control-service-binding", 1, "control-overflow")
}

fn control_service_action_with(
    binding: &str,
    queue_bound: u32,
    overflow_policy: &str,
) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::ControlPlaneService {
            service_curve: id("control-service"),
            queue_bound: bounded(queue_bound),
            overflow_policy: id(overflow_policy),
            event_work_bits: positive(10),
        }),
    )
    .unwrap_or_else(|error| panic!("test control service should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: id(binding),
        target: crucible::model::ResolvedFaultTarget::NetworkPath {
            path_version: id("route-a"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"control-service"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn route_transition_action(binding: &str, new_route: &str) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Network(NetworkEffectSpecification::RouteTransition {
            old_route: id("route-a"),
            new_route: id(new_route),
            convergence_events: id("route-convergence"),
            in_flight_policy: crucible::model::NetworkInFlightPolicy::Preserve,
        }),
    )
    .unwrap_or_else(|error| panic!("test route transition should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id(binding),
        target: crucible::model::ResolvedFaultTarget::NetworkPath {
            path_version: id("route-a"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(new_route.as_bytes()),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn control_topology() -> crucible::model::WorldFaultTopology {
    crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("control-overflow"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                    disposition: crucible::model::NetworkPolicyOverflow::DropNewest,
                    timeout_nanos: None,
                    typed_error: None,
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("control-service"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ServiceCurve {
                    segments: crucible::model::NetworkServiceSegments::new(vec![
                        crucible::model::NetworkServiceSegment {
                            at_nanos: 0,
                            rate_bps: positive(1_000_000_000),
                        },
                    ])
                    .unwrap_or_else(|error| panic!("test service curve: {error}")),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("route-convergence"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::StateMachine {
                    initial: id("pending"),
                    states: vec![id("pending"), id("ready")],
                    transitions: vec![crucible::model::NetworkPolicyTransition {
                        from: id("pending"),
                        event: id("converge"),
                        to: id("ready"),
                        delay_nanos: 0,
                        traffic_policy: crucible::model::NetworkInFlightPolicy::Preserve,
                    }],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("route-replacement-result"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: id("network-route-id-v1"),
                    bytes: b"route-c".to_vec(),
                },
            },
        ],
        network_paths: vec![crucible::model::WorldNetworkPath {
            id: crucible::model::SignalId::parse("route-c")
                .unwrap_or_else(|error| panic!("test route ID: {error}")),
            direction: crucible::model::FaultDirection::AToB,
            hops: Vec::new(),
            mtu_bytes: 1_500,
        }],
        ..crucible::model::WorldFaultTopology::default()
    }
}

fn route_replacement_action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        crucible::model::EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
            technology: id("network-routing-v1"),
            operations: crucible::model::OperationSet::new(vec![
                crucible::model::FaultOperation::NetworkRoute,
            ])
            .unwrap_or_else(|error| panic!("test operation set: {error}")),
            kind: crucible::model::NetworkControlResultKind::Replace,
            result: Some(id("route-replacement-result")),
        }),
    )
    .unwrap_or_else(|error| panic!("test control transform should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("route-transform"),
        target: route_transition_action("ignored", "route-b").target,
        phase: FaultPhase::Resolve,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"route-transform"),
        transition_sequence: 1,
        opportunity: Some(ContentHash::from_bytes(b"control-opportunity")),
        coordinate: FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        },
        cause: BindingActionCause::Opportunity {
            identity: ContentHash::from_bytes(b"control-opportunity"),
            payload: OpportunityPayload::NetworkControl {
                technology: id("ethernet"),
                event_sequence: 1,
                request_digest: ContentHash::from_bytes(b"request"),
                result_schema: id("route-result"),
                result_digest: ContentHash::from_bytes(b"result"),
            },
        },
        expected_precondition: None,
    }
}

#[path = "control_service_tests.rs"]
mod control_service_tests;
#[path = "control_state_tests.rs"]
mod control_state_tests;
