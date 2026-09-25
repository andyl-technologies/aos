//! Tests for deterministic route and forwarding fault behavior.

use super::*;
use crucible::model::{
    BindingActionCause, BindingActionKind, CountLimit, EFFECT_SEMANTIC_VERSION, EffectLifetime,
    EffectRequest, NetworkInFlightPolicy, PositiveU64, ResolvedFaultTarget, ResolvedMappingOutput,
};
use std::sync::Arc;

#[path = "route_tests/campaign_choices.rs"]
mod campaign_choices;
#[path = "route_tests/frame_effects.rs"]
mod frame_effects;
fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

fn positive(value: u64) -> PositiveU64 {
    PositiveU64::new("test", value)
        .unwrap_or_else(|error| panic!("test positive value should be valid: {error}"))
}

fn action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Up,
            queued_policy: NetworkInFlightPolicy::Preserve,
            in_flight_policy: NetworkInFlightPolicy::Preserve,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: id("network-test-binding"),
        target: ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Queue,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"mapped"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

#[test]
fn multicast_recipient_selection_is_shared_across_route_copies() {
    let action = action();
    let membership = id("multicast-members-v1");
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: membership.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::RecipientMembership {
                members: vec![
                    crucible::model::NetworkPolicyRecipient {
                        member: id("receiver-a"),
                        joined_sequence: 1,
                    },
                    crucible::model::NetworkPolicyRecipient {
                        member: id("receiver-b"),
                        joined_sequence: 2,
                    },
                ],
            },
        });
    let retain = crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 1)
        .unwrap_or_else(|error| panic!("recipient count: {error}"));
    let mut outcomes = Vec::new();
    for destination in [id("receiver-a"), id("receiver-b")] {
        let opportunity = FaultOpportunity::new(
            action.target.clone(),
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Deliver,
            FaultCoordinate {
                virtual_ticks: 10,
                retired_instructions: Some(1),
            },
            7,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination,
                producer_sequence: 7,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 64,
                payload_digest: ContentHash::from_bytes(b"multicast-frame"),
            },
        )
        .unwrap_or_else(|error| panic!("recipient opportunity: {error}"));
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_recipient_subset(
            &mut effects,
            &action,
            &opportunity,
            ContentHash::from_bytes(b"recipient-seed"),
            &topology,
            &membership,
            None,
            Some(&crucible::model::NetworkSelection::KeyedUniform),
            Some(&retain),
        )
        .unwrap_or_else(|error| panic!("recipient selection: {error}"));
        outcomes.push(effects.is_dropped());
    }

    assert_eq!(outcomes.iter().filter(|dropped| !**dropped).count(), 1);
}

fn opportunity(sequence: u64) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Queue,
        FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        },
        sequence,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: sequence,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(&[u8::try_from(sequence).unwrap_or(0)]),
        },
    )
    .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
}

fn action_with_network_effect(specification: NetworkEffectSpecification) -> ResolvedBindingAction {
    let mut action = action();
    let descriptor = specification.kind().descriptor();
    let lifetime = if descriptor.lifetimes.contains(&EffectLifetime::Opportunity) {
        EffectLifetime::Opportunity
    } else if descriptor.lifetimes.contains(&EffectLifetime::Impulse) {
        EffectLifetime::Impulse
    } else {
        descriptor.lifetimes[0]
    };
    action.kind = if lifetime == EffectLifetime::Persistent {
        BindingActionKind::UpsertPersistent
    } else {
        BindingActionKind::Apply
    };
    action.phase = descriptor.phases[0];
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            lifetime,
            EffectSpecification::Network(specification),
        )
        .unwrap_or_else(|error| panic!("test network effect: {error}")),
    );
    action
}

fn apply_frame_effect(
    specification: NetworkEffectSpecification,
    sequence: u64,
    payload: &mut Vec<u8>,
) -> crucible::ResolvedNetworkFrameEffects {
    apply_frame_effect_with_topology(
        specification,
        sequence,
        payload,
        &crucible::model::WorldFaultTopology::default(),
    )
}

fn apply_frame_effect_with_topology(
    specification: NetworkEffectSpecification,
    sequence: u64,
    payload: &mut Vec<u8>,
    topology: &crucible::model::WorldFaultTopology,
) -> crucible::ResolvedNetworkFrameEffects {
    let action = action_with_network_effect(specification);
    let opportunity = opportunity(sequence);
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_frame_action(
        payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"frame-effect-production-path"),
        topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("production frame effect application: {error}"));
    effects
}

#[test]
fn queue_policy_typed_effect_reserves_real_production_service() {
    let queue = action_with_network_effect(NetworkEffectSpecification::QueuePolicy {
        capacity_bytes: positive(64),
        capacity_frames: crucible::model::BoundedCount::new(CountLimit::QueueEntries, 4)
            .unwrap_or_else(|error| panic!("test queue frame capacity: {error}")),
        discipline: crucible::model::NetworkQueueDiscipline::Fifo,
        discipline_parameters: None,
        overflow: crucible::model::NetworkQueueOverflow::TailDrop,
        typed_error: None,
    });
    let mut payload = vec![0x42];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[queue],
        &opportunity(10),
        ContentHash::from_bytes(b"queue-policy-production-path"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
        &mut Vec::new(),
        Some(8),
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("production queue policy application: {error}"));

    assert_eq!(application.defer_until, Some(1_000_000_000));
    assert!(effects.serialization_is_accounted());
    let reservations = state
        .queues
        .values()
        .next()
        .map(|queue| queue.reservations.len());
    assert_eq!(reservations, Some(1));
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkQueuePolicy],
        "queue-policy-service-reservation",
        "typed-queue+release-coordinate+serialized-service",
    );
}

#[test]
fn service_curve_typed_effect_changes_real_production_service_time() {
    let segments = crucible::model::NetworkServiceSegments::new(vec![
        crucible::model::NetworkServiceSegment {
            at_nanos: 0,
            rate_bps: positive(8),
        },
        crucible::model::NetworkServiceSegment {
            at_nanos: 500_000_000,
            rate_bps: positive(16),
        },
    ])
    .unwrap_or_else(|error| panic!("test service-curve segments: {error}"));
    let service = action_with_network_effect(NetworkEffectSpecification::ServiceCurve { segments });
    let mut payload = vec![0x42];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[service],
        &opportunity(12),
        ContentHash::from_bytes(b"service-curve-production-path"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("production service-curve application: {error}"));

    assert_eq!(application.defer_until, Some(750_000_000));
    assert!(effects.serialization_is_accounted());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkServiceCurve],
        "piecewise-service-curve",
        "integrated-rate+release-coordinate",
    );
}

#[test]
fn burst_error_typed_effect_advances_retained_state_and_drops_frame() {
    let good = id("burst-good");
    let bad = id("burst-bad");
    let parameters = id("burst-error-parameters");
    let never = crucible::model::ProbabilityMillionths::new(0)
        .unwrap_or_else(|error| panic!("test zero probability: {error}"));
    let always = crucible::model::ProbabilityMillionths::new(1_000_000)
        .unwrap_or_else(|error| panic!("test certain probability: {error}"));
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: parameters.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ErrorStateTable {
                good: good.clone(),
                bad: bad.clone(),
                initial: good.clone(),
                states: vec![
                    crucible::model::NetworkPolicyErrorState {
                        state: good,
                        loss: never,
                        corruption: never,
                        corruption_transform: None,
                    },
                    crucible::model::NetworkPolicyErrorState {
                        state: bad,
                        loss: always,
                        corruption: never,
                        corruption_transform: None,
                    },
                ],
            },
        });
    let action = action_with_network_effect(NetworkEffectSpecification::BurstErrorState {
        good_to_bad: always,
        bad_to_good: never,
        state_parameters: parameters,
    });
    let mut payload = vec![0x42];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_burst_error(
        &mut payload,
        &mut effects,
        &mut state,
        &action,
        &opportunity(11),
        ContentHash::from_bytes(b"burst-error-production-path"),
        &topology,
        always,
        never,
        &id("burst-error-parameters"),
    )
    .unwrap_or_else(|error| panic!("production burst-error application: {error}"));

    assert!(effects.is_dropped());
    assert_eq!(state.burst_states.len(), 1);
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkBurstErrorState],
        "retained-burst-state-transition",
        "state-transition+frame-disposition",
    );
}

#[path = "route_tests/medium.rs"]
mod medium;
use medium::{
    medium_action, medium_opportunity, medium_policy, medium_topology, pending_medium_frame,
};

fn reservation(class: &str, sequence: u64, bytes: u64) -> NetworkQueueReservation {
    NetworkQueueReservation {
        enqueue_ticks: 0,
        base_ready_ticks: 0,
        ready_ticks: 0,
        service_start_ticks: 0,
        finish_ticks: 0,
        bytes,
        payload_bits: bytes * 8,
        remaining_tick_bits: u128::from(bytes) * 8 * 1_000_000_000,
        base_rate_bps: Some(1_000_000),
        service_curves: Vec::new(),
        class: Some(id(class)),
        opportunity: ContentHash::from_bytes(&sequence.to_be_bytes()),
    }
}

fn queue_parameters() -> crucible::model::NetworkPolicyQueueDiscipline {
    crucible::model::NetworkPolicyQueueDiscipline {
        classes: vec![
            crucible::model::NetworkPolicyQueueClass {
                class: id("high"),
                selector: id("high-selector"),
                priority: 0,
                weight: positive(3),
                quantum_bytes: positive(1_500),
            },
            crucible::model::NetworkPolicyQueueClass {
                class: id("low"),
                selector: id("low-selector"),
                priority: 10,
                weight: positive(1),
                quantum_bytes: positive(500),
            },
        ],
        red_minimum_bytes: None,
        red_maximum_bytes: None,
        red_maximum_probability: None,
        red_weight_numerator: None,
        red_weight_denominator: None,
    }
}

#[test]
fn service_curve_integrates_across_rate_changes() {
    let curves = vec![NetworkServiceCurveState {
        activation_ticks: 0,
        segments: vec![
            crucible::model::NetworkServiceSegment {
                at_nanos: 0,
                rate_bps: positive(8),
            },
            crucible::model::NetworkServiceSegment {
                at_nanos: 500_000_000,
                rate_bps: positive(16),
            },
        ],
    }];
    let finish = network_service_finish(0, 8, None, &curves, &action())
        .unwrap_or_else(|error| panic!("service integration should succeed: {error}"));
    assert_eq!(finish, 750_000_000);
}

#[test]
fn queue_reschedule_preserves_exact_partially_served_work() {
    let action = action();
    let mut queued = reservation("high", 1, 1);
    queued.base_rate_bps = Some(8);
    queued.service_start_ticks = 0;
    queued.finish_ticks = 1_000_000_000;
    let mut queue = NetworkQueueState {
        configuration: Some(NetworkQueueConfiguration {
            owner: NetworkEffectStateKey::from_action(&action),
            discipline: crucible::model::NetworkQueueDiscipline::Fifo,
            discipline_parameters: None,
        }),
        reservations: vec![queued],
        ..NetworkQueueState::default()
    };
    reschedule_network_queue(
        &mut queue,
        &mut [],
        &action,
        crucible::model::NetworkQueueDiscipline::Fifo,
        None,
        500_000_000,
        None,
    )
    .unwrap_or_else(|error| panic!("partial queue reschedule: {error}"));
    assert_eq!(queue.reservations[0].remaining_tick_bits, 4_000_000_000);
    assert_eq!(queue.reservations[0].service_start_ticks, 500_000_000);
    assert_eq!(queue.reservations[0].finish_ticks, 1_000_000_000);
}

#[test]
fn class_queue_comparators_use_priority_weight_and_quantum() {
    let parameters = queue_parameters();
    let high = reservation("high", 1, 1_500);
    let low = reservation("low", 2, 500);
    assert_eq!(
        compare_queue_candidates(
            &high,
            &low,
            crucible::model::NetworkQueueDiscipline::StrictPriority,
            Some(&parameters),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ),
        std::cmp::Ordering::Less
    );

    let projected_frames = BTreeMap::from([(id("high"), 3), (id("low"), 0)]);
    assert_eq!(
        compare_queue_candidates(
            &low,
            &high,
            crucible::model::NetworkQueueDiscipline::WeightedRoundRobin,
            Some(&parameters),
            &projected_frames,
            &BTreeMap::new(),
        ),
        std::cmp::Ordering::Less
    );

    let projected_bytes = BTreeMap::from([(id("high"), 4_500), (id("low"), 0)]);
    assert_eq!(
        compare_queue_candidates(
            &low,
            &high,
            crucible::model::NetworkQueueDiscipline::DeficitRoundRobin,
            Some(&parameters),
            &BTreeMap::new(),
            &projected_bytes,
        ),
        std::cmp::Ordering::Less
    );
}

#[path = "route_tests/custody.rs"]
mod custody;
use custody::{custody_action, custody_topology, opportunity_at};

#[path = "route_tests/production_conformance.rs"]
mod production_conformance;
#[path = "route_tests/resource_limits.rs"]
mod resource_limits;
