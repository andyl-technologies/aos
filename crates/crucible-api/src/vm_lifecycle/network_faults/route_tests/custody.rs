//! Contact-plan custody routing and capacity tests.

use super::*;

pub(super) fn custody_topology(
    disposition: crucible::model::NetworkPolicyOverflow,
    contact_start: u64,
) -> crucible::model::WorldFaultTopology {
    let timeout_nanos =
        (disposition == crucible::model::NetworkPolicyOverflow::Timeout).then_some(positive(25));
    let typed_error = (disposition == crucible::model::NetworkPolicyOverflow::TypedError)
        .then_some(id("custody-reject"));
    let mut artifacts = vec![
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("contact-capacity"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ServiceCurve {
                segments: crucible::model::NetworkServiceSegments::new(vec![
                    crucible::model::NetworkServiceSegment {
                        at_nanos: 0,
                        rate_bps: positive(8_000_000_000),
                    },
                ])
                .unwrap_or_else(|error| panic!("contact service curve: {error}")),
            },
        },
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("contact-plan"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                intervals: vec![crucible::model::NetworkPolicyContactInterval {
                    contact: id("contact-a"),
                    service_resource: id("resource-a"),
                    route_cost: positive(1),
                    routing_propagation_nanos: 1,
                    start_nanos: contact_start,
                    end_nanos: contact_start + 100,
                    source: id("sender"),
                    destination: id("receiver"),
                    beam: id("beam-a"),
                    gateway: id("gateway-a"),
                    minimum_range_mm: 1,
                    maximum_range_mm: 2,
                    capacity_profile: id("contact-capacity"),
                    acquisition_nanos: 10,
                    teardown_nanos: 10,
                    confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
                        .unwrap_or_else(|error| panic!("contact confidence: {error}")),
                    provenance: id("contact-test"),
                }],
            },
        },
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("custody-policy"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
                typed_error,
            },
        },
    ];
    if disposition == crucible::model::NetworkPolicyOverflow::TypedError {
        artifacts.push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("custody-reject"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::TypedResponse(
                crucible::model::NetworkPolicyTypedResponseSet {
                    responses: vec![crucible::model::NetworkPolicyTypedResponse {
                        response: crucible::model::NetworkPolicyTypedResponseKind::TcpReset,
                        headers: crucible::model::NetworkPolicyResponseHeaders {
                            source_mac: None,
                            source_ipv4: None,
                            source_ipv6: None,
                            hop_limit: 64,
                            ipv4_identification: 1,
                            delay_nanos: None,
                        },
                    }],
                    unmatched: crucible::model::NetworkPolicyUnmatchedResponse::Suppress,
                },
            ),
        });
    }
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    crucible::model::WorldFaultTopology {
        network_policy_artifacts: artifacts,
        ..crucible::model::WorldFaultTopology::default()
    }
}

pub(super) fn custody_action() -> ResolvedBindingAction {
    action_with_network_effect(NetworkEffectSpecification::CustodyQueue {
        capacity_bytes: positive(1),
        capacity_bundles: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
            .unwrap_or_else(|error| panic!("custody bundle capacity: {error}")),
        expiry_nanos: positive(1_000),
        custody_policy: id("custody-policy"),
        route_contact_plan: id("contact-plan"),
        priority: crucible::model::NetworkBundlePriority::Normal,
        max_visited_hops: crucible::model::BoundedCount::new(
            CountLimit::DuplicatesOrInstructionReplay,
            8,
        )
        .unwrap_or_else(|error| panic!("custody hop bound: {error}")),
    })
}

pub(super) fn opportunity_at(sequence: u64, now: u64) -> FaultOpportunity {
    let mut opportunity = opportunity(sequence);
    opportunity = FaultOpportunity::new(
        opportunity.target().clone(),
        opportunity.operation(),
        opportunity.phase(),
        FaultCoordinate {
            virtual_nanos: now,
            retired_instructions: None,
        },
        sequence,
        opportunity.direction(),
        opportunity.payload().clone(),
    )
    .unwrap_or_else(|error| panic!("coordinate-adjusted opportunity: {error}"));
    opportunity
}

fn pending_custody_frame(
    opportunity: &FaultOpportunity,
    release_nanos: u64,
) -> crucible::BackendNetworkOutput {
    let mut continuation = crucible::BackendNetworkFaultContinuation::default();
    continuation
        .cursor_mut()
        .defer_until(release_nanos, opportunity.id());
    let sequence = match opportunity.payload() {
        OpportunityPayload::NetworkFrame {
            producer_sequence, ..
        } => *producer_sequence,
        _ => panic!("test custody opportunity must be a frame"),
    };
    crucible::BackendNetworkOutput {
        source: crucible::NodeId {
            name: String::from("sender"),
        },
        destination: crucible::NodeId {
            name: String::from("logical-router"),
        },
        emit_icount: crucible::Icount { retired: 0 },
        sequence,
        payload: vec![u8::try_from(sequence).unwrap_or(0)],
        route: Some(crucible::BackendNetworkRoute {
            link: crucible::LinkId::from_name("custody-test-link"),
            direction: crucible::device::NetworkLinkDirection::EndpointAToEndpointB,
            destination: crucible::NodeId {
                name: String::from("receiver"),
            },
        }),
        fault_continuation: continuation,
    }
}

#[test]
fn custody_waits_for_contact_then_conserves_shared_capacity() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut pending = Vec::new();
    let mut typed_response = None;
    let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
    let waiting = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 0),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("queue before contact: {error}"));
    assert_eq!(waiting.defer_until, Some(110));
    assert!(waiting.repeat_phase_on_resume);

    let service = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("reserve at contact: {error}"));
    assert_eq!(service.defer_until, Some(112));
    assert_eq!(first_effects.additional_delay_nanos(), 0);
    assert_eq!(first_effects.accounted_contact_services().len(), 1);
    let released = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 112),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("release after propagation: {error}"));
    assert_eq!(released.defer_until, None);

    let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
    let second = apply_network_custody_queue(
        &[2],
        &mut second_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(2, 112),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("second contact reservation: {error}"));
    assert_eq!(second.defer_until, Some(114));
    apply_network_custody_queue(
        &[2],
        &mut second_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(2, 114),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("second contact release: {error}"));
    assert_eq!(second_effects.additional_delay_nanos(), 0);
    let queue = state
        .custody_queues
        .get(&NetworkEffectStateKey::from_action(&action))
        .unwrap_or_else(|| panic!("custody queue state"));
    assert_eq!(queue.released_bundles, 2);
    assert!(queue.reservations.is_empty());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkCustodyQueue],
        "custody-contact-capacity",
        "queue+contact-reservation+release-ledger",
    );
}

#[test]
fn custody_selects_and_reserves_a_bounded_multihop_contact_route() {
    let mut topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let plan = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &mut plan.artifact
    else {
        panic!("contact plan type")
    };
    let mut first = intervals[0].clone();
    first.contact = id("contact-a-relay");
    first.service_resource = id("radio-a-relay");
    first.destination = id("relay");
    first.route_cost = positive(1);
    let mut second = intervals[0].clone();
    second.contact = id("contact-b-receiver");
    second.service_resource = id("radio-b-receiver");
    second.start_nanos = 120;
    second.end_nanos = 220;
    second.source = id("relay");
    second.route_cost = positive(1);
    let mut direct = intervals[0].clone();
    direct.contact = id("contact-c-direct");
    direct.service_resource = id("radio-c-direct");
    direct.route_cost = positive(10);
    *intervals = vec![first, direct, second];

    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
    let reserved = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 0),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("reserve multihop route: {error}"));
    assert_eq!(reserved.defer_until, Some(110));
    assert!(effects.accounted_contact_services().is_empty());
    assert!(state.contact_services.is_empty());
    let reserved = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("commit multihop route: {error}"));
    assert_eq!(reserved.defer_until, Some(132));
    assert_eq!(effects.accounted_contact_services().len(), 2);
    let queue = state
        .custody_queues
        .get(&NetworkEffectStateKey::from_action(&action))
        .unwrap_or_else(|| panic!("custody queue"));
    assert_eq!(
        queue.reservations[0].contact_path,
        vec![id("contact-a-relay"), id("contact-b-receiver")]
    );
    assert_eq!(state.contact_services.len(), 2);

    let contact = action_with_network_effect(NetworkEffectSpecification::Contact {
        intervals: id("contact-plan"),
        range_delay_lookup: id("direct-range-delay"),
        beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
            .unwrap_or_else(|error| panic!("contact beams: {error}")),
        gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
            .unwrap_or_else(|error| panic!("contact gateways: {error}")),
    });
    apply_network_frame_action(
        &mut vec![1],
        &mut effects,
        &contact,
        &opportunity_at(1, 132),
        ContentHash::from_bytes(b"multihop-contact-composition"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("compose multihop custody with contact: {error}"));
    assert!(!effects.is_dropped());
    assert_eq!(effects.additional_delay_nanos(), 0);
    assert_eq!(state.contact_services.len(), 2);
}

#[test]
fn custody_checkpoint_rejects_broken_contact_graph_joins() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = custody_action();
    let owner = NetworkEffectStateKey::from_action(&action);
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
    let first = opportunity_at(1, 0);
    let waiting = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &first,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("stage custody route: {error}"));
    let service_opportunity = opportunity_at(
        1,
        waiting
            .defer_until
            .unwrap_or_else(|| panic!("custody route must wait for contact")),
    );
    let mut planned_pending = vec![pending_custody_frame(
        &first,
        service_opportunity.coordinate().virtual_nanos,
    )];
    planned_pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            service_opportunity.coordinate().virtual_nanos,
            first.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    validate_custody_contact_topology(&state, &planned_pending, &topology)
        .unwrap_or_else(|error| panic!("valid planned custody checkpoint: {error}"));
    let mut planned_extra = planned_pending.clone();
    let mut planned_effects = crucible::ResolvedNetworkFrameEffects::default();
    planned_effects
        .mark_contact_service_accounted([0x6b; 32])
        .unwrap_or_else(|error| panic!("planned extra contact: {error}"));
    planned_extra[0]
        .fault_continuation
        .set_resolved_frame_effects(planned_effects);
    assert!(validate_custody_contact_topology(&state, &planned_extra, &topology).is_err());
    let committed = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &service_opportunity,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("commit custody route: {error}"));
    let release = committed
        .defer_until
        .unwrap_or_else(|| panic!("committed custody route must have a release"));
    let mut pending = vec![pending_custody_frame(&service_opportunity, release)];
    pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    pending[0]
        .fault_continuation
        .set_resolved_frame_effects(effects);
    validate_custody_contact_topology(&state, &pending, &topology)
        .unwrap_or_else(|error| panic!("valid custody checkpoint join: {error}"));

    let mut mismatched_output = pending.clone();
    mismatched_output[0].payload.push(2);
    assert!(validate_custody_contact_topology(&state, &mismatched_output, &topology).is_err());

    let mut mismatched_priority = state.clone();
    mismatched_priority
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .bundle
        .priority = crucible::model::NetworkBundlePriority::Bulk;
    assert!(validate_custody_contact_topology(&mismatched_priority, &pending, &topology).is_err());

    let mut mismatched_bytes = state.clone();
    mismatched_bytes
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"))
        .reservations[0]
        .bytes = 2;
    assert!(validate_custody_contact_topology(&mismatched_bytes, &pending, &topology).is_err());

    let mut orphaned_ledger = state.clone();
    orphaned_ledger
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"))
        .reservations[0]
        .custody_owner = Some(NetworkEffectStateKey {
        binding: id("missing-custody-binding"),
        target: action.target.clone(),
        effect: crucible::model::EffectKind::NetworkCustodyQueue,
    });
    assert!(validate_custody_contact_topology(&orphaned_ledger, &pending, &topology).is_err());

    let mut overlapping_ledger = state.clone();
    let service = overlapping_ledger
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"));
    let mut duplicate = service.reservations[0].clone();
    duplicate.opportunity = ContentHash::from_bytes(b"overlapping-contact-reservation");
    service.served_bundles += 1;
    service.served_bytes += duplicate.bytes;
    service.reservations.push(duplicate);
    service.reservations.sort_by(|left, right| {
        (left.start_nanos, left.finish_nanos, left.opportunity).cmp(&(
            right.start_nanos,
            right.finish_nanos,
            right.opportunity,
        ))
    });
    assert!(
        validate_network_adapter_checkpoint(
            &NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                journal_sequence: 1,
                observations:
                    super::super::storage_faults::ProductionFaultObservationJournal::default(),
                effect_state: overlapping_ledger,
            },
            FaultResourceLimits::default()
        )
        .is_err()
    );

    let mut mismatched_expiry = state.clone();
    mismatched_expiry
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .expiry_nanos += 1;
    assert!(
        validate_network_adapter_checkpoint(
            &NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                journal_sequence: 1,
                observations:
                    super::super::storage_faults::ProductionFaultObservationJournal::default(),
                effect_state: mismatched_expiry,
            },
            FaultResourceLimits::default()
        )
        .is_err()
    );

    let mut over_byte_capacity = state.clone();
    let reservation = &mut over_byte_capacity
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.bytes = 2;
    reservation.bundle.length_bytes = 2;
    assert!(
        validate_network_adapter_checkpoint(
            &NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                journal_sequence: 1,
                observations:
                    super::super::storage_faults::ProductionFaultObservationJournal::default(),
                effect_state: over_byte_capacity,
            },
            FaultResourceLimits::default()
        )
        .is_err()
    );

    let mut over_bundle_capacity = state.clone();
    let queue = over_bundle_capacity
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"));
    let mut second = queue.reservations[0].clone();
    second.bundle.producer_sequence = 2;
    second.bundle.payload_digest = ContentHash::from_bytes(&[2]);
    second.opportunity = ContentHash::from_bytes(b"second-capacity-bundle");
    second.enqueue_nanos = 1;
    second.expiry_nanos = 1_001;
    queue.reservations.push(second);
    queue.reservations.sort_by(|left, right| {
        (
            left.bundle.priority.rank(),
            left.enqueue_nanos,
            &left.bundle,
        )
            .cmp(&(
                right.bundle.priority.rank(),
                right.enqueue_nanos,
                &right.bundle,
            ))
    });
    assert!(
        validate_network_adapter_checkpoint(
            &NetworkAdapterCheckpoint {
                semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
                coordinate: Some(release),
                coordinate_sequence: 0,
                journal_sequence: 1,
                observations:
                    super::super::storage_faults::ProductionFaultObservationJournal::default(),
                effect_state: over_bundle_capacity,
            },
            FaultResourceLimits::default()
        )
        .is_err()
    );

    let mut missing_contact = state.clone();
    missing_contact
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .contact_path[0] = id("missing-contact");
    assert!(validate_custody_contact_topology(&missing_contact, &pending, &topology).is_err());

    let mut missing_frame_accounting = pending.clone();
    let mut stripped_effects = missing_frame_accounting[0]
        .fault_continuation
        .resolved_frame_effects()
        .clone();
    stripped_effects.require_serialization();
    missing_frame_accounting[0]
        .fault_continuation
        .set_resolved_frame_effects(stripped_effects);
    assert!(
        validate_custody_contact_topology(&state, &missing_frame_accounting, &topology,).is_err()
    );

    let mut extra_frame_accounting = pending.clone();
    let mut extra_effects = extra_frame_accounting[0]
        .fault_continuation
        .resolved_frame_effects()
        .clone();
    extra_effects
        .mark_contact_service_accounted([0x5a; 32])
        .unwrap_or_else(|error| panic!("extra contact accounting: {error}"));
    extra_frame_accounting[0]
        .fault_continuation
        .set_resolved_frame_effects(extra_effects);
    assert!(
        validate_custody_contact_topology(&state, &extra_frame_accounting, &topology,).is_err()
    );

    let mut missing_priority = pending.clone();
    missing_priority[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            None,
        );
    assert!(validate_custody_contact_topology(&state, &missing_priority, &topology).is_err());

    let mut mismatched_cursor = pending.clone();
    mismatched_cursor[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release + 1,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    assert!(validate_custody_contact_topology(&state, &mismatched_cursor, &topology).is_err());

    let mut mismatched_release = state.clone();
    let reservation = &mut mismatched_release
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.release_nanos = reservation.release_nanos.saturating_add(1);
    assert!(validate_custody_contact_topology(&mismatched_release, &pending, &topology,).is_err());

    let mut service_before_enqueue = state.clone();
    let reservation = &mut service_before_enqueue
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.enqueue_nanos = 111;
    reservation.expiry_nanos = 1_111;
    assert!(
        validate_custody_contact_topology(&service_before_enqueue, &pending, &topology).is_err()
    );
}

#[path = "custody/edge_cases.rs"]
mod edge_cases;
