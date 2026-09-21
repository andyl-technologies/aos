//! Custody settlement, expiry, overflow, and resume edge cases.

use super::*;

#[test]
fn completed_contact_ledgers_fold_into_the_settled_cursor() {
    let key = NetworkContactServiceKey {
        plan: id("contact-plan"),
        contact: id("contact-a"),
        service_resource: id("resource-a"),
        source: id("sender"),
        destination: id("receiver"),
        start_nanos: 100,
        end_nanos: 200,
    };
    let mut state = NetworkEffectRuntimeState::default();
    state.contact_services.insert(
        key,
        NetworkContactServiceState {
            settled_cursor_nanos: 100,
            service_cursor_nanos: 112,
            served_bundles: 1,
            served_bytes: 1,
            reservations: vec![NetworkContactServiceReservation {
                custody_owner: None,
                opportunity: ContentHash::from_bytes(b"settled-contact"),
                start_nanos: 110,
                finish_nanos: 112,
                arrival_nanos: 112,
                bytes: 1,
            }],
        },
    );

    prune_network_contact_services(&mut state, 112);
    let service = state
        .contact_services
        .values()
        .next()
        .unwrap_or_else(|| panic!("contact service"));
    assert!(service.reservations.is_empty());
    assert_eq!(service.settled_cursor_nanos, 112);
    assert_eq!(service.service_cursor_nanos, 112);
    assert_eq!(service.served_bundles, 1);
    assert_eq!(service.served_bytes, 1);
}

#[test]
fn direct_contact_counter_overflow_fails_before_mutation() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let plan = topology
        .network_policy_artifact(&id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
    else {
        panic!("contact plan type")
    };
    let interval = intervals[0].clone();
    let action = custody_action();
    for (served_bundles, served_bytes) in [(u64::MAX, 0), (0, u64::MAX)] {
        let key = NetworkContactServiceKey {
            plan: id("contact-plan"),
            contact: interval.contact.clone(),
            service_resource: interval.service_resource.clone(),
            source: interval.source.clone(),
            destination: interval.destination.clone(),
            start_nanos: interval.start_nanos,
            end_nanos: interval.end_nanos,
        };
        let mut state = NetworkEffectRuntimeState::default();
        state.contact_services.insert(
            key.clone(),
            NetworkContactServiceState {
                settled_cursor_nanos: 100,
                service_cursor_nanos: 100,
                served_bundles,
                served_bytes,
                reservations: Vec::new(),
            },
        );
        let error = match reserve_network_contact_service(
            &mut state,
            &topology,
            &id("contact-plan"),
            &interval,
            &id("sender"),
            &id("receiver"),
            110,
            1,
            ContentHash::from_bytes(b"overflow-direct-contact"),
            &action,
            FaultResourceLimits::default(),
        ) {
            Ok(_) => panic!("direct contact counter overflow must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("before direct reservation"));
        let service = state
            .contact_services
            .get(&key)
            .unwrap_or_else(|| panic!("contact service"));
        assert_eq!(service.service_cursor_nanos, 100);
        assert_eq!(service.served_bundles, served_bundles);
        assert_eq!(service.served_bytes, served_bytes);
        assert!(service.reservations.is_empty());
    }
}

#[test]
fn custody_accounting_skips_direct_contact_propagation_and_revalidation() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = action_with_network_effect(NetworkEffectSpecification::Contact {
        intervals: id("contact-plan"),
        range_delay_lookup: id("direct-range-delay"),
        beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
            .unwrap_or_else(|error| panic!("contact beams: {error}")),
        gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
            .unwrap_or_else(|error| panic!("contact gateways: {error}")),
    });
    let key = NetworkContactServiceKey {
        plan: id("contact-plan"),
        contact: id("contact-a"),
        service_resource: id("resource-a"),
        source: id("sender"),
        destination: id("receiver"),
        start_nanos: 100,
        end_nanos: 200,
    };
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    effects
        .mark_contact_service_accounted(network_contact_service_identity(&key))
        .unwrap_or_else(|error| panic!("account custody contact: {error}"));

    apply_network_frame_action(
        &mut vec![1],
        &mut effects,
        &action,
        &opportunity_at(1, 250),
        ContentHash::from_bytes(b"accounted-contact"),
        &topology,
        &mut NetworkEffectRuntimeState::default(),
    )
    .unwrap_or_else(|error| panic!("skip direct contact after custody: {error}"));
    assert!(!effects.is_dropped());
    assert_eq!(effects.additional_delay_nanos(), 0);
}

#[test]
fn custody_priority_arbitrates_equal_contact_release_coordinates() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let bulk = custody_action();
    let mut critical = custody_action();
    critical.binding = id("critical-custody-binding");
    let mut state = NetworkEffectRuntimeState::default();
    let mut response = None;
    let mut bulk_effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut critical_effects = crucible::ResolvedNetworkFrameEffects::default();
    for (sequence, action, priority, effects) in [
        (
            1,
            &bulk,
            crucible::model::NetworkBundlePriority::Bulk,
            &mut bulk_effects,
        ),
        (
            2,
            &critical,
            crucible::model::NetworkBundlePriority::Critical,
            &mut critical_effects,
        ),
    ] {
        let waiting = apply_network_custody_queue(
            &[u8::try_from(sequence).unwrap_or(0)],
            effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            action,
            &opportunity_at(sequence, 0),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            priority,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("stage priority bundle: {error}"));
        assert_eq!(waiting.defer_until, Some(110));
    }
    let critical_service = apply_network_custody_queue(
        &[2],
        &mut critical_effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &critical,
        &opportunity_at(2, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Critical,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("serve critical bundle: {error}"));
    let bulk_service = apply_network_custody_queue(
        &[1],
        &mut bulk_effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &bulk,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Bulk,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("serve bulk bundle: {error}"));
    assert_eq!(critical_service.defer_until, Some(112));
    assert_eq!(bulk_service.defer_until, Some(113));
}

#[test]
fn custody_expiry_precedes_an_unreachable_future_contact() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 2_000);
    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut typed_response = None;
    let waiting = apply_network_custody_queue(
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
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("queue until expiry: {error}"));
    assert_eq!(waiting.defer_until, Some(1_000));
    apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 1_000),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("expire custody bundle: {error}"));
    assert!(effects.is_dropped());
}

#[test]
fn custody_overflow_executes_every_closed_disposition() {
    for disposition in [
        crucible::model::NetworkPolicyOverflow::DropNewest,
        crucible::model::NetworkPolicyOverflow::DropOldest,
        crucible::model::NetworkPolicyOverflow::TypedError,
        crucible::model::NetworkPolicyOverflow::Timeout,
    ] {
        let topology = custody_topology(disposition, 500);
        let action = custody_action();
        let mut state = NetworkEffectRuntimeState::default();
        let first = opportunity_at(1, 0);
        let mut pending = Vec::new();
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut response = None;
        let first_application = apply_network_custody_queue(
            &[1],
            &mut first_effects,
            &mut state,
            &mut pending,
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
        .unwrap_or_else(|error| panic!("first custody admission: {error}"));
        let first_release = first_application
            .defer_until
            .unwrap_or_else(|| panic!("first bundle must wait"));
        pending.push(pending_custody_frame(&first, first_release));

        let second = opportunity_at(2, 1);
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let second_application = apply_network_custody_queue(
            &[2],
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &second,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("custody overflow: {error}"));
        match disposition {
            crucible::model::NetworkPolicyOverflow::DropNewest => {
                assert!(second_effects.is_dropped());
                assert_eq!(pending.len(), 1);
            }
            crucible::model::NetworkPolicyOverflow::DropOldest => {
                assert!(!second_effects.is_dropped());
                assert!(second_application.repeat_phase_on_resume);
                assert!(pending.is_empty());
                let queue = state
                    .custody_queues
                    .get(&NetworkEffectStateKey::from_action(&action))
                    .unwrap_or_else(|| panic!("custody queue"));
                assert_eq!(queue.reservations[0].bundle.producer_sequence, 2);
            }
            crucible::model::NetworkPolicyOverflow::TypedError => {
                assert!(second_effects.is_dropped());
                assert_eq!(response, Some(id("custody-reject")));
            }
            crucible::model::NetworkPolicyOverflow::Timeout => {
                assert_eq!(second_application.defer_until, Some(26));
                let mut timed_out = crucible::ResolvedNetworkFrameEffects::default();
                apply_network_custody_queue(
                    &[2],
                    &mut timed_out,
                    &mut state,
                    &mut pending,
                    &topology,
                    &action,
                    &opportunity_at(2, 26),
                    1,
                    1,
                    1_000,
                    &id("custody-policy"),
                    &id("contact-plan"),
                    crucible::model::NetworkBundlePriority::Normal,
                    8,
                    &mut response,
                )
                .unwrap_or_else(|error| panic!("custody overflow timeout: {error}"));
                assert!(timed_out.is_dropped());
            }
        }
    }
}

#[test]
fn custody_removal_releases_the_real_pending_frame_at_the_boundary() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 500);
    let action = custody_action();
    let first = opportunity_at(1, 0);
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
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
    .unwrap_or_else(|error| panic!("queue custody frame: {error}"));
    let release = waiting
        .defer_until
        .unwrap_or_else(|| panic!("custody frame must be pending"));
    assert_eq!(release, 510);
    let service_opportunity = opportunity_at(1, release);
    let service = apply_network_custody_queue(
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
    .unwrap_or_else(|error| panic!("commit custody contact: {error}"));
    let service_release = service
        .defer_until
        .unwrap_or_else(|| panic!("committed custody frame must be pending"));
    let mut pending = vec![pending_custody_frame(&first, service_release)];
    pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            service_release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    pending[0]
        .fault_continuation
        .set_resolved_frame_effects(effects);
    let mut removal = action;
    removal.kind = BindingActionKind::RemovePersistent;
    removal.coordinate.virtual_nanos = 510;
    assert!(
        apply_network_custody_removals(&mut state, &mut pending, &[removal], 510)
            .unwrap_or_else(|error| panic!("remove custody binding: {error}"))
    );
    assert!(state.custody_queues.is_empty());
    assert!(
        state
            .contact_services
            .values()
            .all(|service| service.reservations.is_empty() && service.served_bundles == 0)
    );
    assert_eq!(
        pending[0].fault_continuation.cursor().not_before_nanos(),
        510
    );
    assert!(
        pending[0]
            .fault_continuation
            .resolved_frame_effects()
            .accounted_contact_services()
            .is_empty()
    );
    assert!(
        !pending[0]
            .fault_continuation
            .resolved_frame_effects()
            .serialization_is_accounted()
    );
}

#[test]
fn simultaneous_custody_queues_fail_before_state_mutation() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = custody_action();
    let mut second = custody_action();
    second.binding = id("second-custody-binding");
    let mut payload = vec![1];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let error = match apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[first, second],
        &opportunity_at(1, 0),
        ContentHash::from_bytes(b"custody-conflict"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    ) {
        Ok(_) => panic!("two custody queues must conflict"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("multiple custody queues"));
    assert!(state.custody_queues.is_empty());
    assert!(state.contact_services.is_empty());
}

#[test]
fn custody_resume_does_not_charge_other_queue_effects_twice() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let token = action_with_network_effect(NetworkEffectSpecification::TokenBucket {
        rate_bps: positive(8),
        burst_bits: positive(16),
        initial_bits: 16,
    });
    let custody = custody_action();
    let actions = vec![token, custody];
    let mut payload = vec![1];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let first = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, 0),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("first queue evaluation: {error}"));
    assert_eq!(
        first.repeat_effect_on_resume,
        Some(crucible::model::EffectKind::NetworkCustodyQueue)
    );
    let token_state = state
        .token_buckets
        .values()
        .next()
        .map(|bucket| {
            (
                bucket.tokens_nano_bits,
                bucket.last_refill_nanos,
                bucket.transition_sequence,
            )
        })
        .unwrap_or_else(|| panic!("token bucket state"));
    let release = first
        .defer_until
        .unwrap_or_else(|| panic!("custody release"));
    let resumed = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, release),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        Some(crucible::model::EffectKind::NetworkCustodyQueue),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("custody resume: {error}"));
    assert_eq!(
        resumed.repeat_effect_on_resume,
        Some(crucible::model::EffectKind::NetworkCustodyQueue)
    );
    let final_release = resumed
        .defer_until
        .unwrap_or_else(|| panic!("committed custody release"));
    let finalized = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, final_release),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        Some(crucible::model::EffectKind::NetworkCustodyQueue),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("custody finalize: {error}"));
    assert_eq!(finalized.repeat_effect_on_resume, None);
    let resumed_token_state = state
        .token_buckets
        .values()
        .next()
        .map(|bucket| {
            (
                bucket.tokens_nano_bits,
                bucket.last_refill_nanos,
                bucket.transition_sequence,
            )
        })
        .unwrap_or_else(|| panic!("resumed token bucket state"));
    assert_eq!(resumed_token_state, token_state);
}
