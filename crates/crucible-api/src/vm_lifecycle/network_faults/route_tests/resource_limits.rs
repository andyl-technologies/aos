//! Exact authored resource admission for live production network ownership.

use super::*;

fn queue_action() -> ResolvedBindingAction {
    action_with_network_effect(NetworkEffectSpecification::QueuePolicy {
        capacity_bytes: positive(64),
        capacity_frames: crucible::model::BoundedCount::new(CountLimit::QueueEntries, 4)
            .unwrap_or_else(|error| panic!("test queue frame capacity: {error}")),
        discipline: crucible::model::NetworkQueueDiscipline::Fifo,
        discipline_parameters: None,
        overflow: crucible::model::NetworkQueueOverflow::TailDrop,
        typed_error: None,
    })
}

fn assert_resource_limit(
    result: Result<NetworkFrameApplication, SchedulerError>,
    expected_field: &'static str,
    expected_current: u64,
    expected_requested: u64,
    expected_configured: u64,
) {
    assert!(matches!(
        result,
        Err(SchedulerError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        }) if field == expected_field
            && current == expected_current
            && requested == expected_requested
            && configured == expected_configured
            && hard == FaultResourceLimits::compiled_maximum()
                .configured(expected_field)
                .unwrap_or(0)
    ));
}

fn scheduler_error<T>(result: Result<T, SchedulerError>, message: &str) -> SchedulerError {
    match result {
        Ok(_value) => panic!("{message}"),
        Err(error) => error,
    }
}

#[test]
fn pending_network_output_admission_uses_frame_and_pending_limits() {
    let opportunity = opportunity(1);
    let output = pending_medium_frame(
        &opportunity,
        10,
        crucible::ResolvedNetworkFrameEffects::default(),
        vec![1, 2],
    );
    let frame_limits = FaultResourceLimits {
        network_frame_bytes: 1,
        ..FaultResourceLimits::default()
    };
    assert!(matches!(
        stage_pending_network_output(&mut Vec::new(), output.clone(), frame_limits),
        Err(SchedulerError::ResourceLimit {
            field: "network_frame_bytes",
            current: 0,
            requested: 2,
            configured: 1,
            hard,
        }) if hard == FaultResourceLimits::compiled_maximum().network_frame_bytes
    ));

    let pending_limits = FaultResourceLimits {
        network_pending_frames: 1,
        ..FaultResourceLimits::default()
    };
    let mut pending = vec![output.clone()];
    assert!(matches!(
        stage_pending_network_output(&mut pending, output, pending_limits),
        Err(SchedulerError::ResourceLimit {
            field: "network_pending_frames",
            current: 1,
            requested: 1,
            configured: 1,
            hard,
        }) if hard == FaultResourceLimits::compiled_maximum().network_pending_frames
    ));
}

#[test]
fn queue_admission_uses_aggregate_frame_and_byte_limits() {
    for (field, limits) in [
        (
            "network_queue_frames",
            FaultResourceLimits {
                network_queue_frames: 1,
                ..FaultResourceLimits::default()
            },
        ),
        (
            "network_queue_bytes",
            FaultResourceLimits {
                network_queue_frames: 4,
                network_queue_bytes: 1,
                ..FaultResourceLimits::default()
            },
        ),
    ] {
        let action = queue_action();
        let mut state = NetworkEffectRuntimeState::default();
        let mut pending = Vec::new();
        let mut first_payload = vec![0x42];
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_frame_actions_with_limits(
            &mut first_payload,
            &mut first_effects,
            std::slice::from_ref(&action),
            &opportunity(10),
            ContentHash::from_bytes(b"network-resource-limit"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
            &mut pending,
            Some(8),
            None,
            limits,
        )
        .unwrap_or_else(|error| panic!("first queue reservation should fit: {error}"));

        let mut second_payload = vec![0x43];
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let result = apply_network_frame_actions_with_limits(
            &mut second_payload,
            &mut second_effects,
            &[action],
            &opportunity(11),
            ContentHash::from_bytes(b"network-resource-limit"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
            &mut pending,
            Some(8),
            None,
            limits,
        );
        assert_resource_limit(result, field, 1, 1, 1);
    }
}

#[test]
fn shared_medium_and_custody_admission_share_the_authored_queue_budget() {
    let resources = crucible::model::ObjectIdSet::new(vec![id("sender-a"), id("sender-b")])
        .unwrap_or_else(|error| panic!("test medium resources: {error}"));
    let policy = id("resource-medium-policy");
    let topology = medium_topology(
        policy.clone(),
        medium_policy(
            crucible::model::NetworkPolicyArbitration::Fifo,
            crucible::model::NetworkPolicyCollision::DropAll,
        ),
        Vec::new(),
    );
    let action = medium_action(resources.clone(), policy.clone(), 1);
    let limits = FaultResourceLimits {
        network_queue_frames: 1,
        ..FaultResourceLimits::default()
    };
    let mut state = NetworkEffectRuntimeState::default();
    let mut first = [1_u8];
    let first_opportunity = medium_opportunity("sender-a", 1, &first);
    apply_network_shared_medium_with_limits(
        &mut first,
        &mut crucible::ResolvedNetworkFrameEffects::default(),
        &mut state,
        &mut [],
        &topology,
        &action,
        &first_opportunity,
        ContentHash::from_bytes(b"resource-medium"),
        &resources,
        &policy,
        1,
        Some(1_000_000_000),
        limits,
    )
    .unwrap_or_else(|error| panic!("first medium reservation should fit: {error}"));
    let mut second = [2_u8];
    let second_opportunity = medium_opportunity("sender-b", 2, &second);
    let error = scheduler_error(
        apply_network_shared_medium_with_limits(
            &mut second,
            &mut crucible::ResolvedNetworkFrameEffects::default(),
            &mut state,
            &mut [],
            &topology,
            &action,
            &second_opportunity,
            ContentHash::from_bytes(b"resource-medium"),
            &resources,
            &policy,
            1,
            Some(1_000_000_000),
            limits,
        ),
        "the second medium reservation must exceed the aggregate queue budget",
    );
    assert!(matches!(
        error,
        SchedulerError::ResourceLimit {
            field: "network_queue_frames",
            current: 1,
            requested: 1,
            configured: 1,
            hard,
        } if hard == FaultResourceLimits::compiled_maximum().network_queue_frames
    ));

    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = custody_action();
    let limits = FaultResourceLimits {
        network_custody_bundles: 1,
        ..FaultResourceLimits::default()
    };
    let mut state = NetworkEffectRuntimeState::default();
    let mut pending = Vec::new();
    let mut typed_response = None;
    apply_network_custody_queue_with_limits(
        &[1],
        &mut crucible::ResolvedNetworkFrameEffects::default(),
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 0),
        2,
        2,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
        limits,
    )
    .unwrap_or_else(|error| panic!("first custody reservation should fit: {error}"));
    let error = scheduler_error(
        apply_network_custody_queue_with_limits(
            &[2],
            &mut crucible::ResolvedNetworkFrameEffects::default(),
            &mut state,
            &mut pending,
            &topology,
            &action,
            &opportunity_at(2, 0),
            2,
            2,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut typed_response,
            limits,
        ),
        "the second custody owner must exceed its authored bundle budget",
    );
    assert!(matches!(
        error,
        SchedulerError::ResourceLimit {
            field: "network_custody_bundles",
            current: 1,
            requested: 1,
            configured: 1,
            hard,
        } if hard == FaultResourceLimits::compiled_maximum().network_custody_bundles
    ));
}

#[test]
fn contact_and_restore_admission_use_authored_aggregate_coordinates() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let plan = topology
        .network_policy_artifact(&id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
    else {
        panic!("contact plan type")
    };
    let mut state = NetworkEffectRuntimeState::default();
    let limits = FaultResourceLimits {
        network_contact_entries: 1,
        ..FaultResourceLimits::default()
    };
    let error = scheduler_error(
        reserve_network_contact_service(
            &mut state,
            &topology,
            &id("contact-plan"),
            &intervals[0],
            &id("sender"),
            &id("receiver"),
            110,
            1,
            ContentHash::from_bytes(b"resource-contact"),
            &custody_action(),
            limits,
        ),
        "one new contact state plus its reservation needs two entries",
    );
    assert!(matches!(
        error,
        SchedulerError::ResourceLimit {
            field: "network_contact_entries",
            current: 0,
            requested: 2,
            configured: 1,
            hard,
        } if hard == FaultResourceLimits::compiled_maximum().network_contact_entries
    ));

    let action = queue_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut pending = Vec::new();
    for sequence in [10, 11] {
        let mut payload = vec![u8::try_from(sequence).unwrap_or(0)];
        apply_network_frame_actions_with_limits(
            &mut payload,
            &mut crucible::ResolvedNetworkFrameEffects::default(),
            std::slice::from_ref(&action),
            &opportunity(sequence),
            ContentHash::from_bytes(b"network-restore-limit"),
            &crucible::model::WorldFaultTopology::default(),
            &mut state,
            &mut pending,
            Some(8),
            None,
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("checkpoint queue reservation should fit: {error}"));
    }
    let checkpoint = NetworkAdapterCheckpoint {
        semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
        coordinate: Some(11),
        coordinate_sequence: 1,
        journal_sequence: 2,
        observations:
            super::super::super::storage_faults::ProductionFaultObservationJournal::default(),
        effect_state: state,
    };
    let limits = FaultResourceLimits {
        network_queue_frames: 1,
        ..FaultResourceLimits::default()
    };
    let error = scheduler_error(
        validate_network_adapter_checkpoint(&checkpoint, limits),
        "restored aggregate queue usage must honor the authored frame ceiling",
    );
    assert!(matches!(
        error,
        SchedulerError::ResourceLimit {
            field: "network_queue_frames",
            current: 0,
            requested: 2,
            configured: 1,
            hard,
        } if hard == FaultResourceLimits::compiled_maximum().network_queue_frames
    ));
}
