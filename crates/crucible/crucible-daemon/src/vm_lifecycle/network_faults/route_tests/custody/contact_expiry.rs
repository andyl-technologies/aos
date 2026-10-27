//! Expiry pruning of closed contact-service windows.
//!
//! A contact-service key carries its window, so a state whose window closed
//! and that holds no reservation can never be served again. These tests show
//! that dropping such states keeps reservation outcomes, checkpoint digests,
//! and restore validation identical to the unpruned state.

use super::*;

/// Window end of the first contact interval in [`custody_topology`] at 100 ns.
const FIRST_WINDOW_END: u64 = 200_000;

fn first_interval(
    topology: &crucible_engine::model::WorldFaultTopology,
) -> crucible_engine::model::NetworkPolicyContactInterval {
    let plan = topology
        .network_policy_artifact(&id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible_engine::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
    else {
        panic!("contact plan type")
    };
    intervals[0].clone()
}

/// Returns the same contact shifted to a later, disjoint window.
fn later_interval(
    interval: &crucible_engine::model::NetworkPolicyContactInterval,
) -> crucible_engine::model::NetworkPolicyContactInterval {
    let mut later = interval.clone();
    later.contact = id("contact-later");
    later.start_ticks += 1_000_000;
    later.end_ticks += 1_000_000;
    later
}

fn reserve_direct(
    state: &mut NetworkEffectRuntimeState,
    topology: &crucible_engine::model::WorldFaultTopology,
    interval: &crucible_engine::model::NetworkPolicyContactInterval,
    now: u64,
    label: &[u8],
) -> Option<(u64, [u8; 32])> {
    reserve_network_contact_service(
        state,
        topology,
        &id("contact-plan"),
        interval,
        &id("sender"),
        &id("receiver"),
        now,
        1,
        ContentHash::from_bytes(label),
        &custody_action(),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("direct contact reservation: {error}"))
}

fn adapter_checkpoint(
    effect_state: NetworkEffectRuntimeState,
    coordinate: u64,
) -> NetworkAdapterCheckpoint {
    NetworkAdapterCheckpoint {
        semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
        coordinate: Some(coordinate),
        coordinate_sequence: 1,
        journal_sequence: 2,
        observations:
            super::super::super::super::storage_faults::ProductionFaultObservationJournal::default(),
        effect_state,
        campaign_records: CampaignRecordLogPosition::empty(),
        campaign_replay_identity: None,
        campaign_marker_releases: Vec::new(),
    }
}

fn evidence(state: &NetworkEffectRuntimeState) -> Vec<u8> {
    let mut material = Vec::new();
    append_network_effect_state(&mut material, state)
        .unwrap_or_else(|error| panic!("contact evidence: {error}"));
    material
}

#[test]
fn closed_empty_contact_windows_are_dropped_and_open_windows_kept() {
    let topology = custody_topology(crucible_engine::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = first_interval(&topology);
    let mut state = NetworkEffectRuntimeState::default();
    assert!(reserve_direct(&mut state, &topology, &first, 110_000, b"first-window").is_some());
    assert_eq!(state.contact_services.len(), 1);

    // The reservation settles before the window closes, so the key survives.
    prune_network_contact_services(&mut state, FIRST_WINDOW_END - 1);
    let service = state
        .contact_services
        .values()
        .next()
        .unwrap_or_else(|| panic!("open contact service"));
    assert!(service.reservations.is_empty());
    assert_eq!(service.served_bundles, 1);

    prune_network_contact_services(&mut state, FIRST_WINDOW_END);
    assert!(state.contact_services.is_empty());
}

#[test]
fn closed_contact_windows_with_reservations_are_not_expired() {
    let key = NetworkContactServiceKey {
        plan: id("contact-plan"),
        contact: id("contact-a"),
        service_resource: id("resource-a"),
        source: id("sender"),
        destination: id("receiver"),
        start_ticks: 100_000,
        end_ticks: FIRST_WINDOW_END,
    };
    let mut service = NetworkContactServiceState {
        settled_cursor_ticks: 100_000,
        service_cursor_ticks: 112_000,
        served_bundles: 1,
        served_bytes: 1,
        reservations: vec![NetworkContactServiceReservation {
            custody_owner: Some(NetworkEffectStateKey::from_action(&custody_action())),
            opportunity: ContentHash::from_bytes(b"live-custody"),
            start_ticks: 110_000,
            finish_ticks: 112_000,
            arrival_ticks: 112_000,
            bytes: 1,
        }],
    };

    assert!(!contact_service_is_expired(&key, &service, u64::MAX));
    service.reservations.clear();
    assert!(!contact_service_is_expired(
        &key,
        &service,
        FIRST_WINDOW_END - 1
    ));
    assert!(contact_service_is_expired(&key, &service, FIRST_WINDOW_END));
}

#[test]
fn pruned_and_unpruned_contact_states_reserve_identically() {
    let topology = custody_topology(crucible_engine::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = first_interval(&topology);
    let later = later_interval(&first);
    let mut unpruned = NetworkEffectRuntimeState::default();
    assert!(reserve_direct(&mut unpruned, &topology, &first, 110_000, b"first-window").is_some());
    prune_network_contact_services(&mut unpruned, FIRST_WINDOW_END - 1);

    // Model a state that skipped expiry pruning: the closed window survives.
    let after_close = FIRST_WINDOW_END + 50_000;
    let mut pruned = unpruned.clone();
    retain_open_contact_services(&mut pruned.contact_services, after_close);
    assert!(pruned.contact_services.is_empty());
    assert_eq!(unpruned.contact_services.len(), 1);

    // A late lookup of the closed window is refused either way.
    assert_eq!(
        reserve_direct(
            &mut unpruned.clone(),
            &topology,
            &first,
            after_close,
            b"late"
        ),
        None
    );
    assert_eq!(
        reserve_direct(&mut pruned.clone(), &topology, &first, after_close, b"late"),
        None
    );

    let now = later.start_ticks + 10_000;
    let from_unpruned = reserve_direct(&mut unpruned, &topology, &later, now, b"later-window");
    let from_pruned = reserve_direct(&mut pruned, &topology, &later, now, b"later-window");
    assert!(from_unpruned.is_some());
    assert_eq!(from_unpruned, from_pruned);
    assert_eq!(evidence(&unpruned), evidence(&pruned));
}

#[test]
fn checkpoint_compaction_drops_closed_windows_and_round_trips() {
    let topology = custody_topology(crucible_engine::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = first_interval(&topology);
    let later = later_interval(&first);
    let mut live = NetworkEffectRuntimeState::default();
    assert!(reserve_direct(&mut live, &topology, &first, 110_000, b"first-window").is_some());

    // The live state still holds the closed window because no reservation
    // has run since it closed; the checkpoint canonicalizes it away.
    let coordinate = FIRST_WINDOW_END + 50_000;
    let compacted = checkpoint_network_effect_state(&live, &[], coordinate);
    assert_eq!(live.contact_services.len(), 1);
    assert!(compacted.contact_services.is_empty());

    let checkpoint = adapter_checkpoint(compacted, coordinate);
    validate_network_adapter_checkpoint(&checkpoint, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("compacted contact checkpoint: {error}"));
    let encoded = serde_json::to_vec(&checkpoint)
        .unwrap_or_else(|error| panic!("encode contact checkpoint: {error}"));
    let decoded: NetworkAdapterCheckpoint = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("decode contact checkpoint: {error}"));
    assert_eq!(
        evidence(&decoded.effect_state),
        evidence(&checkpoint.effect_state)
    );
    let mut restored = decoded.effect_state;

    let now = later.start_ticks + 10_000;
    let from_live = reserve_direct(&mut live, &topology, &later, now, b"later-window");
    let from_restored = reserve_direct(&mut restored, &topology, &later, now, b"later-window");
    assert!(from_live.is_some());
    assert_eq!(from_live, from_restored);
    assert_eq!(evidence(&live), evidence(&restored));
}

#[test]
fn checkpoint_validation_rejects_closed_empty_contact_windows() {
    let topology = custody_topology(crucible_engine::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = first_interval(&topology);
    let mut live = NetworkEffectRuntimeState::default();
    assert!(reserve_direct(&mut live, &topology, &first, 110_000, b"first-window").is_some());
    prune_network_contact_services(&mut live, FIRST_WINDOW_END - 1);

    let open = adapter_checkpoint(live.clone(), FIRST_WINDOW_END - 1);
    validate_network_adapter_checkpoint(&open, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("open contact checkpoint: {error}"));

    let closed = adapter_checkpoint(live, FIRST_WINDOW_END);
    let error = match validate_network_adapter_checkpoint(&closed, FaultResourceLimits::default()) {
        Ok(()) => panic!("a closed, empty contact window must not be restored"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("custody/contact checkpoint is invalid")
    );
}
