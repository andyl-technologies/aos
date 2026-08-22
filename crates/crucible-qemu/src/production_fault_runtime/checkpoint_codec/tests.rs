//! Production fault-runtime checkpoint codec tests.

use super::*;

fn empty_checkpoint(
    plan: &FaultSignalPlan,
    network_state: Option<ProductionNetworkStateCheckpoint>,
) -> ProductionFaultRuntimeCheckpoint {
    let mut checkpoint = ProductionFaultRuntimeCheckpoint {
        runtime: None,
        host: HostFaultActionState::default(),
        qemu_fingerprints: BTreeMap::new(),
        qemu_fault_sequences: BTreeMap::new(),
        qemu_fault_event_sequences: BTreeMap::new(),
        qemu_issued_actions: BTreeMap::new(),
        qemu_action_commits: BTreeMap::new(),
        qemu_active_rule_ids: BTreeSet::new(),
        network_state,
        emitted_events: Vec::new(),
        pending_qemu_observations: Vec::new(),
        pending_qemu_events: BTreeMap::new(),
        identity: ContentHash::from_bytes(b"uninitialized checkpoint identity"),
    };
    checkpoint.identity = production_checkpoint_identity(
        plan.id(),
        checkpoint.runtime.as_ref(),
        &checkpoint.host,
        &checkpoint.qemu_fingerprints,
        &checkpoint.qemu_fault_sequences,
        &checkpoint.qemu_fault_event_sequences,
        &checkpoint.qemu_issued_actions,
        &checkpoint.qemu_action_commits,
        &checkpoint.qemu_active_rule_ids,
        checkpoint.network_state.as_ref(),
        &checkpoint.emitted_events,
        &checkpoint.pending_qemu_observations,
        &checkpoint.pending_qemu_events,
    )
    .unwrap_or_else(|error| panic!("empty checkpoint identity should encode: {error}"));
    checkpoint
}

fn empty_network(adapter_state: Vec<u8>) -> ProductionNetworkStateCheckpoint {
    ProductionNetworkStateCheckpoint::new(
        ContentHash::from_bytes(b"network semantic identity"),
        SchedulerNetworkCheckpoint {
            links: Vec::new(),
            rng_positions: BTreeMap::new(),
            signal_fault_wakeup_nanos: None,
        },
        crucible::VirtualTime { ticks: 17 },
        Vec::new(),
        adapter_state,
    )
}

#[test]
fn complete_production_checkpoint_round_trips_canonically() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"empty checkpoint seed");
    let checkpoint = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));

    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
    let aggregate_limit = u64::try_from(bytes.len().saturating_sub(1))
        .unwrap_or_else(|_| panic!("checkpoint length should fit the aggregate limit"));
    assert!(matches!(
        checkpoint.to_canonical_bytes_with_limit(aggregate_limit),
        Err(ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "production fault checkpoint",
            configured,
            hard: 68_719_476_736,
            ..
        }) if configured == aggregate_limit
    ));

    let restored = ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed)
        .unwrap_or_else(|error| panic!("checkpoint should decode: {error}"));

    assert_eq!(restored.id(), checkpoint.id());
    assert_eq!(
        restored
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("restored checkpoint should encode: {error}")),
        bytes
    );
}

#[test]
fn aggregate_identity_binds_network_adapter_bytes() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"network mutation seed");
    let checkpoint = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));
    let mut mutated = checkpoint.clone();
    mutated
        .network_state
        .as_mut()
        .unwrap_or_else(|| panic!("test checkpoint should own network state"))
        .adapter_state = b"adapter-v2".to_vec();
    let bytes = mutated
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("mutated fixture should encode: {error}"));

    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed),
        Err(ProductionFaultRuntimeCheckpointCodecError::Invalid)
    ));
}

#[test]
fn aggregate_codec_rejects_trailing_bytes() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"trailing checkpoint seed");
    let mut bytes = empty_checkpoint(&plan, None)
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
    bytes.push(0);

    assert!(ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed).is_err());
}

#[test]
fn scheduler_network_resource_coordinates_cross_production_envelope() {
    assert_eq!(
        map_scheduler_network_error(
            crucible::SchedulerNetworkCheckpointCodecError::ResourceLimit {
                field: "directed links",
                current: 0,
                requested: 65_537,
                configured: 65_536,
                hard: 65_536,
            },
        ),
        ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "directed links",
            current: 0,
            requested: 65_537,
            configured: 65_536,
            hard: 65_536,
        }
    );
}

#[test]
fn aggregate_codec_rejects_pre_policy_version() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"old policy checkpoint seed");
    let mut bytes = empty_checkpoint(&plan, None)
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
    bytes[..MAGIC.len()].copy_from_slice(b"crucible.production-fault-runtime.v4\0");

    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed),
        Err(ProductionFaultRuntimeCheckpointCodecError::Version)
    ));
}
