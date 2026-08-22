//! Production fault-runtime checkpoint codec tests.

use super::*;
use sha2::{Digest as _, Sha256};

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
        plan.resource_limits(),
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

fn pending_network_output(payload: Vec<u8>) -> BackendNetworkOutput {
    BackendNetworkOutput {
        source: NodeId {
            name: String::from("sender-a"),
        },
        destination: NodeId {
            name: String::from("receiver-b"),
        },
        emit_icount: crucible::Icount { retired: 17 },
        sequence: 19,
        payload,
        route: None,
        fault_continuation: crucible::BackendNetworkFaultContinuation::default(),
    }
}

fn authenticated_qemu_event(payload: Vec<u8>) -> DequeuedFaultEvent {
    DequeuedFaultEvent {
        header: crucible_shmem::FaultEventHeaderV1 {
            command_kind: crucible_shmem::FaultCommandKind::CpuService,
            outcome: crucible_shmem::FaultEventOutcomeV1::Applied,
            event_sequence: 1,
            rule_command_sequence: 1,
            observed_icount: 1,
            model_phase: 1,
            target_kind: 1,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: Sha256::digest(&payload).into(),
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: u32::try_from(payload.len())
                .unwrap_or_else(|_| panic!("test payload length should fit")),
        },
        payload,
    }
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
fn qemu_event_record_is_admitted_before_output_allocation() {
    let event = authenticated_qemu_event(vec![7; 4096]);
    let encoded_length = event
        .canonical_length()
        .unwrap_or_else(|error| panic!("event fixture should validate: {error}"));
    let node = NodeId {
        name: String::from("node-a"),
    };
    let events = BTreeMap::from([(node, vec![event])]);
    let maximum = u64::try_from(encoded_length.saturating_sub(1))
        .unwrap_or_else(|_| panic!("event length should fit the aggregate limit"));
    let mut budget = CheckpointConstructionBudget::new(maximum);

    assert_eq!(
        encode_qemu_event_map(&events, &mut budget).map(|_| ()),
        Err(ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "production fault checkpoint",
            current: 0,
            requested: u64::try_from(encoded_length).unwrap_or(u64::MAX),
            configured: maximum,
            hard: 68_719_476_736,
        })
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
fn aggregate_identity_preserves_legacy_hex_material_hash() {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let plan = FaultSignalPlan::empty();
    let checkpoint = empty_checkpoint(&plan, None);
    let mut material = Vec::new();
    material.extend_from_slice(&plan.id().bytes);
    material.extend_from_slice(&checkpoint.host.digest().bytes);
    material.push(0);
    let mut encoded = String::with_capacity(material.len() * 2);
    for byte in material {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }

    assert_eq!(
        checkpoint.identity,
        ContentHash::from_canonical_material(
            "crucible.production-fault-runtime-checkpoint.v8",
            &encoded,
        )
    );
}

#[test]
fn aggregate_identity_enforces_authored_limit_before_growth() {
    let plan = FaultSignalPlan::empty();
    let checkpoint = empty_checkpoint(&plan, None);
    let mut limits = plan.resource_limits();
    limits.fat_checkpoint_bytes = 64;

    assert!(matches!(
        production_checkpoint_identity(
            plan.id(),
            limits,
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
        ),
        Err(
            crate::production_fault_runtime::ProductionFaultRuntimeError::ResourceLimit(
                crucible::model::FaultResourceLimitError::Exceeded {
                    field: "fat_checkpoint_bytes",
                    current: 64,
                    requested: 1,
                    configured: 64,
                    hard: 68_719_476_736,
                }
            )
        )
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
fn production_network_codec_propagates_authored_limit_into_scheduler() {
    let network = empty_network(Vec::new());
    let mut budget = CheckpointConstructionBudget::new(1);
    let error = match encode_network(&network, &mut budget) {
        Ok(_) => panic!("scheduler state should exceed the authored limit"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "scheduler network checkpoint bytes",
            current,
            requested,
            configured: 1,
            hard: 68_719_476_736,
        } if current.saturating_add(requested) > 1
    ));
}

#[test]
fn production_network_children_share_one_construction_budget() {
    let output = pending_network_output(vec![7; 256]);
    let output_bytes = output
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("pending output should encode: {error}"));
    let mut network = empty_network(Vec::new());
    let scheduler_bytes = network
        .scheduler
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("scheduler should encode: {error}"));
    network.pending_outputs = vec![output.clone(), output];
    let maximum = u64::try_from(
        scheduler_bytes
            .len()
            .saturating_add(output_bytes.len().saturating_mul(2))
            .saturating_sub(1),
    )
    .unwrap_or_else(|_| panic!("test budget should fit u64"));
    let mut budget = CheckpointConstructionBudget::new(maximum);
    let error = match encode_network(&network, &mut budget) {
        Ok(_) => panic!("the second pending output should exceed the shared budget"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "encoded frame",
            configured,
            hard: 16_777_216,
            ..
        } if configured == u64::try_from(output_bytes.len() - 1).unwrap_or(u64::MAX)
    ));
}

#[test]
fn pending_network_output_resource_coordinates_cross_production_envelope() {
    assert_eq!(
        map_backend_network_output_error(crucible::BackendNetworkOutputCodecError::ResourceLimit {
            field: "frame payload",
            current: 0,
            requested: 16_777_217,
            configured: 16_777_216,
            hard: 16_777_216,
        },),
        ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "frame payload",
            current: 0,
            requested: 16_777_217,
            configured: 16_777_216,
            hard: 16_777_216,
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
