//! Production fault-runtime checkpoint codec tests.

use std::collections::BTreeMap;

use super::*;
use crucible::model::FaultResourceLimits;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

fn empty_checkpoint(
    plan: &FaultSignalPlan,
    network_state: Option<ProductionNetworkStateCheckpoint>,
) -> ProductionFaultRuntimeCheckpoint {
    let mut checkpoint = ProductionFaultRuntimeCheckpoint {
        runtime: None,
        host: HostFaultActionState::default(),
        qemu_fingerprints: std::sync::Arc::new(QemuNodeMap::new()),
        qemu_fault_sequences: std::sync::Arc::new(QemuNodeMap::new()),
        qemu_fault_event_sequences: std::sync::Arc::new(QemuNodeMap::new()),
        qemu_issued_actions: QemuActionMap::new(),
        qemu_action_commits: QemuActionMap::new(),
        qemu_active_rule_ids: QemuActionSet::new(),
        network_state,
        emitted_events: Vec::new(),
        pending_qemu_observations: Vec::new(),
        pending_qemu_events: PendingQemuEventMap::new(),
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
            rng_positions: Vec::new(),
            signal_fault_wakeup_ticks: None,
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

#[derive(Serialize)]
struct HostileCollectionWire {
    qemu_fingerprints: BTreeMap<u8, u8>,
}

#[test]
fn production_decode_rejects_nodes_above_authored_limit_before_wire_decode() {
    let bytes = incomplete_checkpoint_bytes(&HostileCollectionWire {
        qemu_fingerprints: BTreeMap::from([(1, 1), (2, 2)]),
    });
    let limits = FaultResourceLimits {
        nodes: 1,
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
        .unwrap_or_else(|error| panic!("test resource limits should build a plan: {error}"));

    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
            &bytes,
            &plan,
            ContentHash::from_bytes(b"hostile node-count seed"),
        ),
        Err(ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "nodes",
            current: 0,
            requested: 2,
            configured: 1,
            hard: 16_384,
        })
    ));
}

#[derive(Serialize)]
struct HostileActionWire {
    qemu_issued_actions: BTreeMap<u8, u8>,
}

#[test]
fn production_decode_rejects_actions_above_authored_event_limit_before_wire_decode() {
    let bytes = incomplete_checkpoint_bytes(&HostileActionWire {
        qemu_issued_actions: BTreeMap::from([(1, 1), (2, 2)]),
    });
    let limits = FaultResourceLimits {
        event_records: 1,
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
        .unwrap_or_else(|error| panic!("test resource limits should build a plan: {error}"));

    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
            &bytes,
            &plan,
            ContentHash::from_bytes(b"hostile action-count seed"),
        ),
        Err(ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "event_records",
            current: 0,
            requested: 2,
            configured: 1,
            hard: 1_073_741_824,
        })
    ));
}

fn incomplete_checkpoint_bytes(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    ciborium::ser::into_writer(value, &mut bytes)
        .unwrap_or_else(|error| panic!("hostile checkpoint fixture should encode: {error}"));
    bytes
}

#[test]
fn complete_production_checkpoint_round_trips_canonically() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"empty checkpoint seed");
    let mut checkpoint = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));
    let node = NodeId {
        name: String::from("node-a"),
    };
    std::sync::Arc::get_mut(&mut checkpoint.qemu_fingerprints)
        .unwrap_or_else(|| panic!("checkpoint fingerprint fixture should be uniquely owned"))
        .try_insert(node.clone(), ContentHash::from_bytes(b"fingerprint"))
        .unwrap_or_else(|error| panic!("fingerprint fixture should allocate: {error}"));
    std::sync::Arc::get_mut(&mut checkpoint.qemu_fault_sequences)
        .unwrap_or_else(|| panic!("checkpoint command sequence fixture should be uniquely owned"))
        .try_insert(node.clone(), 1)
        .unwrap_or_else(|error| panic!("command sequence fixture should allocate: {error}"));
    std::sync::Arc::get_mut(&mut checkpoint.qemu_fault_event_sequences)
        .unwrap_or_else(|| panic!("checkpoint event sequence fixture should be uniquely owned"))
        .try_insert(node, 1)
        .unwrap_or_else(|error| panic!("event sequence fixture should allocate: {error}"));
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
    .unwrap_or_else(|error| panic!("nonempty checkpoint identity should encode: {error}"));

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
fn sibling_fault_checkpoints_share_immutable_qemu_fingerprints_and_sequences() {
    let plan = FaultSignalPlan::empty();
    let node = NodeId {
        name: String::from("node-a"),
    };
    let fingerprint = ContentHash::from_bytes(b"source qemu fingerprint");
    let source = empty_checkpoint(&plan, None)
        .with_unvalidated_test_node(&plan, node.clone(), fingerprint)
        .unwrap_or_else(|error| panic!("source checkpoint should admit one node: {error}"));

    let first = source
        .try_clone()
        .unwrap_or_else(|error| panic!("first sibling should clone: {error}"));
    let second = source
        .try_clone()
        .unwrap_or_else(|error| panic!("second sibling should clone: {error}"));

    assert!(std::sync::Arc::ptr_eq(
        &first.qemu_fingerprints,
        &second.qemu_fingerprints
    ));
    assert!(std::sync::Arc::ptr_eq(
        &source.qemu_fingerprints,
        &first.qemu_fingerprints
    ));
    assert!(std::sync::Arc::ptr_eq(
        &first.qemu_fault_sequences,
        &second.qemu_fault_sequences
    ));
    assert!(std::sync::Arc::ptr_eq(
        &first.qemu_fault_event_sequences,
        &second.qemu_fault_event_sequences
    ));
    assert_eq!(first.qemu_fingerprint(&node), Some(fingerprint));

    drop(source);
    assert_eq!(second.qemu_fingerprint(&node), Some(fingerprint));
    assert_eq!(first.id(), second.id());
    assert_eq!(
        first
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("first sibling should encode: {error}")),
        second
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("second sibling should encode: {error}"))
    );
}

#[test]
fn fault_checkpoint_clone_cost_keeps_mutable_ledgers_private() {
    const SIBLINGS: usize = 64;
    const AUTHENTICATED_NODES: usize = 4096;
    const ADAPTER_BYTES: usize = 32 * 1024;
    const MAX_PRIVATE_GROWTH_KIB: u64 = 32 * 1024;

    let plan = FaultSignalPlan::empty();
    let node = NodeId {
        name: String::from("node-a"),
    };
    let mut source = empty_checkpoint(&plan, Some(empty_network(vec![7; ADAPTER_BYTES])))
        .with_unvalidated_test_node(&plan, node.clone(), ContentHash::from_bytes(b"qemu"))
        .unwrap_or_else(|error| panic!("source checkpoint should admit one node: {error}"));
    source
        .pending_qemu_events
        .try_insert(node.clone(), vec![authenticated_qemu_event(vec![3; 4096])])
        .unwrap_or_else(|error| panic!("source event ledger should admit one event: {error}"));

    // A one-node pointer check cannot detect an accidental deep copy of the
    // authenticated maps. Fill their supported node domain before cloning.
    let fingerprints = std::sync::Arc::get_mut(&mut source.qemu_fingerprints)
        .unwrap_or_else(|| panic!("source fingerprint map should be uniquely owned"));
    let fault_sequences = std::sync::Arc::get_mut(&mut source.qemu_fault_sequences)
        .unwrap_or_else(|| panic!("source fault sequence map should be uniquely owned"));
    let event_sequences = std::sync::Arc::get_mut(&mut source.qemu_fault_event_sequences)
        .unwrap_or_else(|| panic!("source event sequence map should be uniquely owned"));
    for index in 1..AUTHENTICATED_NODES {
        let node = NodeId {
            name: format!("node-{index:04}"),
        };
        fingerprints
            .try_insert(node.clone(), ContentHash::from_bytes(node.name.as_bytes()))
            .unwrap_or_else(|error| panic!("fingerprint fixture should admit node: {error}"));
        fault_sequences
            .try_insert(node.clone(), 0)
            .unwrap_or_else(|error| panic!("fault sequence fixture should admit node: {error}"));
        event_sequences
            .try_insert(node, 0)
            .unwrap_or_else(|error| panic!("event sequence fixture should admit node: {error}"));
    }
    source.identity = production_checkpoint_identity(
        plan.id(),
        plan.resource_limits(),
        source.runtime.as_ref(),
        &source.host,
        &source.qemu_fingerprints,
        &source.qemu_fault_sequences,
        &source.qemu_fault_event_sequences,
        &source.qemu_issued_actions,
        &source.qemu_action_commits,
        &source.qemu_active_rule_ids,
        source.network_state.as_ref(),
        &source.emitted_events,
        &source.pending_qemu_observations,
        &source.pending_qemu_events,
    )
    .unwrap_or_else(|error| panic!("large source checkpoint should authenticate: {error}"));

    let baseline_kib = fault_clone_private_dirty_kib();
    let mut siblings = (0..SIBLINGS)
        .map(|_| {
            source
                .try_clone()
                .unwrap_or_else(|error| panic!("clone sibling fault checkpoint: {error}"))
        })
        .collect::<Vec<_>>();
    let private_growth_kib = fault_clone_private_dirty_kib().saturating_sub(baseline_kib);
    assert!(
        private_growth_kib <= MAX_PRIVATE_GROWTH_KIB,
        "{SIBLINGS} fault clones consumed {private_growth_kib} KiB private memory"
    );

    let source_network = source
        .network_state
        .as_ref()
        .unwrap_or_else(|| panic!("source network ledger should exist"));
    let source_events = source
        .pending_qemu_events
        .get(&node)
        .unwrap_or_else(|| panic!("source event ledger should exist"));
    for sibling in &siblings {
        let sibling_network = sibling
            .network_state
            .as_ref()
            .unwrap_or_else(|| panic!("sibling network ledger should exist"));
        let sibling_events = sibling
            .pending_qemu_events
            .get(&node)
            .unwrap_or_else(|| panic!("sibling event ledger should exist"));
        assert!(std::sync::Arc::ptr_eq(
            &source.qemu_fingerprints,
            &sibling.qemu_fingerprints
        ));
        assert!(std::sync::Arc::ptr_eq(
            &source.qemu_fault_sequences,
            &sibling.qemu_fault_sequences
        ));
        assert!(std::sync::Arc::ptr_eq(
            &source.qemu_fault_event_sequences,
            &sibling.qemu_fault_event_sequences
        ));
        assert_ne!(
            source_network.adapter_state.as_ptr(),
            sibling_network.adapter_state.as_ptr()
        );
        assert_ne!(
            source_events[0].payload.as_ptr(),
            sibling_events[0].payload.as_ptr()
        );
    }
    siblings[0]
        .pending_qemu_events
        .get_mut(&node)
        .unwrap_or_else(|| panic!("first sibling event ledger should exist"))[0]
        .payload[0] = 9;
    siblings[0]
        .network_state
        .as_mut()
        .unwrap_or_else(|| panic!("first sibling network ledger should exist"))
        .adapter_state[0] = 9;
    assert_eq!(source_events[0].payload[0], 3);
    assert_eq!(
        siblings[1]
            .pending_qemu_events
            .get(&node)
            .unwrap_or_else(|| panic!("second sibling event ledger should exist"))[0]
            .payload[0],
        3
    );
    assert_eq!(source_network.adapter_state[0], 7);
    assert_eq!(
        siblings[1]
            .network_state
            .as_ref()
            .unwrap_or_else(|| panic!("second sibling network ledger should exist"))
            .adapter_state[0],
        7
    );

    println!("fault_checkpoint_siblings={SIBLINGS}");
    println!("qemu_authentication_map_nodes={AUTHENTICATED_NODES}");
    println!("qemu_authentication_map_copies=1");
    println!("fault_clone_private_growth_kib={private_growth_kib}");
    println!("fault_clone_private_growth_limit_kib={MAX_PRIVATE_GROWTH_KIB}");
    println!("child_private_ledgers=network-adapter,pending-qemu-events");
}

fn fault_clone_private_dirty_kib() -> u64 {
    let rollup = std::fs::read_to_string("/proc/self/smaps_rollup")
        .unwrap_or_else(|error| panic!("read fault clone memory rollup: {error}"));
    rollup
        .lines()
        .find_map(|line| line.strip_prefix("Private_Dirty:"))
        .and_then(|value| value.trim().strip_suffix(" kB"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("fault clone memory rollup lacks Private_Dirty in KiB"))
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
    let mut events = PendingQemuEventMap::new();
    events
        .try_insert(node, vec![event])
        .unwrap_or_else(|error| panic!("event map fixture should allocate: {error}"));
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
    let mut mutated = empty_checkpoint(&plan, Some(empty_network(b"adapter-v1".to_vec())));
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
fn aggregate_identity_preserves_canonical_v10_hex_material_hash() {
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
            "crucible.production-fault-runtime-checkpoint.v10",
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
fn aggregate_codec_rejects_the_prior_nanosecond_version() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"unsupported checkpoint seed");
    let mut bytes = empty_checkpoint(&plan, None)
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint should encode: {error}"));
    bytes[..MAGIC.len()].copy_from_slice(b"crucible.production-fault-runtime.v6\0");

    assert!(matches!(
        ProductionFaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed),
        Err(ProductionFaultRuntimeCheckpointCodecError::Version)
    ));
}
