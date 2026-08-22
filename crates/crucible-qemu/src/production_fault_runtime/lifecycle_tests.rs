//! QEMU lifecycle and occurrence-ledger tests.

use super::test_support::*;
use super::*;

#[test]
fn typed_lifecycle_evidence_rejects_policy_and_marker_mismatch() {
    let immediate = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&immediate);
    assert!(validate_node_event_evidence(&event, &immediate).is_ok());

    let mut corrupt = event.clone();
    corrupt.payload[12..16].copy_from_slice(&2_u32.to_le_bytes());
    assert!(validate_node_event_evidence(&corrupt, &immediate).is_err());

    let mut wrong_kind = event.clone();
    wrong_kind.header.command_kind = crucible_shmem::FaultCommandKind::CpuService;
    assert!(validate_node_event_evidence(&wrong_kind, &immediate).is_err());

    let ready = lifecycle_action(
        NodeLifecycleTransition::Reset,
        NodeBootPolicy::RequireReady {
            ready_marker: object_id("guest-ready"),
            maximum_attempts: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 2)
                .unwrap_or_else(|error| panic!("test attempt count should be valid: {error}")),
            retry_delay_nanos: 4096,
            exhausted: NodeLifecycleTransition::PermanentFailure,
        },
    );
    assert!(validate_node_event_evidence(&event, &ready).is_err());
}

#[test]
fn terminal_lifecycle_evidence_reconstructs_the_pre_exit_digest() {
    let crash = lifecycle_action(NodeLifecycleTransition::Crash, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&crash);
    assert!(validate_node_event_evidence(&event, &crash).is_ok());
    let decision = node_lifecycle_decision(
        &NodeId {
            name: "node-a".to_owned(),
        },
        crash.id(),
        &event,
    )
    .unwrap_or_else(|| panic!("terminal event should produce a supervision decision"));
    assert_eq!(decision.expected_exit_code, Some(70));
    assert_eq!(
        decision.requested_transition,
        NodeLifecycleTransition::Crash
    );
    assert_eq!(
        decision.effective_transition,
        NodeLifecycleTransition::Crash
    );
    let mut authorization_evidence: [u8; LIFECYCLE_EVIDENCE_BYTES] = event
        .payload
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("lifecycle evidence should have its fixed ABI length"));
    authorization_evidence[24..32].fill(0);
    assert_eq!(
        decision.event_evidence.bytes,
        <[u8; 32]>::from(Sha256::digest(authorization_evidence))
    );

    let mut substituted = event.clone();
    substituted.payload[256] ^= 1;
    assert!(validate_node_event_evidence(&substituted, &crash).is_err());

    let mut changed_device_encoding_size = event.clone();
    changed_device_encoding_size.payload[120..128].copy_from_slice(&129_u64.to_le_bytes());
    assert!(validate_node_event_evidence(&changed_device_encoding_size, &crash).is_ok());
}

#[test]
fn ready_exhaustion_names_the_effective_terminal_transition() {
    let reset = lifecycle_action(
        NodeLifecycleTransition::Reset,
        NodeBootPolicy::RequireReady {
            ready_marker: object_id("guest-ready"),
            maximum_attempts: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 2)
                .unwrap_or_else(|error| panic!("test attempt count should be valid: {error}")),
            retry_delay_nanos: 4096,
            exhausted: NodeLifecycleTransition::PowerOff,
        },
    );
    let mut event = lifecycle_event(&reset);
    let pre_exit_hash = [11_u8; 32];
    let mut material = [0_u8; 48];
    material[0..8].copy_from_slice(b"CRUCTRM1");
    material[8..12].copy_from_slice(
        &u32::from(lifecycle_tag(NodeLifecycleTransition::PowerOff)).to_le_bytes(),
    );
    material[16..48].copy_from_slice(&pre_exit_hash);
    let after_hash: [u8; 32] = Sha256::digest(material).into();
    event.payload[196..200].copy_from_slice(&2_u32.to_le_bytes());
    event.payload[160..192].copy_from_slice(&after_hash);
    event.payload[256..288].copy_from_slice(&pre_exit_hash);
    event.payload[288..292].copy_from_slice(
        &u32::from(lifecycle_tag(NodeLifecycleTransition::PowerOff)).to_le_bytes(),
    );
    event.payload[292..296]
        .copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED.to_le_bytes());
    event.payload[296..300].copy_from_slice(
        &(LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED).to_le_bytes(),
    );
    event.header.after_hash = after_hash;
    assert!(validate_node_event_evidence(&event, &reset).is_ok());

    let decision = node_lifecycle_decision(
        &NodeId {
            name: "node-a".to_owned(),
        },
        reset.id(),
        &event,
    )
    .unwrap_or_else(|| panic!("exhaustion should produce a supervision decision"));
    assert_eq!(
        decision.requested_transition,
        NodeLifecycleTransition::Reset
    );
    assert_eq!(
        decision.effective_transition,
        NodeLifecycleTransition::PowerOff
    );
    assert_eq!(decision.expected_exit_code, Some(71));
}

#[test]
fn fail_closed_lifecycle_accepts_an_explicit_missing_pre_exit_measurement() {
    let reset = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let mut event = lifecycle_event(&reset);
    event.header.outcome = FaultEventOutcomeV1::Error;
    event.header.after_hash = event.header.before_hash;
    event.payload[112..120].fill(0);
    event.payload[120..128].fill(0);
    event.payload[160..192].copy_from_slice(&event.header.before_hash);
    event.payload[288..292].copy_from_slice(
        &u32::from(lifecycle_tag(NodeLifecycleTransition::PermanentFailure)).to_le_bytes(),
    );
    event.payload[292..296].copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED.to_le_bytes());
    event.payload[296..300].copy_from_slice(&LIFECYCLE_TERMINAL_EXIT_REQUIRED.to_le_bytes());
    assert!(validate_node_event_evidence(&event, &reset).is_ok());

    event.payload[256] = 1;
    assert!(validate_node_event_evidence(&event, &reset).is_err());
}

#[test]
fn qemu_action_ledger_retains_impulses_and_removed_rules_for_events() {
    let committed = |action: &ResolvedBindingAction, command_sequence: u64| {
        BTreeMap::from([(
            action.id(),
            CommittedQemuActionEvidence {
                command_sequence,
                command_kind: crucible_shmem::FaultCommandKind::NodeLifecycle as u16,
                before_hash: [command_sequence as u8; 32],
                after_hash: [command_sequence as u8 + 1; 32],
            },
        )])
    };
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"qemu-action-ledger"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));

    let impulse = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    runtime
        .update_qemu_action_ledger(std::slice::from_ref(&impulse), committed(&impulse, 1))
        .unwrap_or_else(|error| panic!("impulse should enter issued ledger: {error}"));
    assert_eq!(
        runtime.qemu_issued_actions.get(&impulse.id()),
        Some(&impulse)
    );

    let mut persistent = impulse.clone();
    persistent.kind = BindingActionKind::UpsertPersistent;
    persistent.binding = object_id("node-hang");
    persistent.transition_sequence = 2;
    runtime
        .update_qemu_action_ledger(std::slice::from_ref(&persistent), committed(&persistent, 2))
        .unwrap_or_else(|error| panic!("persistent rule should enter issued ledger: {error}"));

    let mut remove = persistent.clone();
    remove.kind = BindingActionKind::RemovePersistent;
    remove.transition_sequence = 3;
    runtime
        .update_qemu_action_ledger(std::slice::from_ref(&remove), committed(&remove, 3))
        .unwrap_or_else(|error| panic!("known rule should be removable: {error}"));
    assert_eq!(
        runtime.qemu_issued_actions.get(&persistent.id()),
        Some(&persistent),
        "recovery evidence names the issued upsert after removal"
    );
    assert_eq!(runtime.qemu_active_rule_ids.len(), 0);
    let event_node = NodeId {
        name: String::from("node-a"),
    };
    let retained_event = lifecycle_event(&impulse);
    runtime
        .pending_qemu_events
        .try_insert(event_node.clone(), vec![retained_event.clone()])
        .unwrap_or_else(|error| panic!("pending event fixture should allocate: {error}"));
    let duplicate = runtime
        .try_clone()
        .unwrap_or_else(|error| panic!("runtime ledger should clone fallibly: {error}"));
    let duplicated_impulse = duplicate
        .qemu_issued_actions
        .get(&impulse.id())
        .unwrap_or_else(|| panic!("duplicated ledger should retain the impulse"));
    assert_eq!(duplicated_impulse, &impulse);
    assert_ne!(
        duplicated_impulse.binding.as_str().as_ptr(),
        impulse.binding.as_str().as_ptr(),
        "heap-owning ledger identifiers must not be shallow aliases"
    );
    let duplicated_event = &duplicate
        .pending_qemu_events
        .get(&event_node)
        .unwrap_or_else(|| panic!("duplicated ledger should retain the node event"))[0];
    assert_eq!(duplicated_event, &retained_event);
    assert_ne!(
        duplicated_event.payload.as_ptr(),
        retained_event.payload.as_ptr(),
        "event evidence payloads must be duplicated through fallible storage"
    );
    assert!(
        runtime
            .update_qemu_action_ledger(std::slice::from_ref(&remove), committed(&remove, 4))
            .is_err()
    );
}

#[test]
fn immediate_qemu_event_must_match_the_exact_apply_result() {
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&action);
    let commit = CommittedQemuActionEvidence {
        command_sequence: event.header.rule_command_sequence,
        command_kind: event.header.command_kind as u16,
        before_hash: event.header.before_hash,
        after_hash: event.header.after_hash,
    };
    assert!(qemu_event_matches_commit(&event, &action, &commit));

    let mut wrong_sequence = event.clone();
    wrong_sequence.header.rule_command_sequence += 1;
    assert!(!qemu_event_matches_commit(
        &wrong_sequence,
        &action,
        &commit
    ));

    let mut wrong_before = event.clone();
    wrong_before.header.before_hash[0] ^= 1;
    assert!(!qemu_event_matches_commit(&wrong_before, &action, &commit));

    let mut wrong_after = event;
    wrong_after.header.after_hash[0] ^= 1;
    assert!(!qemu_event_matches_commit(&wrong_after, &action, &commit));
}

#[test]
fn armed_accelerator_event_matches_the_installing_apply_result() {
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let mut event = lifecycle_event(&action);
    event.header.command_kind = crucible_shmem::FaultCommandKind::AcceleratorResultTransform;
    let commit = CommittedQemuActionEvidence {
        command_sequence: event.header.rule_command_sequence,
        command_kind: event.header.command_kind as u16,
        before_hash: [41; 32],
        after_hash: [42; 32],
    };

    assert!(qemu_event_matches_commit(&event, &action, &commit));

    event.header.rule_command_sequence += 1;
    assert!(!qemu_event_matches_commit(&event, &action, &commit));
}

#[test]
fn checkpoint_rejects_unacknowledged_node_boot_edge() {
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"pending-node-boot"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime.pending_node_boot.insert(NodeId {
        name: String::from("node-a"),
    });

    assert!(matches!(
        runtime.checkpoint(&mut nodes),
        Err(ProductionFaultRuntimeError::PendingQemuFaultEvents)
    ));
    runtime.acknowledge_node_boot_requests();
    runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("acknowledged boot edge should checkpoint: {error}"));
}
