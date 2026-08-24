//! QEMU lifecycle and occurrence-ledger tests.

use super::test_support::*;
use super::*;

#[test]
fn lifecycle_intent_preview_is_action_exact_and_ignores_active_hang_rules() {
    let terminal = lifecycle_action(NodeLifecycleTransition::Crash, NodeBootPolicy::Immediate);
    let mut active_hang = terminal.clone();
    active_hang.kind = BindingActionKind::UpsertPersistent;
    active_hang.binding = object_id("node-hang-a");
    active_hang.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Node(NodeEffectSpecification::Hang {
                scope: NodeHangScope::Node,
                recovery_event: object_id("node-recovered"),
                watchdog_policy: NodeWatchdogPolicy::TransitionAfter {
                    timeout_nanos: PositiveU64::new("timeout_nanos", 17)
                        .unwrap_or_else(|error| panic!("test timeout should be valid: {error}")),
                    transition: NodeLifecycleTransition::PowerOff,
                    downtime_nanos: 0,
                    boot_policy: NodeBootPolicy::Immediate,
                    volatile_state_policy: NodeStatePolicy::Preserve,
                    device_state_policy: NodeStatePolicy::Clear,
                },
            }),
        )
        .unwrap_or_else(|error| panic!("test hang effect should be valid: {error}")),
    );
    let mut second_hang = active_hang.clone();
    second_hang.binding = object_id("node-hang-b");
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"lifecycle-intent-preview"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime
        .qemu_issued_actions
        .try_insert(active_hang.id(), active_hang.clone())
        .unwrap_or_else(|error| panic!("first hang should enter the test ledger: {error}"));
    runtime
        .qemu_issued_actions
        .try_insert(second_hang.id(), second_hang.clone())
        .unwrap_or_else(|error| panic!("second hang should enter the test ledger: {error}"));
    runtime
        .qemu_active_rule_ids
        .try_insert(active_hang.id())
        .unwrap_or_else(|error| panic!("first hang identity should enter the set: {error}"));
    runtime
        .qemu_active_rule_ids
        .try_insert(second_hang.id())
        .unwrap_or_else(|error| panic!("second hang identity should enter the set: {error}"));
    let event = lifecycle_event(&terminal);
    runtime.pending_node_lifecycle.push(
        node_lifecycle_decision(
            &NodeId {
                name: "node-a".to_owned(),
            },
            terminal.id(),
            &event,
            0,
            FaultResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("terminal evidence should authenticate: {error}"))
        .unwrap_or_else(|| panic!("terminal evidence should produce lifecycle work")),
    );

    let intents = runtime
        .preview_node_lifecycle_intents(
            FaultCoordinate {
                virtual_nanos: 17,
                retired_instructions: None,
            },
            0,
            &mut QemuNodeSet::new(),
        )
        .unwrap_or_else(|error| panic!("lifecycle intent preview should succeed: {error}"));

    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].action, terminal.id());
    assert_eq!(intents[0].node.name, "node-a");
    assert_eq!(
        intents[0].requested_transition,
        NodeLifecycleTransition::Crash
    );
}

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
        0,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("terminal decision should allocate: {error}"))
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
fn boot_ready_exhaustion_preserves_requested_intent_and_effective_terminal_decision() {
    let boot = lifecycle_action(
        NodeLifecycleTransition::Boot,
        NodeBootPolicy::RequireReady {
            ready_marker: object_id("guest-ready"),
            maximum_attempts: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 2)
                .unwrap_or_else(|error| panic!("test attempt count should be valid: {error}")),
            retry_delay_nanos: 4096,
            exhausted: NodeLifecycleTransition::PowerOff,
        },
    );
    let mut event = lifecycle_event(&boot);
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
    assert!(validate_node_event_evidence(&event, &boot).is_ok());

    let decision = node_lifecycle_decision(
        &NodeId {
            name: "node-a".to_owned(),
        },
        boot.id(),
        &event,
        0,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("terminal decision should allocate: {error}"))
    .unwrap_or_else(|| panic!("exhaustion should produce a supervision decision"));
    assert_eq!(
        decision.requested_transition,
        NodeLifecycleTransition::Boot
    );
    assert_eq!(
        decision.effective_transition,
        NodeLifecycleTransition::PowerOff
    );
    assert_eq!(decision.expected_exit_code, Some(71));

    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"boot-ready-exhaustion"),
        test_host_manifests(),
        &QemuNodeSet::new(),
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime.pending_node_lifecycle.push(decision);

    let intents = runtime
        .preview_node_lifecycle_intents(
            FaultCoordinate {
                virtual_nanos: 17,
                retired_instructions: None,
            },
            0,
            &mut QemuNodeSet::new(),
        )
        .unwrap_or_else(|error| panic!("exhausted Boot intent should preview: {error}"));
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].requested_transition, NodeLifecycleTransition::Boot);

    let work = runtime
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("exhausted Boot work should transfer: {error}"));
    assert_eq!(work.decisions().len(), 1);
    assert_eq!(
        work.decisions()[0].requested_transition,
        NodeLifecycleTransition::Boot
    );
    assert_eq!(
        work.decisions()[0].effective_transition,
        NodeLifecycleTransition::PowerOff
    );
    assert_eq!(
        work.decisions()[0].cause,
        LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED
    );
    assert_eq!(work.decisions()[0].expected_exit_code, Some(71));
    runtime
        .acknowledge_node_lifecycle_work(work)
        .unwrap_or_else(|error| panic!("exhausted Boot work should acknowledge: {error}"));
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
        vec![(
            action.id(),
            CommittedQemuActionEvidence {
                command_sequence,
                command_kind: crucible_shmem::FaultCommandKind::NodeLifecycle as u16,
                before_hash: [command_sequence as u8; 32],
                after_hash: [command_sequence as u8 + 1; 32],
            },
        )]
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
    let staged_impulse = runtime
        .stage_qemu_action_ledger(std::slice::from_ref(&impulse))
        .unwrap_or_else(|error| panic!("impulse ledger storage should stage: {error}"));
    assert_eq!(runtime.qemu_issued_actions.len(), 0);
    assert_eq!(runtime.qemu_action_commits.len(), 0);
    assert_eq!(runtime.qemu_active_rule_ids.len(), 0);
    assert_eq!(runtime.qemu_issued_actions.capacity(), 1);
    assert_eq!(runtime.qemu_action_commits.capacity(), 1);
    runtime
        .commit_staged_qemu_action_ledger(staged_impulse, committed(&impulse, 1))
        .unwrap_or_else(|error| panic!("impulse should enter issued ledger: {error}"));
    assert_eq!(
        runtime.qemu_issued_actions.get(&impulse.id()),
        Some(&impulse)
    );

    let mut persistent = impulse.clone();
    persistent.kind = BindingActionKind::UpsertPersistent;
    persistent.binding = object_id("node-hang");
    persistent.transition_sequence = 2;
    let staged_persistent = runtime
        .stage_qemu_action_ledger(std::slice::from_ref(&persistent))
        .unwrap_or_else(|error| panic!("persistent ledger storage should stage: {error}"));
    assert_eq!(runtime.qemu_active_rule_ids.len(), 0);
    assert!(runtime.qemu_active_rule_ids.capacity() >= 1);
    runtime
        .commit_staged_qemu_action_ledger(staged_persistent, committed(&persistent, 2))
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
    runtime.pending_node_boot.push(NodeId {
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

#[test]
fn lifecycle_work_transfer_preserves_buffers_and_holds_checkpoint_barrier_until_ack() {
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&action);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let decision = node_lifecycle_decision(
        &node,
        action.id(),
        &event,
        0,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("lifecycle evidence should authenticate: {error}"))
    .unwrap_or_else(|| panic!("lifecycle evidence should produce a decision"));
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"lifecycle-work-transfer"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime.pending_node_lifecycle.push(decision);
    runtime.pending_node_boot.push(node);
    let decision_storage = runtime.pending_node_lifecycle.as_ptr();
    let boot_storage = runtime.pending_node_boot.as_ptr();

    let work = runtime
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("lifecycle work should transfer: {error}"));

    assert_eq!(work.decisions().as_ptr(), decision_storage);
    assert_eq!(work.boot_requests().as_ptr(), boot_storage);
    assert!(runtime.node_lifecycle_decisions().is_empty());
    assert!(runtime.node_boot_requests().is_empty());
    assert!(matches!(
        runtime.checkpoint(&mut nodes),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
    assert!(matches!(
        runtime.take_node_lifecycle_work(),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
    runtime
        .acknowledge_node_lifecycle_work(work)
        .unwrap_or_else(|error| panic!("owned lifecycle work should acknowledge: {error}"));
    runtime.checkpoint(&mut nodes).unwrap_or_else(|error| {
        panic!("acknowledged lifecycle ownership should checkpoint: {error}")
    });
    let empty = runtime
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("empty lifecycle work should transfer: {error}"));
    runtime
        .acknowledge_node_lifecycle_work(empty)
        .unwrap_or_else(|error| panic!("empty lifecycle work should acknowledge: {error}"));
}
