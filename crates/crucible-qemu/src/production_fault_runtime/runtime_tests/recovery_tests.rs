//! Recovery-event, rejection, resource-limit, and identity tests.

use super::*;

#[test]
fn live_host_fault_event_drain_reaches_production_authentication() {
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&action);
    let commit = CommittedQemuActionEvidence {
        command_sequence: event.header.rule_command_sequence,
        command_kind: event.header.command_kind as u16,
        before_hash: event.header.before_hash,
        after_hash: event.header.after_hash,
    };
    let host_runtime =
        crate::supervision::host_io_runtime::tests::staged_fault_event_runtime(event.clone())
            .unwrap_or_else(|error| panic!("real host runtime should stage the event: {error}"));
    let mut nodes = QemuNodeSet::new();
    let node = NodeId {
        name: String::from("node-a"),
    };
    let _prior = nodes.insert(
        node.clone(),
        crate::node::tests::host_io_runtime::scripted_node_with_live_host_runtime(host_runtime)
            .unwrap_or_else(|error| panic!("live-host test node should build: {error}")),
    );
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"live-host-event-authentication"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("production runtime should initialize: {error}"));
    runtime
        .update_qemu_action_ledger(std::slice::from_ref(&action), vec![(action.id(), commit)])
        .unwrap_or_else(|error| panic!("authenticated action should enter the ledger: {error}"));

    let intents = runtime
        .preview_node_lifecycle_intents(action.coordinate, 0, &mut nodes)
        .unwrap_or_else(|error| panic!("event preview should authenticate: {error}"));
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].action, action.id());
    assert_eq!(
        intents[0].event_evidence,
        Some(ContentHash {
            bytes: Sha256::digest({
                let mut normalized = event.payload.clone();
                normalized[24..32].fill(0);
                normalized
            })
            .into(),
        })
    );
    assert_eq!(
        nodes
            .staged_fault_event_count()
            .unwrap_or_else(|error| panic!(
                "previewed event count should remain readable: {error}"
            )),
        1
    );

    runtime
        .drain_qemu_observations(&mut nodes, action.coordinate, 0)
        .unwrap_or_else(|error| panic!("production host drain should authenticate: {error}"));

    assert_eq!(runtime.pending_qemu_events.len(), 0);
    assert_eq!(runtime.pending_qemu_observations.len(), 1);
    assert_eq!(
        runtime.pending_qemu_observations[0].coordinate,
        action.coordinate
    );
    assert_eq!(runtime.pending_node_lifecycle.len(), 1);
    assert_eq!(
        nodes
            .staged_fault_event_count()
            .unwrap_or_else(|error| panic!("staged event count should be readable: {error}")),
        0
    );
    nodes
        .take(&node)
        .unwrap_or_else(|| panic!("live-host test node should remain present"))
        .shutdown_child()
        .unwrap_or_else(|error| panic!("live-host test node should shut down: {error}"));
}

#[test]
fn production_checkpoints_referenced_storage_recovery_events() {
    let active = signal_id("stall-transition");
    let recovery = signal_id("storage-recovered");
    let schema = signal_id("storage-recovery-v1");
    let transition_schema = signal_id("storage-transition-v1");
    let transition_value = SignalValue::Event {
        schema: transition_schema.clone(),
        payload: vec![1],
    };
    let program = crucible::model::SignalProgram::new(
        vec![
            SignalNode {
                id: active.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(transition_schema),
                    SignalUnit::Dimensionless,
                    0,
                )
                .unwrap_or_else(|error| panic!("test signal shape should be valid: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 0 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: transition_value.clone(),
                    }],
                }),
            },
            SignalNode {
                id: recovery.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .unwrap_or_else(|error| panic!("test event shape should be valid: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 5 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema,
                            payload: vec![1],
                        },
                    }],
                }),
            },
        ],
        vec![active.clone(), recovery.clone()],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test signal program should be valid: {error}"));
    let target = ResolvedFaultTarget::BlockDevice {
        device: ContentHash::from_bytes(b"storage-recovery-device"),
    };
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Storage(StorageEffectSpecification::StallTimeout {
            stall_nanos: PositiveU64::new("stall_nanos", 20)
                .unwrap_or_else(|error| panic!("test stall should be positive: {error}")),
            recovery_event: Some(object_id(recovery.as_str())),
            timeout_result: object_id("timeout-result"),
        }),
    )
    .unwrap_or_else(|error| panic!("test stall effect should be valid: {error}"));
    let transition_table = object_id("storage-stall-transition-table");
    let mapping_registry = BindingMappingRegistry::new(
        vec![StateTransitionTableDeclaration {
            id: transition_table.clone(),
            semantic_version: 1,
            input: transition_value
                .value_type()
                .unwrap_or_else(|| panic!("test transition value should be typed")),
            effect: EffectKind::StorageStallTimeout,
            transitions: [(transition_value, object_id("retain-completion"))]
                .into_iter()
                .collect(),
            default_transition: object_id("retain-completion"),
        }],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test mapping registry should be valid: {error}"));
    let binding = FaultBinding::new_with_registry(
        object_id("storage-stall-binding"),
        vec![active],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::StateTransition { transition_table },
        TargetSelector::Exact(
            ResolvedTargetSet::new(vec![target], false)
                .unwrap_or_else(|error| panic!("test target should be valid: {error}")),
        ),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
        &mapping_registry,
    )
    .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
    let plan = FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("test plan should be valid: {error}"));
    let artifacts: Arc<dyn SignalArtifactProvider> = Arc::new(NoArtifacts);
    let mut nodes = QemuNodeSet::new();
    let seed = ContentHash::from_bytes(b"storage-recovery-event-test");
    let mut runtime = ProductionFaultRuntime::new(
        plan.clone(),
        Some(Arc::clone(&artifacts)),
        SignalBoundarySnapshot::default(),
        seed,
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("production plan should be admitted: {error}"));

    let first = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            0,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("initial boundary should execute: {error}"));
    assert_eq!(first.next_wakeup_nanos, Some(5));
    assert!(first.emitted_events.is_empty());
    let recovered = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 5,
                retired_instructions: None,
            },
            0,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("recovery boundary should execute: {error}"));
    assert_eq!(recovered.emitted_events.len(), 1);
    assert_eq!(recovered.emitted_events[0].signal, recovery);

    let checkpoint = runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("production checkpoint should succeed: {error}"));
    let restored = ProductionFaultRuntime::restore(
        plan,
        Some(artifacts),
        seed,
        checkpoint,
        test_host_manifests(),
        &mut nodes,
    )
    .unwrap_or_else(|error| panic!("production checkpoint should restore: {error}"));
    assert_eq!(restored.emitted_events(), runtime.emitted_events());
}

#[test]
fn rejected_qemu_event_validation_retains_the_raw_event() {
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"retain-rejected-qemu-event"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    let node = NodeId {
        name: String::from("node-a"),
    };
    let payload = vec![1, 2, 3];
    let event = DequeuedFaultEvent {
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
            evidence_hash: [7; 32],
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: u32::try_from(payload.len())
                .unwrap_or_else(|_| panic!("test payload length should fit")),
        },
        payload,
    };
    runtime
        .pending_qemu_events
        .try_insert(node.clone(), vec![event.clone()])
        .unwrap_or_else(|error| panic!("pending event fixture should allocate: {error}"));

    let result = runtime.drain_qemu_observations(
        &mut nodes,
        FaultCoordinate {
            virtual_nanos: 1,
            retired_instructions: Some(1),
        },
        0,
    );

    assert!(result.is_err());
    assert_eq!(
        runtime.pending_qemu_events.get(&node),
        Some(&vec![event.clone()])
    );

    let mut second = event.clone();
    second.header.event_sequence = 2;
    let sequences = BTreeMap::from([(node.clone(), 3)]);
    let mut pending = PendingQemuEventMap::new();
    pending
        .try_insert(node.clone(), vec![event.clone(), second.clone()])
        .unwrap_or_else(|error| panic!("pending sequence fixture should allocate: {error}"));
    assert!(validate_pending_qemu_event_sequences(&pending, &sequences).is_ok());
    second.header.event_sequence = 3;
    let mut noncontiguous = PendingQemuEventMap::new();
    noncontiguous
        .try_insert(node, vec![event, second])
        .unwrap_or_else(|error| panic!("noncontiguous fixture should allocate: {error}"));
    assert!(validate_pending_qemu_event_sequences(&noncontiguous, &sequences).is_err());
}

#[test]
fn production_event_limits_cover_all_retained_event_classes_in_aggregate() {
    let limits = FaultResourceLimits {
        event_records: 1,
        ..FaultResourceLimits::default()
    };
    let observations = vec![pending_qemu_observation(), pending_qemu_observation()];

    assert!(
        validate_production_event_state(
            &[],
            &[],
            &observations,
            &[],
            &PendingQemuEventMap::new(),
            limits,
        )
        .is_err()
    );
}

#[test]
fn qemu_event_staging_uses_remaining_aggregate_ledger_capacity() {
    let limits = FaultResourceLimits {
        event_records: 2,
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
        .unwrap_or_else(|error| panic!("empty aggregate-limit plan should be valid: {error}"));
    let nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"aggregate-event-ledger"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("aggregate-limit runtime should initialize: {error}"));
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let identity = action.id();
    runtime
        .qemu_issued_actions
        .try_insert(identity, action)
        .unwrap_or_else(|error| panic!("issued-action fixture should allocate: {error}"));
    runtime
        .qemu_action_commits
        .try_insert(
            identity,
            CommittedQemuActionEvidence {
                command_sequence: 1,
                command_kind: crucible_shmem::FaultCommandKind::NodeLifecycle as u16,
                before_hash: [1; 32],
                after_hash: [2; 32],
            },
        )
        .unwrap_or_else(|error| panic!("commit fixture should allocate: {error}"));

    assert_eq!(
        runtime
            .event_staging_capacity(&[], None)
            .unwrap_or_else(|error| panic!("aggregate capacity should be exact: {error}")),
        0
    );
}

#[test]
fn pending_qemu_observation_identity_covers_kind_binding_and_target() {
    let original = pending_qemu_observation();
    let limits = FaultResourceLimits::default();
    let original_material = observation_identity_material(&original, limits)
        .unwrap_or_else(|error| panic!("observation should encode: {error}"));
    let target = original
        .target
        .as_ref()
        .unwrap_or_else(|| panic!("observation fixture should carry a target"));
    let mut target_bytes = Vec::new();
    target_bytes
        .try_reserve_exact(target.canonical_material_length())
        .unwrap_or_else(|error| panic!("target fixture reservation should succeed: {error}"));
    target
        .append_canonical_material_bytes(&mut target_bytes)
        .unwrap_or_else(|error| panic!("reserved target fixture should encode: {error}"));
    assert_eq!(target_bytes, target.canonical_material().as_bytes());

    let mut changed_kind = original.clone();
    changed_kind.kind = FaultObservationKind::FaultOpportunity;
    let mut changed_binding = original.clone();
    changed_binding.binding = Some(object_id("other-binding"));
    let mut changed_target = original;
    changed_target.target = Some(ResolvedFaultTarget::Node {
        node: object_id("node-b"),
    });

    for changed in [changed_kind, changed_binding, changed_target] {
        assert_ne!(
            observation_identity_material(&changed, limits)
                .unwrap_or_else(|error| panic!("changed observation should encode: {error}")),
            original_material
        );
    }
}

#[test]
fn pending_qemu_observation_identity_reserves_before_growth() {
    let observation = pending_qemu_observation();
    let limits = FaultResourceLimits {
        event_log_bytes: 1,
        ..FaultResourceLimits::default()
    };

    assert!(matches!(
        observation_identity_material(&observation, limits),
        Err(ProductionFaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "event_log_bytes",
                current: 0,
                requested,
                configured: 1,
                hard: 274_877_906_944,
            }
        )) if requested > 1
    ));
}

#[test]
fn pending_observation_reports_the_exhausted_checkpoint_resource() {
    let observation = pending_qemu_observation();
    let limits = FaultResourceLimits {
        fat_checkpoint_bytes: 64,
        ..FaultResourceLimits::default()
    };

    assert!(matches!(
        observation_identity_material_at_checkpoint_offset(&observation, limits, 63),
        Err(ProductionFaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "fat_checkpoint_bytes",
                current: 63,
                requested,
                configured: 64,
                hard: 68_719_476_736,
            }
        )) if requested > 1
    ));
}
