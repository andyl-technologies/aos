//! Tests authored fault-resource admission against the resolved world.

use super::*;

#[test]
fn world_resource_admission_applies_authored_static_topology_limits() {
    let assert_limit = |limits: FaultResourceLimits,
                        world: &World,
                        expected_field: &'static str,
                        expected_requested: u64| {
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
            .unwrap_or_else(|error| panic!("empty bounded plan should build: {error}"));
        let error = match plan.validate_for_world(world) {
            Ok(()) => panic!("world usage above an authored limit must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            FaultSignalAuthoringError::ResourceLimit(FaultResourceLimitError::Exceeded {
                field,
                current: 0,
                requested,
                configured: 1,
                hard: _,
            }) if field == expected_field && requested == expected_requested
        ));
    };

    assert_limit(
        FaultResourceLimits {
            network_interfaces: 1,
            ..FaultResourceLimits::default()
        },
        &test_world(),
        "network_interfaces",
        2,
    );
    assert_limit(
        FaultResourceLimits {
            nodes: 1,
            ..FaultResourceLimits::default()
        },
        &test_world(),
        "nodes",
        2,
    );

    let mut node = test_world().vm_nodes()[0].clone();
    node.smp_vcpus = 2;
    let one_node = World::from_nodes_and_links(vec![node], Vec::new())
        .unwrap_or_else(|error| panic!("single SMP test world should build: {error}"));
    assert_limit(
        FaultResourceLimits {
            vcpus_per_node: 1,
            ..FaultResourceLimits::default()
        },
        &one_node,
        "vcpus_per_node",
        2,
    );

    let mut topology = test_world().fault_topology().clone();
    topology
        .storage_policy_artifacts
        .push(WorldStoragePolicyArtifact {
            id: object_id("bounded-storage-retries"),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::Path(StoragePolicyPath {
                selection: StoragePolicyPathSelection::ActivePassive,
                maximum_attempts: BoundedCount::new(CountLimit::LargeStateEntries, 3)
                    .unwrap_or_else(|error| panic!("storage attempts: {error}")),
                retry_delay_nanos: PositiveU64::new("storage retry delay", 1)
                    .unwrap_or_else(|error| panic!("storage retry delay: {error}")),
                recovery_probe_interval_nanos: PositiveU64::new("storage recovery probe", 1)
                    .unwrap_or_else(|error| panic!("storage recovery probe: {error}")),
                retry_results: vec![StoragePolicyResult::IoError],
            }),
        });
    let storage_retry_world = test_world()
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("storage retry resource world: {error}"));
    assert_limit(
        FaultResourceLimits {
            storage_retries_per_operation: 1,
            ..FaultResourceLimits::default()
        },
        &storage_retry_world,
        "storage_retries_per_operation",
        2,
    );

    let mut topology = test_world().fault_topology().clone();
    topology
        .network_policy_artifacts
        .push(WorldNetworkPolicyArtifact {
            id: object_id("bounded-contention"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::MediumAccess(NetworkPolicyMediumAccess {
                arbitration: NetworkPolicyArbitration::Contention,
                arbitration_key: None,
                fixed_slot_nanos: None,
                contention: Some(NetworkPolicyContention {
                    collision: NetworkPolicyCollision::DropAll,
                    capture_threshold_millionths: None,
                    undetected_transform: None,
                    backoff_slot_nanos: PositiveU64::new("backoff", 1)
                        .unwrap_or_else(|error| panic!("contention backoff: {error}")),
                    maximum_backoff_exponent: 1,
                    maximum_retries: 2,
                }),
                duty_cycle_numerator: PositiveU64::new("duty", 1)
                    .unwrap_or_else(|error| panic!("contention duty numerator: {error}")),
                duty_cycle_denominator: PositiveU64::new("duty", 1)
                    .unwrap_or_else(|error| panic!("contention duty denominator: {error}")),
            }),
        });
    let retry_world = test_world()
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("contention resource world: {error}"));
    assert_limit(
        FaultResourceLimits {
            network_retries_per_frame_per_hop: 1,
            ..FaultResourceLimits::default()
        },
        &retry_world,
        "network_retries_per_frame_per_hop",
        2,
    );

    let assert_effect_limit = |effect: NetworkEffectSpecification,
                               limits: FaultResourceLimits,
                               expected_field: &'static str,
                               expected_requested: u64| {
        assert!(matches!(
            world_resource_limits::validate_network_effect_specification_resource_limits(
                limits, &effect,
            ),
            Err(FaultSignalAuthoringError::ResourceLimit(
                FaultResourceLimitError::Exceeded {
                    field,
                    current: 0,
                    requested,
                    configured: 1,
                    hard: _,
                }
            )) if field == expected_field && requested == expected_requested
        ));
    };
    let count = || {
        BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 2)
            .unwrap_or_else(|error| panic!("bounded network effect count: {error}"))
    };
    assert_effect_limit(
        NetworkEffectSpecification::Duplicate {
            probability: ProbabilityMillionths::new(1)
                .unwrap_or_else(|error| panic!("duplicate probability: {error}")),
            gap_nanos: 0,
            copies: count(),
        },
        FaultResourceLimits {
            network_duplicates_per_frame_per_hop: 1,
            ..FaultResourceLimits::default()
        },
        "network_duplicates_per_frame_per_hop",
        2,
    );
    assert_effect_limit(
        NetworkEffectSpecification::DetectedFrameError {
            kind: DetectedFrameErrorKind::Crc,
            receiver_action: DetectedFrameErrorAction::Retry,
            retry_delay_nanos: Some(
                PositiveU64::new("retry delay", 1)
                    .unwrap_or_else(|error| panic!("retry delay: {error}")),
            ),
            retry_limit: Some(count()),
            retry_attempts: Some(
                BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 1)
                    .unwrap_or_else(|error| panic!("retry attempts: {error}")),
            ),
            retry_succeeds: Some(true),
            reset_nanos: None,
        },
        FaultResourceLimits {
            network_retries_per_frame_per_hop: 1,
            ..FaultResourceLimits::default()
        },
        "network_retries_per_frame_per_hop",
        2,
    );
    assert_effect_limit(
        NetworkEffectSpecification::ForwardingMutation {
            selector: object_id("forwarding-selector"),
            mutation: NetworkForwardingMutationKind::Loop {
                next_hop: object_id("left"),
                hop_limit: PositiveU64::new("hop limit", 2)
                    .unwrap_or_else(|error| panic!("loop hop limit: {error}")),
            },
        },
        FaultResourceLimits {
            network_loop_hops: 1,
            ..FaultResourceLimits::default()
        },
        "network_loop_hops",
        2,
    );

    let program = program(true);
    let binding = binding_with_network_effect(
        &program,
        NetworkEffectSpecification::ForwardingMutation {
            selector: object_id("forwarding-selector"),
            mutation: NetworkForwardingMutationKind::Loop {
                next_hop: object_id("left"),
                hop_limit: PositiveU64::new("hop limit", 2)
                    .unwrap_or_else(|error| panic!("loop hop limit: {error}")),
            },
        },
    );
    let plan = FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits {
            network_loop_hops: 1,
            ..FaultResourceLimits::default()
        },
    )
    .unwrap_or_else(|error| panic!("bounded forwarding plan should build: {error}"));
    assert!(matches!(
        plan.validate_for_world(&test_world()),
        Err(FaultSignalAuthoringError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "network_loop_hops",
                current: 0,
                requested: 2,
                configured: 1,
                hard: _,
            }
        ))
    ));
}

fn binding_with_network_effect(
    program: &SignalProgram,
    effect: NetworkEffectSpecification,
) -> FaultBinding {
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: test_segment_id(),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("network resource test target: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(effect),
    )
    .unwrap_or_else(|error| panic!("network resource test effect: {error}"));
    FaultBinding::new(
        object_id("network-resource-binding"),
        program.exported_outputs().to_vec(),
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )
    .unwrap_or_else(|error| panic!("network resource test binding: {error}"))
}
