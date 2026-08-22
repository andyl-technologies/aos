//! Production checkpoint, replay, resource, and host-adapter tests.

use super::test_support::*;
use super::*;

#[path = "runtime_tests/recovery_tests.rs"]
mod recovery_tests;

fn pending_qemu_observation() -> FaultObservation {
    FaultObservation {
        semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
        kind: FaultObservationKind::EffectApplied,
        coordinate: FaultCoordinate {
            virtual_nanos: 7,
            retired_instructions: Some(11),
        },
        binding: Some(object_id("node-fault")),
        target: Some(ResolvedFaultTarget::Node {
            node: object_id("node-a"),
        }),
        opportunity: Some(ContentHash::from_bytes(b"node-opportunity")),
        evidence: ContentHash::from_bytes(b"qemu-evidence"),
    }
}

fn availability_plan(
    target: &ResolvedFaultTarget,
    phase: FaultPhase,
    state: NetworkAvailabilityState,
    queued_policy: NetworkInFlightPolicy,
    in_flight_policy: NetworkInFlightPolicy,
) -> FaultSignalPlan {
    let output = signal_id("network-down");
    let program = crucible::model::SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("test signal shape should be valid: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(true),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test signal program should be valid: {error}"));
    let targets = ResolvedTargetSet::new(vec![target.clone()], false)
        .unwrap_or_else(|error| panic!("test target set should be valid: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state,
            queued_policy,
            in_flight_policy,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
    let binding = FaultBinding::new(
        object_id("network-down-binding"),
        program.exported_outputs().to_vec(),
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(targets),
        [phase].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
    FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("test plan should be valid: {error}"))
}

fn finite_search_plan(target: &ResolvedFaultTarget) -> FaultSignalPlan {
    let output = signal_id("network-delay");
    let program = crucible::model::SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                .unwrap_or_else(|error| panic!("test signal shape should be valid: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(5),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test signal program should be valid: {error}"));
    let targets = ResolvedTargetSet::new(vec![target.clone()], false)
        .unwrap_or_else(|error| panic!("test target set should be valid: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("test delay should be valid: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
    let binding = FaultBinding::new(
        object_id("network-delay-binding"),
        program.exported_outputs().to_vec(),
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: crucible::model::MappedEffectParameter::DurationNanos,
            points: vec![
                crucible::model::BindingMapPoint {
                    input: SignalValue::U64(0),
                    output: SignalValue::DurationNanos(10),
                },
                crucible::model::BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(30),
                },
            ],
            rounding: crucible::model::SignalRounding::NearestTiesToEven,
            overflow: crucible::model::SignalOverflow::Error,
        },
        TargetSelector::Exact(targets),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::BranchParameter {
            parameter: crucible::model::MappedEffectParameter::DurationNanos,
            candidates: vec![
                SignalValue::DurationNanos(10),
                SignalValue::DurationNanos(20),
            ],
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("test binding should be valid: {error}"));
    FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("test plan should be valid: {error}"))
}

#[test]
fn production_search_choices_must_cross_scheduler_boundary_before_checkpoint() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("segment-a"),
        direction: FaultDirection::AToB,
    };
    let plan = finite_search_plan(&target);
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-search-choice"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("search runtime should initialize: {error}"));

    let evaluation = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            0,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("search boundary should evaluate: {error}"));
    assert_eq!(evaluation.search_choices.len(), 1);
    assert!(matches!(
        runtime.checkpoint(&mut nodes),
        Err(ProductionFaultRuntimeError::PendingSearchChoices)
    ));

    let pending = runtime.drain_search_choices();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1, evaluation.search_choices);
    runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("drained search choice should checkpoint: {error}"));
}

#[test]
fn empty_plan_checkpoint_preserves_custom_resource_identity() {
    let mut limits = FaultResourceLimits::default();
    limits.event_records -= 1;
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
        .unwrap_or_else(|error| panic!("custom empty plan should be valid: {error}"));
    let mut nodes = QemuNodeSet::new();
    let seed = ContentHash::from_bytes(b"custom-empty-plan");
    let runtime = ProductionFaultRuntime::new(
        plan.clone(),
        None,
        SignalBoundarySnapshot::default(),
        seed,
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    let checkpoint = runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("empty checkpoint should encode: {error}"));
    ProductionFaultRuntime::restore(
        plan,
        None,
        seed,
        checkpoint,
        test_host_manifests(),
        &mut nodes,
    )
    .unwrap_or_else(|error| panic!("custom empty checkpoint should restore: {error}"));
}

#[test]
fn production_checkpoint_preserves_runtime_resource_limit_coordinates() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("resource-limit-segment"),
        direction: FaultDirection::AToB,
    };
    let plan = availability_plan(
        &target,
        FaultPhase::Admit,
        NetworkAvailabilityState::Down,
        NetworkInFlightPolicy::Drop,
        NetworkInFlightPolicy::Drop,
    );
    let mut nodes = QemuNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        plan,
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"runtime-resource-limit"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("resource-limit runtime should initialize: {error}"));
    let checkpoint = runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("resource-limit checkpoint should capture: {error}"));

    assert!(matches!(
        checkpoint.to_canonical_bytes_with_limit(1),
        Err(ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
            field: "fat_checkpoint_bytes",
            configured: 1,
            hard: 68_719_476_736,
            ..
        })
    ));
}

#[test]
fn production_availability_survives_checkpoint_restore() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("segment-left-right"),
        direction: FaultDirection::AToB,
    };
    let plan = availability_plan(
        &target,
        FaultPhase::Admit,
        NetworkAvailabilityState::Down,
        NetworkInFlightPolicy::Drop,
        NetworkInFlightPolicy::Drop,
    );
    let artifacts: Arc<dyn SignalArtifactProvider> = Arc::new(NoArtifacts);
    let mut nodes = QemuNodeSet::new();
    let seed = ContentHash::from_bytes(b"production-availability-test");
    let coordinate = FaultCoordinate {
        virtual_nanos: 17,
        retired_instructions: None,
    };
    let mut runtime = ProductionFaultRuntime::new(
        plan.clone(),
        Some(Arc::clone(&artifacts)),
        SignalBoundarySnapshot::default(),
        seed,
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("production plan should be admitted: {error}"));

    let evaluation = runtime
        .evaluate_boundary(coordinate, 0, &mut nodes)
        .unwrap_or_else(|error| panic!("availability boundary should execute: {error}"));
    assert_eq!(evaluation.actions.len(), 1);
    let action = runtime
        .host_state()
        .matching(&target, FaultPhase::Admit)
        .next()
        .unwrap_or_else(|| panic!("availability action should be committed"));
    assert!(matches!(
        action.effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            ..
        })
    ));

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
    assert_eq!(
        restored
            .host_state()
            .matching(&target, FaultPhase::Admit)
            .count(),
        1
    );
}

#[test]
fn production_admits_every_availability_target_phase_state_and_policy() {
    let targets = [
        ResolvedFaultTarget::NetworkInterface {
            endpoint: object_id("endpoint-a"),
            interface: object_id("interface-a"),
        },
        ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-left-right"),
            direction: FaultDirection::AToB,
        },
        ResolvedFaultTarget::NetworkMedium {
            medium: object_id("medium-a"),
            resource: object_id("channel-a"),
        },
        ResolvedFaultTarget::NetworkQueue {
            owner: object_id("forwarder-a"),
            queue: object_id("queue-a"),
        },
        ResolvedFaultTarget::NetworkForwarder {
            forwarder: object_id("forwarder-a"),
        },
        ResolvedFaultTarget::NetworkPath {
            path_version: object_id("path-v1"),
            direction: FaultDirection::AToB,
        },
        ResolvedFaultTarget::NetworkAttachment {
            endpoint: object_id("endpoint-a"),
            interface: object_id("interface-a"),
            attachment: object_id("attachment-a"),
        },
        ResolvedFaultTarget::NetworkContact {
            plan: object_id("contact-plan-a"),
            endpoint_a: object_id("endpoint-a"),
            endpoint_b: object_id("endpoint-b"),
            contact: object_id("contact-a"),
        },
    ];
    let nodes = QemuNodeSet::new();
    for target in targets {
        for phase in [FaultPhase::Admit, FaultPhase::Resolve] {
            for state in [
                NetworkAvailabilityState::Up,
                NetworkAvailabilityState::Down,
                NetworkAvailabilityState::ReceiveOnly,
                NetworkAvailabilityState::TransmitOnly,
            ] {
                for queued in [
                    NetworkInFlightPolicy::Preserve,
                    NetworkInFlightPolicy::Reevaluate,
                    NetworkInFlightPolicy::Drop,
                    NetworkInFlightPolicy::TypedError,
                ] {
                    for in_flight in [
                        NetworkInFlightPolicy::Preserve,
                        NetworkInFlightPolicy::Reevaluate,
                        NetworkInFlightPolicy::Drop,
                        NetworkInFlightPolicy::TypedError,
                    ] {
                        let result = ProductionFaultRuntime::new(
                            availability_plan(&target, phase, state, queued, in_flight),
                            Some(Arc::new(NoArtifacts)),
                            SignalBoundarySnapshot::default(),
                            ContentHash::from_bytes(b"availability-admission-matrix"),
                            test_host_manifests(),
                            &nodes,
                        );
                        assert!(
                            result.is_ok(),
                            "target {:?}, phase {phase:?}, state {state:?}, policy pair {queued:?}/{in_flight:?}",
                            target.kind()
                        );
                    }
                }
            }
        }
    }
}
