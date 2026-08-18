//! Tests for production network-fault runtime behavior.

use std::sync::Arc;

use super::*;

#[test]
fn production_fault_cursor_sequences_only_within_one_coordinate() {
    let mut cursor = ProductionFaultEvaluationCursor::default();
    let first = cursor
        .next_sequence(10)
        .unwrap_or_else(|error| panic!("{error}"));
    let second = cursor
        .next_sequence(10)
        .unwrap_or_else(|error| panic!("{error}"));
    let third = cursor
        .next_sequence(11)
        .unwrap_or_else(|error| panic!("{error}"));
    let fourth = cursor
        .next_sequence(11)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!((first.same_coordinate, first.journal), (0, 0));
    assert_eq!((second.same_coordinate, second.journal), (1, 1));
    assert_eq!((third.same_coordinate, third.journal), (0, 2));
    assert_eq!((fourth.same_coordinate, fourth.journal), (1, 3));
}

#[test]
fn production_journal_sequence_never_reuses_an_a_b_a_coordinate() {
    let mut cursor = ProductionFaultEvaluationCursor::default();
    let first = cursor
        .next_sequence(10)
        .unwrap_or_else(|error| panic!("{error}"));
    let second = cursor
        .next_sequence(20)
        .unwrap_or_else(|error| panic!("{error}"));
    let third = cursor
        .next_sequence(10)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!((first.same_coordinate, first.journal), (0, 0));
    assert_eq!((second.same_coordinate, second.journal), (0, 1));
    assert_eq!((third.same_coordinate, third.journal), (0, 2));
    assert_eq!(cursor.coordinate, Some(10));
    assert_eq!(cursor.coordinate_sequence, 0);
    assert_eq!(cursor.journal_sequence, 3);
}

use crucible::model::{
    BindingActionCause, BindingMapping, BindingObservabilityPolicy, BindingSampling,
    BindingSearchPolicy, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EvaluatedSignal,
    FaultBinding, FaultDirection, FaultOperation, FaultResourceLimits, InverseCdfTable,
    NetworkInFlightPolicy, ResolvedFaultTarget, ResolvedMappingOutput, ResolvedTargetSet,
    SampleObservation, SignalChoiceContext, SignalCoordinate, SignalDomain, SignalEvaluationError,
    SignalId, SignalNode, SignalNodeKind, SignalResourceLimits, SignalShape,
    SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType, TargetSelector,
    WorldNetworkInterface, WorldNetworkSegment, WorldNetworkSegmentKind, WorldNetworkTechnology,
};
use crucible::{
    BackendNetworkOutput, Icount, LinkDef, MemoryDagStore, QuantumLoop, ReadyPoint,
    SchedulerLivenessScenario, Shift, SimInstant, VmArchitecture, WhiteBoxPolicy,
    WorldIoLayoutPolicy, WorldNode, deterministic_node_mac,
};

struct NoArtifacts;

impl crucible::model::SignalArtifactProvider for NoArtifacts {
    fn inverse_cdf_table(
        &self,
        content: &ContentHash,
    ) -> Result<InverseCdfTable, SignalEvaluationError> {
        Err(SignalEvaluationError::ArtifactContentMismatch(*content))
    }

    fn evaluate_artifact_source(
        &self,
        node: &SignalNode,
        _source: &SignalSourceSpecification,
        _coordinate: &SignalCoordinate,
        _same_coordinate_sequence: u64,
        _choice: &SignalChoiceContext,
        _inputs: &[EvaluatedSignal],
        _resource_limits: FaultResourceLimits,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        Err(SignalEvaluationError::ArtifactSourceRequired(
            node.id.clone(),
        ))
    }
}

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("test signal ID should be valid: {error}"))
}

fn node(name: &str) -> WorldNode {
    WorldNode {
        id: crucible::NodeId {
            name: name.to_owned(),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn availability_world() -> (crucible::World, FaultObjectId) {
    let link = LinkDef::new(
        crucible::NodeId {
            name: String::from("left"),
        },
        crucible::NodeId {
            name: String::from("right"),
        },
    )
    .unwrap_or_else(|error| panic!("test link should be valid: {error}"));
    let segment = link
        .fault_segment_id()
        .unwrap_or_else(|error| panic!("test segment ID should be valid: {error}"));
    let segment_signal = SignalId::parse(segment.as_str())
        .unwrap_or_else(|error| panic!("test segment signal ID should be valid: {error}"));
    let topology = crucible::model::WorldFaultTopology {
        network_interfaces: vec![
            WorldNetworkInterface {
                id: signal_id("left-interface"),
                endpoint: signal_id("left"),
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
            WorldNetworkInterface {
                id: signal_id("right-interface"),
                endpoint: signal_id("right"),
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            },
        ],
        network_segments: vec![WorldNetworkSegment {
            id: segment_signal,
            kind: WorldNetworkSegmentKind::Ethernet,
            interface_a: signal_id("left-interface"),
            interface_b: signal_id("right-interface"),
            minimum_latency_nanos: 1,
            mtu_bytes: 1500,
            medium: None,
            forwarders: Vec::new(),
            fault_domains: Vec::new(),
        }],
        ..crucible::model::WorldFaultTopology::default()
    };
    let world =
        crucible::World::from_nodes_and_links(vec![node("left"), node("right")], vec![link])
            .unwrap_or_else(|error| panic!("test World should be valid: {error}"))
            .with_fault_topology(topology)
            .unwrap_or_else(|error| panic!("test fault topology should be valid: {error}"));
    (world, segment)
}

fn down_plan(segment: FaultObjectId) -> crucible::model::FaultSignalPlan {
    down_plan_at(segment, FaultPhase::Admit)
}

fn down_plan_at(segment: FaultObjectId, phase: FaultPhase) -> crucible::model::FaultSignalPlan {
    down_plan_with_policies(
        segment,
        phase,
        NetworkInFlightPolicy::Drop,
        NetworkInFlightPolicy::Drop,
    )
}

fn down_plan_with_policies(
    segment: FaultObjectId,
    phase: FaultPhase,
    queued_policy: NetworkInFlightPolicy,
    in_flight_policy: NetworkInFlightPolicy,
) -> crucible::model::FaultSignalPlan {
    let output = signal_id("network-down");
    let program = crucible::model::SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("test shape should be valid: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(true),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test program should be valid: {error}"));
    let targets = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment,
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("test targets should be valid: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
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
    crucible::model::FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test plan should be valid: {error}"))
}

#[test]
fn directional_availability_has_a_closed_lattice() {
    for direction in [
        FaultDirection::AToB,
        FaultDirection::BToA,
        FaultDirection::Ingress,
        FaultDirection::Egress,
    ] {
        assert!(availability_allows(NetworkAvailabilityState::Up, direction));
        assert!(!availability_allows(
            NetworkAvailabilityState::Down,
            direction
        ));
    }
    assert!(availability_allows(
        NetworkAvailabilityState::ReceiveOnly,
        FaultDirection::Ingress
    ));
    assert!(!availability_allows(
        NetworkAvailabilityState::ReceiveOnly,
        FaultDirection::Egress
    ));
    assert!(availability_allows(
        NetworkAvailabilityState::TransmitOnly,
        FaultDirection::Egress
    ));
    assert!(!availability_allows(
        NetworkAvailabilityState::TransmitOnly,
        FaultDirection::Ingress
    ));
}

#[test]
fn production_boundary_drops_a_preexisting_world_link_frame() {
    let (world, segment) = availability_world();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-availability-drop",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    let source = crucible::NodeId {
        name: String::from("left"),
    };
    let destination = crucible::NodeId {
        name: String::from("right"),
    };
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    QuantumLoop::append_backend_network_outputs(
        &mut scheduler,
        vec![BackendNetworkOutput {
            source: source.clone(),
            destination: destination.clone(),
            emit_icount: Icount { retired: 0 },
            sequence: 1,
            payload,
            route: None,
            fault_continuation: Default::default(),
        }],
    )
    .unwrap_or_else(|error| panic!("test frame should route: {error}"));

    let nodes = ProductionNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        down_plan(segment.clone()),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-availability-drop"),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
    let mut interceptor = ProductionFaultNetworkInterceptor::new(
        runtime,
        world.fault_topology().clone(),
        world.links().to_vec(),
    );
    let mut nodes = nodes;
    let mut queued_forward_payload = vec![0_u8; 14];
    queued_forward_payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    let mut queued_reverse_payload = vec![0_u8; 14];
    queued_reverse_payload[..6].copy_from_slice(&deterministic_node_mac(&source));
    let mut pending_outputs = vec![
        BackendNetworkOutput {
            source: source.clone(),
            destination: destination.clone(),
            emit_icount: Icount { retired: 7 },
            sequence: 2,
            payload: queued_forward_payload,
            route: None,
            fault_continuation: Default::default(),
        },
        BackendNetworkOutput {
            source: destination.clone(),
            destination: source.clone(),
            emit_icount: Icount { retired: 8 },
            sequence: 3,
            payload: queued_reverse_payload,
            route: None,
            fault_continuation: Default::default(),
        },
    ];
    let append = interceptor
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            &mut scheduler,
            &mut nodes,
            &mut pending_outputs,
        )
        .unwrap_or_else(|error| panic!("availability boundary should execute: {error}"));

    assert!(!append.entries.is_empty());
    assert_eq!(interceptor.transition_ledger.len(), 1);
    let transition = interceptor
        .transition_ledger
        .values()
        .next()
        .unwrap_or_else(|| panic!("transition ledger should contain the applied action"));
    assert_eq!(transition.in_flight.frame_count, 1);
    assert_eq!(transition.queued.len(), 1);
    assert_eq!(transition.old_state, NetworkAvailabilityState::Up);
    assert_eq!(pending_outputs.len(), 1);
    assert_eq!(pending_outputs[0].source, destination);
    assert_eq!(pending_outputs[0].destination, source);
    assert!(pending_outputs[0].route.is_some());
    let committed_frontier = VirtualTime { ticks: 73 };
    interceptor
        .observations
        .lock()
        .unwrap_or_else(|error| panic!("test observation journal should lock: {error}"))
        .append(
            7,
            vec![FaultObservation {
                semantic_version: FAULT_RUNTIME_STATE_VERSION,
                kind: FaultObservationKind::EffectApplied,
                coordinate: FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                binding: None,
                target: None,
                opportunity: None,
                evidence: ContentHash::from_bytes(b"undrained-observation"),
            }],
        )
        .unwrap_or_else(|error| panic!("test observation should append: {error}"));
    let inconsistent_journal_error = interceptor
        .checkpoint(&scheduler, committed_frontier, &pending_outputs, &mut nodes)
        .err()
        .unwrap_or_else(|| panic!("checkpoint should reject an inconsistent journal"));
    assert!(
        inconsistent_journal_error
            .to_string()
            .contains("observation journal is inconsistent"),
        "unexpected checkpoint rejection: {inconsistent_journal_error}"
    );
    let mut journal = interceptor
        .observations
        .lock()
        .unwrap_or_else(|error| panic!("test observation journal should lock: {error}"));
    let drained = journal.drain_ready(u64::MAX);
    assert_eq!(drained.len(), 1);
    drop(journal);
    let checkpoint = interceptor
        .checkpoint(&scheduler, committed_frontier, &pending_outputs, &mut nodes)
        .unwrap_or_else(|error| panic!("network checkpoint should encode: {error}"));
    let restored_scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-availability-drop",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut restored_scheduler = SingleScheduler::from_world(
        restored_scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("restored scheduler should build: {error}"));
    let malformed = interceptor
        .runtime
        .lock()
        .unwrap_or_else(|error| panic!("test fault runtime lock should be available: {error}"))
        .checkpoint_with_network_state(
            &mut nodes,
            ProductionNetworkStateCheckpoint::new(
                ContentHash::from_bytes(b"unauthenticated-network-state"),
                scheduler.network_checkpoint(),
                committed_frontier,
                pending_outputs.clone(),
                b"{}".to_vec(),
            ),
        )
        .unwrap_or_else(|error| panic!("malformed fixture should authenticate outside: {error}"));
    let mismatched_scheduler_before = restored_scheduler
        .network_continuation_digest()
        .unwrap_or_else(|error| panic!("scheduler should digest: {error}"));
    let mut mismatched_pending = Vec::new();
    let mismatch = ProductionFaultNetworkInterceptor::restore(
        down_plan(segment.clone()),
        Some(Arc::new(NoArtifacts)),
        ContentHash::from_bytes(b"production-availability-drop"),
        checkpoint.clone(),
        super::super::fault_implementation::test_host_manifests(),
        &mut nodes,
        world.fault_topology().clone(),
        world.links().to_vec(),
        &mut restored_scheduler,
        &mut mismatched_pending,
        Arc::new(Mutex::new(
            super::storage_faults::ProductionFaultObservationJournal::default(),
        )),
    )
    .err()
    .unwrap_or_else(|| panic!("mismatched scheduler continuation should fail closed"));
    assert!(
        mismatch
            .to_string()
            .contains("scheduler and production-fault network continuations differ")
    );
    assert_eq!(
        restored_scheduler
            .network_continuation_digest()
            .unwrap_or_else(|error| panic!("scheduler should digest: {error}")),
        mismatched_scheduler_before
    );
    assert!(mismatched_pending.is_empty());
    restored_scheduler
        .restore_network_checkpoint(&scheduler.network_checkpoint())
        .unwrap_or_else(|error| panic!("test scheduler continuation should restore: {error}"));
    let scheduler_before_rejection = restored_scheduler
        .network_continuation_digest()
        .unwrap_or_else(|error| panic!("scheduler should digest: {error}"));
    let mut rejected_pending = Vec::new();
    let error = ProductionFaultNetworkInterceptor::restore(
        down_plan(segment.clone()),
        Some(Arc::new(NoArtifacts)),
        ContentHash::from_bytes(b"production-availability-drop"),
        malformed,
        super::super::fault_implementation::test_host_manifests(),
        &mut nodes,
        world.fault_topology().clone(),
        world.links().to_vec(),
        &mut restored_scheduler,
        &mut rejected_pending,
        Arc::new(Mutex::new(
            super::storage_faults::ProductionFaultObservationJournal::default(),
        )),
    )
    .err()
    .unwrap_or_else(|| panic!("malformed adapter checkpoint should fail closed"));
    assert!(error.to_string().contains("network adapter checkpoint"));
    assert_eq!(
        restored_scheduler
            .network_continuation_digest()
            .unwrap_or_else(|digest_error| panic!("scheduler should digest: {digest_error}")),
        scheduler_before_rejection
    );
    assert!(rejected_pending.is_empty());
    let mut restored_pending = Vec::new();
    let (restored_interceptor, restored_committed_frontier) =
        ProductionFaultNetworkInterceptor::restore(
            down_plan(segment),
            Some(Arc::new(NoArtifacts)),
            ContentHash::from_bytes(b"production-availability-drop"),
            checkpoint.clone(),
            super::super::fault_implementation::test_host_manifests(),
            &mut nodes,
            world.fault_topology().clone(),
            world.links().to_vec(),
            &mut restored_scheduler,
            &mut restored_pending,
            Arc::new(Mutex::new(
                super::storage_faults::ProductionFaultObservationJournal::default(),
            )),
        )
        .unwrap_or_else(|error| panic!("network continuation should restore: {error}"));
    assert_eq!(restored_committed_frontier, committed_frontier);
    let restored_checkpoint = restored_interceptor
        .checkpoint(
            &restored_scheduler,
            restored_committed_frontier,
            &restored_pending,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("restored checkpoint should encode: {error}"));
    assert_eq!(restored_checkpoint.id(), checkpoint.id());
    assert_eq!(restored_pending, pending_outputs);
    let mut divergent_pending = pending_outputs.clone();
    divergent_pending[0].payload.push(0xff);
    let divergent = interceptor
        .checkpoint(
            &scheduler,
            committed_frontier,
            &divergent_pending,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("divergent checkpoint should encode: {error}"));
    assert_ne!(checkpoint.id(), divergent.id());
    let divergent_frontier = interceptor
        .checkpoint(
            &scheduler,
            VirtualTime {
                ticks: committed_frontier.ticks + 1,
            },
            &pending_outputs,
            &mut nodes,
        )
        .unwrap_or_else(|error| panic!("divergent frontier should encode: {error}"));
    assert_ne!(checkpoint.id(), divergent_frontier.id());
    let after = scheduler
        .drop_network_inflight_for_route(&source, &destination)
        .unwrap_or_else(|error| panic!("test route should remain valid: {error}"));
    assert_eq!(after.frame_count, 0);
}

#[test]
fn production_resolve_availability_suppresses_the_routed_frame() {
    let (world, segment) = availability_world();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-resolve-availability",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    let mut nodes = ProductionNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        down_plan_at(segment, FaultPhase::Resolve),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-resolve-availability"),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
    let mut interceptor = ProductionFaultNetworkInterceptor::new(
        runtime,
        world.fault_topology().clone(),
        world.links().to_vec(),
    );
    let mut pending_outputs = Vec::new();
    interceptor
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            &mut scheduler,
            &mut nodes,
            &mut pending_outputs,
        )
        .unwrap_or_else(|error| panic!("resolve availability should activate: {error}"));

    let source = crucible::NodeId {
        name: String::from("left"),
    };
    let destination = crucible::NodeId {
        name: String::from("right"),
    };
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    let mut outputs = vec![BackendNetworkOutput {
        source,
        destination,
        emit_icount: Icount { retired: 0 },
        sequence: 1,
        payload,
        route: None,
        fault_continuation: Default::default(),
    }];
    interceptor
        .intercept_network_outputs(
            &mut scheduler,
            &mut nodes,
            VirtualTime { ticks: 0 },
            &mut pending_outputs,
            &mut outputs,
        )
        .unwrap_or_else(|error| panic!("resolve opportunity should execute: {error}"));
    assert!(outputs.is_empty());
}

#[test]
fn production_preserve_keeps_queued_and_inflight_frames_on_the_old_profile() {
    let (world, segment) = availability_world();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-preserve-availability",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    let source = crucible::NodeId {
        name: String::from("left"),
    };
    let destination = crucible::NodeId {
        name: String::from("right"),
    };
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    QuantumLoop::append_backend_network_outputs(
        &mut scheduler,
        vec![BackendNetworkOutput {
            source: source.clone(),
            destination: destination.clone(),
            emit_icount: Icount { retired: 0 },
            sequence: 1,
            payload: payload.clone(),
            route: None,
            fault_continuation: Default::default(),
        }],
    )
    .unwrap_or_else(|error| panic!("test frame should route: {error}"));

    let mut nodes = ProductionNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        down_plan_with_policies(
            segment,
            FaultPhase::Admit,
            NetworkInFlightPolicy::Preserve,
            NetworkInFlightPolicy::Preserve,
        ),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-preserve-availability"),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
    let mut interceptor = ProductionFaultNetworkInterceptor::new(
        runtime,
        world.fault_topology().clone(),
        world.links().to_vec(),
    );
    let mut pending_outputs = vec![BackendNetworkOutput {
        source: source.clone(),
        destination: destination.clone(),
        emit_icount: Icount { retired: 0 },
        sequence: 2,
        payload,
        route: None,
        fault_continuation: Default::default(),
    }];
    interceptor
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            &mut scheduler,
            &mut nodes,
            &mut pending_outputs,
        )
        .unwrap_or_else(|error| panic!("preserve transition should execute: {error}"));

    assert_eq!(pending_outputs.len(), 1);
    let preserved = &pending_outputs[0]
        .fault_continuation
        .preserved_availability()[0];
    assert_eq!(preserved.binding, object_id("network-down-binding"));
    assert!(
        pending_outputs[0]
            .fault_continuation
            .preserves_availability(
                &preserved.binding,
                &preserved.target,
                preserved.phase,
                preserved.transition_sequence,
            )
    );
    let preserved_inflight = scheduler
        .drop_network_inflight_for_route(&source, &destination)
        .unwrap_or_else(|error| panic!("preserved route should remain valid: {error}"));
    assert_eq!(preserved_inflight.frame_count, 1);
    let mut outputs = std::mem::take(&mut pending_outputs);
    interceptor
        .intercept_network_outputs(
            &mut scheduler,
            &mut nodes,
            VirtualTime { ticks: 0 },
            &mut pending_outputs,
            &mut outputs,
        )
        .unwrap_or_else(|error| panic!("preserved frame should bypass new outage: {error}"));
    assert_eq!(outputs.len(), 1);
}

#[test]
fn production_reevaluate_retains_work_until_the_next_declared_phase() {
    let (world, segment) = availability_world();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-reevaluate-availability",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    let source = crucible::NodeId {
        name: String::from("left"),
    };
    let destination = crucible::NodeId {
        name: String::from("right"),
    };
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    QuantumLoop::append_backend_network_outputs(
        &mut scheduler,
        vec![BackendNetworkOutput {
            source: source.clone(),
            destination: destination.clone(),
            emit_icount: Icount { retired: 0 },
            sequence: 1,
            payload: payload.clone(),
            route: None,
            fault_continuation: Default::default(),
        }],
    )
    .unwrap_or_else(|error| panic!("test frame should route: {error}"));

    let mut nodes = ProductionNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        down_plan_with_policies(
            segment,
            FaultPhase::Admit,
            NetworkInFlightPolicy::Reevaluate,
            NetworkInFlightPolicy::Reevaluate,
        ),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-reevaluate-availability"),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
    let mut interceptor = ProductionFaultNetworkInterceptor::new(
        runtime,
        world.fault_topology().clone(),
        world.links().to_vec(),
    );
    let mut pending_outputs = vec![BackendNetworkOutput {
        source: source.clone(),
        destination: destination.clone(),
        emit_icount: Icount { retired: 0 },
        sequence: 2,
        payload,
        route: None,
        fault_continuation: Default::default(),
    }];
    interceptor
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            &mut scheduler,
            &mut nodes,
            &mut pending_outputs,
        )
        .unwrap_or_else(|error| panic!("reevaluate transition should execute: {error}"));

    assert_eq!(pending_outputs.len(), 1);
    assert!(
        pending_outputs[0]
            .fault_continuation
            .preserved_availability()
            .is_empty()
    );
    let retained_inflight = scheduler
        .drop_network_inflight_for_route(&source, &destination)
        .unwrap_or_else(|error| panic!("resolved route should remain valid: {error}"));
    assert_eq!(retained_inflight.frame_count, 1);

    let mut outputs = std::mem::take(&mut pending_outputs);
    interceptor
        .intercept_network_outputs(
            &mut scheduler,
            &mut nodes,
            VirtualTime { ticks: 0 },
            &mut pending_outputs,
            &mut outputs,
        )
        .unwrap_or_else(|error| panic!("reevaluated frame should execute: {error}"));
    assert!(outputs.is_empty());
}

#[test]
fn continuation_digest_covers_response_and_forwarding_lineage() {
    let source = crucible::NodeId {
        name: String::from("sender"),
    };
    let destination = crucible::NodeId {
        name: String::from("receiver"),
    };
    let base = BackendNetworkOutput {
        source,
        destination: destination.clone(),
        emit_icount: Icount { retired: 1 },
        sequence: 7,
        payload: vec![0; 14],
        route: None,
        fault_continuation: Default::default(),
    };
    let evidence = |output: &BackendNetworkOutput| {
        let mut material = Vec::new();
        append_backend_output_evidence(&mut material, output)
            .unwrap_or_else(|error| panic!("test continuation evidence: {error}"));
        ContentHash::from_bytes(&material)
    };
    let baseline = evidence(&base);

    let cause = ContentHash::from_bytes(b"typed-reject");
    let mut response = base.clone();
    response.fault_continuation = response
        .fault_continuation
        .generated_response(cause)
        .unwrap_or_else(|| panic!("first response must fit"));
    assert_ne!(baseline, evidence(&response));

    let mut rerouted = base;
    rerouted.fault_continuation = rerouted
        .fault_continuation
        .forwarding_mutation(ContentHash::from_bytes(b"wrong-port"), destination)
        .unwrap_or_else(|| panic!("first forwarding mutation must fit"));
    assert_ne!(baseline, evidence(&rerouted));
    assert_ne!(evidence(&response), evidence(&rerouted));
}

#[test]
fn shared_medium_checkpoint_joins_pending_frames_and_hashes_every_reservation_field() {
    let opportunity = ContentHash::from_bytes(b"medium-reservation");
    let target = ResolvedFaultTarget::NetworkMedium {
        medium: object_id("radio-medium"),
        resource: object_id("radio-channel"),
    };
    let key = NetworkEffectStateKey {
        binding: object_id("medium-binding"),
        target,
        effect: crucible::model::EffectKind::NetworkSharedMedium,
    };
    let reservation = NetworkMediumReservation {
        opportunity,
        producer: object_id("left"),
        arbitration_key: vec![0, 1],
        arrival_nanos: 10,
        start_nanos: 20,
        finish_nanos: 30,
        duration_nanos: 10,
        transmit_power_femtowatts: 40,
        terminal_collision_applied: false,
    };
    let mut state = NetworkEffectRuntimeState::default();
    state.shared_media.insert(
        key.clone(),
        NetworkMediumState {
            resources: vec![object_id("left"), object_id("right")],
            policy: object_id("radio-access"),
            transition_sequence: 1,
            service_cursor_nanos: 30,
            reservations: vec![reservation],
        },
    );
    let mut continuation = crucible::BackendNetworkFaultContinuation::default();
    continuation.cursor_mut().defer_until(30, opportunity);
    let pending = vec![BackendNetworkOutput {
        source: crucible::NodeId {
            name: String::from("left"),
        },
        destination: crucible::NodeId {
            name: String::from("right"),
        },
        emit_icount: Icount { retired: 0 },
        sequence: 1,
        payload: vec![0],
        route: None,
        fault_continuation: continuation,
    }];
    let retained = checkpoint_network_effect_state(&state, &pending, 30);
    validate_medium_pending_links(&retained, &pending)
        .unwrap_or_else(|error| panic!("joined medium checkpoint: {error}"));
    assert_eq!(retained.shared_media.len(), 1);
    assert!(
        checkpoint_network_effect_state(&state, &[], 30)
            .shared_media
            .is_empty()
    );
    assert!(validate_medium_pending_links(&state, &[]).is_err());

    let connection = NetworkConnectionEntry {
        machine: NetworkStateMachineRuntime {
            current: object_id("connected"),
            pending: Vec::new(),
            transition_sequence: 1,
        },
        created_by: opportunity,
        last_used_nanos: 30,
    };
    state
        .connection_tables
        .entry(key)
        .or_default()
        .insert(opportunity, connection);
    let checkpoint = NetworkAdapterCheckpoint {
        semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
        coordinate: Some(30),
        coordinate_sequence: 1,
        journal_sequence: 2,
        observations: super::storage_faults::ProductionFaultObservationJournal::default(),
        effect_state: state.clone(),
    };
    let encoded = serde_json::to_vec(&checkpoint)
        .unwrap_or_else(|error| panic!("encode nonempty network checkpoint: {error}"));
    let decoded: NetworkAdapterCheckpoint = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("decode nonempty network checkpoint: {error}"));
    assert_eq!(decoded.effect_state.shared_media.len(), 1);
    assert_eq!(decoded.effect_state.connection_tables.len(), 1);

    let evidence = |state: &NetworkEffectRuntimeState| {
        let mut material = Vec::new();
        append_network_effect_state(&mut material, state)
            .unwrap_or_else(|error| panic!("medium state evidence: {error}"));
        ContentHash::from_bytes(&material)
    };
    let baseline = evidence(&retained);
    let mut changed = retained;
    changed
        .shared_media
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("retained medium state must exist"))
        .reservations[0]
        .transmit_power_femtowatts = 41;
    assert_ne!(baseline, evidence(&changed));
}

fn association_control_event(values: [i64; 2]) -> boundary::QueuedNetworkControlEvent {
    let mapping = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("association-policy"),
        input_contracts: Vec::new(),
        inputs: values.into_iter().map(SignalValue::I64).collect(),
    };
    let mapped_digest = ContentHash::from_bytes(
        &serde_json::to_vec(&mapping)
            .unwrap_or_else(|error| panic!("encode test mapping: {error}")),
    );
    let action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("association-event"),
        target: ResolvedFaultTarget::NetworkAttachment {
            endpoint: object_id("endpoint-a"),
            interface: object_id("interface-a"),
            attachment: object_id("attachment-a"),
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::StateMachine,
                EffectSpecification::Network(NetworkEffectSpecification::Association {
                    policy: object_id("association-policy"),
                }),
            )
            .unwrap_or_else(|error| panic!("association effect: {error}")),
        ),
        mapping_output: Arc::new(mapping),
        mapped_digest,
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let bytes = values
        .into_iter()
        .flat_map(i64::to_be_bytes)
        .collect::<Vec<_>>();
    boundary::QueuedNetworkControlEvent {
        sequence: 0,
        operation: FaultOperation::NetworkAssociate,
        technology: object_id("network-wireless-v1"),
        result_schema: object_id("network-association-inputs-i64-v1"),
        result_digest: ContentHash::from_bytes(&bytes),
        release_nanos: 1,
        action,
    }
}

fn control_transform_action(
    kind: crucible::model::NetworkControlResultKind,
    result: FaultObjectId,
) -> ResolvedBindingAction {
    typed_control_transform_action(
        object_id("network-wireless-v1"),
        FaultOperation::NetworkAssociate,
        kind,
        result,
        object_id("network-association-inputs-i64-v1"),
        association_control_event([0, 0]).action.target,
    )
}

fn typed_control_transform_action(
    technology: FaultObjectId,
    operation: FaultOperation,
    kind: crucible::model::NetworkControlResultKind,
    result: FaultObjectId,
    result_schema: FaultObjectId,
    target: ResolvedFaultTarget,
) -> ResolvedBindingAction {
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("association-transform"),
        target,
        phase: FaultPhase::Resolve,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Opportunity,
                EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
                    technology: technology.clone(),
                    operations: crucible::model::OperationSet::new(vec![operation])
                        .unwrap_or_else(|error| panic!("transform operations: {error}")),
                    kind,
                    result: Some(result),
                }),
            )
            .unwrap_or_else(|error| panic!("control transform effect: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"transform"),
        transition_sequence: 1,
        opportunity: Some(ContentHash::from_bytes(b"control-opportunity")),
        coordinate: FaultCoordinate {
            virtual_nanos: 1,
            retired_instructions: None,
        },
        cause: BindingActionCause::Opportunity {
            identity: ContentHash::from_bytes(b"control-opportunity"),
            payload: OpportunityPayload::NetworkControl {
                technology: technology.clone(),
                event_sequence: 1,
                request_digest: ContentHash::from_bytes(b"request"),
                result_schema,
                result_digest: ContentHash::from_bytes(b"result"),
            },
        },
        expected_precondition: None,
    }
}

#[test]
fn association_control_bias_and_replacement_preserve_digest_invariants() {
    let replacement_bytes = [30_i64, 40_i64]
        .into_iter()
        .flat_map(i64::to_be_bytes)
        .collect::<Vec<_>>();
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("association-bias"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-score-bias-i64-v1"),
                    bytes: 5_i64.to_be_bytes().to_vec(),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("association-replacement"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-association-inputs-i64-v1"),
                    bytes: replacement_bytes.clone(),
                },
            },
        ],
        ..crucible::model::WorldFaultTopology::default()
    };
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));

    let biased = apply_network_control_transforms(
        association_control_event([10, 20]),
        &[control_transform_action(
            crucible::model::NetworkControlResultKind::Bias,
            object_id("association-bias"),
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("bias association result: {error}"))
    .unwrap_or_else(|| panic!("bias must retain the control result"));
    assert_eq!(
        route::mapped_network_integers(&biased.action),
        Ok(vec![15, 25])
    );
    assert_eq!(
        biased.result_digest,
        ContentHash::from_bytes(
            &[15_i64, 25_i64]
                .into_iter()
                .flat_map(i64::to_be_bytes)
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        biased.action.mapped_digest,
        ContentHash::from_bytes(
            &serde_json::to_vec(biased.action.mapping_output.as_ref())
                .unwrap_or_else(|error| panic!("encode biased mapping: {error}"))
        )
    );

    let replaced = apply_network_control_transforms(
        association_control_event([10, 20]),
        &[control_transform_action(
            crucible::model::NetworkControlResultKind::Replace,
            object_id("association-replacement"),
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("replace association result: {error}"))
    .unwrap_or_else(|| panic!("replacement must retain the control result"));
    assert_eq!(
        route::mapped_network_integers(&replaced.action),
        Ok(vec![30, 40])
    );
    assert_eq!(
        replaced.result_digest,
        ContentHash::from_bytes(&replacement_bytes)
    );
    assert_eq!(
        replaced.action.mapped_digest,
        ContentHash::from_bytes(
            &serde_json::to_vec(replaced.action.mapping_output.as_ref())
                .unwrap_or_else(|error| panic!("encode replaced mapping: {error}"))
        )
    );
}

#[test]
fn forwarder_and_contact_replacements_execute_only_within_world_contracts() {
    let positive = |field, value| {
        crucible::model::PositiveU64::new(field, value)
            .unwrap_or_else(|error| panic!("test positive value: {error}"))
    };
    let forwarder_target = ResolvedFaultTarget::NetworkForwarder {
        forwarder: object_id("forwarder-a"),
    };
    let forwarder_action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("forwarder-event"),
        target: forwarder_target.clone(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::StateMachine,
                EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
                    transition: crucible::model::NetworkForwarderTransition::Restart,
                    downtime_nanos: positive("downtime", 1),
                    queue_policy: crucible::model::NetworkStatePolicy::Preserve,
                    table_policy: crucible::model::NetworkStatePolicy::Preserve,
                }),
            )
            .unwrap_or_else(|error| panic!("forwarder lifecycle: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"forwarder"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let forwarder_event = boundary::QueuedNetworkControlEvent {
        sequence: 0,
        operation: FaultOperation::NetworkChange,
        technology: object_id("network-forwarder-v1"),
        result_schema: object_id("network-forwarder-state-v1"),
        result_digest: ContentHash::from_bytes(&[1]),
        release_nanos: 1,
        action: forwarder_action,
    };

    let contact_target = ResolvedFaultTarget::NetworkContact {
        plan: object_id("contact-plan-a"),
        endpoint_a: object_id("ground"),
        endpoint_b: object_id("satellite"),
        contact: object_id("contact-a"),
    };
    let members = |value| {
        crucible::model::ObjectIdSet::new(vec![object_id(value)])
            .unwrap_or_else(|error| panic!("test contact members: {error}"))
    };
    let contact_action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("contact-event"),
        target: contact_target.clone(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::StateMachine,
                EffectSpecification::Network(NetworkEffectSpecification::Contact {
                    intervals: object_id("contact-plan-a"),
                    range_delay_lookup: object_id("range-delay"),
                    beams: members("beam-a"),
                    gateways: members("gateway-a"),
                }),
            )
            .unwrap_or_else(|error| panic!("contact effect: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"contact"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let contact_event = boundary::QueuedNetworkControlEvent {
        sequence: 0,
        operation: FaultOperation::NetworkAcquire,
        technology: object_id("network-contact-v1"),
        result_schema: object_id("network-contact-plan-v1"),
        result_digest: ContentHash::from_bytes(b"contact-plan-a"),
        release_nanos: 1,
        action: contact_action,
    };
    let contact_interval = |beam: &str| crucible::model::NetworkPolicyContactInterval {
        contact: object_id(&format!("contact-{beam}")),
        service_resource: object_id(&format!("resource-{beam}")),
        route_cost: positive("route_cost", 1),
        routing_propagation_nanos: 1,
        start_nanos: 0,
        end_nanos: 100,
        source: object_id("ground"),
        destination: object_id("satellite"),
        beam: object_id(beam),
        gateway: object_id("gateway-a"),
        minimum_range_mm: 1,
        maximum_range_mm: 2,
        capacity_profile: object_id("capacity-a"),
        acquisition_nanos: 0,
        teardown_nanos: 0,
        confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
            .unwrap_or_else(|error| panic!("contact confidence: {error}")),
        provenance: object_id("trace-a"),
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-plan-b"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                    intervals: vec![contact_interval("beam-a")],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-plan-invalid"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                    intervals: vec![contact_interval("beam-b")],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-result"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-contact-plan-v1"),
                    bytes: b"contact-plan-b".to_vec(),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-result-invalid"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-contact-plan-v1"),
                    bytes: b"contact-plan-invalid".to_vec(),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("forwarder-result"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-forwarder-state-v1"),
                    bytes: vec![3],
                },
            },
        ],
        ..crucible::model::WorldFaultTopology::default()
    };
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));

    let forwarder = apply_network_control_transforms(
        forwarder_event,
        &[typed_control_transform_action(
            object_id("network-forwarder-v1"),
            FaultOperation::NetworkChange,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("forwarder-result"),
            object_id("network-forwarder-state-v1"),
            forwarder_target,
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("replace forwarder state: {error}"))
    .unwrap_or_else(|| panic!("forwarder replacement must remain active"));
    assert!(matches!(
        forwarder.action.effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition: crucible::model::NetworkForwarderTransition::PowerLoss,
            ..
        })
    ));

    let valid = apply_network_control_transforms(
        contact_event.clone(),
        &[typed_control_transform_action(
            object_id("network-contact-v1"),
            FaultOperation::NetworkAcquire,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("contact-result"),
            object_id("network-contact-plan-v1"),
            contact_target.clone(),
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("replace contact plan: {error}"))
    .unwrap_or_else(|| panic!("contact replacement must remain active"));
    assert!(matches!(
        valid.action.effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Contact { intervals, .. })
            if intervals == &object_id("contact-plan-b")
    ));
    let error = apply_network_control_transforms(
        contact_event,
        &[typed_control_transform_action(
            object_id("network-contact-v1"),
            FaultOperation::NetworkAcquire,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("contact-result-invalid"),
            object_id("network-contact-plan-v1"),
            contact_target,
        )],
        &topology,
    )
    .err()
    .unwrap_or_else(|| panic!("undeclared contact beam must fail"));
    assert!(error.to_string().contains("undeclared beam or gateway"));
}
