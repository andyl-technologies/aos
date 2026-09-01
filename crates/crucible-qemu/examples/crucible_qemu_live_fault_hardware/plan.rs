//! Signal plan for the live clock, memory, and accelerator hardware gate.

use crucible::model::{
    AcceleratorJobSelector, AcceleratorResultMutation, AcceleratorThermalPower,
    AcceleratorTransition, BindingEventParent, BindingMapping, BindingMappingRegistry,
    BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, ByteRange,
    ClockMonotonicityPolicy, ClockMutation, ClockOverdueTimerPolicy, ClockSourceTransition,
    ClockSynchronizationPolicy, EFFECT_SEMANTIC_VERSION, EffectKind, EffectLifetime, EffectRequest,
    EffectSpecification, ExactRatio, FaultAdapter, FaultBinding, FaultObjectId, FaultOperation,
    FaultPhase, FaultResourceLimits, FaultSignalPlan, FaultTargetKind, HexBytes,
    MemoryAddressSpace, MemoryEccKind, MemoryMutationAtomicity, MemoryMutationKind,
    NodeEffectSpecification, NodeOccurrencePolicy, NodeStatePolicy, ObjectIdSet, OperationSet,
    OpportunityFilter, ResolvedFaultTarget, ResolvedTargetSet, SignalBoundaryBehavior,
    SignalCoordinate, SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalPoint,
    SignalProgram, SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit,
    SignalValue, SignalValueType, StateTransitionTableDeclaration, TargetSelector,
};

/// Builds the production signal plan exercised by the hardware gate.
pub(super) fn fault_hardware_plan() -> Result<FaultSignalPlan, String> {
    let clock_output = signal_id("guest-clock-offset")?;
    let clock_event_schema = signal_id("guest-clock-offset-event")?;
    let clock_source_output = signal_id("guest-clock-source-degraded")?;
    let accelerator_lifecycle_output = signal_id("accelerator-lifecycle-reset")?;
    let accelerator_memory_output = signal_id("accelerator-memory-corrected")?;
    let accelerator_output = signal_id("tpu-result-hazard")?;
    let accelerator_service_output = signal_id("accelerator-service-active")?;
    let clock_program = SignalProgram::new(
        vec![
            SignalNode {
                id: clock_output.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(clock_event_schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .map_err(|error| format!("clock activation shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 1 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: clock_event_schema.clone(),
                            payload: Vec::new(),
                        },
                    }],
                }),
            },
            SignalNode {
                id: clock_source_output.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(clock_event_schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .map_err(|error| format!("clock source activation shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 6 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: clock_event_schema.clone(),
                            payload: Vec::new(),
                        },
                    }],
                }),
            },
            SignalNode {
                id: accelerator_lifecycle_output.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(clock_event_schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .map_err(|error| format!("accelerator lifecycle activation shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 3 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: clock_event_schema.clone(),
                            payload: Vec::new(),
                        },
                    }],
                }),
            },
            SignalNode {
                id: accelerator_memory_output.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(clock_event_schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .map_err(|error| format!("accelerator memory activation shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 4 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: clock_event_schema.clone(),
                            payload: Vec::new(),
                        },
                    }],
                }),
            },
            SignalNode {
                id: accelerator_output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(
                    SignalValueType::ProbabilityMillionths,
                    SignalUnit::ProbabilityMillionths,
                    0,
                )
                .map_err(|error| format!("accelerator hazard shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::ProbabilityMillionths(1_000_000),
                },
            },
            SignalNode {
                id: accelerator_service_output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .map_err(|error| format!("accelerator service shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::Step {
                    points: vec![SignalPoint {
                        coordinate: SignalCoordinate::VirtualTime { nanos: 5 },
                        sequence: 0,
                        value: SignalValue::Bool(true),
                    }],
                    before: SignalBoundaryBehavior::Constant(SignalValue::Bool(false)),
                }),
            },
        ],
        vec![
            clock_output.clone(),
            clock_source_output.clone(),
            accelerator_lifecycle_output.clone(),
            accelerator_memory_output.clone(),
            accelerator_output.clone(),
            accelerator_service_output.clone(),
        ],
        SignalResourceLimits::default(),
    )
    .map_err(|error| format!("clock signal program: {error}"))?;
    let transition_request = SignalValue::Event {
        schema: clock_event_schema.clone(),
        payload: Vec::new(),
    };
    let clock_transition_table = object_id("clock-source-transition-table")?;
    let accelerator_transition_table = object_id("accelerator-lifecycle-transition-table")?;
    let mapping_registry = BindingMappingRegistry::new(
        vec![
            StateTransitionTableDeclaration {
                id: clock_transition_table.clone(),
                semantic_version: 1,
                input: SignalValueType::Event(clock_event_schema.clone()),
                effect: EffectKind::ClockSourceState,
                transitions: [(
                    transition_request.clone(),
                    object_id("clock-source-degraded-transition")?,
                )]
                .into_iter()
                .collect(),
                default_transition: object_id("clock-source-degraded-transition")?,
            },
            StateTransitionTableDeclaration {
                id: accelerator_transition_table.clone(),
                semantic_version: 1,
                input: SignalValueType::Event(clock_event_schema),
                effect: EffectKind::AcceleratorLifecycle,
                transitions: [(
                    transition_request,
                    object_id("accelerator-reset-transition")?,
                )]
                .into_iter()
                .collect(),
                default_transition: object_id("accelerator-reset-transition")?,
            },
        ],
        Vec::new(),
    )
    .map_err(|error| format!("hardware mapping registry: {error}"))?;

    let clock_target = ResolvedFaultTarget::ClockSource {
        node: object_id("fault-hardware-node")?,
        source: object_id("x86-tsc-vcpu-0")?,
    };
    let clock_source_transition_target = ResolvedFaultTarget::ClockSource {
        node: object_id("fault-hardware-node")?,
        source: object_id("x86-local-apic-timer-vcpu-0")?,
    };
    let clock_binding = FaultBinding::new(
        object_id("guest-clock-offset-binding")?,
        vec![clock_output.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set(clock_target.clone())?),
        [FaultPhase::ClockRead].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::ClockTransform {
                source: object_id("x86-tsc-vcpu-0")?,
                mutation: ClockMutation::Offset {
                    offset_nanos: 1_000_000_000,
                },
                monotonicity: ClockMonotonicityPolicy::ClampMonotonic,
                overdue_timer_policy: ClockOverdueTimerPolicy::FireAtBoundary,
            }),
        )
        .map_err(|error| format!("clock effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("clock binding: {error}"))?;
    let clock_source_binding = FaultBinding::new_with_registry(
        object_id("guest-clock-source-degraded-binding")?,
        vec![clock_source_output],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::StateTransition {
            transition_table: clock_transition_table,
        },
        TargetSelector::Exact(target_set(clock_source_transition_target)?),
        [FaultPhase::SourceSwitch].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Node(NodeEffectSpecification::ClockSourceState {
                sources: ObjectIdSet::new(vec![object_id("x86-local-apic-timer-vcpu-0")?])
                    .map_err(|error| format!("clock source set: {error}"))?,
                transition: ClockSourceTransition::Degraded,
                synchronization_policy: ClockSynchronizationPolicy::Step,
            }),
        )
        .map_err(|error| format!("clock source effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
        &mapping_registry,
    )
    .map_err(|error| format!("clock source binding: {error}"))?;

    // 0x9ffff is the last writable conventional-RAM byte below the PC ROM
    // aperture. Linux has completed firmware handoff before this boundary, so
    // flipping one bit is inert to the workload while necessarily changing the
    // execution fingerprint's writable-RAM digest.
    let memory_range =
        ByteRange::new(0x9ffff, 1).map_err(|error| format!("fingerprint memory range: {error}"))?;
    let memory_binding = FaultBinding::new(
        object_id("fingerprint-memory-binding")?,
        vec![clock_output.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set(ResolvedFaultTarget::MemoryRange {
            node: object_id("fault-hardware-node")?,
            address_space: object_id("gpa")?,
            guest_address: memory_range.start(),
            vcpu: None,
            length_bytes: memory_range.length(),
        })?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
                address_space: MemoryAddressSpace::GuestPhysical,
                range: memory_range,
                mutation: MemoryMutationKind::BitFlip {
                    mask: HexBytes::parse("01", 1)
                        .map_err(|error| format!("fingerprint memory mask: {error}"))?,
                },
                atomicity: MemoryMutationAtomicity::AllOrNothing,
            }),
        )
        .map_err(|error| format!("fingerprint memory effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("fingerprint memory binding: {error}"))?;

    let accelerator_lifecycle_binding = FaultBinding::new_with_registry(
        object_id("accelerator-lifecycle-reset-binding")?,
        vec![accelerator_lifecycle_output],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::StateTransition {
            transition_table: accelerator_transition_table,
        },
        TargetSelector::Exact(target_set(accelerator_target()?)?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Node(NodeEffectSpecification::AcceleratorLifecycle {
                device: object_id("accelerator-0")?,
                transition: AcceleratorTransition::Reset,
                queue_policy: NodeStatePolicy::Preserve,
                memory_policy: NodeStatePolicy::Preserve,
            }),
        )
        .map_err(|error| format!("accelerator lifecycle effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
        &mapping_registry,
    )
    .map_err(|error| format!("accelerator lifecycle binding: {error}"))?;

    let accelerator_memory_binding = FaultBinding::new(
        object_id("accelerator-memory-corrected-binding")?,
        vec![accelerator_memory_output],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set(accelerator_target()?)?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::AcceleratorMemoryEvent {
                range: ByteRange::new(0, 1)
                    .map_err(|error| format!("accelerator memory range: {error}"))?,
                ecc: Some(MemoryEccKind::Corrected),
                syndrome: Some(0x51),
                transform: None,
            }),
        )
        .map_err(|error| format!("accelerator memory effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("accelerator memory binding: {error}"))?;

    let accelerator_service_binding = FaultBinding::new(
        object_id("accelerator-service-throttle-binding")?,
        vec![accelerator_service_output],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set(accelerator_target()?)?),
        [FaultPhase::Execute].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Node(NodeEffectSpecification::AcceleratorService {
                capacity: ExactRatio::new(1, 2)
                    .map_err(|error| format!("accelerator capacity: {error}"))?,
                memory_bytes_per_second: None,
                jobs_per_second: None,
                thermal_power: AcceleratorThermalPower {
                    temperature_millikelvin: 315_000,
                    power_milliwatts: 25_000,
                },
            }),
        )
        .map_err(|error| format!("accelerator service effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("accelerator service binding: {error}"))?;

    let accelerator_binding = FaultBinding::new(
        object_id("tpu-result-transform-binding")?,
        vec![accelerator_output],
        BindingSampling::AtOpportunity,
        BindingMapping::Hazard,
        TargetSelector::Exact(target_set(accelerator_target()?)?),
        [FaultPhase::Complete].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Node(NodeEffectSpecification::AcceleratorResultTransform {
                job_selector: AcceleratorJobSelector {
                    job_kind: object_id("matrix-multiply")?,
                    queue: Some(0),
                    occurrence: NodeOccurrencePolicy::Every,
                },
                transform: AcceleratorResultMutation {
                    offset: 0,
                    mask: HexBytes::parse("ff", 1)
                        .map_err(|error| format!("accelerator mask: {error}"))?,
                    value: HexBytes::parse("2b", 1)
                        .map_err(|error| format!("accelerator value: {error}"))?,
                },
            }),
        )
        .map_err(|error| format!("accelerator effect: {error}"))?,
        Some(OpportunityFilter {
            adapter: FaultAdapter::Node,
            operations: OperationSet::new(vec![FaultOperation::AcceleratorComplete])
                .map_err(|error| format!("accelerator operations: {error}"))?,
            phases: [FaultPhase::Complete].into_iter().collect(),
            target_kinds: [FaultTargetKind::Accelerator].into_iter().collect(),
        }),
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("accelerator binding: {error}"))?;

    FaultSignalPlan::new(
        vec![clock_program],
        vec![
            clock_binding,
            clock_source_binding,
            memory_binding,
            accelerator_lifecycle_binding,
            accelerator_memory_binding,
            accelerator_service_binding,
            accelerator_binding,
        ],
        FaultResourceLimits::default(),
    )
    .map_err(|error| format!("fault hardware plan: {error}"))
}

pub(super) fn accelerator_target() -> Result<ResolvedFaultTarget, String> {
    Ok(ResolvedFaultTarget::Accelerator {
        node: object_id("fault-hardware-node")?,
        device: object_id("accelerator-0")?,
    })
}

fn target_set(target: ResolvedFaultTarget) -> Result<ResolvedTargetSet, String> {
    ResolvedTargetSet::new(vec![target], false).map_err(|error| format!("fault target: {error}"))
}

fn signal_id(value: &str) -> Result<SignalId, String> {
    SignalId::parse(value).map_err(|error| format!("signal ID `{value}`: {error}"))
}

fn object_id(value: &str) -> Result<FaultObjectId, String> {
    FaultObjectId::parse(value).map_err(|error| format!("object ID `{value}`: {error}"))
}
