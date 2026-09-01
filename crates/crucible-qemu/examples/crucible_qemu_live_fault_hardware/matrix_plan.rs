//! Closed signal plans for the live clock and accelerator variant matrix.

use crucible::model::{
    AcceleratorThermalPower, AcceleratorTransition, BindingEventParent, BindingMapping,
    BindingMappingRegistry, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy,
    ByteRange, ClockFailureBehavior, ClockFreezeReleasePolicy, ClockMonotonicityPolicy,
    ClockMutation, ClockOverdueTimerPolicy, ClockSourceTransition, ClockSynchronizationPolicy,
    ClockWanderProcess, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, ExactRatio, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
    FaultSignalPlan, HexBytes, MemoryEccKind, NodeEffectSpecification, NodeStatePolicy,
    ObjectIdSet, PositiveU64, ResolvedFaultTarget, ResolvedTargetSet, SignalBoundaryBehavior,
    SignalCoordinate, SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalPoint,
    SignalProgram, SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit,
    SignalValue, SignalValueType, StateTransitionTableDeclaration, TargetSelector,
};

/// One exact live-QEMU case in the closed hardware variant matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HardwareVariantCase {
    /// Stable evidence name emitted by the executable gate.
    pub(super) name: &'static str,
    /// Stable binding and QEMU-rule identity for this exact case.
    pub(super) binding: &'static str,
    /// Virtual-time coordinate that activates this case.
    pub(super) coordinate: u64,
}

/// Returns the complete ordered live-QEMU hardware variant matrix.
pub(super) fn hardware_variant_cases() -> &'static [HardwareVariantCase] {
    &HARDWARE_VARIANT_CASES
}

const HARDWARE_VARIANT_CASES: [HardwareVariantCase; 23] = [
    case("clock-offset-clamp-fire", 1),
    case("clock-drift-allow-reschedule", 2),
    case("clock-jump-fault-drop", 3),
    case("clock-freeze-resume", 4),
    case("clock-freeze-catch-up", 5),
    case("clock-jitter-table", 6),
    case("clock-wander-process", 7),
    case("clock-source-degraded-step", 8),
    case("clock-source-healthy-step", 9),
    case("clock-source-failed-stop", 10),
    case("clock-source-recovered-step", 11),
    case("clock-source-failed-read-error", 12),
    case("clock-source-fallback-slew", 13),
    case("clock-source-final-healthy", 14),
    case("accelerator-disappear-preserve", 15),
    case("accelerator-reconnect-preserve", 16),
    case("accelerator-reset-clear", 17),
    case("accelerator-memory-corrected", 18),
    case("accelerator-memory-uncorrectable", 19),
    case("accelerator-memory-transform", 20),
    case("accelerator-service-capacity", 21),
    case("accelerator-service-memory-rate", 22),
    case("accelerator-service-job-rate", 23),
];

/// Builds the one-plan, one-action-per-boundary production variant matrix.
#[cfg(test)]
pub(super) fn hardware_variant_plan() -> Result<FaultSignalPlan, String> {
    build_hardware_variant_plan(matrix_effects()?)
}

/// Builds the exact one-case plan applied by the live matrix runner.
pub(super) fn hardware_variant_case_plan(
    case: HardwareVariantCase,
) -> Result<FaultSignalPlan, String> {
    let matrix = matrix_effects()?
        .into_iter()
        .find(|matrix| matrix.case == case)
        .ok_or_else(|| format!("hardware variant `{}` is absent from the matrix", case.name))?;
    build_hardware_variant_plan(vec![matrix])
}

/// Builds a typed read-error request for a source that does not advertise it.
pub(super) fn unsupported_clock_read_error_plan() -> Result<FaultSignalPlan, String> {
    let apic = object_id("x86-local-apic-timer-vcpu-0")?;
    build_hardware_variant_plan(vec![MatrixEffect {
        case: HardwareVariantCase {
            name: "clock-source-unsupported-read-error",
            binding: "hardware-clock-source-rejection",
            coordinate: 1,
        },
        activation: Activation::StateMachine,
        target: ResolvedFaultTarget::ClockSource {
            node: object_id("fault-hardware-matrix-node")?,
            source: apic.clone(),
        },
        phase: FaultPhase::SourceSwitch,
        effect: NodeEffectSpecification::ClockSourceState {
            sources: ObjectIdSet::new(vec![apic])
                .map_err(|error| format!("hardware rejection clock source set: {error}"))?,
            transition: ClockSourceTransition::Failed {
                behavior: ClockFailureBehavior::ReadError,
            },
            synchronization_policy: ClockSynchronizationPolicy::Step,
        },
    }])
}

fn build_hardware_variant_plan(cases: Vec<MatrixEffect>) -> Result<FaultSignalPlan, String> {
    let event_schema = signal_id("hardware-variant-event")?;
    let mut nodes = Vec::with_capacity(cases.len());
    let mut outputs = Vec::with_capacity(cases.len());
    let mut bindings = Vec::with_capacity(cases.len());
    let mut transitions = Vec::new();

    for matrix in &cases {
        let output = signal_id(&format!("{}-signal", matrix.case.name))?;
        let event_value = SignalValue::Event {
            schema: event_schema.clone(),
            payload: Vec::new(),
        };
        let (kind, sampling, mapping, lifetime) = match matrix.activation {
            Activation::Impulse => (
                SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime {
                                nanos: matrix.case.coordinate,
                            }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: event_value,
                    }],
                }),
                BindingSampling::AtEvent(BindingEventParent::VirtualTime),
                BindingMapping::ImpulseOnEvent,
                EffectLifetime::Impulse,
            ),
            Activation::StateMachine => {
                let table = object_id(&format!("{}-transition-table", matrix.case.name))?;
                transitions.push(StateTransitionTableDeclaration {
                    id: table.clone(),
                    semantic_version: 1,
                    input: SignalValueType::Event(event_schema.clone()),
                    effect: matrix.effect.kind(),
                    transitions: [(
                        event_value.clone(),
                        object_id(&format!("{}-transition", matrix.case.name))?,
                    )]
                    .into_iter()
                    .collect(),
                    default_transition: object_id(&format!(
                        "{}-default-transition",
                        matrix.case.name
                    ))?,
                });
                (
                    SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                        events: vec![SignalPoint {
                            coordinate: SignalCoordinate::Event {
                                parent: Box::new(SignalCoordinate::VirtualTime {
                                    nanos: matrix.case.coordinate,
                                }),
                                sequence: 0,
                            },
                            sequence: 0,
                            value: event_value,
                        }],
                    }),
                    BindingSampling::AtEvent(BindingEventParent::VirtualTime),
                    BindingMapping::StateTransition {
                        transition_table: table,
                    },
                    EffectLifetime::StateMachine,
                )
            }
            Activation::Persistent => (
                SignalNodeKind::Source(SignalSourceSpecification::Step {
                    points: vec![SignalPoint {
                        coordinate: SignalCoordinate::VirtualTime {
                            nanos: matrix.case.coordinate,
                        },
                        sequence: 0,
                        value: SignalValue::Bool(true),
                    }],
                    before: SignalBoundaryBehavior::Constant(SignalValue::Bool(false)),
                }),
                BindingSampling::AtBoundary,
                BindingMapping::ActiveWhenTrue { invert: false },
                EffectLifetime::Persistent,
            ),
        };
        let shape = match matrix.activation {
            Activation::Persistent => {
                SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            }
            Activation::Impulse | Activation::StateMachine => SignalShape::new(
                SignalValueType::Event(event_schema.clone()),
                SignalUnit::Dimensionless,
                0,
            ),
        }
        .map_err(|error| format!("{} signal shape: {error}", matrix.case.name))?;
        nodes.push(SignalNode {
            id: output.clone(),
            domain: match matrix.activation {
                Activation::Persistent => SignalDomain::VirtualTime,
                Activation::Impulse | Activation::StateMachine => SignalDomain::Event,
            },
            output: shape,
            inputs: Vec::new(),
            kind,
        });
        outputs.push(output.clone());
        bindings.push(PendingBinding {
            id: object_id(matrix.case.binding)?,
            output,
            sampling,
            mapping,
            target: matrix.target.clone(),
            phase: matrix.phase,
            lifetime,
            effect: matrix.effect.clone(),
        });
    }

    let program = SignalProgram::new(nodes, outputs, SignalResourceLimits::default())
        .map_err(|error| format!("hardware variant signal program: {error}"))?;
    let registry = BindingMappingRegistry::new(transitions, Vec::new())
        .map_err(|error| format!("hardware variant mapping registry: {error}"))?;
    let mut admitted = Vec::with_capacity(bindings.len());
    for binding in bindings {
        admitted.push(
            FaultBinding::new_with_registry(
                binding.id,
                vec![binding.output],
                binding.sampling,
                binding.mapping,
                TargetSelector::Exact(target_set(binding.target)?),
                [binding.phase].into_iter().collect(),
                EffectRequest::new(
                    EFFECT_SEMANTIC_VERSION,
                    binding.lifetime,
                    EffectSpecification::Node(binding.effect),
                )
                .map_err(|error| format!("hardware variant effect: {error}"))?,
                None,
                BindingSearchPolicy::Fixed,
                BindingObservabilityPolicy::default(),
                &program,
                &registry,
            )
            .map_err(|error| format!("hardware variant binding: {error}"))?,
        );
    }

    FaultSignalPlan::new(vec![program], admitted, FaultResourceLimits::default())
        .map_err(|error| format!("hardware variant plan: {error}"))
}

#[derive(Clone, Copy)]
enum Activation {
    Impulse,
    StateMachine,
    Persistent,
}

#[derive(Clone)]
struct MatrixEffect {
    case: HardwareVariantCase,
    activation: Activation,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    effect: NodeEffectSpecification,
}

struct PendingBinding {
    id: FaultObjectId,
    output: SignalId,
    sampling: BindingSampling,
    mapping: BindingMapping,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    lifetime: EffectLifetime,
    effect: NodeEffectSpecification,
}

fn matrix_effects() -> Result<Vec<MatrixEffect>, String> {
    let cases = hardware_variant_cases();
    let tsc = object_id("x86-tsc-vcpu-0")?;
    let apic = object_id("x86-local-apic-timer-vcpu-0")?;
    let accelerator = object_id("accelerator-0")?;
    let clock_target = ResolvedFaultTarget::ClockSource {
        node: object_id("fault-hardware-matrix-node")?,
        source: tsc.clone(),
    };
    let source_target = ResolvedFaultTarget::ClockSource {
        node: object_id("fault-hardware-matrix-node")?,
        source: apic.clone(),
    };
    let accelerator_target = ResolvedFaultTarget::Accelerator {
        node: object_id("fault-hardware-matrix-node")?,
        device: accelerator.clone(),
    };
    let positive =
        |field, value| PositiveU64::new(field, value).map_err(|error| format!("{field}: {error}"));
    let ratio = |numerator, denominator| {
        ExactRatio::new(numerator, denominator)
            .map_err(|error| format!("hardware matrix ratio: {error}"))
    };

    let transforms = [
        (
            ClockMutation::Offset {
                offset_nanos: 1_000_000,
            },
            ClockMonotonicityPolicy::ClampMonotonic,
            ClockOverdueTimerPolicy::FireAtBoundary,
        ),
        (
            ClockMutation::Drift {
                ratio: ratio(1_000_001, 1_000_000)?,
            },
            ClockMonotonicityPolicy::AllowBackward,
            ClockOverdueTimerPolicy::ReschedulePeriodic,
        ),
        (
            ClockMutation::Jump {
                delta_nanos: -10_000,
            },
            ClockMonotonicityPolicy::FaultOnBackward,
            ClockOverdueTimerPolicy::Drop,
        ),
        (
            ClockMutation::Freeze {
                value_nanos: 2_000_000,
                release: ClockFreezeReleasePolicy::ResumeFromFrozen,
            },
            ClockMonotonicityPolicy::ClampMonotonic,
            ClockOverdueTimerPolicy::FireAtBoundary,
        ),
        (
            ClockMutation::Freeze {
                value_nanos: 2_100_000,
                release: ClockFreezeReleasePolicy::CatchUpJump,
            },
            ClockMonotonicityPolicy::AllowBackward,
            ClockOverdueTimerPolicy::Drop,
        ),
        (
            ClockMutation::Jitter {
                maximum_nanos: positive("maximum_nanos", 50)?,
                distribution_nanos: vec![-50, 0, 50],
            },
            ClockMonotonicityPolicy::ClampMonotonic,
            ClockOverdueTimerPolicy::ReschedulePeriodic,
        ),
        (
            ClockMutation::Wander {
                process: ClockWanderProcess {
                    step_nanos: positive("step_nanos", 1_000)?,
                    maximum_offset_nanos: positive("maximum_offset_nanos", 10_000)?,
                    maximum_rate_ppb: positive("maximum_rate_ppb", 500)?,
                    increments_ppb: vec![-100, 0, 100],
                },
            },
            ClockMonotonicityPolicy::ClampMonotonic,
            ClockOverdueTimerPolicy::ReschedulePeriodic,
        ),
    ];
    let mut effects = Vec::with_capacity(cases.len());
    for (index, (mutation, monotonicity, overdue_timer_policy)) in
        transforms.into_iter().enumerate()
    {
        effects.push(MatrixEffect {
            case: cases[index],
            activation: if index < 3 {
                Activation::Impulse
            } else {
                Activation::Persistent
            },
            target: clock_target.clone(),
            phase: FaultPhase::ClockRead,
            effect: NodeEffectSpecification::ClockTransform {
                source: tsc.clone(),
                mutation,
                monotonicity,
                overdue_timer_policy,
            },
        });
    }

    let source_transitions = [
        (
            ClockSourceTransition::Degraded,
            ClockSynchronizationPolicy::Step,
        ),
        (
            ClockSourceTransition::Healthy,
            ClockSynchronizationPolicy::Step,
        ),
        (
            ClockSourceTransition::Failed {
                behavior: ClockFailureBehavior::Stop,
            },
            ClockSynchronizationPolicy::Step,
        ),
        (
            ClockSourceTransition::Healthy,
            ClockSynchronizationPolicy::Step,
        ),
        (
            ClockSourceTransition::Failed {
                behavior: ClockFailureBehavior::ReadError,
            },
            ClockSynchronizationPolicy::Step,
        ),
        (
            ClockSourceTransition::Fallback {
                source: object_id("x86-hpet-0")?,
            },
            ClockSynchronizationPolicy::Slew {
                rate: ratio(1, 16)?,
                threshold_nanos: positive("threshold_nanos", 1_000)?,
            },
        ),
        (
            ClockSourceTransition::Healthy,
            ClockSynchronizationPolicy::Step,
        ),
    ];
    for (offset, (transition, synchronization_policy)) in source_transitions.into_iter().enumerate()
    {
        let (target, source) = if offset == 4 {
            (clock_target.clone(), tsc.clone())
        } else {
            (source_target.clone(), apic.clone())
        };
        effects.push(MatrixEffect {
            case: cases[7 + offset],
            activation: Activation::StateMachine,
            target,
            phase: FaultPhase::SourceSwitch,
            effect: NodeEffectSpecification::ClockSourceState {
                sources: ObjectIdSet::new(vec![source])
                    .map_err(|error| format!("hardware matrix clock source set: {error}"))?,
                transition,
                synchronization_policy,
            },
        });
    }

    let lifecycle = [
        (
            AcceleratorTransition::Disappear,
            NodeStatePolicy::Preserve,
            NodeStatePolicy::Preserve,
        ),
        (
            AcceleratorTransition::Reconnect,
            NodeStatePolicy::Preserve,
            NodeStatePolicy::Preserve,
        ),
        (
            AcceleratorTransition::Reset,
            NodeStatePolicy::Clear,
            NodeStatePolicy::DeviceReset,
        ),
    ];
    for (offset, (transition, queue_policy, memory_policy)) in lifecycle.into_iter().enumerate() {
        effects.push(MatrixEffect {
            case: cases[14 + offset],
            activation: Activation::StateMachine,
            target: accelerator_target.clone(),
            phase: FaultPhase::Boundary,
            effect: NodeEffectSpecification::AcceleratorLifecycle {
                device: accelerator.clone(),
                transition,
                queue_policy,
                memory_policy,
            },
        });
    }

    let memory = [
        (Some(MemoryEccKind::Corrected), Some(0x51), None),
        (Some(MemoryEccKind::Uncorrectable), Some(0x52), None),
        (
            None,
            None,
            Some(
                HexBytes::parse("a5", 1)
                    .map_err(|error| format!("accelerator memory transform: {error}"))?,
            ),
        ),
    ];
    for (offset, (ecc, syndrome, transform)) in memory.into_iter().enumerate() {
        effects.push(MatrixEffect {
            case: cases[17 + offset],
            activation: Activation::Impulse,
            target: accelerator_target.clone(),
            phase: FaultPhase::Boundary,
            effect: NodeEffectSpecification::AcceleratorMemoryEvent {
                range: ByteRange::new(offset as u64, 1)
                    .map_err(|error| format!("accelerator matrix range: {error}"))?,
                ecc,
                syndrome,
                transform,
            },
        });
    }

    let services = [
        (ratio(1, 2)?, None, None, 315_000, 25_000),
        (
            ratio(1, 1)?,
            Some(positive("memory_bytes_per_second", 4_096)?),
            None,
            320_000,
            30_000,
        ),
        (
            ratio(1, 1)?,
            None,
            Some(positive("jobs_per_second", 8)?),
            325_000,
            35_000,
        ),
    ];
    for (offset, (capacity, memory_bytes_per_second, jobs_per_second, temperature, power)) in
        services.into_iter().enumerate()
    {
        effects.push(MatrixEffect {
            case: cases[20 + offset],
            activation: Activation::Persistent,
            target: accelerator_target.clone(),
            phase: FaultPhase::Execute,
            effect: NodeEffectSpecification::AcceleratorService {
                capacity,
                memory_bytes_per_second,
                jobs_per_second,
                thermal_power: AcceleratorThermalPower {
                    temperature_millikelvin: temperature,
                    power_milliwatts: power,
                },
            },
        });
    }

    if effects.len() != cases.len() {
        return Err(format!(
            "hardware variant plan built {} effects for {} cases",
            effects.len(),
            cases.len()
        ));
    }
    Ok(effects)
}

const fn case(name: &'static str, coordinate: u64) -> HardwareVariantCase {
    HardwareVariantCase {
        name,
        binding: name,
        coordinate,
    }
}

fn target_set(target: ResolvedFaultTarget) -> Result<ResolvedTargetSet, String> {
    ResolvedTargetSet::new(vec![target], false)
        .map_err(|error| format!("hardware matrix target: {error}"))
}

fn signal_id(value: &str) -> Result<SignalId, String> {
    SignalId::parse(value).map_err(|error| format!("signal ID `{value}`: {error}"))
}

fn object_id(value: &str) -> Result<FaultObjectId, String> {
    FaultObjectId::parse(value).map_err(|error| format!("object ID `{value}`: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{hardware_variant_cases, hardware_variant_plan};

    #[test]
    fn closed_hardware_variant_matrix_admits_every_exact_case() {
        let plan = hardware_variant_plan()
            .unwrap_or_else(|error| panic!("hardware variant plan did not admit: {error}"));
        assert_eq!(plan.bindings().len(), hardware_variant_cases().len());
        assert_eq!(hardware_variant_cases().len(), 23);
    }
}
