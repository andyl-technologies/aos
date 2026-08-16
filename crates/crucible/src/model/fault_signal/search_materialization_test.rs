//! Tests bounded search materialization for signal outcomes and mappings.

use super::*;
use crate::MemoryDagStore;

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value).unwrap_or_else(|error| panic!("invalid test object ID: {error}"))
}

fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("invalid test signal ID: {error}"))
}

#[test]
fn mapping_mutation_becomes_an_ordinary_fixed_binding() {
    let output = signal_id("output");
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(5),
            },
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test program: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("invalid delay: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"));
    let points = vec![
        BindingMapPoint {
            input: SignalValue::U64(0),
            output: SignalValue::DurationNanos(10),
        },
        BindingMapPoint {
            input: SignalValue::U64(10),
            output: SignalValue::DurationNanos(30),
        },
    ];
    let binding = FaultBinding::new(
        object_id("binding-mutation"),
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points,
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        },
        TargetSelector::Exact(
            ResolvedTargetSet::new(
                vec![ResolvedFaultTarget::NetworkSegment {
                    segment: object_id("segment-a"),
                    direction: FaultDirection::AToB,
                }],
                false,
            )
            .unwrap_or_else(|error| panic!("invalid target: {error}")),
        ),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::MutateMapping {
            point_indices: vec![1],
            candidates: vec![MappingMaterialization {
                points: vec![MappingPointMutation {
                    index: 1,
                    point: BindingMapPoint {
                        input: SignalValue::U64(10),
                        output: SignalValue::DurationNanos(50),
                    },
                }],
            }],
            maximum_mutations: PositiveU64::new("maximum_mutations", 1)
                .unwrap_or_else(|error| panic!("invalid mutation limit: {error}")),
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid mutation binding: {error}"));

    let materialized = materialize_mapping(
        &program,
        &binding,
        MappingMaterialization {
            points: vec![MappingPointMutation {
                index: 1,
                point: BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(50),
                },
            }],
        },
    )
    .unwrap_or_else(|error| panic!("materialization failed: {error}"));

    assert_eq!(materialized.program.id(), program.id());
    assert_eq!(materialized.binding.id(), binding.id());
    assert!(matches!(
        materialized.binding.search(),
        BindingSearchPolicy::Fixed
    ));
    assert!(matches!(
        materialized.binding.mapping(),
        BindingMapping::PiecewiseParameter { points, .. }
            if points[1].output == SignalValue::DurationNanos(50)
    ));
    assert_ne!(
        binding
            .contract_digest()
            .unwrap_or_else(|error| panic!("binding contract encoding failed: {error}")),
        materialized
            .binding
            .contract_digest()
            .unwrap_or_else(|error| panic!("materialized contract encoding failed: {error}"))
    );
    assert_ne!(materialized.provenance, ContentHash::default());

    let other = signal_id("other-output");
    let different_program = SignalProgram::new(
        vec![
            program.nodes()[0].clone(),
            SignalNode {
                id: other.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                    .unwrap_or_else(|error| panic!("invalid other shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::U64(6),
                },
            },
        ],
        vec![signal_id("output"), other],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid different program: {error}"));
    assert!(matches!(
        materialize_mapping(
            &different_program,
            &binding,
            MappingMaterialization {
                points: vec![MappingPointMutation {
                    index: 1,
                    point: BindingMapPoint {
                        input: SignalValue::U64(10),
                        output: SignalValue::DurationNanos(60),
                    },
                }],
            },
        ),
        Err(SearchMaterializationError::ProgramIdentity)
    ));
}

#[test]
fn finite_mapping_candidates_materialize_complete_fixed_plans() {
    let output = signal_id("output");
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(5),
            },
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test program: {error}"));
    let target = TargetSelector::Exact(
        ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("invalid target: {error}")),
    );
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("invalid delay: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid effect: {error}"));
    let points = vec![
        BindingMapPoint {
            input: SignalValue::U64(0),
            output: SignalValue::DurationNanos(10),
        },
        BindingMapPoint {
            input: SignalValue::U64(10),
            output: SignalValue::DurationNanos(30),
        },
    ];
    let candidates = [40_u64, 50]
        .into_iter()
        .map(|value| MappingMaterialization {
            points: vec![MappingPointMutation {
                index: 1,
                point: BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(value),
                },
            }],
        })
        .collect();
    let binding = FaultBinding::new(
        object_id("binding-finite-mutation"),
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points,
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        },
        target,
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::MutateMapping {
            point_indices: vec![1],
            candidates,
            maximum_mutations: PositiveU64::new("maximum_mutations", 1)
                .unwrap_or_else(|error| panic!("invalid mutation limit: {error}")),
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid mutation binding: {error}"));
    let plan = FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("invalid mutation plan: {error}"));

    let cases = materialize_search_plans(&plan, &MemoryDagStore::new())
        .unwrap_or_else(|error| panic!("mutation space should materialize: {error}"));
    assert_eq!(cases.len(), 2);
    assert!(cases.iter().all(|case| {
        case.plan.bindings().iter().all(|binding| {
            !matches!(
                binding.search(),
                BindingSearchPolicy::MutateTraceWindow { .. }
                    | BindingSearchPolicy::MutateMapping { .. }
            )
        })
    }));
    assert_ne!(cases[0].provenance, cases[1].provenance);
}

#[test]
fn candidate_product_respects_the_scenario_search_bound() {
    let output = signal_id("bounded-output");
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(5),
            },
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test program: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(
                PositiveU64::new("delay_nanos", 1)
                    .unwrap_or_else(|error| panic!("invalid delay: {error}")),
            ),
            distance_velocity_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid effect: {error}"));
    let target = TargetSelector::Exact(
        ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("invalid target: {error}")),
    );
    let candidates = [40_u64, 50]
        .into_iter()
        .map(|value| MappingMaterialization {
            points: vec![MappingPointMutation {
                index: 1,
                point: BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(value),
                },
            }],
        })
        .collect();
    let binding = FaultBinding::new(
        object_id("binding-bounded-mutation"),
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points: vec![
                BindingMapPoint {
                    input: SignalValue::U64(0),
                    output: SignalValue::DurationNanos(10),
                },
                BindingMapPoint {
                    input: SignalValue::U64(10),
                    output: SignalValue::DurationNanos(30),
                },
            ],
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        },
        target,
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::MutateMapping {
            point_indices: vec![1],
            candidates,
            maximum_mutations: PositiveU64::new("maximum_mutations", 1)
                .unwrap_or_else(|error| panic!("invalid mutation limit: {error}")),
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid mutation binding: {error}"));
    let limits = FaultResourceLimits {
        search_choices_per_state: 1,
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(vec![program], vec![binding], limits)
        .unwrap_or_else(|error| panic!("bounded mutation plan should admit: {error}"));

    assert!(matches!(
        materialize_search_plans(&plan, &MemoryDagStore::new()),
        Err(SearchMaterializationError::CandidateProductLimit)
    ));
}
