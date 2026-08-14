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
    let mut limits = FaultResourceLimits::default();
    limits.search_choices_per_state = 1;
    let plan = FaultSignalPlan::new(vec![program], vec![binding], limits)
        .unwrap_or_else(|error| panic!("bounded mutation plan should admit: {error}"));

    assert!(matches!(
        materialize_search_plans(&plan, &MemoryDagStore::new()),
        Err(SearchMaterializationError::CandidateProductLimit)
    ));
}

#[test]
fn trace_mutation_rewrites_canonical_artifacts_and_program_identity() {
    let one =
        PositiveU64::new("one", 1).unwrap_or_else(|error| panic!("invalid unit ratio: {error}"));
    let time_mapping = NormalizedTraceTimeMapping::new(vec![TraceTimeSegment {
        source_start: 0,
        source_end: None,
        source_epoch: 0,
        virtual_epoch_nanos: 0,
        numerator: one,
        denominator: one,
        rounding: SignalRounding::Floor,
    }])
    .unwrap_or_else(|error| panic!("invalid time mapping: {error}"));
    let raw = b"coordinate,event_sequence,value,validity\n1,,7,valid\n2,,8,valid\n";
    let imported = import_signal_trace(
        TraceImportFormat::Csv,
        raw,
        TraceImportOptions {
            channel: signal_id("channel-a"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                .unwrap_or_else(|error| panic!("invalid trace shape: {error}")),
            event_channel: false,
            time_basis: TraceTimeBasis::Nanoseconds,
            time_mapping,
            source_alias: object_id("device-a"),
            privacy_policy: ContentHash::from_bytes(b"privacy"),
            coordinate_frame: None,
            redaction: None,
        },
    )
    .unwrap_or_else(|error| panic!("trace import failed: {error}"));
    let store = MemoryDagStore::new();
    let original_artifact = store_imported_signal_trace(&store, raw, &imported)
        .unwrap_or_else(|error| panic!("trace store failed: {error}"));
    let output = signal_id("output");
    let unrelated = signal_id("unrelated-trace");
    let trace_source = SignalSourceSpecification::Trace {
        artifact: original_artifact,
        raw_provenance: ContentHash::from_bytes(raw),
        channel: signal_id("channel-a"),
        quality_channel: None,
        quality_accept: None,
        interpolation: SignalInterpolation::HoldPrevious,
        before: SignalBoundaryBehavior::Error,
        after: SignalBoundaryBehavior::Hold,
        missing: MissingSampleBehavior::Hold,
        time_mapping: Some(TraceTimeMapping {
            source_epoch: 1,
            virtual_epoch_nanos: 101,
            scale: ExactRatio::new(1, 1)
                .unwrap_or_else(|error| panic!("invalid source time scale: {error}")),
            rounding: SignalRounding::Floor,
        }),
    };
    let program = SignalProgram::new(
        vec![
            SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                    .unwrap_or_else(|error| panic!("invalid signal shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(trace_source.clone()),
            },
            SignalNode {
                id: unrelated.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::U64, SignalUnit::VirtualNanoseconds, 0)
                    .unwrap_or_else(|error| panic!("invalid signal shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(trace_source),
            },
        ],
        vec![output.clone(), unrelated.clone()],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid trace program: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid trace effect: {error}"));
    let binding = FaultBinding::new(
        object_id("binding-trace-mutation"),
        vec![output.clone()],
        BindingSampling::AtBoundary,
        BindingMapping::Threshold {
            comparison: ThresholdComparison::GreaterThan,
            threshold: SignalValue::U64(10),
            clear_threshold: None,
            residence_nanos: 0,
        },
        TargetSelector::Exact(
            ResolvedTargetSet::new(
                vec![ResolvedFaultTarget::NetworkSegment {
                    segment: object_id("segment-a"),
                    direction: FaultDirection::AToB,
                }],
                false,
            )
            .unwrap_or_else(|error| panic!("invalid trace target: {error}")),
        ),
        [FaultPhase::Admit].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::MutateTraceWindow {
            start_nanos: 101,
            end_nanos: 102,
            candidates: [98_u64, 99]
                .into_iter()
                .map(|value| TraceWindowMaterialization {
                    trace_node: output.clone(),
                    samples: vec![TraceSampleMutation {
                        coordinate: 101,
                        event_sequence: None,
                        value: SignalValue::U64(value),
                    }],
                })
                .collect(),
            maximum_mutations: PositiveU64::new("maximum_mutations", 1)
                .unwrap_or_else(|error| panic!("invalid mutation bound: {error}")),
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid trace binding: {error}"));

    assert!(matches!(
        materialize_trace_window(
            &program,
            &binding,
            &store,
            TraceWindowMaterialization {
                trace_node: unrelated,
                samples: vec![TraceSampleMutation {
                    coordinate: 101,
                    event_sequence: None,
                    value: SignalValue::U64(98),
                }],
            },
        ),
        Err(SearchMaterializationError::UnauthorizedTraceNode)
    ));

    let materialized = materialize_trace_window(
        &program,
        &binding,
        &store,
        TraceWindowMaterialization {
            trace_node: output,
            samples: vec![TraceSampleMutation {
                coordinate: 101,
                event_sequence: None,
                value: SignalValue::U64(99),
            }],
        },
    )
    .unwrap_or_else(|error| panic!("trace materialization failed: {error}"));
    assert_ne!(materialized.program.id(), program.id());
    assert!(matches!(
        materialized.binding.search(),
        BindingSearchPolicy::Fixed
    ));
    let materialized_artifact = materialized
        .program
        .nodes()
        .iter()
        .find_map(|node| match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::Trace { artifact, .. }) => {
                Some(*artifact)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("materialized program must retain a trace source"));
    let loaded = load_stored_signal_trace(&store, materialized_artifact)
        .unwrap_or_else(|error| panic!("materialized trace failed to load: {error}"));
    assert_eq!(loaded.chunks[0].entries[0].value, SignalValue::U64(99));
    assert_ne!(materialized.provenance, ContentHash::default());

    let mapping_effect = EffectRequest::new(
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
    .unwrap_or_else(|error| panic!("invalid mapping effect: {error}"));
    let mapping_candidates = [40_u64, 50, 60]
        .into_iter()
        .map(|value| MappingMaterialization {
            points: vec![MappingPointMutation {
                index: 1,
                point: BindingMapPoint {
                    input: SignalValue::U64(100),
                    output: SignalValue::DurationNanos(value),
                },
            }],
        })
        .collect();
    let mapping_binding = FaultBinding::new(
        object_id("binding-z-mapping-mutation"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::PiecewiseParameter {
            parameter: MappedEffectParameter::DurationNanos,
            points: vec![
                BindingMapPoint {
                    input: SignalValue::U64(0),
                    output: SignalValue::DurationNanos(10),
                },
                BindingMapPoint {
                    input: SignalValue::U64(100),
                    output: SignalValue::DurationNanos(30),
                },
            ],
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
            .unwrap_or_else(|error| panic!("invalid mapping target: {error}")),
        ),
        [FaultPhase::Resolve].into_iter().collect(),
        mapping_effect,
        None,
        BindingSearchPolicy::MutateMapping {
            point_indices: vec![1],
            candidates: mapping_candidates,
            maximum_mutations: PositiveU64::new("maximum_mutations", 1)
                .unwrap_or_else(|error| panic!("invalid mutation bound: {error}")),
        },
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid mapping binding: {error}"));
    let plan = FaultSignalPlan::new(
        vec![program],
        vec![binding, mapping_binding],
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid mixed mutation plan: {error}"));
    let plans = materialize_search_plans(&plan, &store)
        .unwrap_or_else(|error| panic!("mixed mutation space should materialize: {error}"));
    assert_eq!(plans.len(), 6);
    for plan in plans {
        assert_eq!(plan.cases.len(), 2);
        assert!(plan.plan.bindings().iter().all(|binding| {
            matches!(binding.search(), BindingSearchPolicy::Fixed)
                && binding.program() == plan.plan.programs()[0].id()
        }));
        assert_eq!(plan.artifacts, plan.cases[0].artifacts);
        assert!(plan.cases[1].artifacts.is_empty());
        let manifest = plan.cases[0]
            .artifacts
            .last()
            .copied()
            .unwrap_or_else(|| panic!("trace mutation must retain its manifest"));
        assert!(matches!(
            &plan.plan.programs()[0].nodes()[0].kind,
            SignalNodeKind::Source(SignalSourceSpecification::Trace { artifact, .. })
                if *artifact == manifest
        ));
    }
}
