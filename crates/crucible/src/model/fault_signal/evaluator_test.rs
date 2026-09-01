//! Tests for deterministic signal evaluation and checkpoint continuation.

use super::*;
use crate::model::MemoryDagStore;

fn id(value: &str) -> SignalId {
    match SignalId::parse(value) {
        Ok(value) => value,
        Err(error) => panic!("test signal ID must be valid: {error}"),
    }
}

fn object_id(value: &str) -> FaultObjectId {
    match FaultObjectId::parse(value) {
        Ok(value) => value,
        Err(error) => panic!("test object ID must be valid: {error}"),
    }
}

fn shape(value_type: SignalValueType, unit: SignalUnit) -> SignalShape {
    match SignalShape::new(value_type, unit, 0) {
        Ok(value) => value,
        Err(error) => panic!("test shape must be valid: {error}"),
    }
}

fn choice() -> SignalChoiceContext {
    SignalChoiceContext {
        scenario_seed: ContentHash::from_bytes(b"scenario"),
        consumer: object_id("consumer"),
        opportunity: None,
        transition_sequence: None,
    }
}

#[test]
fn ramp_and_ratio_arithmetic_are_exact() {
    let value_shape = shape(SignalValueType::I64, SignalUnit::Dimensionless);
    let ramp = SignalNode {
        id: id("ramp"),
        domain: SignalDomain::VirtualTime,
        output: value_shape.clone(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::Ramp {
            start: SignalCoordinate::VirtualTime { nanos: 0 },
            end: SignalCoordinate::VirtualTime { nanos: 10 },
            start_value: SignalValue::I64(-10),
            end_value: SignalValue::I64(10),
            rounding: SignalRounding::NearestTiesToEven,
        }),
    };
    let scaled = SignalNode {
        id: id("scaled"),
        domain: SignalDomain::VirtualTime,
        output: value_shape,
        inputs: vec![id("ramp")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::RatioArithmetic {
            operator: PureSignalOperator::MultiplyRatio,
            ratio: match ExactRatio::new(3, 2) {
                Ok(value) => value,
                Err(error) => panic!("test ratio must be valid: {error}"),
            },
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        }),
    };
    let program = match SignalProgram::new(
        vec![scaled, ramp],
        vec![id("scaled")],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    };
    let store = MemoryDagStore::new();
    let provider = DagSignalArtifactProvider::new(&store);
    let mut evaluator = match SignalEvaluator::new(
        &program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test evaluator must initialize: {error}"),
    };
    let result = evaluator.evaluate(&SignalEvaluationRequest {
        output: id("scaled"),
        coordinate: SignalCoordinate::VirtualTime { nanos: 7 },
        same_coordinate_sequence: 0,
        choice: choice(),
    });
    assert!(matches!(
        result,
        Ok(EvaluatedSignal::Value(SignalValue::I64(6)))
    ));
}

#[test]
fn ratio_division_preserves_a_negative_divisor() {
    let value_shape = shape(SignalValueType::I64, SignalUnit::Dimensionless);
    let input = SignalNode {
        id: id("input"),
        domain: SignalDomain::VirtualTime,
        output: value_shape.clone(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::I64(8),
        },
    };
    let divided = SignalNode {
        id: id("divided"),
        domain: SignalDomain::VirtualTime,
        output: value_shape,
        inputs: vec![id("input")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::RatioArithmetic {
            operator: PureSignalOperator::DivideRatio,
            ratio: match ExactRatio::new(-2, 1) {
                Ok(value) => value,
                Err(error) => panic!("test ratio must be valid: {error}"),
            },
            rounding: SignalRounding::NearestTiesToEven,
            overflow: SignalOverflow::Error,
        }),
    };
    let program = match SignalProgram::new(
        vec![divided, input],
        vec![id("divided")],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    };
    let store = MemoryDagStore::new();
    let provider = DagSignalArtifactProvider::new(&store);
    let mut evaluator = match SignalEvaluator::new(
        &program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test evaluator must initialize: {error}"),
    };
    assert!(matches!(
        evaluator.evaluate(&SignalEvaluationRequest {
            output: id("divided"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 0 },
            same_coordinate_sequence: 0,
            choice: choice(),
        }),
        Ok(EvaluatedSignal::Value(SignalValue::I64(-4)))
    ));
}

#[test]
fn field_sample_uses_content_addressed_grid_and_explicit_position() {
    let grid_shape = shape(SignalValueType::I64, SignalUnit::Millidecibels);
    let artifact = match NormalizedSpatialArtifact::new(
        id("city-frame"),
        grid_shape.clone(),
        SpatialArtifactKind::RegularGrid {
            origin_mm: [0; 3],
            cell_size_mm: [10; 3],
            dimensions: [2, 1, 1],
            values: vec![SignalValue::I64(-100), SignalValue::I64(-200)],
        },
    ) {
        Ok(value) => value,
        Err(error) => panic!("test grid must be valid: {error}"),
    };
    let store = MemoryDagStore::new();
    let stored = store.put(&artifact.encode());
    assert!(matches!(stored, Ok(content) if content == artifact.content()));
    let field = SignalNode {
        id: id("field"),
        domain: SignalDomain::Spatial,
        output: grid_shape.clone(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::RegularGrid {
            artifact: artifact.content(),
            coordinate_frame: id("city-frame"),
            origin_mm: [0; 3],
            cell_size_mm: [10; 3],
            dimensions: [2, 1, 1],
            interpolation: SignalInterpolation::Nearest,
            outside: SignalBoundaryBehavior::Error,
        }),
    };
    let position = SignalNode {
        id: id("position"),
        domain: SignalDomain::VirtualTime,
        output: shape(
            SignalValueType::Vector3(SignalVectorElementType::I64),
            SignalUnit::Millimetres,
        ),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::Vector3(vec![
                SignalValue::I64(9),
                SignalValue::I64(0),
                SignalValue::I64(0),
            ]),
        },
    };
    let sample = SignalNode {
        id: id("sample"),
        domain: SignalDomain::VirtualTime,
        output: grid_shape,
        inputs: vec![id("field"), id("position")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::FieldSample),
    };
    let program = match SignalProgram::new(
        vec![sample, field, position],
        vec![id("sample")],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    };
    let provider = DagSignalArtifactProvider::new(&store);
    let mut evaluator = match SignalEvaluator::new(
        &program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test evaluator must initialize: {error}"),
    };
    let result = evaluator.evaluate(&SignalEvaluationRequest {
        output: id("sample"),
        coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
        same_coordinate_sequence: 0,
        choice: choice(),
    });
    assert!(matches!(
        result,
        Ok(EvaluatedSignal::Value(SignalValue::I64(-200)))
    ));
}

#[test]
fn checkpoint_restore_preserves_stateful_continuation() {
    let event_schema = id("arrival");
    let events = SignalNode {
        id: id("events"),
        domain: SignalDomain::VirtualTime,
        output: shape(
            SignalValueType::Event(event_schema.clone()),
            SignalUnit::Dimensionless,
        ),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
            events: vec![
                SignalPoint {
                    coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema: event_schema.clone(),
                        payload: Vec::new(),
                    },
                },
                SignalPoint {
                    coordinate: SignalCoordinate::VirtualTime { nanos: 2 },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema: event_schema,
                        payload: Vec::new(),
                    },
                },
            ],
        }),
    };
    let counter = SignalNode {
        id: id("counter"),
        domain: SignalDomain::VirtualTime,
        output: shape(SignalValueType::U64, SignalUnit::Dimensionless),
        inputs: vec![id("events")],
        kind: SignalNodeKind::Stateful {
            specification: StatefulSignalSpecification::Counter {
                initial: 0,
                maximum: 10,
                overflow: SignalOverflow::Error,
                reset_event: None,
            },
            state_bytes: 32,
        },
    };
    let program = match SignalProgram::new(
        vec![counter, events],
        vec![id("counter")],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    };
    let store = MemoryDagStore::new();
    let provider = DagSignalArtifactProvider::new(&store);
    let mut uninterrupted = match SignalEvaluator::new(
        &program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test evaluator must initialize: {error}"),
    };
    let first = SignalEvaluationRequest {
        output: id("counter"),
        coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
        same_coordinate_sequence: 0,
        choice: choice(),
    };
    assert!(matches!(
        uninterrupted.evaluate(&first),
        Ok(EvaluatedSignal::Value(SignalValue::U64(1)))
    ));
    let checkpoint = match uninterrupted.checkpoint() {
        Ok(value) => value,
        Err(error) => panic!("test checkpoint must encode: {error}"),
    };
    let mut restored = match SignalEvaluator::restore(
        &program,
        &provider,
        &checkpoint,
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test checkpoint must restore: {error}"),
    };
    let second = SignalEvaluationRequest {
        output: id("counter"),
        coordinate: SignalCoordinate::VirtualTime { nanos: 2 },
        same_coordinate_sequence: 0,
        choice: choice(),
    };
    assert_eq!(
        uninterrupted.evaluate(&second).ok(),
        restored.evaluate(&second).ok()
    );
    assert_eq!(uninterrupted.checkpoint().ok(), restored.checkpoint().ok());
}

#[test]
fn event_merge_maps_global_sequence_to_source_then_local_sequence() {
    let event_schema = id("merged-event");
    let event_shape = shape(
        SignalValueType::Event(event_schema.clone()),
        SignalUnit::Dimensionless,
    );
    let source = |source_id: &str, payload: u8| SignalNode {
        id: id(source_id),
        domain: SignalDomain::VirtualTime,
        output: event_shape.clone(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
            events: vec![SignalPoint {
                coordinate: SignalCoordinate::VirtualTime { nanos: 10 },
                sequence: 0,
                value: SignalValue::Event {
                    schema: event_schema.clone(),
                    payload: vec![payload],
                },
            }],
        }),
    };
    let merge = SignalNode {
        id: id("merge"),
        domain: SignalDomain::VirtualTime,
        output: event_shape.clone(),
        inputs: vec![id("source-b"), id("source-a")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::MergeEvents {
            source_sequence_limit: 4,
        }),
    };
    let program = match SignalProgram::new(
        vec![merge, source("source-b", 2), source("source-a", 1)],
        vec![id("merge")],
        SignalResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test program must be valid: {error}"),
    };
    let store = MemoryDagStore::new();
    let provider = DagSignalArtifactProvider::new(&store);
    let mut evaluator = match SignalEvaluator::new(
        &program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test evaluator must initialize: {error}"),
    };
    let evaluate = |evaluator: &mut SignalEvaluator<'_>, sequence| {
        evaluator.evaluate(&SignalEvaluationRequest {
            output: id("merge"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 10 },
            same_coordinate_sequence: sequence,
            choice: choice(),
        })
    };
    assert!(matches!(
        evaluate(&mut evaluator, 0),
        Ok(EvaluatedSignal::Value(SignalValue::Event { payload, .. })) if payload == vec![1]
    ));
    assert!(matches!(
        evaluate(&mut evaluator, 4),
        Ok(EvaluatedSignal::Value(SignalValue::Event { payload, .. })) if payload == vec![2]
    ));
}

#[test]
fn trace_interpolate_policy_bridges_an_invalid_exact_sample() {
    let mut entries = vec![
        MappedTraceEntry {
            coordinate: 0,
            event_sequence: None,
            value: SignalValue::I64(0),
            validity: TraceValidity::Valid,
        },
        MappedTraceEntry {
            coordinate: 5,
            event_sequence: None,
            value: SignalValue::I64(99),
            validity: TraceValidity::InvalidQuality,
        },
        MappedTraceEntry {
            coordinate: 10,
            event_sequence: None,
            value: SignalValue::I64(10),
            validity: TraceValidity::Valid,
        },
    ];
    assert!(matches!(
        sample_mapped_entries(
            &mut entries,
            5,
            None,
            SignalInterpolation::Linear {
                rounding: SignalRounding::NearestTiesToEven,
                overflow: SignalOverflow::Error,
            },
            MissingSampleBehavior::Interpolate,
        ),
        Ok(EvaluatedSignal::Value(SignalValue::I64(5)))
    ));
}

#[test]
fn cadence_integrator_commits_prior_input_at_boundaries() {
    let specification = StatefulSignalSpecification::Integrator {
        initial: SignalValue::I64(0),
        cadence_nanos: 10,
        time_unit_nanos: 10,
        rounding: SignalRounding::NearestTiesToEven,
        overflow: SignalOverflow::Error,
    };
    let node = SignalNode {
        id: id("integrator"),
        domain: SignalDomain::VirtualTime,
        output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
        inputs: vec![id("input")],
        kind: SignalNodeKind::Stateful {
            specification: specification.clone(),
            state_bytes: 256,
        },
    };
    let mut state = EvaluatorNodeState::Integrator {
        accumulator: SignalValue::I64(0),
        pending: SignalValue::I64(0),
        previous_input: None,
        last_nanos: None,
    };
    let mut emitted = Vec::new();
    let mut evaluate = |nanos, input| {
        evaluate_stateful_node(
            &node,
            &specification,
            &SignalEvaluationRequest {
                output: id("integrator"),
                coordinate: SignalCoordinate::VirtualTime { nanos },
                same_coordinate_sequence: 0,
                choice: choice(),
            },
            &[EvaluatedSignal::Value(SignalValue::I64(input))],
            &mut state,
            &mut emitted,
            FaultResourceLimits::default(),
        )
    };

    assert!(matches!(
        evaluate(0, 2),
        Ok(EvaluatedSignal::Value(SignalValue::I64(0)))
    ));
    assert!(matches!(
        evaluate(5, 4),
        Ok(EvaluatedSignal::Value(SignalValue::I64(0)))
    ));
    assert!(matches!(
        evaluate(10, 6),
        Ok(EvaluatedSignal::Value(SignalValue::I64(3)))
    ));
}

#[test]
fn leaky_integrator_rejects_excess_catch_up_before_mutation() {
    let specification = StatefulSignalSpecification::LeakyIntegrator {
        initial: SignalValue::I64(0),
        cadence_nanos: 10,
        time_unit_nanos: 10,
        decay_ratio: match ExactRatio::new(1, 2) {
            Ok(value) => value,
            Err(error) => panic!("test ratio must be valid: {error}"),
        },
        maximum_catch_up_steps: 2,
        rounding: SignalRounding::NearestTiesToEven,
        overflow: SignalOverflow::Error,
    };
    let node = SignalNode {
        id: id("leaky"),
        domain: SignalDomain::VirtualTime,
        output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
        inputs: vec![id("input")],
        kind: SignalNodeKind::Stateful {
            specification: specification.clone(),
            state_bytes: 256,
        },
    };
    let mut state = EvaluatorNodeState::LeakyIntegrator {
        accumulator: SignalValue::I64(0),
        previous_input: None,
        last_nanos: None,
    };
    let mut emitted = Vec::new();
    let first = evaluate_stateful_node(
        &node,
        &specification,
        &SignalEvaluationRequest {
            output: id("leaky"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 0 },
            same_coordinate_sequence: 0,
            choice: choice(),
        },
        &[EvaluatedSignal::Value(SignalValue::I64(10))],
        &mut state,
        &mut emitted,
        FaultResourceLimits::default(),
    );
    assert!(first.is_ok());
    let before = state.clone();
    let result = evaluate_stateful_node(
        &node,
        &specification,
        &SignalEvaluationRequest {
            output: id("leaky"),
            coordinate: SignalCoordinate::VirtualTime { nanos: 30 },
            same_coordinate_sequence: 0,
            choice: choice(),
        },
        &[EvaluatedSignal::Value(SignalValue::I64(10))],
        &mut state,
        &mut emitted,
        FaultResourceLimits::default(),
    );
    assert!(matches!(
        result,
        Err(SignalEvaluationError::CatchUpLimitExceeded {
            requested: 3,
            maximum: 2,
        })
    ));
    assert_eq!(state, before);
}

#[test]
fn stochastic_keys_ignore_unselected_identity_domains() {
    let node = SignalNode {
        id: id("random"),
        domain: SignalDomain::VirtualTime,
        output: shape(SignalValueType::I64, SignalUnit::Dimensionless),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::UniformInteger {
            minimum: 0,
            maximum: 10,
            key_domain: StochasticKeyDomain::Coordinate,
            opportunity_filter: None,
        }),
    };
    let request = SignalEvaluationRequest {
        output: id("random"),
        coordinate: SignalCoordinate::VirtualTime { nanos: 7 },
        same_coordinate_sequence: 2,
        choice: choice(),
    };
    let mut unrelated = request.clone();
    unrelated.choice.transition_sequence = Some(99);
    assert_eq!(
        keyed_u64(&node, &request, StochasticKeyDomain::Coordinate, 0),
        keyed_u64(&node, &unrelated, StochasticKeyDomain::Coordinate, 0)
    );

    let mut moved = unrelated.clone();
    moved.coordinate = SignalCoordinate::VirtualTime { nanos: 8 };
    moved.same_coordinate_sequence = 0;
    assert_eq!(
        keyed_u64(&node, &unrelated, StochasticKeyDomain::Transition, 0),
        keyed_u64(&node, &moved, StochasticKeyDomain::Transition, 0)
    );
}

#[test]
fn window_includes_the_current_live_sample() {
    let result = evaluate_window(
        PureSignalOperator::WindowMean,
        10,
        4,
        SignalRounding::NearestTiesToEven,
        SignalOverflow::Error,
        &SignalCoordinate::VirtualTime { nanos: 10 },
        0,
        None,
        &EvaluatedSignal::Value(SignalValue::I64(7)),
    );
    assert!(matches!(
        result,
        Ok(EvaluatedSignal::Value(SignalValue::I64(7)))
    ));
}
