//! Signal-program admission and canonicalization tests.

use super::*;

fn id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("test id must parse: {error}"))
}

fn bool_shape() -> SignalShape {
    SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
        .unwrap_or_else(|error| panic!("test shape must validate: {error}"))
}

fn constant(name: &str, value: bool) -> SignalNode {
    SignalNode {
        id: id(name),
        domain: SignalDomain::VirtualTime,
        output: bool_shape(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::Bool(value),
        },
    }
}

fn i64_shape(unit: SignalUnit) -> SignalShape {
    SignalShape::new(SignalValueType::I64, unit, 0)
        .unwrap_or_else(|error| panic!("test shape must validate: {error}"))
}

fn i64_constant(name: &str, value: i64, unit: SignalUnit) -> SignalNode {
    SignalNode {
        id: id(name),
        domain: SignalDomain::VirtualTime,
        output: i64_shape(unit),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::I64(value),
        },
    }
}

#[test]
fn identifier_contract_is_strict() {
    for valid in ["a", "loss-signal", "node2-clock"] {
        assert!(SignalId::parse(valid).is_ok(), "{valid}");
    }
    for invalid in ["", "A", "-a", "a-", "a--b", "a_b", "é"] {
        assert!(SignalId::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn exact_ratios_must_be_reduced() {
    assert_eq!(
        ExactRatio::new(-2, 3)
            .unwrap_or_else(|error| panic!("reduced ratio must parse: {error}"))
            .numerator(),
        -2
    );
    assert!(ExactRatio::new(2, 4).is_err());
    assert!(ExactRatio::new(1, 0).is_err());
}

#[test]
fn authored_order_does_not_change_identity() {
    let source = constant("source", true);
    let output = SignalNode {
        id: id("output"),
        domain: SignalDomain::VirtualTime,
        output: bool_shape(),
        inputs: vec![id("source")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::Simple {
            operator: PureSignalOperator::Not,
            overflow: SignalOverflow::Error,
        }),
    };
    let first = SignalProgram::new(
        vec![output.clone(), source.clone()],
        vec![id("output")],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("program must validate: {error}"));
    let second = SignalProgram::new(
        vec![source, output],
        vec![id("output")],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("program must validate: {error}"));
    assert_eq!(first.id(), second.id());
    assert_eq!(first.nodes()[0].id.as_str(), "source");
    assert_eq!(first.nodes()[1].id.as_str(), "output");
}

#[test]
fn commutative_input_order_does_not_change_identity() {
    let left = i64_constant("left", 1, SignalUnit::Dimensionless);
    let right = i64_constant("right", 2, SignalUnit::Dimensionless);
    let add = |inputs| SignalNode {
        id: id("sum"),
        domain: SignalDomain::VirtualTime,
        output: i64_shape(SignalUnit::Dimensionless),
        inputs,
        kind: SignalNodeKind::Pure(PureSignalSpecification::Simple {
            operator: PureSignalOperator::Add,
            overflow: SignalOverflow::Error,
        }),
    };
    let first = SignalProgram::new(
        vec![
            left.clone(),
            right.clone(),
            add(vec![id("left"), id("right")]),
        ],
        vec![id("sum")],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("program must validate: {error}"));
    let second = SignalProgram::new(
        vec![left, right, add(vec![id("right"), id("left")])],
        vec![id("sum")],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("program must validate: {error}"));
    assert_eq!(first.id(), second.id());
    assert_eq!(first.nodes()[2].inputs, vec![id("left"), id("right")]);
}

#[test]
fn impossible_math_and_stochastic_parameters_fail_admission() {
    let source = i64_constant("source", 4, SignalUnit::Dimensionless);
    let divide = SignalNode {
        id: id("divide"),
        domain: SignalDomain::VirtualTime,
        output: i64_shape(SignalUnit::Dimensionless),
        inputs: vec![id("source")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::RatioArithmetic {
            operator: PureSignalOperator::DivideRatio,
            ratio: ExactRatio::new(0, 1)
                .unwrap_or_else(|error| panic!("zero ratio is canonical: {error}")),
            rounding: SignalRounding::Floor,
            overflow: SignalOverflow::Error,
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![source, divide],
            vec![id("divide")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidOperator { .. })
    ));

    let wait = SignalNode {
        id: id("wait"),
        domain: SignalDomain::Operation,
        output: SignalShape::new(
            SignalValueType::DurationNanos,
            SignalUnit::VirtualNanoseconds,
            0,
        )
        .unwrap_or_else(|error| panic!("duration shape must validate: {error}")),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::WeibullWait {
            shape: ExactRatio::new(1, 1)
                .unwrap_or_else(|error| panic!("shape must validate: {error}")),
            scale_nanos: 0,
            sampler_version: SIGNAL_EVALUATOR_VERSION,
            sampler_table: ContentHash::from_bytes(b"weibull-table"),
            key_domain: StochasticKeyDomain::Opportunity,
            maximum_nanos: None,
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![wait],
            vec![id("wait")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidSource { .. })
    ));
}

#[test]
fn boundary_lookup_and_conversion_types_fail_closed() {
    let bad_boundary = SignalNode {
        id: id("step"),
        domain: SignalDomain::VirtualTime,
        output: bool_shape(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::Step {
            points: vec![SignalPoint {
                coordinate: SignalCoordinate::VirtualTime { nanos: 1 },
                sequence: 0,
                value: SignalValue::Bool(true),
            }],
            before: SignalBoundaryBehavior::Constant(SignalValue::I64(0)),
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![bad_boundary],
            vec![id("step")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidSource { .. })
    ));

    let source = i64_constant("source", 1, SignalUnit::Millimetres);
    let bad_lookup = SignalNode {
        id: id("lookup"),
        domain: SignalDomain::VirtualTime,
        output: i64_shape(SignalUnit::Millimetres),
        inputs: vec![id("source")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::LookupStep {
            points: vec![(SignalValue::Bool(false), SignalValue::I64(1))],
            before: SignalBoundaryBehavior::Hold,
            after: SignalBoundaryBehavior::Hold,
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![source.clone(), bad_lookup],
            vec![id("lookup")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InputGroupMismatch { .. })
    ));

    let bad_conversion = SignalNode {
        id: id("converted"),
        domain: SignalDomain::VirtualTime,
        output: i64_shape(SignalUnit::Microvolts),
        inputs: vec![id("source")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::UnitConvert {
            from_unit: SignalUnit::Millimetres,
            to_unit: SignalUnit::Microvolts,
            ratio: ExactRatio::new(1, 1)
                .unwrap_or_else(|error| panic!("ratio must validate: {error}")),
            offset: ExactRatio::new(0, 1)
                .unwrap_or_else(|error| panic!("offset must validate: {error}")),
            rounding: SignalRounding::Floor,
            overflow: SignalOverflow::Error,
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![source, bad_conversion],
            vec![id("converted")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidOperator { .. })
    ));
}

#[test]
fn stateful_outputs_and_positional_inputs_are_checked() {
    let event_shape = SignalShape::new(
        SignalValueType::Event(id("packet")),
        SignalUnit::Dimensionless,
        0,
    )
    .unwrap_or_else(|error| panic!("event shape must validate: {error}"));
    let event = SignalNode {
        id: id("events"),
        domain: SignalDomain::Event,
        output: event_shape.clone(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
            events: vec![SignalPoint {
                coordinate: SignalCoordinate::Event {
                    parent: Box::new(SignalCoordinate::VirtualTime { nanos: 1 }),
                    sequence: 0,
                },
                sequence: 0,
                value: SignalValue::Event {
                    schema: id("packet"),
                    payload: Vec::new(),
                },
            }],
        }),
    };
    let counter = SignalNode {
        id: id("counter"),
        domain: SignalDomain::Event,
        output: bool_shape(),
        inputs: vec![id("events")],
        kind: SignalNodeKind::Stateful {
            specification: StatefulSignalSpecification::Counter {
                initial: 0,
                maximum: 10,
                overflow: SignalOverflow::Error,
                reset_event: None,
            },
            state_bytes: 16,
        },
    };
    assert!(matches!(
        SignalProgram::new(
            vec![event.clone(), counter],
            vec![id("counter")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidStatefulOperator { .. })
    ));

    let gate = SignalNode {
        id: id("gate"),
        domain: SignalDomain::Event,
        output: event_shape,
        inputs: vec![id("events"), id("events")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::GateEvents),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![event, gate],
            vec![id("gate")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InputShapeMismatch { .. })
    ));
}

#[test]
fn cycles_and_unreferenced_nodes_fail_admission() {
    let mut left = constant("left", true);
    left.inputs = vec![id("right")];
    left.kind = SignalNodeKind::Pure(PureSignalSpecification::Simple {
        operator: PureSignalOperator::Not,
        overflow: SignalOverflow::Error,
    });
    let mut right = constant("right", false);
    right.inputs = vec![id("left")];
    right.kind = left.kind.clone();
    assert!(matches!(
        SignalProgram::new(
            vec![left, right],
            vec![id("left")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::Cycle { .. })
    ));

    assert!(matches!(
        SignalProgram::new(
            vec![constant("used", true), constant("unused", false)],
            vec![id("used")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::UnreferencedNode { .. })
    ));
}

#[test]
fn limits_and_domain_crossings_fail_closed() {
    let limits = SignalResourceLimits {
        nodes: 1,
        ..SignalResourceLimits::default()
    };
    assert!(matches!(
        SignalProgram::new(
            vec![constant("a", true), constant("b", false)],
            vec![id("a"), id("b")],
            limits
        ),
        Err(SignalProgramError::ResourceExceeded { .. })
    ));

    let source = constant("source", true);
    let output = SignalNode {
        id: id("output"),
        domain: SignalDomain::Operation,
        output: bool_shape(),
        inputs: vec![id("source")],
        kind: SignalNodeKind::Pure(PureSignalSpecification::Simple {
            operator: PureSignalOperator::Not,
            overflow: SignalOverflow::Error,
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![source, output],
            vec![id("output")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::ImplicitDomainCrossing { .. })
    ));
}

#[test]
fn authored_payload_limits_apply_before_canonical_material_is_built() {
    let oversized = SignalValue::Bytes(vec![0; HARD_SIGNAL_LITERAL_BYTES_PER_VALUE + 1]);
    assert_eq!(oversized.value_type(), None);

    let mut node = constant("payload", true);
    node.output = SignalShape::new(SignalValueType::Bytes, SignalUnit::Dimensionless, 0)
        .unwrap_or_else(|error| panic!("bytes shape: {error}"));
    node.kind = SignalNodeKind::Constant {
        value: SignalValue::Bytes(vec![0; 256]),
    };
    let limits = SignalResourceLimits {
        authored_payload_bytes: 32,
        ..SignalResourceLimits::default()
    };
    assert!(matches!(
        SignalProgram::new(vec![node], vec![id("payload")], limits),
        Err(SignalProgramError::ResourceExceeded {
            field: "signal_authored_payload_bytes",
            ..
        })
    ));
}

#[test]
fn malformed_literals_and_invalid_source_schemas_fail() {
    let bad_probability = SignalNode {
        id: id("bad"),
        domain: SignalDomain::Operation,
        output: SignalShape::new(
            SignalValueType::ProbabilityMillionths,
            SignalUnit::ProbabilityMillionths,
            0,
        )
        .unwrap_or_else(|error| panic!("test shape must validate: {error}")),
        inputs: Vec::new(),
        kind: SignalNodeKind::Constant {
            value: SignalValue::ProbabilityMillionths(1_000_001),
        },
    };
    assert!(matches!(
        SignalProgram::new(
            vec![bad_probability],
            vec![id("bad")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidValue { .. })
    ));

    let source = SignalNode {
        id: id("pulse"),
        domain: SignalDomain::VirtualTime,
        output: bool_shape(),
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::PeriodicPulse {
            epoch: SignalCoordinate::VirtualTime { nanos: 0 },
            period: 0,
            width: 0,
            phase: 0,
            inactive: SignalValue::Bool(false),
            active: SignalValue::Bool(true),
        }),
    };
    assert!(matches!(
        SignalProgram::new(
            vec![source],
            vec![id("pulse")],
            SignalResourceLimits::default()
        ),
        Err(SignalProgramError::InvalidSource { .. })
    ));
}
