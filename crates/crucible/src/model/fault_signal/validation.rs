//! Admission and canonical graph ordering for signal programs.
//!
//! This module owns structural, resource, type, unit, domain, and reachability
//! validation. A program becomes executable only after all checks complete and
//! its nodes have been placed in a deterministic topological order.

use super::*;

pub(super) fn validate_and_order(
    nodes: Vec<SignalNode>,
    exports: &[SignalId],
    limits: SignalResourceLimits,
) -> Result<Vec<SignalNode>, SignalProgramError> {
    let node_count = u64::try_from(nodes.len()).map_err(|_| SignalProgramError::CountOverflow {
        field: "signal_nodes",
    })?;
    if node_count > u64::from(limits.nodes) {
        return Err(SignalProgramError::ResourceExceeded {
            field: "signal_nodes",
            current: node_count,
            requested: node_count,
            configured: u64::from(limits.nodes),
            hard: u64::from(HARD_SIGNAL_NODE_LIMIT),
        });
    }
    if exports.is_empty() {
        return Err(SignalProgramError::NoExportedOutputs);
    }

    let mut by_id = BTreeMap::new();
    let mut edge_count = 0_u64;
    let mut state_bytes = 0_u64;
    let mut authored_payload_bytes = 0_u64;
    for mut node in nodes {
        canonicalize_node_inputs(&mut node);
        node.output.validate()?;
        let input_count =
            u64::try_from(node.inputs.len()).map_err(|_| SignalProgramError::CountOverflow {
                field: "signal_inputs_per_node",
            })?;
        if input_count > u64::from(limits.inputs_per_node) {
            return Err(SignalProgramError::NodeInputLimit {
                id: node.id.clone(),
                current: input_count,
                configured: u64::from(limits.inputs_per_node),
                hard: u64::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT),
            });
        }
        edge_count =
            edge_count
                .checked_add(input_count)
                .ok_or(SignalProgramError::CountOverflow {
                    field: "signal_edges",
                })?;
        validate_node_contract(&node, limits)?;
        let node_payload_bytes = encoded_node_parameter_bytes(&node)?;
        authored_payload_bytes = authored_payload_bytes
            .checked_add(node_payload_bytes)
            .ok_or(SignalProgramError::CountOverflow {
                field: "signal_authored_payload_bytes",
            })?;
        if let SignalNodeKind::Stateful {
            state_bytes: node_state_bytes,
            ..
        } = &node.kind
        {
            state_bytes = state_bytes.checked_add(*node_state_bytes).ok_or(
                SignalProgramError::CountOverflow {
                    field: "signal_state_bytes",
                },
            )?;
        }
        let id = node.id.clone();
        if by_id.insert(id.clone(), node).is_some() {
            return Err(SignalProgramError::DuplicateNode { id });
        }
    }
    check_resource(
        "signal_edges",
        edge_count,
        u64::from(limits.edges),
        u64::from(HARD_SIGNAL_EDGE_LIMIT),
    )?;
    check_resource(
        "signal_state_bytes",
        state_bytes,
        limits.state_bytes,
        HARD_SIGNAL_STATE_BYTES_LIMIT,
    )?;
    check_resource(
        "signal_authored_payload_bytes",
        authored_payload_bytes,
        limits.authored_payload_bytes,
        HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
    )?;

    for export in exports {
        if !by_id.contains_key(export) {
            return Err(SignalProgramError::MissingExport { id: export.clone() });
        }
    }
    for node in by_id.values() {
        for (index, input) in node.inputs.iter().enumerate() {
            let source = by_id
                .get(input)
                .ok_or_else(|| SignalProgramError::MissingInput {
                    node: node.id.clone(),
                    input: input.clone(),
                })?;
            validate_edge_contract(node, source, index)?;
        }
        validate_input_group(node, &by_id)?;
    }

    let reachable = reachable_nodes(&by_id, exports)?;
    if let Some(id) = by_id.keys().find(|id| !reachable.contains(*id)) {
        return Err(SignalProgramError::UnreferencedNode { id: (*id).clone() });
    }
    topological_order(by_id, limits.graph_depth)
}

pub(super) fn encoded_node_parameter_bytes(node: &SignalNode) -> Result<u64, SignalProgramError> {
    struct Counter {
        bytes: u64,
    }

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let length = u64::try_from(bytes.len()).map_err(|_| {
                std::io::Error::other("signal authored payload byte count overflowed")
            })?;
            self.bytes = self.bytes.checked_add(length).ok_or_else(|| {
                std::io::Error::other("signal authored payload byte count overflowed")
            })?;
            if self.bytes > HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT {
                return Err(std::io::Error::other(
                    "signal authored payload exceeds compiled hard ceiling",
                ));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter { bytes: 0 };
    serde_json::to_writer(&mut counter, &node.kind).map_err(|_| {
        SignalProgramError::ResourceExceeded {
            field: "signal_authored_payload_bytes",
            current: counter.bytes,
            requested: counter.bytes,
            configured: HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
            hard: HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
        }
    })?;
    Ok(counter.bytes)
}

pub(super) fn canonicalize_node_inputs(node: &mut SignalNode) {
    let commutative = matches!(
        &node.kind,
        SignalNodeKind::Pure(PureSignalSpecification::Simple {
            operator: PureSignalOperator::Add
                | PureSignalOperator::Min
                | PureSignalOperator::Max
                | PureSignalOperator::Equal
                | PureSignalOperator::NotEqual
                | PureSignalOperator::All
                | PureSignalOperator::Any,
            ..
        }) | SignalNodeKind::Pure(PureSignalSpecification::MergeEvents { .. })
    );
    if commutative {
        node.inputs.sort();
    }
}

pub(super) fn check_resource(
    field: &'static str,
    current: u64,
    configured: u64,
    hard: u64,
) -> Result<(), SignalProgramError> {
    if current > configured {
        return Err(SignalProgramError::ResourceExceeded {
            field,
            current,
            requested: current,
            configured,
            hard,
        });
    }
    Ok(())
}

pub(super) fn validate_node_contract(
    node: &SignalNode,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    match &node.kind {
        SignalNodeKind::Constant { value } => {
            if !node.inputs.is_empty() {
                return Err(SignalProgramError::InvalidInputCount {
                    node: node.id.clone(),
                    expected: "zero",
                    actual: node.inputs.len(),
                });
            }
            let actual = value
                .value_type()
                .ok_or_else(|| SignalProgramError::InvalidValue {
                    node: node.id.clone(),
                })?;
            if actual != node.output.value_type {
                return Err(SignalProgramError::LiteralTypeMismatch {
                    node: node.id.clone(),
                    declared: node.output.value_type.material(),
                    actual: actual.material(),
                });
            }
            return Ok(());
        }
        SignalNodeKind::Source(specification) => {
            let expected_inputs = match specification {
                SignalSourceSpecification::TransmitterField {
                    position_signal,
                    orientation_signal,
                    environment_signals,
                    ..
                } => {
                    let mut expected = vec![position_signal.clone()];
                    expected.extend(orientation_signal.iter().cloned());
                    expected.extend(environment_signals.iter().cloned());
                    expected
                }
                _ => Vec::new(),
            };
            if node.inputs != expected_inputs {
                return Err(SignalProgramError::InvalidInputCount {
                    node: node.id.clone(),
                    expected: "the source schema's referenced signals in field order",
                    actual: node.inputs.len(),
                });
            }
            validate_source(node, specification, limits)?;
        }
        SignalNodeKind::Pure(specification) => validate_pure(node, specification, limits)?,
        SignalNodeKind::Stateful {
            specification,
            state_bytes,
        } => {
            if *state_bytes == 0 {
                return Err(SignalProgramError::ZeroStateBound {
                    node: node.id.clone(),
                });
            }
            validate_stateful(node, specification, limits)?;
        }
    }
    validate_operator_arity(node)
}

pub(super) fn validate_source(
    node: &SignalNode,
    specification: &SignalSourceSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let valid_value =
        |value: &SignalValue| value.value_type().as_ref() == Some(&node.output.value_type);
    let valid_point = |point: &SignalPoint| {
        coordinate_domain(&point.coordinate) == node.domain && valid_value(&point.value)
    };
    let valid = match specification {
        SignalSourceSpecification::Step { points, before } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.iter().all(valid_point)
                && ordered_points(points)
                && boundary_valid(before, &node.output.value_type)
        }
        SignalSourceSpecification::Pulse {
            start,
            duration,
            inactive,
            active,
        } => {
            coordinate_domain(start) == node.domain
                && *duration > 0
                && valid_value(inactive)
                && valid_value(active)
        }
        SignalSourceSpecification::PeriodicPulse {
            epoch,
            period,
            width,
            phase,
            inactive,
            active,
        } => {
            coordinate_domain(epoch) == node.domain
                && *period > 0
                && *width <= *period
                && *phase < *period
                && valid_value(inactive)
                && valid_value(active)
        }
        SignalSourceSpecification::Ramp {
            start,
            end,
            start_value,
            end_value,
            ..
        } => {
            coordinate_domain(start) == node.domain
                && coordinate_domain(end) == node.domain
                && start < end
                && valid_value(start_value)
                && valid_value(end_value)
                && node.output.value_type.is_numeric()
        }
        SignalSourceSpecification::Triangle {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            ..
        }
        | SignalSourceSpecification::Sawtooth {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            ..
        } => {
            coordinate_domain(epoch) == node.domain
                && *period > 0
                && *phase < *period
                && valid_value(minimum)
                && valid_value(maximum)
                && minimum < maximum
                && node.output.value_type.is_numeric()
        }
        SignalSourceSpecification::EventSequence { events } => {
            matches!(node.output.value_type, SignalValueType::Event(_))
                && point_count_valid(events.len(), limits.lookup_points_per_node)
                && events.iter().all(valid_point)
                && ordered_points(events)
        }
        SignalSourceSpecification::Trace {
            quality_channel,
            quality_accept,
            time_mapping,
            interpolation,
            missing,
            before,
            after,
            ..
        } => {
            quality_channel.is_some() == quality_accept.is_some()
                && time_mapping_valid(time_mapping)
                && (*missing != MissingSampleBehavior::Interpolate
                    || !matches!(interpolation, SignalInterpolation::Exact))
                && boundary_valid(before, &node.output.value_type)
                && boundary_valid(after, &node.output.value_type)
        }
        SignalSourceSpecification::Telemetry { boundary_delay, .. } => *boundary_delay == 1,
        SignalSourceSpecification::PointSet {
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::ZoneMap {
            boundary, overlap, ..
        } => {
            node.domain == SignalDomain::Spatial
                && matches!(boundary.as_str(), "inclusive" | "exclusive")
                && overlap.as_str() == "priority-then-id"
        }
        SignalSourceSpecification::PathProfile {
            interpolation,
            before,
            after,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(before, &node.output.value_type)
                && spatial_boundary_valid(after, &node.output.value_type)
        }
        SignalSourceSpecification::RegularGrid {
            cell_size_mm,
            dimensions,
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && cell_size_mm.iter().all(|value| *value > 0)
                && dimensions.iter().all(|value| *value > 0)
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::TiledGrid {
            tile_size_mm,
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && tile_size_mm.iter().all(|value| *value > 0)
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::SeededField {
            quantization_mm,
            correlation_mm,
            distribution,
            distribution_parameters,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && quantization_mm.iter().all(|value| *value > 0)
                && correlation_mm.iter().all(|value| *value > 0)
                && seeded_distribution_valid(
                    distribution,
                    distribution_parameters,
                    &node.output.value_type,
                )
        }
        SignalSourceSpecification::TransmitterField { model, .. } => matches!(
            model.as_str(),
            "free-space" | "log-distance" | "two-ray" | "calibrated-lookup"
        ),
        SignalSourceSpecification::Bernoulli {
            probability_millionths,
            ..
        } => {
            *probability_millionths <= 1_000_000 && node.output.value_type == SignalValueType::Bool
        }
        SignalSourceSpecification::UniformInteger {
            minimum, maximum, ..
        } => minimum <= maximum && node.output.value_type == SignalValueType::I64,
        SignalSourceSpecification::ExponentialWait {
            rate,
            sampler_version,
            ..
        } => {
            *sampler_version == SIGNAL_EVALUATOR_VERSION
                && rate.numerator() > 0
                && node.output.value_type == SignalValueType::DurationNanos
        }
        SignalSourceSpecification::WeibullWait {
            shape,
            scale_nanos,
            sampler_version,
            ..
        } => {
            *sampler_version == SIGNAL_EVALUATOR_VERSION
                && shape.numerator() > 0
                && *scale_nanos > 0
                && node.output.value_type == SignalValueType::DurationNanos
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidSource {
            node: node.id.clone(),
        });
    }
    Ok(())
}

pub(super) fn boundary_valid(
    boundary: &SignalBoundaryBehavior,
    value_type: &SignalValueType,
) -> bool {
    match boundary {
        SignalBoundaryBehavior::Constant(value) => value.value_type().as_ref() == Some(value_type),
        SignalBoundaryBehavior::Error
        | SignalBoundaryBehavior::Hold
        | SignalBoundaryBehavior::Repeat
        | SignalBoundaryBehavior::Inactive => true,
    }
}

pub(super) fn spatial_boundary_valid(
    boundary: &SignalBoundaryBehavior,
    value_type: &SignalValueType,
) -> bool {
    !matches!(boundary, SignalBoundaryBehavior::Repeat) && boundary_valid(boundary, value_type)
}

pub(super) fn spatial_interpolation_valid(
    interpolation: SignalInterpolation,
    value_type: &SignalValueType,
) -> bool {
    !matches!(interpolation, SignalInterpolation::Linear { .. }) || value_type.is_numeric()
}

pub(super) fn seeded_distribution_valid(
    distribution: &SignalId,
    parameters: &[i64],
    value_type: &SignalValueType,
) -> bool {
    match distribution.as_str() {
        "uniform-integer" => {
            value_type == &SignalValueType::I64
                && parameters.len() == 2
                && parameters[0] <= parameters[1]
        }
        "probability-millionths" => {
            value_type == &SignalValueType::ProbabilityMillionths
                && parameters.len() == 1
                && (0..=1_000_000).contains(&parameters[0])
        }
        "signed-hash" => value_type == &SignalValueType::I64 && parameters.is_empty(),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SignalDimension {
    Dimensionless,
    Time,
    Length,
    SquareLength,
    Velocity,
    Angle,
    Temperature,
    Voltage,
    Current,
    Power,
    Energy,
    LogRatio,
    AbsoluteRadioPower,
    Frequency,
    DataRate,
    OperationRate,
    Concentration,
    Probability,
    Acceleration,
    Precipitation,
}

pub(super) fn compatible_units(from: SignalUnit, to: SignalUnit) -> bool {
    unit_dimension(from) == unit_dimension(to)
}

pub(super) fn unit_dimension(unit: SignalUnit) -> SignalDimension {
    match unit {
        SignalUnit::Dimensionless => SignalDimension::Dimensionless,
        SignalUnit::VirtualNanoseconds => SignalDimension::Time,
        SignalUnit::Millimetres => SignalDimension::Length,
        SignalUnit::SquareMillimetres => SignalDimension::SquareLength,
        SignalUnit::MillimetresPerSecond => SignalDimension::Velocity,
        SignalUnit::Millidegrees => SignalDimension::Angle,
        SignalUnit::Millicelsius => SignalDimension::Temperature,
        SignalUnit::Microvolts => SignalDimension::Voltage,
        SignalUnit::Microamps => SignalDimension::Current,
        SignalUnit::Microwatts | SignalUnit::Femtowatts => SignalDimension::Power,
        SignalUnit::Microjoules => SignalDimension::Energy,
        SignalUnit::Millidecibels => SignalDimension::LogRatio,
        SignalUnit::MillidecibelMilliwatts => SignalDimension::AbsoluteRadioPower,
        SignalUnit::Kilohertz => SignalDimension::Frequency,
        SignalUnit::BitsPerSecond | SignalUnit::BytesPerSecond => SignalDimension::DataRate,
        SignalUnit::OperationsPerSecond => SignalDimension::OperationRate,
        SignalUnit::PartsPerMillion => SignalDimension::Concentration,
        SignalUnit::ProbabilityMillionths => SignalDimension::Probability,
        SignalUnit::MicrometresPerSecondSquared => SignalDimension::Acceleration,
        SignalUnit::MicrometresPerHour => SignalDimension::Precipitation,
    }
}

pub(super) fn coordinate_domain(coordinate: &SignalCoordinate) -> SignalDomain {
    match coordinate {
        SignalCoordinate::VirtualTime { .. } => SignalDomain::VirtualTime,
        SignalCoordinate::NodeCounter { .. } => SignalDomain::NodeCounter,
        SignalCoordinate::Operation { .. } => SignalDomain::Operation,
        SignalCoordinate::Spatial { .. } => SignalDomain::Spatial,
        SignalCoordinate::Event { .. } => SignalDomain::Event,
        SignalCoordinate::State { .. } => SignalDomain::State,
    }
}

pub(super) fn ordered_points(points: &[SignalPoint]) -> bool {
    points.windows(2).all(|pair| {
        pair[0].coordinate < pair[1].coordinate
            || (pair[0].coordinate == pair[1].coordinate && pair[0].sequence < pair[1].sequence)
    })
}

pub(super) fn time_mapping_valid(mapping: &Option<TraceTimeMapping>) -> bool {
    mapping
        .as_ref()
        .is_none_or(|mapping| mapping.scale.numerator() > 0)
}

pub(super) fn validate_pure(
    node: &SignalNode,
    specification: &PureSignalSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let valid = match specification {
        PureSignalSpecification::Simple { operator, .. } => matches!(
            operator,
            PureSignalOperator::Add
                | PureSignalOperator::Subtract
                | PureSignalOperator::Absolute
                | PureSignalOperator::Negate
                | PureSignalOperator::Min
                | PureSignalOperator::Max
                | PureSignalOperator::Equal
                | PureSignalOperator::NotEqual
                | PureSignalOperator::Less
                | PureSignalOperator::LessEqual
                | PureSignalOperator::Greater
                | PureSignalOperator::GreaterEqual
                | PureSignalOperator::All
                | PureSignalOperator::Any
                | PureSignalOperator::Not
                | PureSignalOperator::Select
                | PureSignalOperator::EdgeRising
                | PureSignalOperator::EdgeFalling
        ),
        PureSignalSpecification::RatioArithmetic {
            operator, ratio, ..
        } => {
            matches!(
                operator,
                PureSignalOperator::MultiplyRatio | PureSignalOperator::DivideRatio
            ) && !(*operator == PureSignalOperator::DivideRatio && ratio.numerator() == 0)
        }
        PureSignalSpecification::Clamp {
            minimum, maximum, ..
        } => {
            minimum.value_type().as_ref() == Some(&node.output.value_type)
                && maximum.value_type().as_ref() == Some(&node.output.value_type)
                && minimum <= maximum
        }
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && points.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
                && boundary_valid(before, &node.output.value_type)
                && boundary_valid(after, &node.output.value_type)
        }
        PureSignalSpecification::PiecewiseLinear { points, .. } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && node.output.value_type.is_numeric()
                && points.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
        }
        PureSignalSpecification::EnumMap { entries } => {
            point_count_valid(entries.len(), limits.lookup_points_per_node)
                && entries.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && entries.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
        }
        PureSignalSpecification::UnitConvert {
            from_unit, to_unit, ..
        } => compatible_units(*from_unit, *to_unit) && *to_unit == node.output.unit,
        PureSignalSpecification::Delay {
            delay,
            retained_samples,
        } => *delay > 0 && *retained_samples > 0,
        PureSignalSpecification::SampleHold {
            cadence,
            epoch,
            retained_samples,
        } => *cadence > 0 && *retained_samples > 0 && coordinate_domain(epoch) == node.domain,
        PureSignalSpecification::Window {
            operator,
            window,
            retained_samples,
            ..
        } => {
            matches!(
                operator,
                PureSignalOperator::WindowMin
                    | PureSignalOperator::WindowMax
                    | PureSignalOperator::WindowMean
            ) && *window > 0
                && *retained_samples > 0
        }
        PureSignalSpecification::Distance { metric, .. } => {
            matches!(
                metric.as_str(),
                "manhattan" | "euclidean" | "euclidean-squared"
            )
        }
        PureSignalSpecification::OrientationDelta { convention } => {
            convention.as_str() == "yaw-pitch-roll-millidegrees"
        }
        PureSignalSpecification::ZoneContains { .. } | PureSignalSpecification::FieldSample => true,
        PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        } => {
            *source_sequence_limit > 0
                && matches!(node.output.value_type, SignalValueType::Event(_))
                && u64::try_from(node.inputs.len())
                    .is_ok_and(|count| count.checked_mul(*source_sequence_limit).is_some())
        }
        PureSignalSpecification::GateEvents => {
            matches!(node.output.value_type, SignalValueType::Event(_))
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidOperator {
            node: node.id.clone(),
        });
    }
    Ok(())
}

pub(super) fn validate_stateful(
    node: &SignalNode,
    specification: &StatefulSignalSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let expected_inputs = match specification {
        StatefulSignalSpecification::MarkovChain { .. }
        | StatefulSignalSpecification::BurstProcess { .. } => 0,
        StatefulSignalSpecification::QueueModel { .. } => 2,
        StatefulSignalSpecification::FiniteStateMachine { transitions, .. } => {
            let guards = transitions
                .iter()
                .filter_map(|transition| transition.guard.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if node.inputs.get(1..) != Some(guards.as_slice()) {
                return Err(SignalProgramError::InvalidStatefulOperator {
                    node: node.id.clone(),
                });
            }
            node.inputs.len()
        }
        _ => 1,
    };
    if node.inputs.len() != expected_inputs {
        return Err(SignalProgramError::InvalidInputCount {
            node: node.id.clone(),
            expected: match expected_inputs {
                0 => "zero",
                1 => "one",
                2 => "two",
                _ => "the registered number of",
            },
            actual: node.inputs.len(),
        });
    }
    let valid = match specification {
        StatefulSignalSpecification::Hysteresis {
            set_when,
            clear_when,
            ..
        } => {
            node.output.value_type == SignalValueType::Bool
                && set_when.value_type() == clear_when.value_type()
                && clear_when < set_when
        }
        StatefulSignalSpecification::Debounce {
            initial,
            residence_nanos,
        } => initial.value_type().as_ref() == Some(&node.output.value_type) && *residence_nanos > 0,
        StatefulSignalSpecification::Integrator {
            initial,
            time_unit_nanos,
            ..
        } => {
            initial.value_type().as_ref() == Some(&node.output.value_type)
                && node.output.value_type.is_numeric()
                && *time_unit_nanos > 0
        }
        StatefulSignalSpecification::LeakyIntegrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            maximum_catch_up_steps,
            ..
        } => {
            initial.value_type().as_ref() == Some(&node.output.value_type)
                && node.output.value_type.is_numeric()
                && *cadence_nanos > 0
                && *time_unit_nanos > 0
                && *maximum_catch_up_steps > 0
        }
        StatefulSignalSpecification::FiniteStateMachine {
            states,
            initial,
            transitions,
            ..
        } => {
            matches!(node.output.value_type, SignalValueType::Enum(_))
                && point_count_valid(states.len(), limits.states_per_node)
                && sorted_unique(states)
                && states.contains(initial)
                && point_count_valid(transitions.len(), limits.transitions_per_node)
                && transitions.iter().all(|transition| {
                    states.contains(&transition.from)
                        && states.contains(&transition.to)
                        && transition
                            .timer_operations
                            .iter()
                            .all(|operation| match operation {
                                StateMachineTimerOperation::Start { duration_nanos, .. } => {
                                    *duration_nanos > 0
                                }
                                StateMachineTimerOperation::Cancel { .. } => true,
                            })
                })
                && transitions.windows(2).all(|pair| {
                    (&pair[0].from, &pair[0].event, &pair[0].guard)
                        < (&pair[1].from, &pair[1].event, &pair[1].guard)
                })
        }
        StatefulSignalSpecification::MarkovChain {
            states,
            initial,
            probability_rows,
            ..
        } => {
            matches!(node.output.value_type, SignalValueType::Enum(_))
                && point_count_valid(states.len(), limits.states_per_node)
                && sorted_unique(states)
                && states.contains(initial)
                && probability_rows.len() == states.len()
                && probability_rows.iter().all(|row| {
                    row.len() == states.len()
                        && row.iter().all(|value| *value <= 1_000_000)
                        && row.iter().map(|value| u64::from(*value)).sum::<u64>() == 1_000_000
                })
        }
        StatefulSignalSpecification::BurstProcess {
            good_to_bad_millionths,
            bad_to_good_millionths,
            ..
        } => {
            node.output.value_type == SignalValueType::Bool
                && *good_to_bad_millionths <= 1_000_000
                && *bad_to_good_millionths <= 1_000_000
        }
        StatefulSignalSpecification::Counter {
            initial, maximum, ..
        } => {
            initial <= maximum
                && node.output.value_type == SignalValueType::U64
                && node.output.unit == SignalUnit::Dimensionless
                && node.output.scale_decimal_exponent == 0
        }
        StatefulSignalSpecification::QueueModel { capacity, .. } => {
            *capacity > 0
                && node.output.value_type == SignalValueType::U64
                && node.output.unit == SignalUnit::Dimensionless
                && node.output.scale_decimal_exponent == 0
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidStatefulOperator {
            node: node.id.clone(),
        });
    }
    Ok(())
}

pub(super) fn sorted_unique(values: &[SignalId]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(super) fn point_count_valid(count: usize, configured: u32) -> bool {
    count > 0 && u32::try_from(count).is_ok_and(|count| count <= configured)
}

impl PureSignalSpecification {
    pub(super) fn operator(&self) -> PureSignalOperator {
        match self {
            Self::Simple { operator, .. }
            | Self::RatioArithmetic { operator, .. }
            | Self::Window { operator, .. } => *operator,
            Self::Clamp { .. } => PureSignalOperator::Clamp,
            Self::LookupStep { .. } => PureSignalOperator::LookupStep,
            Self::PiecewiseLinear { .. } => PureSignalOperator::PiecewiseLinear,
            Self::EnumMap { .. } => PureSignalOperator::EnumMap,
            Self::UnitConvert { .. } => PureSignalOperator::UnitConvert,
            Self::Delay { .. } => PureSignalOperator::Delay,
            Self::SampleHold { .. } => PureSignalOperator::SampleHold,
            Self::Distance { .. } => PureSignalOperator::Distance,
            Self::ZoneContains { .. } => PureSignalOperator::ZoneContains,
            Self::FieldSample => PureSignalOperator::FieldSample,
            Self::OrientationDelta { .. } => PureSignalOperator::OrientationDelta,
            Self::MergeEvents { .. } => PureSignalOperator::MergeEvents,
            Self::GateEvents => PureSignalOperator::GateEvents,
        }
    }
}

pub(super) fn validate_operator_arity(node: &SignalNode) -> Result<(), SignalProgramError> {
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let (minimum, maximum, expected) = match operator {
        PureSignalOperator::Add
        | PureSignalOperator::Min
        | PureSignalOperator::Max
        | PureSignalOperator::All
        | PureSignalOperator::Any
        | PureSignalOperator::MergeEvents => (1, usize::MAX, "one or more"),
        PureSignalOperator::Subtract
        | PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual
        | PureSignalOperator::Distance
        | PureSignalOperator::ZoneContains
        | PureSignalOperator::FieldSample
        | PureSignalOperator::OrientationDelta
        | PureSignalOperator::GateEvents => (2, 2, "two"),
        PureSignalOperator::Select => (3, 3, "three"),
        _ => (1, 1, "one"),
    };
    if node.inputs.len() < minimum || node.inputs.len() > maximum {
        return Err(SignalProgramError::InvalidInputCount {
            node: node.id.clone(),
            expected,
            actual: node.inputs.len(),
        });
    }
    Ok(())
}

pub(super) fn validate_edge_contract(
    node: &SignalNode,
    source: &SignalNode,
    index: usize,
) -> Result<(), SignalProgramError> {
    if node.domain != source.domain && !cross_domain_operator(&node.kind) {
        return Err(SignalProgramError::ImplicitDomainCrossing {
            node: node.id.clone(),
            input: source.id.clone(),
            node_domain: node.domain,
            input_domain: source.domain,
        });
    }
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let same_shape = source.output == node.output;
    let boolean = SignalValueType::Bool;
    let shape_ok = match operator {
        PureSignalOperator::Add
        | PureSignalOperator::Subtract
        | PureSignalOperator::Min
        | PureSignalOperator::Max
        | PureSignalOperator::Clamp
        | PureSignalOperator::Absolute
        | PureSignalOperator::Negate
        | PureSignalOperator::MultiplyRatio
        | PureSignalOperator::DivideRatio
        | PureSignalOperator::Delay
        | PureSignalOperator::SampleHold
        | PureSignalOperator::WindowMin
        | PureSignalOperator::WindowMax
        | PureSignalOperator::WindowMean => same_shape && source.output.value_type.is_numeric(),
        PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual => {
            node.output.value_type == boolean && node.output.unit == SignalUnit::Dimensionless
        }
        PureSignalOperator::All | PureSignalOperator::Any | PureSignalOperator::Not => {
            source.output.value_type == boolean
                && node.output.value_type == boolean
                && source.output.unit == SignalUnit::Dimensionless
                && node.output.unit == SignalUnit::Dimensionless
        }
        PureSignalOperator::Select => {
            if index == 0 {
                source.output.value_type == boolean
            } else {
                source.output == node.output
            }
        }
        PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling => {
            source.output.value_type == boolean
                && matches!(node.output.value_type, SignalValueType::Event(_))
        }
        PureSignalOperator::GateEvents => {
            if index == 0 {
                matches!(source.output.value_type, SignalValueType::Event(_))
                    && source.output == node.output
            } else {
                source.output.value_type == boolean
            }
        }
        PureSignalOperator::MergeEvents => source.output == node.output,
        PureSignalOperator::UnitConvert
        | PureSignalOperator::LookupStep
        | PureSignalOperator::PiecewiseLinear
        | PureSignalOperator::EnumMap
        | PureSignalOperator::Distance
        | PureSignalOperator::ZoneContains
        | PureSignalOperator::FieldSample
        | PureSignalOperator::OrientationDelta => true,
    };
    if !shape_ok {
        return Err(SignalProgramError::InputShapeMismatch {
            node: node.id.clone(),
            input: source.id.clone(),
            input_shape: source.output.material(),
            output_shape: node.output.material(),
        });
    }
    if matches!(
        operator,
        PureSignalOperator::Absolute | PureSignalOperator::Negate
    ) && !source.output.value_type.is_signed()
    {
        return Err(SignalProgramError::SignedInputRequired {
            node: node.id.clone(),
        });
    }
    Ok(())
}

pub(super) fn validate_input_group(
    node: &SignalNode,
    nodes: &BTreeMap<SignalId, SignalNode>,
) -> Result<(), SignalProgramError> {
    let inputs = node
        .inputs
        .iter()
        .map(|id| {
            nodes
                .get(id)
                .ok_or_else(|| SignalProgramError::MissingInput {
                    node: node.id.clone(),
                    input: id.clone(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let SignalNodeKind::Stateful { specification, .. } = &node.kind {
        let valid = match specification {
            StatefulSignalSpecification::Hysteresis {
                set_when,
                clear_when,
                ..
            } => inputs.first().is_some_and(|input| {
                input.output.value_type.is_numeric()
                    && set_when.value_type().as_ref() == Some(&input.output.value_type)
                    && clear_when.value_type().as_ref() == Some(&input.output.value_type)
            }),
            StatefulSignalSpecification::Debounce { .. } => inputs
                .first()
                .is_some_and(|input| input.output == node.output),
            StatefulSignalSpecification::Integrator { .. }
            | StatefulSignalSpecification::LeakyIntegrator { .. } => inputs
                .first()
                .is_some_and(|input| input.output.value_type.is_numeric()),
            StatefulSignalSpecification::FiniteStateMachine { .. } => {
                inputs.first().is_some_and(|input| {
                    matches!(input.output.value_type, SignalValueType::Event(_))
                }) && inputs.iter().skip(1).all(|input| {
                    input.output.value_type == SignalValueType::Bool
                        && input.output.unit == SignalUnit::Dimensionless
                })
            }
            StatefulSignalSpecification::MarkovChain { .. }
            | StatefulSignalSpecification::BurstProcess { .. } => inputs.is_empty(),
            StatefulSignalSpecification::Counter { .. } => inputs
                .first()
                .is_some_and(|input| matches!(input.output.value_type, SignalValueType::Event(_))),
            StatefulSignalSpecification::QueueModel { .. } => {
                inputs.first().is_some_and(|input| {
                    matches!(input.output.value_type, SignalValueType::Event(_))
                }) && inputs.get(1).is_some_and(|input| {
                    matches!(
                        input.output.value_type,
                        SignalValueType::RatePerSecond | SignalValueType::U64
                    )
                })
            }
        };
        if !valid {
            return Err(SignalProgramError::InputGroupMismatch {
                node: node.id.clone(),
            });
        }
        return Ok(());
    }
    if let SignalNodeKind::Source(SignalSourceSpecification::TransmitterField { .. }) = &node.kind {
        let position_valid = inputs.first().is_some_and(|input| {
            matches!(input.output.value_type, SignalValueType::Vector3(_))
                && input.output.unit == SignalUnit::Millimetres
        });
        let orientation_valid = match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::TransmitterField {
                orientation_signal,
                ..
            }) if orientation_signal.is_some() => inputs.get(1).is_some_and(|input| {
                matches!(input.output.value_type, SignalValueType::Vector3(_))
                    && input.output.unit == SignalUnit::Millidegrees
            }),
            _ => true,
        };
        let environment_start = match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::TransmitterField {
                orientation_signal,
                ..
            }) => 1 + usize::from(orientation_signal.is_some()),
            _ => 1,
        };
        let environments_valid = inputs[environment_start..]
            .iter()
            .all(|input| input.output == node.output);
        if !position_valid || !orientation_valid || !environments_valid {
            return Err(SignalProgramError::InputGroupMismatch {
                node: node.id.clone(),
            });
        }
        return Ok(());
    }
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let pair_equal = inputs
        .first()
        .is_none_or(|first| inputs.iter().all(|input| input.output == first.output));
    let valid = match operator {
        PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual => {
            pair_equal
                && inputs
                    .first()
                    .is_some_and(|input| input.output.value_type.is_numeric())
        }
        PureSignalOperator::Select => {
            inputs
                .get(1)
                .zip(inputs.get(2))
                .is_some_and(|(when_true, when_false)| {
                    when_true.output == when_false.output && when_true.output == node.output
                })
        }
        PureSignalOperator::MergeEvents => pair_equal,
        PureSignalOperator::UnitConvert => {
            let PureSignalSpecification::UnitConvert {
                from_unit, to_unit, ..
            } = specification
            else {
                return Err(SignalProgramError::InvalidOperator {
                    node: node.id.clone(),
                });
            };
            inputs.first().is_some_and(|input| {
                input.output.unit == *from_unit
                    && node.output.unit == *to_unit
                    && input.output.value_type == node.output.value_type
                    && input.output.value_type.is_numeric()
            })
        }
        PureSignalOperator::EnumMap => inputs
            .first()
            .is_some_and(|input| matches!(input.output.value_type, SignalValueType::Enum(_))),
        PureSignalOperator::LookupStep | PureSignalOperator::PiecewiseLinear => {
            let points = match specification {
                PureSignalSpecification::LookupStep { points, .. }
                | PureSignalSpecification::PiecewiseLinear { points, .. } => points,
                _ => {
                    return Err(SignalProgramError::InvalidOperator {
                        node: node.id.clone(),
                    });
                }
            };
            inputs.first().is_some_and(|input| {
                input.output.value_type.is_numeric()
                    && points
                        .iter()
                        .all(|(key, _)| key.value_type().as_ref() == Some(&input.output.value_type))
            })
        }
        PureSignalOperator::FieldSample => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(field, position)| {
                    field.domain == SignalDomain::Spatial
                        && field.output == node.output
                        && is_position_shape(&position.output)
                        && position.output.unit == SignalUnit::Millimetres
                })
        }
        PureSignalOperator::ZoneContains => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(position, zones)| {
                    zones.domain == SignalDomain::Spatial
                        && matches!(zones.output.value_type, SignalValueType::Enum(_))
                        && is_position_shape(&position.output)
                        && position.output.unit == SignalUnit::Millimetres
                        && node.output.value_type == SignalValueType::Bool
                })
        }
        PureSignalOperator::Distance => {
            let PureSignalSpecification::Distance { metric, .. } = specification else {
                return Err(SignalProgramError::InvalidOperator {
                    node: node.id.clone(),
                });
            };
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(left, right)| {
                    left.output == right.output
                        && is_position_shape(&left.output)
                        && left.output.unit == SignalUnit::Millimetres
                        && node.output.value_type == SignalValueType::I64
                        && node.output.scale_decimal_exponent == left.output.scale_decimal_exponent
                        && node.output.unit
                            == if metric.as_str() == "euclidean-squared" {
                                SignalUnit::SquareMillimetres
                            } else {
                                SignalUnit::Millimetres
                            }
                })
        }
        PureSignalOperator::OrientationDelta => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(left, right)| {
                    left.output == right.output
                        && matches!(
                            left.output.value_type,
                            SignalValueType::Vector3(ref element)
                                if element.as_ref() == &SignalValueType::I64
                        )
                        && left.output.unit == SignalUnit::Millidegrees
                        && node.output == left.output
                })
        }
        _ => true,
    };
    if !valid {
        return Err(SignalProgramError::InputGroupMismatch {
            node: node.id.clone(),
        });
    }
    Ok(())
}

pub(super) fn is_position_shape(shape: &SignalShape) -> bool {
    matches!(
        &shape.value_type,
        SignalValueType::Vector2(element) | SignalValueType::Vector3(element)
            if element.as_ref() == &SignalValueType::I64
    )
}

pub(super) fn cross_domain_operator(kind: &SignalNodeKind) -> bool {
    matches!(
        kind,
        SignalNodeKind::Pure(PureSignalSpecification::FieldSample)
            | SignalNodeKind::Pure(PureSignalSpecification::SampleHold { .. })
    )
}

pub(super) fn reachable_nodes(
    nodes: &BTreeMap<SignalId, SignalNode>,
    exports: &[SignalId],
) -> Result<BTreeSet<SignalId>, SignalProgramError> {
    let mut reachable = BTreeSet::new();
    let mut pending = exports.to_vec();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let node = nodes
            .get(&id)
            .ok_or_else(|| SignalProgramError::MissingExport { id: id.clone() })?;
        pending.extend(node.inputs.iter().cloned());
    }
    Ok(reachable)
}

pub(super) fn topological_order(
    mut nodes: BTreeMap<SignalId, SignalNode>,
    configured_depth: u16,
) -> Result<Vec<SignalNode>, SignalProgramError> {
    let mut dependants: BTreeMap<SignalId, Vec<SignalId>> = BTreeMap::new();
    let mut indegree = BTreeMap::new();
    let mut depth = BTreeMap::new();
    for node in nodes.values() {
        indegree.insert(node.id.clone(), node.inputs.len());
        for input in &node.inputs {
            dependants
                .entry(input.clone())
                .or_default()
                .push(node.id.clone());
        }
    }
    for values in dependants.values_mut() {
        values.sort();
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<VecDeque<_>>();
    let mut ordered_ids = Vec::with_capacity(nodes.len());
    while let Some(id) = ready.pop_front() {
        let node_depth = *depth.entry(id.clone()).or_insert(1_u16);
        if node_depth > configured_depth {
            return Err(SignalProgramError::GraphDepthExceeded {
                node: id,
                current: u64::from(node_depth),
                configured: u64::from(configured_depth),
                hard: u64::from(HARD_SIGNAL_GRAPH_DEPTH_LIMIT),
            });
        }
        ordered_ids.push(id.clone());
        if let Some(children) = dependants.get(&id) {
            for child in children {
                let child_depth =
                    node_depth
                        .checked_add(1)
                        .ok_or(SignalProgramError::CountOverflow {
                            field: "signal_graph_depth",
                        })?;
                depth
                    .entry(child.clone())
                    .and_modify(|current| *current = (*current).max(child_depth))
                    .or_insert(child_depth);
                let count =
                    indegree
                        .get_mut(child)
                        .ok_or_else(|| SignalProgramError::MissingInput {
                            node: child.clone(),
                            input: id.clone(),
                        })?;
                *count = count
                    .checked_sub(1)
                    .ok_or(SignalProgramError::CountOverflow {
                        field: "signal_edges",
                    })?;
                if *count == 0 {
                    let position = ready.partition_point(|candidate| candidate < child);
                    ready.insert(position, child.clone());
                }
            }
        }
    }
    if ordered_ids.len() != nodes.len() {
        let id = indegree
            .into_iter()
            .find_map(|(id, count)| (count != 0).then_some(id))
            .ok_or(SignalProgramError::CountOverflow {
                field: "signal_nodes",
            })?;
        return Err(SignalProgramError::Cycle { node: id });
    }
    ordered_ids
        .into_iter()
        .map(|id| {
            nodes.remove(&id).ok_or(SignalProgramError::CountOverflow {
                field: "signal_nodes",
            })
        })
        .collect()
}
