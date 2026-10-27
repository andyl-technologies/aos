//! Borrowed canonical signal-program formatting and exact admitted rendering.
//!
//! Renderers preserve semantic input order and separators without allocating
//! intermediate fragments. The final retained text is counted and admitted
//! before its sole exact-sized allocation.

use std::fmt::{self, Display};

use super::*;

pub(super) fn program_material(
    nodes: &[SignalNode],
    exports: &[SignalId],
    limits: SignalResourceLimits,
) -> Result<String, SignalProgramError> {
    crate::model::canonical::material_string(&program_stream(nodes, exports, limits)).map_err(
        |source| match source {
            crate::model::EngineError::ArtifactDecodeAdmission { source } => {
                SignalProgramError::OriginalAdmission(source)
            }
            source => SignalProgramError::CanonicalMaterial(Box::new(source)),
        },
    )
}

fn program_stream<'a>(
    nodes: &'a [SignalNode],
    exports: &'a [SignalId],
    limits: SignalResourceLimits,
) -> impl Display + 'a {
    display(move |formatter| {
        write!(
            formatter,
            "evaluator_version={SIGNAL_EVALUATOR_VERSION}\nlimit.signal_nodes={}\nlimit.signal_edges={}\nlimit.signal_inputs_per_node={}\nlimit.signal_graph_depth={}\nlimit.signal_state_bytes={}\nlimit.state_machine_states_per_node={}\nlimit.state_machine_transitions_per_node={}\nlimit.lookup_points_per_node={}",
            limits.nodes,
            limits.edges,
            limits.inputs_per_node,
            limits.graph_depth,
            limits.state_bytes,
            limits.states_per_node,
            limits.transitions_per_node,
            limits.lookup_points_per_node
        )?;

        for export in exports {
            write!(formatter, "\nexport={}", export.as_str())?;
        }
        for node in nodes {
            write!(
                formatter,
                "\nnode={}\ndomain={}\noutput={}",
                node.id.as_str(),
                node.domain.material(),
                shape_material(&node.output)
            )?;
            for input in &node.inputs {
                write!(formatter, "\ninput={}", input.as_str())?;
            }
            match &node.kind {
                SignalNodeKind::Constant { value } => write!(
                    formatter,
                    "\nkind=constant\nvalue={}",
                    value_material(value)
                )?,
                SignalNodeKind::Source(specification) => write!(
                    formatter,
                    "\nkind=source:{}\nsource={}",
                    source_name(specification),
                    source_material(specification)
                )?,
                SignalNodeKind::Pure(specification) => write!(
                    formatter,
                    "\nkind=pure:{}\npure={}",
                    operator_name(specification.operator()),
                    pure_material(specification)
                )?,
                SignalNodeKind::Stateful {
                    specification,
                    state_bytes,
                } => write!(
                    formatter,
                    "\nkind=stateful:{}\nstate_bytes={state_bytes}\nstateful={}",
                    stateful_name(specification),
                    stateful_material(specification)
                )?,
            }
        }
        Ok(())
    })
}

mod pure;
mod source;
mod stateful;

use pure::pure_material;
use source::source_material;
use stateful::stateful_material;

#[cfg(test)]
mod tests;

struct Material<F>(F);

fn display<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(render: F) -> Material<F> {
    Material(render)
}

impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> Display for Material<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(formatter)
    }
}

fn joined<I>(values: I, separator: &'static str) -> impl Display
where
    I: Clone + IntoIterator,
    I::Item: Display,
{
    display(move |formatter| {
        for (index, value) in values.clone().into_iter().enumerate() {
            if index != 0 {
                formatter.write_str(separator)?;
            }
            write!(formatter, "{value}")?;
        }
        Ok(())
    })
}

fn hex_material(bytes: &[u8]) -> impl Display + '_ {
    display(move |formatter| {
        for byte in bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    })
}

fn type_material(value: &SignalValueType) -> impl Display + '_ {
    display(move |formatter| match value {
        SignalValueType::Bool => formatter.write_str("bool"),
        SignalValueType::I64 => formatter.write_str("i64"),
        SignalValueType::U64 => formatter.write_str("u64"),
        SignalValueType::Ratio => formatter.write_str("ratio"),
        SignalValueType::DurationNanos => formatter.write_str("duration_nanos"),
        SignalValueType::RatePerSecond => formatter.write_str("rate_per_second"),
        SignalValueType::ProbabilityMillionths => formatter.write_str("probability_millionths"),
        SignalValueType::Enum(schema) => write!(formatter, "enum:{}", schema.as_str()),
        SignalValueType::Event(schema) => write!(formatter, "event:{}", schema.as_str()),
        SignalValueType::Vector2(element) => write!(formatter, "vector2:{}", element.material()),
        SignalValueType::Vector3(element) => write!(formatter, "vector3:{}", element.material()),
        SignalValueType::Bytes => formatter.write_str("bytes"),
    })
}

fn shape_material(shape: &SignalShape) -> impl Display + '_ {
    display(move |formatter| {
        write!(
            formatter,
            "{}|{}|{}",
            type_material(&shape.value_type),
            shape.unit.material(),
            shape.scale_decimal_exponent
        )
    })
}

fn value_material(value: &SignalValue) -> impl Display + '_ {
    display(move |formatter| match value {
        SignalValue::Bool(value) => write!(formatter, "bool:{value}"),
        SignalValue::I64(value) => write!(formatter, "i64:{value}"),
        SignalValue::U64(value) => write!(formatter, "u64:{value}"),
        SignalValue::Ratio(value) => write!(
            formatter,
            "ratio:{}/{}",
            value.numerator(),
            value.denominator()
        ),
        SignalValue::DurationNanos(value) => write!(formatter, "duration_nanos:{value}"),
        SignalValue::RatePerSecond(value) => write!(formatter, "rate_per_second:{value}"),
        SignalValue::ProbabilityMillionths(value) => {
            write!(formatter, "probability_millionths:{value}")
        }
        SignalValue::Enum { schema, variant } => {
            write!(formatter, "enum:{}:{}", schema.as_str(), variant.as_str())
        }
        SignalValue::Event { schema, payload } => write!(
            formatter,
            "event:{}:{}",
            schema.as_str(),
            hex_material(payload)
        ),
        SignalValue::Vector2(values) => write!(
            formatter,
            "vector2:[{}]",
            joined(values.iter().map(value_material), ",")
        ),
        SignalValue::Vector3(values) => write!(
            formatter,
            "vector3:[{}]",
            joined(values.iter().map(value_material), ",")
        ),
        SignalValue::Bytes(value) => write!(formatter, "bytes:{}", hex_material(value)),
    })
}

fn coordinate_material(coordinate: &SignalCoordinate) -> impl Display + '_ {
    display(move |formatter| match coordinate {
        SignalCoordinate::VirtualTime { ticks } => write!(formatter, "virtual_time:{ticks}"),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => write!(
            formatter,
            "node_counter:{}:{retired_instructions}",
            node.as_str()
        ),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => write!(
            formatter,
            "operation:{}:{}:{}:{producer_sequence}:{suboperation}",
            adapter.as_str(),
            target.as_str(),
            operation.as_str()
        ),
        SignalCoordinate::Spatial {
            frame,
            x_mm,
            y_mm,
            z_mm,
            yaw_mdeg,
            pitch_mdeg,
            roll_mdeg,
        } => write!(
            formatter,
            "spatial:{}:{x_mm}:{y_mm}:{z_mm}:{yaw_mdeg}:{pitch_mdeg}:{roll_mdeg}",
            frame.as_str()
        ),
        SignalCoordinate::Event { parent, sequence } => write!(
            formatter,
            "event:{}:{sequence}",
            coordinate_material(parent)
        ),
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => write!(
            formatter,
            "state:{}:{}:{boundary_sequence}",
            adapter.as_str(),
            target.as_str()
        ),
    })
}

fn point_list_material(points: &[SignalPoint]) -> impl Display + '_ {
    joined(
        points.iter().map(|point| {
            display(move |formatter| {
                write!(
                    formatter,
                    "{}#{}=>{}",
                    coordinate_material(&point.coordinate),
                    point.sequence,
                    value_material(&point.value)
                )
            })
        }),
        ",",
    )
}

fn boundary_material(boundary: &SignalBoundaryBehavior) -> impl Display + '_ {
    display(move |formatter| match boundary {
        SignalBoundaryBehavior::Error => formatter.write_str("error"),
        SignalBoundaryBehavior::Hold => formatter.write_str("hold"),
        SignalBoundaryBehavior::Constant(value) => {
            write!(formatter, "constant:{}", value_material(value))
        }
        SignalBoundaryBehavior::Repeat => formatter.write_str("repeat"),
        SignalBoundaryBehavior::Inactive => formatter.write_str("inactive"),
    })
}

fn time_mapping_material(mapping: &Option<TraceTimeMapping>) -> impl Display + '_ {
    display(move |formatter| match mapping {
        None => formatter.write_str("none"),
        Some(mapping) => write!(
            formatter,
            "some:{}:{}:{}/{}:{}",
            mapping.source_epoch,
            mapping.virtual_epoch_ticks,
            mapping.scale.numerator(),
            mapping.scale.denominator(),
            rounding_name(mapping.rounding)
        ),
    })
}

fn value_pair_list_material(points: &[(SignalValue, SignalValue)]) -> impl Display + '_ {
    joined(
        points.iter().map(|(input, output)| {
            display(move |formatter| {
                write!(
                    formatter,
                    "{}=>{}",
                    value_material(input),
                    value_material(output)
                )
            })
        }),
        ",",
    )
}

fn transition_material(transition: &StateMachineTransition) -> impl Display + '_ {
    display(move |formatter| {
        write!(
            formatter,
            "{}:{}:{}=>{}:{}:{}",
            transition.from.as_str(),
            transition.event.as_str(),
            optional_id_material(&transition.guard),
            transition.to.as_str(),
            optional_id_material(&transition.emit),
            joined(transition.timer_operations.iter().map(timer_material), "/")
        )
    })
}

fn timer_material(operation: &StateMachineTimerOperation) -> impl Display + '_ {
    display(move |formatter| match operation {
        StateMachineTimerOperation::Start {
            timer,
            duration_nanos,
        } => write!(formatter, "start:{}:{duration_nanos}", timer.as_str()),
        StateMachineTimerOperation::Cancel { timer } => {
            write!(formatter, "cancel:{}", timer.as_str())
        }
    })
}

fn id_list_material(values: &[SignalId]) -> impl Display + '_ {
    joined(values.iter().map(SignalId::as_str), ",")
}

fn i64_slice_material(values: &[i64]) -> impl Display + '_ {
    joined(values.iter(), ",")
}

fn i64_array_material(values: &[i64; 3]) -> impl Display + '_ {
    i64_slice_material(values)
}

fn u64_array_material(values: &[u64; 3]) -> impl Display + '_ {
    joined(values.iter(), ",")
}

fn u32_array_material(values: &[u32; 3]) -> impl Display + '_ {
    joined(values.iter(), ",")
}

fn optional_id_material(value: &Option<SignalId>) -> impl Display + '_ {
    display(move |formatter| match value {
        None => formatter.write_str("none"),
        Some(value) => write!(formatter, "some:{}", value.as_str()),
    })
}

fn optional_i64_material(value: Option<i64>) -> impl Display {
    display(move |formatter| match value {
        None => formatter.write_str("none"),
        Some(value) => write!(formatter, "some:{value}"),
    })
}

fn optional_u64_material(value: Option<u64>) -> impl Display {
    display(move |formatter| match value {
        None => formatter.write_str("none"),
        Some(value) => write!(formatter, "some:{value}"),
    })
}

fn interpolation_name(value: SignalInterpolation) -> impl Display {
    display(move |formatter| match value {
        SignalInterpolation::Exact => formatter.write_str("exact"),
        SignalInterpolation::HoldPrevious => formatter.write_str("hold_previous"),
        SignalInterpolation::Nearest => formatter.write_str("nearest"),
        SignalInterpolation::Linear { rounding, overflow } => write!(
            formatter,
            "linear(rounding={},overflow={})",
            rounding_name(rounding),
            overflow_name(overflow)
        ),
    })
}

fn missing_name(value: MissingSampleBehavior) -> &'static str {
    match value {
        MissingSampleBehavior::Error => "error",
        MissingSampleBehavior::Hold => "hold",
        MissingSampleBehavior::Interpolate => "interpolate",
        MissingSampleBehavior::Inactive => "inactive",
    }
}

fn rounding_name(value: SignalRounding) -> &'static str {
    match value {
        SignalRounding::Floor => "floor",
        SignalRounding::Ceiling => "ceiling",
        SignalRounding::TowardZero => "toward_zero",
        SignalRounding::AwayFromZero => "away_from_zero",
        SignalRounding::NearestTiesToEven => "nearest_ties_to_even",
    }
}

fn overflow_name(value: SignalOverflow) -> &'static str {
    match value {
        SignalOverflow::Error => "error",
        SignalOverflow::Saturate => "saturate",
    }
}

fn key_domain_name(value: StochasticKeyDomain) -> &'static str {
    match value {
        StochasticKeyDomain::Opportunity => "opportunity",
        StochasticKeyDomain::Transition => "transition",
        StochasticKeyDomain::Coordinate => "coordinate",
    }
}

fn operator_name(value: PureSignalOperator) -> &'static str {
    match value {
        PureSignalOperator::Add => "add",
        PureSignalOperator::Subtract => "subtract",
        PureSignalOperator::MultiplyRatio => "multiply_ratio",
        PureSignalOperator::DivideRatio => "divide_ratio",
        PureSignalOperator::Absolute => "absolute",
        PureSignalOperator::Negate => "negate",
        PureSignalOperator::Min => "min",
        PureSignalOperator::Max => "max",
        PureSignalOperator::Clamp => "clamp",
        PureSignalOperator::Equal => "equal",
        PureSignalOperator::NotEqual => "not_equal",
        PureSignalOperator::Less => "less",
        PureSignalOperator::LessEqual => "less_equal",
        PureSignalOperator::Greater => "greater",
        PureSignalOperator::GreaterEqual => "greater_equal",
        PureSignalOperator::All => "all",
        PureSignalOperator::Any => "any",
        PureSignalOperator::Not => "not",
        PureSignalOperator::Select => "select",
        PureSignalOperator::LookupStep => "lookup_step",
        PureSignalOperator::PiecewiseLinear => "piecewise_linear",
        PureSignalOperator::EnumMap => "enum_map",
        PureSignalOperator::UnitConvert => "unit_convert",
        PureSignalOperator::Delay => "delay",
        PureSignalOperator::SampleHold => "sample_hold",
        PureSignalOperator::WindowMin => "window_min",
        PureSignalOperator::WindowMax => "window_max",
        PureSignalOperator::WindowMean => "window_mean",
        PureSignalOperator::Distance => "distance",
        PureSignalOperator::ZoneContains => "zone_contains",
        PureSignalOperator::FieldSample => "field_sample",
        PureSignalOperator::OrientationDelta => "orientation_delta",
        PureSignalOperator::EdgeRising => "edge_rising",
        PureSignalOperator::EdgeFalling => "edge_falling",
        PureSignalOperator::MergeEvents => "merge_events",
        PureSignalOperator::GateEvents => "gate_events",
    }
}

fn source_name(specification: &SignalSourceSpecification) -> &'static str {
    match specification {
        SignalSourceSpecification::Step { .. } => "step",
        SignalSourceSpecification::Pulse { .. } => "pulse",
        SignalSourceSpecification::PeriodicPulse { .. } => "periodic_pulse",
        SignalSourceSpecification::Ramp { .. } => "ramp",
        SignalSourceSpecification::Triangle { .. } => "triangle",
        SignalSourceSpecification::Sawtooth { .. } => "sawtooth",
        SignalSourceSpecification::EventSequence { .. } => "event_sequence",
        SignalSourceSpecification::Trace { .. } => "trace",
        SignalSourceSpecification::Telemetry { .. } => "telemetry",
        SignalSourceSpecification::PointSet { .. } => "point_set",
        SignalSourceSpecification::RegularGrid { .. } => "regular_grid",
        SignalSourceSpecification::TiledGrid { .. } => "tiled_grid",
        SignalSourceSpecification::ZoneMap { .. } => "zone_map",
        SignalSourceSpecification::PathProfile { .. } => "path_profile",
        SignalSourceSpecification::SeededField { .. } => "seeded_field",
        SignalSourceSpecification::TransmitterField { .. } => "transmitter_field",
        SignalSourceSpecification::Bernoulli { .. } => "bernoulli",
        SignalSourceSpecification::UniformInteger { .. } => "uniform_integer",
        SignalSourceSpecification::ExponentialWait { .. } => "exponential_wait",
        SignalSourceSpecification::WeibullWait { .. } => "weibull_wait",
    }
}

fn stateful_name(specification: &StatefulSignalSpecification) -> &'static str {
    match specification {
        StatefulSignalSpecification::Hysteresis { .. } => "hysteresis",
        StatefulSignalSpecification::Debounce { .. } => "debounce",
        StatefulSignalSpecification::Integrator { .. } => "integrator",
        StatefulSignalSpecification::LeakyIntegrator { .. } => "leaky_integrator",
        StatefulSignalSpecification::FiniteStateMachine { .. } => "finite_state_machine",
        StatefulSignalSpecification::MarkovChain { .. } => "markov_chain",
        StatefulSignalSpecification::BurstProcess { .. } => "burst_process",
        StatefulSignalSpecification::Counter { .. } => "counter",
        StatefulSignalSpecification::QueueModel { .. } => "queue_model",
    }
}
