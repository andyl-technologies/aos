//! Canonical signal-program identity material.

use super::*;

pub(super) fn program_material(
    nodes: &[SignalNode],
    exports: &[SignalId],
    limits: SignalResourceLimits,
) -> String {
    let mut lines = vec![
        format!("evaluator_version={SIGNAL_EVALUATOR_VERSION}"),
        format!("limit.signal_nodes={}", limits.nodes),
        format!("limit.signal_edges={}", limits.edges),
        format!("limit.signal_inputs_per_node={}", limits.inputs_per_node),
        format!("limit.signal_graph_depth={}", limits.graph_depth),
        format!("limit.signal_state_bytes={}", limits.state_bytes),
        format!(
            "limit.state_machine_states_per_node={}",
            limits.states_per_node
        ),
        format!(
            "limit.state_machine_transitions_per_node={}",
            limits.transitions_per_node
        ),
        format!(
            "limit.lookup_points_per_node={}",
            limits.lookup_points_per_node
        ),
    ];
    for export in exports {
        lines.push(format!("export={}", export.as_str()));
    }
    for node in nodes {
        lines.push(format!("node={}", node.id.as_str()));
        lines.push(format!("domain={}", node.domain.material()));
        lines.push(format!("output={}", node.output.material()));
        for input in &node.inputs {
            lines.push(format!("input={}", input.as_str()));
        }
        push_kind_material(&node.kind, &mut lines);
    }
    lines.join("\n")
}

fn push_kind_material(kind: &SignalNodeKind, lines: &mut Vec<String>) {
    match kind {
        SignalNodeKind::Constant { value } => {
            lines.push(String::from("kind=constant"));
            lines.push(format!("value={}", value.material()));
        }
        SignalNodeKind::Source(specification) => {
            lines.push(format!("kind=source:{}", source_name(specification)));
            lines.push(format!("source={}", source_material(specification)));
        }
        SignalNodeKind::Pure(specification) => {
            lines.push(format!(
                "kind=pure:{}",
                operator_name(specification.operator())
            ));
            lines.push(format!("pure={}", pure_material(specification)));
        }
        SignalNodeKind::Stateful {
            specification,
            state_bytes,
        } => {
            lines.push(format!("kind=stateful:{}", stateful_name(specification)));
            lines.push(format!("state_bytes={state_bytes}"));
            lines.push(format!("stateful={}", stateful_material(specification)));
        }
    }
}

mod pure;
mod source;
mod stateful;

use pure::pure_material;
use source::source_material;
use stateful::stateful_material;

fn coordinate_material(coordinate: &SignalCoordinate) -> String {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => format!("virtual_time:{nanos}"),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => format!("node_counter:{}:{retired_instructions}", node.as_str()),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => format!(
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
        } => format!(
            "spatial:{}:{x_mm}:{y_mm}:{z_mm}:{yaw_mdeg}:{pitch_mdeg}:{roll_mdeg}",
            frame.as_str()
        ),
        SignalCoordinate::Event { parent, sequence } => {
            format!("event:{}:{sequence}", coordinate_material(parent))
        }
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => format!(
            "state:{}:{}:{boundary_sequence}",
            adapter.as_str(),
            target.as_str()
        ),
    }
}

fn point_list_material(points: &[SignalPoint]) -> String {
    points
        .iter()
        .map(|point| {
            format!(
                "{}#{}=>{}",
                coordinate_material(&point.coordinate),
                point.sequence,
                point.value.material()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn boundary_material(boundary: &SignalBoundaryBehavior) -> String {
    match boundary {
        SignalBoundaryBehavior::Error => String::from("error"),
        SignalBoundaryBehavior::Hold => String::from("hold"),
        SignalBoundaryBehavior::Constant(value) => format!("constant:{}", value.material()),
        SignalBoundaryBehavior::Repeat => String::from("repeat"),
        SignalBoundaryBehavior::Inactive => String::from("inactive"),
    }
}

fn time_mapping_material(mapping: &Option<TraceTimeMapping>) -> String {
    mapping.as_ref().map_or_else(
        || String::from("none"),
        |mapping| {
            format!(
                "some:{}:{}:{}/{}:{}",
                mapping.source_epoch,
                mapping.virtual_epoch_nanos,
                mapping.scale.numerator(),
                mapping.scale.denominator(),
                rounding_name(mapping.rounding)
            )
        },
    )
}

fn value_pair_list_material(points: &[(SignalValue, SignalValue)]) -> String {
    points
        .iter()
        .map(|(input, output)| format!("{}=>{}", input.material(), output.material()))
        .collect::<Vec<_>>()
        .join(",")
}

fn transition_material(transition: &StateMachineTransition) -> String {
    let timers = transition
        .timer_operations
        .iter()
        .map(|operation| match operation {
            StateMachineTimerOperation::Start {
                timer,
                duration_nanos,
            } => format!("start:{}:{duration_nanos}", timer.as_str()),
            StateMachineTimerOperation::Cancel { timer } => {
                format!("cancel:{}", timer.as_str())
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "{}:{}:{}=>{}:{}:{}",
        transition.from.as_str(),
        transition.event.as_str(),
        optional_id_material(&transition.guard),
        transition.to.as_str(),
        optional_id_material(&transition.emit),
        timers
    )
}

fn id_list_material(values: &[SignalId]) -> String {
    values
        .iter()
        .map(SignalId::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn i64_slice_material(values: &[i64]) -> String {
    values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn i64_array_material(values: &[i64; 3]) -> String {
    i64_slice_material(values)
}

fn u64_array_material(values: &[u64; 3]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn u32_array_material(values: &[u32; 3]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn optional_id_material(value: &Option<SignalId>) -> String {
    value.as_ref().map_or_else(
        || String::from("none"),
        |value| format!("some:{}", value.as_str()),
    )
}

fn optional_i64_material(value: Option<i64>) -> String {
    value.map_or_else(|| String::from("none"), |value| format!("some:{value}"))
}

fn optional_u64_material(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("none"), |value| format!("some:{value}"))
}

fn interpolation_name(value: SignalInterpolation) -> String {
    match value {
        SignalInterpolation::Exact => String::from("exact"),
        SignalInterpolation::HoldPrevious => String::from("hold_previous"),
        SignalInterpolation::Nearest => String::from("nearest"),
        SignalInterpolation::Linear { rounding, overflow } => format!(
            "linear(rounding={},overflow={})",
            rounding_name(rounding),
            overflow_name(overflow)
        ),
    }
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
