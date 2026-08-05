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

fn source_material(specification: &SignalSourceSpecification) -> String {
    match specification {
        SignalSourceSpecification::Step { points, before } => format!(
            "points={};before={}",
            point_list_material(points),
            boundary_material(before)
        ),
        SignalSourceSpecification::Pulse {
            start,
            duration,
            inactive,
            active,
        } => format!(
            "start={};duration={duration};inactive={};active={}",
            coordinate_material(start),
            inactive.material(),
            active.material()
        ),
        SignalSourceSpecification::PeriodicPulse {
            epoch,
            period,
            width,
            phase,
            inactive,
            active,
        } => format!(
            "epoch={};period={period};width={width};phase={phase};inactive={};active={}",
            coordinate_material(epoch),
            inactive.material(),
            active.material()
        ),
        SignalSourceSpecification::Ramp {
            start,
            end,
            start_value,
            end_value,
            rounding,
        } => format!(
            "start={};end={};start_value={};end_value={};rounding={}",
            coordinate_material(start),
            coordinate_material(end),
            start_value.material(),
            end_value.material(),
            rounding_name(*rounding)
        ),
        SignalSourceSpecification::Triangle {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            rounding,
        }
        | SignalSourceSpecification::Sawtooth {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            rounding,
        } => format!(
            "epoch={};period={period};phase={phase};minimum={};maximum={};rounding={}",
            coordinate_material(epoch),
            minimum.material(),
            maximum.material(),
            rounding_name(*rounding)
        ),
        SignalSourceSpecification::EventSequence { events } => {
            format!("events={}", point_list_material(events))
        }
        SignalSourceSpecification::Trace {
            artifact,
            raw_provenance,
            channel,
            quality_channel,
            quality_accept,
            interpolation,
            before,
            after,
            missing,
            time_mapping,
        } => format!(
            "artifact={};raw_provenance={};channel={};quality_channel={};quality_accept={};interpolation={};before={};after={};missing={};time_mapping={}",
            artifact.to_hex(),
            raw_provenance.to_hex(),
            channel.as_str(),
            optional_id_material(quality_channel),
            optional_i64_material(*quality_accept),
            interpolation_name(*interpolation),
            boundary_material(before),
            boundary_material(after),
            missing_name(*missing),
            time_mapping_material(time_mapping)
        ),
        SignalSourceSpecification::Telemetry {
            adapter,
            target,
            field,
            boundary_delay,
        } => format!(
            "adapter={};target={};field={};boundary_delay={boundary_delay}",
            adapter.as_str(),
            target.as_str(),
            field.as_str()
        ),
        SignalSourceSpecification::PointSet {
            artifact,
            coordinate_frame,
            interpolation,
            outside,
        } => format!(
            "artifact={};coordinate_frame={};interpolation={};outside={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::RegularGrid {
            artifact,
            coordinate_frame,
            origin_mm,
            cell_size_mm,
            dimensions,
            interpolation,
            outside,
        } => format!(
            "artifact={};coordinate_frame={};origin_mm={};cell_size_mm={};dimensions={};interpolation={};outside={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            i64_array_material(origin_mm),
            u64_array_material(cell_size_mm),
            u32_array_material(dimensions),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::TiledGrid {
            manifest,
            coordinate_frame,
            tile_size_mm,
            interpolation,
            outside,
        } => format!(
            "manifest={};coordinate_frame={};tile_size_mm={};interpolation={};outside={}",
            manifest.to_hex(),
            coordinate_frame.as_str(),
            u64_array_material(tile_size_mm),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::ZoneMap {
            artifact,
            coordinate_frame,
            boundary,
            overlap,
        } => format!(
            "artifact={};coordinate_frame={};boundary={};overlap={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            boundary.as_str(),
            overlap.as_str()
        ),
        SignalSourceSpecification::PathProfile {
            artifact,
            path,
            interpolation,
            before,
            after,
        } => format!(
            "artifact={};path={};interpolation={};before={};after={}",
            artifact.to_hex(),
            path.as_str(),
            interpolation_name(*interpolation),
            boundary_material(before),
            boundary_material(after)
        ),
        SignalSourceSpecification::SeededField {
            field_seed_domain,
            coordinate_frame,
            quantization_mm,
            correlation_mm,
            distribution,
            distribution_parameters,
        } => format!(
            "field_seed_domain={};coordinate_frame={};quantization_mm={};correlation_mm={};distribution={};distribution_parameters={}",
            field_seed_domain.as_str(),
            coordinate_frame.as_str(),
            u64_array_material(quantization_mm),
            u64_array_material(correlation_mm),
            distribution.as_str(),
            i64_slice_material(distribution_parameters)
        ),
        SignalSourceSpecification::TransmitterField {
            transmitter,
            coordinate_frame,
            position_signal,
            orientation_signal,
            model,
            lookup,
            environment_signals,
        } => format!(
            "transmitter={};coordinate_frame={};position_signal={};orientation_signal={};model={};lookup={};environment_signals={}",
            transmitter.as_str(),
            coordinate_frame.as_str(),
            position_signal.as_str(),
            optional_id_material(orientation_signal),
            model.as_str(),
            lookup.to_hex(),
            id_list_material(environment_signals)
        ),
        SignalSourceSpecification::Bernoulli {
            probability_millionths,
            key_domain,
            opportunity_filter,
        } => format!(
            "probability_millionths={probability_millionths};key_domain={};opportunity_filter={}",
            key_domain_name(*key_domain),
            optional_id_material(opportunity_filter)
        ),
        SignalSourceSpecification::UniformInteger {
            minimum,
            maximum,
            key_domain,
            opportunity_filter,
        } => format!(
            "minimum={minimum};maximum={maximum};key_domain={};opportunity_filter={}",
            key_domain_name(*key_domain),
            optional_id_material(opportunity_filter)
        ),
        SignalSourceSpecification::ExponentialWait {
            rate,
            sampler_version,
            sampler_table,
            key_domain,
            maximum_nanos,
        } => format!(
            "rate={}/{};sampler_version={sampler_version};sampler_table={};key_domain={};maximum_nanos={}",
            rate.numerator(),
            rate.denominator(),
            sampler_table.to_hex(),
            key_domain_name(*key_domain),
            optional_u64_material(*maximum_nanos)
        ),
        SignalSourceSpecification::WeibullWait {
            shape,
            scale_nanos,
            sampler_version,
            sampler_table,
            key_domain,
            maximum_nanos,
        } => format!(
            "shape={}/{};scale_nanos={scale_nanos};sampler_version={sampler_version};sampler_table={};key_domain={};maximum_nanos={}",
            shape.numerator(),
            shape.denominator(),
            sampler_table.to_hex(),
            key_domain_name(*key_domain),
            optional_u64_material(*maximum_nanos)
        ),
    }
}

fn pure_material(specification: &PureSignalSpecification) -> String {
    match specification {
        PureSignalSpecification::Simple { operator, overflow } => format!(
            "operator={};overflow={}",
            operator_name(*operator),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::RatioArithmetic {
            operator,
            ratio,
            rounding,
            overflow,
        } => format!(
            "operator={};ratio={}/{};rounding={};overflow={}",
            operator_name(*operator),
            ratio.numerator(),
            ratio.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Clamp {
            minimum,
            maximum,
            overflow,
        } => format!(
            "minimum={};maximum={};overflow={}",
            minimum.material(),
            maximum.material(),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => format!(
            "points={};before={};after={}",
            value_pair_list_material(points),
            boundary_material(before),
            boundary_material(after)
        ),
        PureSignalSpecification::PiecewiseLinear {
            points,
            rounding,
            overflow,
        } => format!(
            "points={};rounding={};overflow={}",
            value_pair_list_material(points),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::EnumMap { entries } => format!(
            "entries={}",
            entries
                .iter()
                .map(|(variant, value)| format!("{}=>{}", variant.as_str(), value.material()))
                .collect::<Vec<_>>()
                .join(",")
        ),
        PureSignalSpecification::UnitConvert {
            from_unit,
            to_unit,
            ratio,
            offset,
            rounding,
            overflow,
        } => format!(
            "from_unit={};to_unit={};ratio={}/{};offset={}/{};rounding={};overflow={}",
            from_unit.material(),
            to_unit.material(),
            ratio.numerator(),
            ratio.denominator(),
            offset.numerator(),
            offset.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Delay {
            delay,
            retained_samples,
        } => format!("delay={delay};retained_samples={retained_samples}"),
        PureSignalSpecification::SampleHold {
            cadence,
            epoch,
            retained_samples,
        } => {
            format!(
                "cadence={cadence};epoch={};retained_samples={retained_samples}",
                coordinate_material(epoch)
            )
        }
        PureSignalSpecification::Window {
            operator,
            window,
            sampling_cadence,
            retained_samples,
            rounding,
            overflow,
        } => format!(
            "operator={};window={window};sampling_cadence={sampling_cadence};retained_samples={retained_samples};rounding={};overflow={}",
            operator_name(*operator),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Distance { metric, rounding } => format!(
            "metric={};rounding={}",
            metric.as_str(),
            rounding_name(*rounding)
        ),
        PureSignalSpecification::ZoneContains { zone } => {
            format!("zone={}", zone.as_str())
        }
        PureSignalSpecification::FieldSample => String::new(),
        PureSignalSpecification::OrientationDelta { convention } => {
            format!("convention={}", convention.as_str())
        }
        PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        } => {
            format!(
                "same_coordinate_order=source_then_sequence;source_sequence_limit={source_sequence_limit}"
            )
        }
        PureSignalSpecification::GateEvents => String::new(),
    }
}

fn stateful_material(specification: &StatefulSignalSpecification) -> String {
    match specification {
        StatefulSignalSpecification::Hysteresis {
            initial,
            set_when,
            clear_when,
            minimum_residence_nanos,
        } => format!(
            "initial={initial};set_when={};clear_when={};minimum_residence_nanos={minimum_residence_nanos}",
            set_when.material(),
            clear_when.material()
        ),
        StatefulSignalSpecification::Debounce {
            initial,
            residence_nanos,
        } => format!(
            "initial={};residence_nanos={residence_nanos}",
            initial.material()
        ),
        StatefulSignalSpecification::Integrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            rounding,
            overflow,
        } => format!(
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};rounding={};overflow={}",
            initial.material(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        StatefulSignalSpecification::LeakyIntegrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            decay_ratio,
            maximum_catch_up_steps,
            rounding,
            overflow,
        } => format!(
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};decay_ratio={}/{};maximum_catch_up_steps={maximum_catch_up_steps};rounding={};overflow={}",
            initial.material(),
            decay_ratio.numerator(),
            decay_ratio.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        StatefulSignalSpecification::FiniteStateMachine {
            states,
            initial,
            transitions,
            unmatched_event,
        } => format!(
            "states={};initial={};transitions={};unmatched_event={}",
            id_list_material(states),
            initial.as_str(),
            transitions
                .iter()
                .map(transition_material)
                .collect::<Vec<_>>()
                .join(","),
            unmatched_event.as_str()
        ),
        StatefulSignalSpecification::MarkovChain {
            states,
            initial,
            opportunity,
            probability_rows,
        } => format!(
            "states={};initial={};opportunity={};probability_rows={}",
            id_list_material(states),
            initial.as_str(),
            opportunity.as_str(),
            probability_rows
                .iter()
                .map(|row| row.iter().map(u32::to_string).collect::<Vec<_>>().join("/"))
                .collect::<Vec<_>>()
                .join(",")
        ),
        StatefulSignalSpecification::BurstProcess {
            initial_bad,
            good_to_bad_millionths,
            bad_to_good_millionths,
            opportunity,
        } => format!(
            "initial_bad={initial_bad};good_to_bad_millionths={good_to_bad_millionths};bad_to_good_millionths={bad_to_good_millionths};opportunity={}",
            opportunity.as_str()
        ),
        StatefulSignalSpecification::Counter {
            initial,
            maximum,
            overflow,
            reset_event,
        } => format!(
            "initial={initial};maximum={maximum};overflow={};reset_event={}",
            overflow_name(*overflow),
            optional_id_material(reset_event)
        ),
        StatefulSignalSpecification::QueueModel {
            capacity,
            discipline,
            overflow,
        } => format!(
            "capacity={capacity};discipline={};overflow={}",
            discipline.as_str(),
            overflow.as_str()
        ),
    }
}

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
