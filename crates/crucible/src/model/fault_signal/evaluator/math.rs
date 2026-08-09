//! Deterministic arithmetic and state transitions for evaluator nodes.
//!
//! These routines implement admitted operators without consulting ambient
//! time, randomness, or device state. All mutable inputs arrive through the
//! parent evaluator's explicit coordinate and boundary snapshot.

use super::*;

pub(super) fn history_limits(program: &SignalProgram) -> BTreeMap<SignalId, usize> {
    let mut limits: BTreeMap<SignalId, usize> = BTreeMap::new();
    for node in program.nodes() {
        let (input, retained) = match &node.kind {
            SignalNodeKind::Pure(
                PureSignalSpecification::Delay {
                    retained_samples, ..
                }
                | PureSignalSpecification::SampleHold {
                    retained_samples, ..
                }
                | PureSignalSpecification::Window {
                    retained_samples, ..
                },
            ) => (node.inputs.first(), *retained_samples),
            SignalNodeKind::Pure(PureSignalSpecification::Simple {
                operator: PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling,
                ..
            }) => (node.inputs.first(), 1),
            _ => (None, 0),
        };
        if let Some(input) = input {
            let retained = usize::try_from(retained).unwrap_or(usize::MAX);
            limits
                .entry(input.clone())
                .and_modify(|limit| *limit = (*limit).max(retained))
                .or_insert(retained);
        }
    }
    limits
}

pub(super) fn initial_states(
    program: &SignalProgram,
) -> Result<BTreeMap<SignalId, EvaluatorNodeState>, SignalEvaluationError> {
    let mut states = BTreeMap::new();
    for node in program.nodes() {
        let SignalNodeKind::Stateful { specification, .. } = &node.kind else {
            continue;
        };
        let state = match specification {
            StatefulSignalSpecification::Hysteresis { initial, .. } => {
                EvaluatorNodeState::Hysteresis {
                    value: *initial,
                    last_transition_nanos: 0,
                }
            }
            StatefulSignalSpecification::Debounce { initial, .. } => EvaluatorNodeState::Debounce {
                committed: initial.clone(),
                candidate: None,
                candidate_since_nanos: None,
            },
            StatefulSignalSpecification::Integrator {
                initial,
                rounding,
                overflow,
                ..
            } => EvaluatorNodeState::Integrator {
                accumulator: initial.clone(),
                pending: scale_value_fraction(initial, 0, 1, *rounding, *overflow)?,
                previous_input: None,
                last_nanos: None,
            },
            StatefulSignalSpecification::LeakyIntegrator { initial, .. } => {
                EvaluatorNodeState::LeakyIntegrator {
                    accumulator: initial.clone(),
                    previous_input: None,
                    last_nanos: None,
                }
            }
            StatefulSignalSpecification::FiniteStateMachine { initial, .. } => {
                EvaluatorNodeState::FiniteStateMachine {
                    state: initial.clone(),
                    timers: BTreeMap::new(),
                }
            }
            StatefulSignalSpecification::MarkovChain { initial, .. } => {
                EvaluatorNodeState::MarkovChain {
                    state: initial.clone(),
                    transition_sequence: 0,
                }
            }
            StatefulSignalSpecification::BurstProcess { initial_bad, .. } => {
                EvaluatorNodeState::BurstProcess {
                    bad: *initial_bad,
                    transition_sequence: 0,
                }
            }
            StatefulSignalSpecification::Counter { initial, .. } => {
                EvaluatorNodeState::Counter { count: *initial }
            }
            StatefulSignalSpecification::QueueModel { .. } => EvaluatorNodeState::QueueModel {
                backlog: 0,
                service_remainder: 0,
                last_nanos: None,
            },
        };
        states.insert(node.id.clone(), state);
    }
    Ok(states)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn integrate_to_cadence(
    accumulator: &mut SignalValue,
    pending: &mut SignalValue,
    previous_input: &SignalValue,
    last_nanos: u64,
    now_nanos: u64,
    cadence_nanos: u64,
    time_unit_nanos: u64,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<(), SignalEvaluationError> {
    let last_bucket = last_nanos / cadence_nanos;
    let now_bucket = now_nanos / cadence_nanos;
    if last_bucket == now_bucket {
        let contribution = scale_value_fraction(
            previous_input,
            u128::from(now_nanos - last_nanos),
            u128::from(time_unit_nanos),
            rounding,
            overflow,
        )?;
        *pending = arithmetic_values(pending, &contribution, false, overflow)?;
        return Ok(());
    }

    let first_boundary = last_bucket
        .checked_add(1)
        .and_then(|bucket| bucket.checked_mul(cadence_nanos))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let first = scale_value_fraction(
        previous_input,
        u128::from(first_boundary - last_nanos),
        u128::from(time_unit_nanos),
        rounding,
        overflow,
    )?;
    *pending = arithmetic_values(pending, &first, false, overflow)?;
    *accumulator = arithmetic_values(accumulator, pending, false, overflow)?;

    *pending = scale_value_fraction(previous_input, 0, 1, rounding, overflow)?;
    let complete_cadences = now_bucket - last_bucket - 1;
    if complete_cadences > 0 {
        let per_cadence = scale_value_fraction(
            previous_input,
            u128::from(cadence_nanos),
            u128::from(time_unit_nanos),
            rounding,
            overflow,
        )?;
        let complete = scale_value_fraction(
            &per_cadence,
            u128::from(complete_cadences),
            1,
            rounding,
            overflow,
        )?;
        *accumulator = arithmetic_values(accumulator, &complete, false, overflow)?;
    }

    let final_boundary = now_bucket
        .checked_mul(cadence_nanos)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let tail = scale_value_fraction(
        previous_input,
        u128::from(now_nanos - final_boundary),
        u128::from(time_unit_nanos),
        rounding,
        overflow,
    )?;
    *pending = arithmetic_values(pending, &tail, false, overflow)?;
    Ok(())
}

pub(super) fn validate_evaluated_shape(
    node: &SignalNode,
    output: &EvaluatedSignal,
) -> Result<(), SignalEvaluationError> {
    let EvaluatedSignal::Value(value) = output else {
        return Ok(());
    };
    if value.value_type().as_ref() != Some(&node.output.value_type) {
        return Err(SignalEvaluationError::OutputShapeMismatch(node.id.clone()));
    }
    Ok(())
}

pub(super) fn coordinate_domain_runtime(coordinate: &SignalCoordinate) -> SignalDomain {
    match coordinate {
        SignalCoordinate::VirtualTime { .. } => SignalDomain::VirtualTime,
        SignalCoordinate::NodeCounter { .. } => SignalDomain::NodeCounter,
        SignalCoordinate::Operation { .. } => SignalDomain::Operation,
        SignalCoordinate::Spatial { .. } => SignalDomain::Spatial,
        SignalCoordinate::Event { .. } => SignalDomain::Event,
        SignalCoordinate::State { .. } => SignalDomain::State,
    }
}

pub(super) fn coordinate_offset(
    epoch: &SignalCoordinate,
    coordinate: &SignalCoordinate,
) -> Result<u64, SignalEvaluationError> {
    match (epoch, coordinate) {
        (
            SignalCoordinate::VirtualTime { nanos: epoch },
            SignalCoordinate::VirtualTime { nanos },
        ) => nanos
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        (
            SignalCoordinate::NodeCounter {
                node: epoch_node,
                retired_instructions: epoch,
            },
            SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            },
        ) if epoch_node == node => retired_instructions
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        (
            SignalCoordinate::Operation {
                adapter: epoch_adapter,
                target: epoch_target,
                operation: epoch_operation,
                producer_sequence: epoch,
                suboperation: epoch_suboperation,
            },
            SignalCoordinate::Operation {
                adapter,
                target,
                operation,
                producer_sequence,
                suboperation,
            },
        ) if epoch_adapter == adapter
            && epoch_target == target
            && epoch_operation == operation
            && epoch_suboperation == suboperation =>
        {
            producer_sequence
                .checked_sub(*epoch)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)
        }
        (
            SignalCoordinate::State {
                adapter: epoch_adapter,
                target: epoch_target,
                boundary_sequence: epoch,
            },
            SignalCoordinate::State {
                adapter,
                target,
                boundary_sequence,
            },
        ) if epoch_adapter == adapter && epoch_target == target => boundary_sequence
            .checked_sub(*epoch)
            .ok_or(SignalEvaluationError::CoordinateBeforeEpoch),
        _ => Err(SignalEvaluationError::IncompatibleCoordinates),
    }
}

pub(super) fn coordinate_nanos(
    coordinate: &SignalCoordinate,
) -> Result<u64, SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => Ok(*nanos),
        _ => Err(SignalEvaluationError::VirtualTimeRequired),
    }
}

pub(super) fn add_coordinate(
    epoch: &SignalCoordinate,
    delta: u64,
) -> Result<SignalCoordinate, SignalEvaluationError> {
    match epoch {
        SignalCoordinate::VirtualTime { nanos } => Ok(SignalCoordinate::VirtualTime {
            nanos: nanos
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => Ok(SignalCoordinate::NodeCounter {
            node: node.clone(),
            retired_instructions: retired_instructions
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => Ok(SignalCoordinate::Operation {
            adapter: adapter.clone(),
            target: target.clone(),
            operation: operation.clone(),
            producer_sequence: producer_sequence
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
            suboperation: *suboperation,
        }),
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => Ok(SignalCoordinate::State {
            adapter: adapter.clone(),
            target: target.clone(),
            boundary_sequence: boundary_sequence
                .checked_add(delta)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
        }),
        SignalCoordinate::Spatial { .. } | SignalCoordinate::Event { .. } => {
            Err(SignalEvaluationError::IncompatibleCoordinates)
        }
    }
}

pub(super) fn subtract_coordinate(
    coordinate: &SignalCoordinate,
    delta: u64,
) -> Result<SignalCoordinate, SignalEvaluationError> {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => Ok(SignalCoordinate::VirtualTime {
            nanos: nanos
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => Ok(SignalCoordinate::NodeCounter {
            node: node.clone(),
            retired_instructions: retired_instructions
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => Ok(SignalCoordinate::Operation {
            adapter: adapter.clone(),
            target: target.clone(),
            operation: operation.clone(),
            producer_sequence: producer_sequence
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
            suboperation: *suboperation,
        }),
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => Ok(SignalCoordinate::State {
            adapter: adapter.clone(),
            target: target.clone(),
            boundary_sequence: boundary_sequence
                .checked_sub(delta)
                .ok_or(SignalEvaluationError::CoordinateBeforeEpoch)?,
        }),
        SignalCoordinate::Spatial { .. } | SignalCoordinate::Event { .. } => {
            Err(SignalEvaluationError::IncompatibleCoordinates)
        }
    }
}

pub(super) fn evaluate_step(
    points: &[SignalPoint],
    before: &SignalBoundaryBehavior,
    coordinate: &SignalCoordinate,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let repeated_coordinate;
    let coordinate =
        if coordinate < &points[0].coordinate && matches!(before, SignalBoundaryBehavior::Repeat) {
            let first = &points[0].coordinate;
            let last = &points[points.len() - 1].coordinate;
            let extent = coordinate_offset(first, last)?;
            if extent == 0 {
                return Err(SignalEvaluationError::InvalidRepeatExtent);
            }
            let distance = coordinate_offset(coordinate, first)?;
            let remainder = distance % extent;
            repeated_coordinate = if remainder == 0 {
                first.clone()
            } else {
                subtract_coordinate(last, remainder)?
            };
            &repeated_coordinate
        } else {
            coordinate
        };
    let index = points.partition_point(|point| point.coordinate <= *coordinate);
    if let Some(point) = index.checked_sub(1).and_then(|index| points.get(index)) {
        return Ok(EvaluatedSignal::Value(point.value.clone()));
    }
    evaluate_boundary(before, points.first().map(|point| &point.value), None)
}

pub(in crate::model::fault_signal) fn evaluate_boundary(
    behavior: &SignalBoundaryBehavior,
    nearest: Option<&SignalValue>,
    repeated: Option<&SignalValue>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match behavior {
        SignalBoundaryBehavior::Error => Err(SignalEvaluationError::OutsideSourceExtent),
        SignalBoundaryBehavior::Hold => nearest
            .cloned()
            .map(EvaluatedSignal::Value)
            .ok_or(SignalEvaluationError::OutsideSourceExtent),
        SignalBoundaryBehavior::Constant(value) => Ok(EvaluatedSignal::Value(value.clone())),
        SignalBoundaryBehavior::Repeat => repeated
            .cloned()
            .map(EvaluatedSignal::Value)
            .ok_or(SignalEvaluationError::InvalidRepeatExtent),
        SignalBoundaryBehavior::Inactive => Ok(EvaluatedSignal::Inactive),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_ramp(
    start: &SignalCoordinate,
    end: &SignalCoordinate,
    start_value: &SignalValue,
    end_value: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if coordinate <= start {
        return Ok(EvaluatedSignal::Value(start_value.clone()));
    }
    if coordinate >= end {
        return Ok(EvaluatedSignal::Value(end_value.clone()));
    }
    let elapsed = coordinate_offset(start, coordinate)?;
    let width = coordinate_offset(start, end)?;
    Ok(EvaluatedSignal::Value(interpolate_value(
        start_value,
        end_value,
        elapsed,
        width,
        rounding,
        overflow,
    )?))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_triangle(
    epoch: &SignalCoordinate,
    period: u64,
    phase: u64,
    minimum: &SignalValue,
    maximum: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let position = coordinate_offset(epoch, coordinate)?
        .checked_add(phase)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        % period;
    let rising_width = period / 2;
    if rising_width == 0 {
        return Err(SignalEvaluationError::InvalidPeriod);
    }
    if position <= rising_width {
        Ok(EvaluatedSignal::Value(interpolate_value(
            minimum,
            maximum,
            position,
            rising_width,
            rounding,
            SignalOverflow::Error,
        )?))
    } else {
        Ok(EvaluatedSignal::Value(interpolate_value(
            maximum,
            minimum,
            position - rising_width,
            period - rising_width,
            rounding,
            SignalOverflow::Error,
        )?))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_sawtooth(
    epoch: &SignalCoordinate,
    period: u64,
    phase: u64,
    minimum: &SignalValue,
    maximum: &SignalValue,
    coordinate: &SignalCoordinate,
    rounding: SignalRounding,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let position = coordinate_offset(epoch, coordinate)?
        .checked_add(phase)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?
        % period;
    Ok(EvaluatedSignal::Value(interpolate_value(
        minimum,
        maximum,
        position,
        period,
        rounding,
        SignalOverflow::Error,
    )?))
}

pub(super) fn evaluate_event_sequence(
    events: &[SignalPoint],
    coordinate: &SignalCoordinate,
    sequence: u64,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let start = events.partition_point(|event| event.coordinate < *coordinate);
    let Some(event) = events[start..]
        .iter()
        .take_while(|event| event.coordinate == *coordinate)
        .find(|event| event.sequence == sequence)
    else {
        return Ok(EvaluatedSignal::Inactive);
    };
    Ok(EvaluatedSignal::Value(event.value.clone()))
}

pub(super) fn choice_applies(
    domain: StochasticKeyDomain,
    opportunity_filter: Option<&SignalId>,
    request: &SignalEvaluationRequest,
) -> Result<bool, SignalEvaluationError> {
    match domain {
        StochasticKeyDomain::Opportunity if request.choice.opportunity.is_none() => {
            Err(SignalEvaluationError::OpportunityIdentityRequired)
        }
        StochasticKeyDomain::Transition if request.choice.transition_sequence.is_none() => {
            Err(SignalEvaluationError::TransitionIdentityRequired)
        }
        _ if opportunity_filter.is_some() && request.choice.opportunity.is_none() => {
            Err(SignalEvaluationError::OpportunityIdentityRequired)
        }
        _ => Ok(opportunity_filter.is_none_or(|filter| {
            request
                .choice
                .opportunity
                .as_ref()
                .is_some_and(|opportunity| opportunity.operation().as_str() == filter.as_str())
        })),
    }
}

pub(super) fn keyed_u64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    domain: StochasticKeyDomain,
    counter: u64,
) -> u64 {
    let mut material = Vec::new();
    material.extend_from_slice(&request.choice.scenario_seed.bytes);
    material.extend_from_slice(node.id.as_str().as_bytes());
    material.extend_from_slice(request.choice.consumer.as_str().as_bytes());
    material.push(match domain {
        StochasticKeyDomain::Opportunity => 0,
        StochasticKeyDomain::Transition => 1,
        StochasticKeyDomain::Coordinate => 2,
    });
    match domain {
        StochasticKeyDomain::Opportunity => {
            if let Some(opportunity) = &request.choice.opportunity {
                material.extend_from_slice(&opportunity.id().bytes);
            }
        }
        StochasticKeyDomain::Transition => material.extend_from_slice(
            &request
                .choice
                .transition_sequence
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        ),
        StochasticKeyDomain::Coordinate => {
            append_coordinate_bytes(&mut material, &request.coordinate);
            material.extend_from_slice(&request.same_coordinate_sequence.to_be_bytes());
        }
    }
    material.extend_from_slice(&counter.to_be_bytes());
    let hash = ContentHash::from_bytes(&material);
    u64::from_be_bytes(hash.bytes[..8].try_into().unwrap_or([0; 8]))
}

pub(super) fn keyed_transition_u64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    transition_sequence: u64,
) -> u64 {
    let mut keyed_request = request.clone();
    keyed_request.choice.transition_sequence = Some(transition_sequence);
    keyed_u64(node, &keyed_request, StochasticKeyDomain::Transition, 0)
}

pub(super) fn append_coordinate_bytes(output: &mut Vec<u8>, coordinate: &SignalCoordinate) {
    match coordinate {
        SignalCoordinate::VirtualTime { nanos } => {
            output.push(0);
            output.extend_from_slice(&nanos.to_be_bytes());
        }
        SignalCoordinate::NodeCounter {
            node,
            retired_instructions,
        } => {
            output.push(1);
            output.extend_from_slice(node.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(&retired_instructions.to_be_bytes());
        }
        SignalCoordinate::Operation {
            adapter,
            target,
            operation,
            producer_sequence,
            suboperation,
        } => {
            output.push(2);
            for id in [adapter, target, operation] {
                output.extend_from_slice(id.as_str().as_bytes());
                output.push(0);
            }
            output.extend_from_slice(&producer_sequence.to_be_bytes());
            output.extend_from_slice(&suboperation.to_be_bytes());
        }
        SignalCoordinate::Spatial {
            frame,
            x_mm,
            y_mm,
            z_mm,
            yaw_mdeg,
            pitch_mdeg,
            roll_mdeg,
        } => {
            output.push(3);
            output.extend_from_slice(frame.as_str().as_bytes());
            output.push(0);
            for value in [x_mm, y_mm, z_mm, yaw_mdeg, pitch_mdeg, roll_mdeg] {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        SignalCoordinate::Event { parent, sequence } => {
            output.push(4);
            append_coordinate_bytes(output, parent);
            output.extend_from_slice(&sequence.to_be_bytes());
        }
        SignalCoordinate::State {
            adapter,
            target,
            boundary_sequence,
        } => {
            output.push(5);
            output.extend_from_slice(adapter.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(target.as_str().as_bytes());
            output.push(0);
            output.extend_from_slice(&boundary_sequence.to_be_bytes());
        }
    }
}

pub(super) fn uniform_i64(
    node: &SignalNode,
    request: &SignalEvaluationRequest,
    domain: StochasticKeyDomain,
    minimum: i64,
    maximum: i64,
) -> Result<i64, SignalEvaluationError> {
    let width = i128::from(maximum)
        .checked_sub(i128::from(minimum))
        .and_then(|value| value.checked_add(1))
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let width = u128::try_from(width).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    if width == (u128::from(u64::MAX) + 1) {
        return Ok(i64::from_be_bytes(
            keyed_u64(node, request, domain, 0).to_be_bytes(),
        ));
    }
    let width = u64::try_from(width).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let rejection = u64::MAX - u64::MAX % width;
    for counter in 0..=u64::MAX {
        let draw = keyed_u64(node, request, domain, counter);
        if draw < rejection {
            let offset = i128::from(draw % width);
            return i64::try_from(i128::from(minimum) + offset)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow);
        }
    }
    Err(SignalEvaluationError::KeyStreamExhausted)
}

pub(super) fn evaluate_simple(
    node: &SignalNode,
    operator: PureSignalOperator,
    overflow: SignalOverflow,
    inputs: &[EvaluatedSignal],
    history: Option<&VecDeque<HistoryEntry>>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if inputs
        .iter()
        .any(|input| input == &EvaluatedSignal::Inactive)
    {
        return Ok(EvaluatedSignal::Inactive);
    }
    let values = inputs
        .iter()
        .map(EvaluatedSignal::value)
        .collect::<Result<Vec<_>, _>>()?;
    let value = match operator {
        PureSignalOperator::Add => {
            let mut result = values[0].clone();
            for value in values.iter().skip(1) {
                result = arithmetic_values(&result, value, false, overflow)?;
            }
            result
        }
        PureSignalOperator::Subtract => arithmetic_values(values[0], values[1], true, overflow)?,
        PureSignalOperator::Absolute => absolute_value(values[0], overflow)?,
        PureSignalOperator::Negate => negate_value(values[0], overflow)?,
        PureSignalOperator::Min => {
            let mut result = values[0];
            for value in values.iter().skip(1) {
                if compare_numeric(value, result)?.is_lt() {
                    result = value;
                }
            }
            result.clone()
        }
        PureSignalOperator::Max => {
            let mut result = values[0];
            for value in values.iter().skip(1) {
                if compare_numeric(value, result)?.is_gt() {
                    result = value;
                }
            }
            result.clone()
        }
        PureSignalOperator::Equal => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_eq())
        }
        PureSignalOperator::NotEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_eq())
        }
        PureSignalOperator::Less => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_lt())
        }
        PureSignalOperator::LessEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_gt())
        }
        PureSignalOperator::Greater => {
            SignalValue::Bool(compare_numeric(values[0], values[1])?.is_gt())
        }
        PureSignalOperator::GreaterEqual => {
            SignalValue::Bool(!compare_numeric(values[0], values[1])?.is_lt())
        }
        PureSignalOperator::All => SignalValue::Bool(
            values
                .iter()
                .map(|value| bool_value(value))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .all(|value| value),
        ),
        PureSignalOperator::Any => SignalValue::Bool(
            values
                .iter()
                .map(|value| bool_value(value))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .any(|value| value),
        ),
        PureSignalOperator::Not => SignalValue::Bool(!bool_value(values[0])?),
        PureSignalOperator::Select => {
            if bool_value(values[0])? {
                values[1].clone()
            } else {
                values[2].clone()
            }
        }
        PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling => {
            let current = bool_value(values[0])?;
            let previous = history
                .and_then(|history| history.back())
                .and_then(|entry| match &entry.output {
                    EvaluatedSignal::Value(SignalValue::Bool(value)) => Some(*value),
                    _ => None,
                })
                .unwrap_or(current);
            let edge = if operator == PureSignalOperator::EdgeRising {
                !previous && current
            } else {
                previous && !current
            };
            if !edge {
                return Ok(EvaluatedSignal::Inactive);
            }
            let SignalValueType::Event(schema) = &node.output.value_type else {
                return Err(SignalEvaluationError::TypeMismatch);
            };
            SignalValue::Event {
                schema: schema.clone(),
                payload: Vec::new(),
            }
        }
        _ => return Err(SignalEvaluationError::InvalidOperator),
    };
    Ok(EvaluatedSignal::Value(value))
}

pub(super) fn bool_value(value: &SignalValue) -> Result<bool, SignalEvaluationError> {
    match value {
        SignalValue::Bool(value) => Ok(*value),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(in crate::model::fault_signal) fn arithmetic_values(
    left: &SignalValue,
    right: &SignalValue,
    subtract: bool,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match (left, right) {
        (SignalValue::I64(left), SignalValue::I64(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::I64(narrow_i64(value, overflow)?))
        }
        (SignalValue::U64(left), SignalValue::U64(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::U64(narrow_u64(value, overflow)?))
        }
        (SignalValue::DurationNanos(left), SignalValue::DurationNanos(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::DurationNanos(narrow_u64(value, overflow)?))
        }
        (SignalValue::RatePerSecond(left), SignalValue::RatePerSecond(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            Ok(SignalValue::RatePerSecond(narrow_u64(value, overflow)?))
        }
        (SignalValue::ProbabilityMillionths(left), SignalValue::ProbabilityMillionths(right)) => {
            let value = if subtract {
                i128::from(*left) - i128::from(*right)
            } else {
                i128::from(*left) + i128::from(*right)
            };
            let maximum = 1_000_000_i128;
            let value = match overflow {
                SignalOverflow::Error if !(0..=maximum).contains(&value) => {
                    return Err(SignalEvaluationError::ArithmeticOverflow);
                }
                SignalOverflow::Saturate => value.clamp(0, maximum),
                SignalOverflow::Error => value,
            };
            Ok(SignalValue::ProbabilityMillionths(
                u32::try_from(value).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            ))
        }
        (SignalValue::Ratio(left), SignalValue::Ratio(right)) => {
            let left_denominator = i128::from(left.denominator());
            let right_denominator = i128::from(right.denominator());
            let left_scaled = i128::from(left.numerator())
                .checked_mul(right_denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let right_scaled = i128::from(right.numerator())
                .checked_mul(left_denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let numerator = if subtract {
                left_scaled.checked_sub(right_scaled)
            } else {
                left_scaled.checked_add(right_scaled)
            }
            .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = left
                .denominator()
                .checked_mul(right.denominator())
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            Ok(SignalValue::Ratio(ratio_from_i128(
                numerator,
                denominator,
                overflow,
            )?))
        }
        (SignalValue::Vector2(left), SignalValue::Vector2(right)) => Ok(SignalValue::Vector2(
            vector_arithmetic(left, right, subtract, overflow)?,
        )),
        (SignalValue::Vector3(left), SignalValue::Vector3(right)) => Ok(SignalValue::Vector3(
            vector_arithmetic(left, right, subtract, overflow)?,
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn vector_arithmetic(
    left: &[SignalValue],
    right: &[SignalValue],
    subtract: bool,
    overflow: SignalOverflow,
) -> Result<Vec<SignalValue>, SignalEvaluationError> {
    if left.len() != right.len() {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    left.iter()
        .zip(right)
        .map(|(left, right)| arithmetic_values(left, right, subtract, overflow))
        .collect()
}

pub(super) fn absolute_value(
    value: &SignalValue,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok(SignalValue::I64(match value.checked_abs() {
            Some(value) => value,
            None if overflow == SignalOverflow::Saturate => i64::MAX,
            None => return Err(SignalEvaluationError::ArithmeticOverflow),
        })),
        SignalValue::Ratio(value) => Ok(SignalValue::Ratio(
            ExactRatio::new(
                match value.numerator().checked_abs() {
                    Some(value) => value,
                    None if overflow == SignalOverflow::Saturate => i64::MAX,
                    None => return Err(SignalEvaluationError::ArithmeticOverflow),
                },
                value.denominator(),
            )
            .map_err(SignalEvaluationError::Program)?,
        )),
        _ => Ok(value.clone()),
    }
}

pub(super) fn negate_value(
    value: &SignalValue,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok(SignalValue::I64(match value.checked_neg() {
            Some(value) => value,
            None if overflow == SignalOverflow::Saturate => i64::MAX,
            None => return Err(SignalEvaluationError::ArithmeticOverflow),
        })),
        SignalValue::Ratio(value) => Ok(SignalValue::Ratio(
            ExactRatio::new(
                match value.numerator().checked_neg() {
                    Some(value) => value,
                    None if overflow == SignalOverflow::Saturate => i64::MAX,
                    None => return Err(SignalEvaluationError::ArithmeticOverflow),
                },
                value.denominator(),
            )
            .map_err(SignalEvaluationError::Program)?,
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(in crate::model::fault_signal) fn compare_numeric(
    left: &SignalValue,
    right: &SignalValue,
) -> Result<std::cmp::Ordering, SignalEvaluationError> {
    let (left_numerator, left_denominator) = numeric_fraction(left)?;
    let (right_numerator, right_denominator) = numeric_fraction(right)?;
    let left = left_numerator
        .checked_mul(
            i128::try_from(right_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let right = right_numerator
        .checked_mul(
            i128::try_from(left_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    Ok(left.cmp(&right))
}

pub(in crate::model::fault_signal) fn numeric_fraction(
    value: &SignalValue,
) -> Result<(i128, u128), SignalEvaluationError> {
    match value {
        SignalValue::I64(value) => Ok((i128::from(*value), 1)),
        SignalValue::U64(value)
        | SignalValue::DurationNanos(value)
        | SignalValue::RatePerSecond(value) => Ok((i128::from(*value), 1)),
        SignalValue::ProbabilityMillionths(value) => Ok((i128::from(*value), 1)),
        SignalValue::Ratio(value) => Ok((
            i128::from(value.numerator()),
            u128::from(value.denominator()),
        )),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(in crate::model::fault_signal) fn scale_value(
    value: &SignalValue,
    ratio: ExactRatio,
    offset: ExactRatio,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::Vector2(values) => Ok(SignalValue::Vector2(
            values
                .iter()
                .map(|value| scale_value(value, ratio, offset, rounding, overflow))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        SignalValue::Vector3(values) => Ok(SignalValue::Vector3(
            values
                .iter()
                .map(|value| scale_value(value, ratio, offset, rounding, overflow))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => {
            let (numerator, denominator) = numeric_fraction(value)?;
            let scaled_numerator = numerator
                .checked_mul(i128::from(ratio.numerator()))
                .and_then(|value| value.checked_mul(i128::from(offset.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let offset_numerator = i128::from(offset.numerator())
                .checked_mul(
                    i128::try_from(denominator)
                        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                )
                .and_then(|value| value.checked_mul(i128::from(ratio.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let result_numerator = scaled_numerator
                .checked_add(offset_numerator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let result_denominator = denominator
                .checked_mul(u128::from(ratio.denominator()))
                .and_then(|value| value.checked_mul(u128::from(offset.denominator())))
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            value_from_fraction(
                value,
                result_numerator,
                result_denominator,
                rounding,
                overflow,
            )
        }
    }
}

pub(in crate::model::fault_signal) fn interpolate_value(
    start: &SignalValue,
    end: &SignalValue,
    elapsed: u64,
    width: u64,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    if width == 0 || elapsed > width {
        return Err(SignalEvaluationError::InvalidPeriod);
    }
    let difference = arithmetic_values(end, start, true, overflow)?;
    let divisor = gcd_u64(elapsed, width);
    let scaled = scale_value(
        &difference,
        ExactRatio::new(
            i64::try_from(elapsed / divisor)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            width / divisor,
        )
        .map_err(SignalEvaluationError::Program)?,
        ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?,
        rounding,
        overflow,
    )?;
    arithmetic_values(start, &scaled, false, overflow)
}

pub(super) fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

pub(in crate::model::fault_signal) fn value_from_fraction(
    exemplar: &SignalValue,
    numerator: i128,
    denominator: u128,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    if denominator == 0 {
        return Err(SignalEvaluationError::DivisionByZero);
    }
    if matches!(exemplar, SignalValue::Ratio(_)) {
        let denominator =
            u64::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
        return Ok(SignalValue::Ratio(ratio_from_i128(
            numerator,
            denominator,
            overflow,
        )?));
    }
    let rounded = round_signed(numerator, denominator, rounding)?;
    match exemplar {
        SignalValue::I64(_) => Ok(SignalValue::I64(narrow_i64(rounded, overflow)?)),
        SignalValue::U64(_) => Ok(SignalValue::U64(narrow_u64(rounded, overflow)?)),
        SignalValue::DurationNanos(_) => {
            Ok(SignalValue::DurationNanos(narrow_u64(rounded, overflow)?))
        }
        SignalValue::RatePerSecond(_) => {
            Ok(SignalValue::RatePerSecond(narrow_u64(rounded, overflow)?))
        }
        SignalValue::ProbabilityMillionths(_) => {
            let value = match overflow {
                SignalOverflow::Saturate => rounded.clamp(0, 1_000_000),
                SignalOverflow::Error if !(0..=1_000_000).contains(&rounded) => {
                    return Err(SignalEvaluationError::ArithmeticOverflow);
                }
                SignalOverflow::Error => rounded,
            };
            Ok(SignalValue::ProbabilityMillionths(
                u32::try_from(value).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            ))
        }
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn round_signed(
    numerator: i128,
    denominator: u128,
    rounding: SignalRounding,
) -> Result<i128, SignalEvaluationError> {
    let denominator =
        i128::try_from(denominator).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder == 0 {
        return Ok(quotient);
    }
    let direction = if numerator < 0 { -1 } else { 1 };
    let increment = match rounding {
        SignalRounding::TowardZero => 0,
        SignalRounding::AwayFromZero => direction,
        SignalRounding::Floor if numerator < 0 => -1,
        SignalRounding::Floor => 0,
        SignalRounding::Ceiling if numerator > 0 => 1,
        SignalRounding::Ceiling => 0,
        SignalRounding::NearestTiesToEven => {
            let doubled = remainder
                .unsigned_abs()
                .checked_mul(2)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = u128::try_from(denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
            if doubled > denominator || (doubled == denominator && quotient % 2 != 0) {
                direction
            } else {
                0
            }
        }
    };
    quotient
        .checked_add(increment)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)
}

pub(super) fn ratio_from_i128(
    numerator: i128,
    denominator: u64,
    overflow: SignalOverflow,
) -> Result<ExactRatio, SignalEvaluationError> {
    let numerator = match i64::try_from(numerator) {
        Ok(value) => value,
        Err(_) if overflow == SignalOverflow::Saturate && numerator < 0 => i64::MIN,
        Err(_) if overflow == SignalOverflow::Saturate => i64::MAX,
        Err(_) => return Err(SignalEvaluationError::ArithmeticOverflow),
    };
    ExactRatio::new(numerator, denominator).map_err(SignalEvaluationError::Program)
}

pub(super) fn narrow_i64(
    value: i128,
    overflow: SignalOverflow,
) -> Result<i64, SignalEvaluationError> {
    match i64::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) if overflow == SignalOverflow::Saturate && value < 0 => Ok(i64::MIN),
        Err(_) if overflow == SignalOverflow::Saturate => Ok(i64::MAX),
        Err(_) => Err(SignalEvaluationError::ArithmeticOverflow),
    }
}

pub(super) fn narrow_u64(
    value: i128,
    overflow: SignalOverflow,
) -> Result<u64, SignalEvaluationError> {
    match u64::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) if overflow == SignalOverflow::Saturate && value < 0 => Ok(0),
        Err(_) if overflow == SignalOverflow::Saturate => Ok(u64::MAX),
        Err(_) => Err(SignalEvaluationError::ArithmeticOverflow),
    }
}

pub(super) fn evaluate_lookup_step(
    input: &SignalValue,
    points: &[(SignalValue, SignalValue)],
    before: &SignalBoundaryBehavior,
    after: &SignalBoundaryBehavior,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if compare_numeric(input, &points[0].0)?.is_lt() {
        return evaluate_boundary(before, Some(&points[0].1), None);
    }
    if compare_numeric(input, &points[points.len() - 1].0)?.is_gt() {
        return evaluate_boundary(after, Some(&points[points.len() - 1].1), None);
    }
    let mut selected = &points[0].1;
    for (key, output) in points {
        if compare_numeric(key, input)?.is_gt() {
            break;
        }
        selected = output;
    }
    Ok(EvaluatedSignal::Value(selected.clone()))
}

pub(in crate::model::fault_signal) fn evaluate_piecewise_linear(
    input: &SignalValue,
    points: &[(SignalValue, SignalValue)],
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if !compare_numeric(input, &points[0].0)?.is_gt() {
        return Ok(EvaluatedSignal::Value(points[0].1.clone()));
    }
    if !compare_numeric(input, &points[points.len() - 1].0)?.is_lt() {
        return Ok(EvaluatedSignal::Value(points[points.len() - 1].1.clone()));
    }
    let upper = points.partition_point(|(key, _)| {
        !compare_numeric(key, input).is_ok_and(std::cmp::Ordering::is_gt)
    });
    let (lower_key, lower_value) = &points[upper - 1];
    let (upper_key, upper_value) = &points[upper];
    let (input_numerator, input_denominator) = numeric_fraction(input)?;
    let (lower_numerator, lower_denominator) = numeric_fraction(lower_key)?;
    let (upper_numerator, upper_denominator) = numeric_fraction(upper_key)?;
    let position_numerator = input_numerator
        .checked_mul(
            i128::try_from(lower_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .and_then(|value| {
            lower_numerator
                .checked_mul(i128::try_from(input_denominator).ok()?)
                .and_then(|lower| value.checked_sub(lower))
        })
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let position_denominator = input_denominator
        .checked_mul(lower_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let span_numerator = upper_numerator
        .checked_mul(
            i128::try_from(lower_denominator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .and_then(|value| {
            lower_numerator
                .checked_mul(i128::try_from(upper_denominator).ok()?)
                .and_then(|lower| value.checked_sub(lower))
        })
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let span_denominator = upper_denominator
        .checked_mul(lower_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    if position_numerator < 0 || span_numerator <= 0 {
        return Err(SignalEvaluationError::ArithmeticOverflow);
    }
    let numerator = u128::try_from(position_numerator)
        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?
        .checked_mul(span_denominator)
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let denominator = position_denominator
        .checked_mul(
            u128::try_from(span_numerator)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
        )
        .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    let difference = arithmetic_values(upper_value, lower_value, true, overflow)?;
    let scaled = scale_value_fraction(&difference, numerator, denominator, rounding, overflow)?;
    Ok(EvaluatedSignal::Value(arithmetic_values(
        lower_value,
        &scaled,
        false,
        overflow,
    )?))
}

pub(super) fn scale_value_fraction(
    value: &SignalValue,
    numerator: u128,
    denominator: u128,
    rounding: SignalRounding,
    overflow: SignalOverflow,
) -> Result<SignalValue, SignalEvaluationError> {
    match value {
        SignalValue::Vector2(values) => Ok(SignalValue::Vector2(
            values
                .iter()
                .map(|value| {
                    scale_value_fraction(value, numerator, denominator, rounding, overflow)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        SignalValue::Vector3(values) => Ok(SignalValue::Vector3(
            values
                .iter()
                .map(|value| {
                    scale_value_fraction(value, numerator, denominator, rounding, overflow)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => {
            let (value_numerator, value_denominator) = numeric_fraction(value)?;
            let numerator = value_numerator
                .checked_mul(
                    i128::try_from(numerator)
                        .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                )
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            let denominator = value_denominator
                .checked_mul(denominator)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            value_from_fraction(value, numerator, denominator, rounding, overflow)
        }
    }
}

pub(super) fn history_at(
    history: Option<&VecDeque<HistoryEntry>>,
    target: &SignalCoordinate,
    same_coordinate_sequence: u64,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    history
        .and_then(|history| {
            history.iter().rev().find(|entry| {
                (&entry.coordinate, entry.same_coordinate_sequence)
                    <= (target, same_coordinate_sequence)
            })
        })
        .map(|entry| entry.output.clone())
        .ok_or(SignalEvaluationError::HistoryUnavailable)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_window(
    operator: PureSignalOperator,
    window: u64,
    retained_samples: usize,
    rounding: SignalRounding,
    overflow: SignalOverflow,
    coordinate: &SignalCoordinate,
    same_coordinate_sequence: u64,
    history: Option<&VecDeque<HistoryEntry>>,
    current: &EvaluatedSignal,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let start = subtract_coordinate(coordinate, window)?;
    let mut values = history
        .into_iter()
        .flat_map(|history| history.iter())
        .filter(|entry| {
            entry.coordinate >= start
                && (&entry.coordinate, entry.same_coordinate_sequence)
                    < (coordinate, same_coordinate_sequence)
        })
        .filter_map(|entry| match &entry.output {
            EvaluatedSignal::Value(value) => Some(value.clone()),
            EvaluatedSignal::Inactive => None,
        })
        .collect::<Vec<_>>();
    if let EvaluatedSignal::Value(value) = current {
        values.push(value.clone());
    }
    if values.len() > retained_samples {
        values.drain(..values.len() - retained_samples);
    }
    if values.is_empty() {
        return Err(SignalEvaluationError::HistoryUnavailable);
    }
    let mut aggregate = values[0].clone();
    match operator {
        PureSignalOperator::WindowMin => {
            for value in values.iter().skip(1) {
                if compare_numeric(value, &aggregate)?.is_lt() {
                    aggregate = value.clone();
                }
            }
        }
        PureSignalOperator::WindowMax => {
            for value in values.iter().skip(1) {
                if compare_numeric(value, &aggregate)?.is_gt() {
                    aggregate = value.clone();
                }
            }
        }
        PureSignalOperator::WindowMean => {
            for value in values.iter().skip(1) {
                aggregate = arithmetic_values(&aggregate, value, false, overflow)?;
            }
            aggregate = scale_value_fraction(
                &aggregate,
                1,
                u128::try_from(values.len())
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
                rounding,
                overflow,
            )?;
        }
        _ => return Err(SignalEvaluationError::InvalidOperator),
    }
    Ok(EvaluatedSignal::Value(aggregate))
}

pub(super) fn evaluate_distance(
    metric: &SignalId,
    rounding: SignalRounding,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let left = vector_i64(inputs[0].value()?)?;
    let right = vector_i64(inputs[1].value()?)?;
    if left.len() != right.len() {
        return Err(SignalEvaluationError::TypeMismatch);
    }
    let deltas = left
        .iter()
        .zip(right)
        .map(|(left, right)| i128::from(*left) - i128::from(right))
        .collect::<Vec<_>>();
    let distance = match metric.as_str() {
        "manhattan" => deltas
            .iter()
            .try_fold(0_i128, |total, delta| total.checked_add(delta.abs())),
        "euclidean-squared" => deltas.iter().try_fold(0_i128, |total, delta| {
            delta
                .checked_mul(*delta)
                .and_then(|square| total.checked_add(square))
        }),
        "euclidean" => {
            let squared = deltas
                .iter()
                .try_fold(0_u128, |total, delta| {
                    delta
                        .unsigned_abs()
                        .checked_mul(delta.unsigned_abs())
                        .and_then(|square| total.checked_add(square))
                })
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
            Some(
                i128::try_from(integer_square_root(squared, rounding)?)
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
            )
        }
        _ => return Err(SignalEvaluationError::UnknownMetric(metric.clone())),
    }
    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
    Ok(EvaluatedSignal::Value(SignalValue::I64(
        i64::try_from(distance).map_err(|_| SignalEvaluationError::ArithmeticOverflow)?,
    )))
}

pub(in crate::model::fault_signal) fn integer_square_root(
    value: u128,
    rounding: SignalRounding,
) -> Result<u128, SignalEvaluationError> {
    if value < 2 {
        return Ok(value);
    }
    let mut low = 1_u128;
    let mut high = value.min(u128::from(u64::MAX));
    while low <= high {
        let middle = low + (high - low) / 2;
        if middle <= value / middle {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    let floor = high;
    let exact = floor.checked_mul(floor) == Some(value);
    Ok(match rounding {
        SignalRounding::Ceiling | SignalRounding::AwayFromZero if !exact => floor + 1,
        SignalRounding::NearestTiesToEven if !exact => {
            let lower_delta = value - floor * floor;
            let upper = floor + 1;
            let upper_delta = upper * upper - value;
            if upper_delta < lower_delta || (upper_delta == lower_delta && floor % 2 == 1) {
                upper
            } else {
                floor
            }
        }
        _ => floor,
    })
}

pub(super) fn vector_i64(value: &SignalValue) -> Result<Vec<i64>, SignalEvaluationError> {
    let values = match value {
        SignalValue::Vector2(values) | SignalValue::Vector3(values) => values,
        _ => return Err(SignalEvaluationError::TypeMismatch),
    };
    values
        .iter()
        .map(|value| match value {
            SignalValue::I64(value) => Ok(*value),
            _ => Err(SignalEvaluationError::TypeMismatch),
        })
        .collect()
}

pub(super) fn evaluate_zone_contains(
    zone: &SignalId,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let contains = match inputs[0].value()? {
        SignalValue::Enum { variant, .. } => variant == zone,
        SignalValue::Bool(value) => *value,
        _ => return Err(SignalEvaluationError::TypeMismatch),
    };
    Ok(EvaluatedSignal::Value(SignalValue::Bool(contains)))
}

pub(in crate::model::fault_signal) fn position_vector(
    value: &SignalValue,
) -> Result<[i64; 3], SignalEvaluationError> {
    match vector_i64(value)?.as_slice() {
        [x, y] => Ok([*x, *y, 0]),
        [x, y, z] => Ok([*x, *y, *z]),
        _ => Err(SignalEvaluationError::TypeMismatch),
    }
}

pub(super) fn spatial_frame(node: &SignalNode) -> Result<SignalId, SignalEvaluationError> {
    match &node.kind {
        SignalNodeKind::Source(
            SignalSourceSpecification::PointSet {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::RegularGrid {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::TiledGrid {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::ZoneMap {
                coordinate_frame, ..
            }
            | SignalSourceSpecification::SeededField {
                coordinate_frame, ..
            },
        ) => Ok(coordinate_frame.clone()),
        _ => Err(SignalEvaluationError::SpatialFieldRequired(node.id.clone())),
    }
}

pub(super) fn evaluate_orientation_delta(
    convention: &SignalId,
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    if convention.as_str() != "yaw-pitch-roll-millidegrees" {
        return Err(SignalEvaluationError::UnknownOrientationConvention(
            convention.clone(),
        ));
    }
    let left = vector_i64(inputs[0].value()?)?;
    let right = vector_i64(inputs[1].value()?)?;
    let deltas = left
        .iter()
        .zip(right)
        .map(|(left, right)| {
            let raw = (i128::from(*left) - i128::from(right)).rem_euclid(360_000);
            let delta = if raw > 180_000 { raw - 360_000 } else { raw };
            i64::try_from(delta)
                .map(SignalValue::I64)
                .map_err(|_| SignalEvaluationError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvaluatedSignal::Value(if deltas.len() == 2 {
        SignalValue::Vector2(deltas)
    } else {
        SignalValue::Vector3(deltas)
    }))
}

pub(super) fn merge_events(
    inputs: &[EvaluatedSignal],
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    Ok(inputs
        .iter()
        .find(|input| matches!(input, EvaluatedSignal::Value(_)))
        .cloned()
        .unwrap_or(EvaluatedSignal::Inactive))
}

pub(super) fn state_output(
    node: &SignalNode,
    state: &EvaluatorNodeState,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    let value = match state {
        EvaluatorNodeState::Hysteresis { value, .. }
        | EvaluatorNodeState::BurstProcess { bad: value, .. } => SignalValue::Bool(*value),
        EvaluatorNodeState::Debounce { committed, .. }
        | EvaluatorNodeState::Integrator {
            accumulator: committed,
            ..
        }
        | EvaluatorNodeState::LeakyIntegrator {
            accumulator: committed,
            ..
        } => committed.clone(),
        EvaluatorNodeState::FiniteStateMachine { state, .. }
        | EvaluatorNodeState::MarkovChain { state, .. } => {
            let SignalValueType::Enum(schema) = &node.output.value_type else {
                return Err(SignalEvaluationError::TypeMismatch);
            };
            SignalValue::Enum {
                schema: schema.clone(),
                variant: state.clone(),
            }
        }
        EvaluatorNodeState::Counter { count } => SignalValue::U64(*count),
        EvaluatorNodeState::QueueModel { backlog, .. } => SignalValue::U64(u64::from(*backlog)),
    };
    Ok(EvaluatedSignal::Value(value))
}

pub(super) fn evaluate_stateful_node(
    node: &SignalNode,
    specification: &StatefulSignalSpecification,
    request: &SignalEvaluationRequest,
    inputs: &[EvaluatedSignal],
    state: &mut EvaluatorNodeState,
    emitted_events: &mut Vec<StatefulSignalEvent>,
) -> Result<EvaluatedSignal, SignalEvaluationError> {
    match (specification, &mut *state) {
        (
            StatefulSignalSpecification::Hysteresis {
                set_when,
                clear_when,
                minimum_residence_nanos,
                ..
            },
            EvaluatorNodeState::Hysteresis {
                value,
                last_transition_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let input = inputs[0].value()?;
            let desired = if *value {
                !compare_numeric(input, clear_when)?.is_lt()
            } else {
                !compare_numeric(input, set_when)?.is_lt()
            };
            if desired != *value
                && now.saturating_sub(*last_transition_nanos) >= *minimum_residence_nanos
            {
                *value = desired;
                *last_transition_nanos = now;
            }
        }
        (
            StatefulSignalSpecification::Debounce {
                residence_nanos, ..
            },
            EvaluatorNodeState::Debounce {
                committed,
                candidate,
                candidate_since_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let input = inputs[0].value()?;
            if input == committed {
                *candidate = None;
                *candidate_since_nanos = None;
            } else if candidate.as_ref() != Some(input) {
                *candidate = Some(input.clone());
                *candidate_since_nanos = Some(now);
            } else if candidate_since_nanos
                .is_some_and(|since| now.saturating_sub(since) >= *residence_nanos)
            {
                *committed = input.clone();
                *candidate = None;
                *candidate_since_nanos = None;
            }
        }
        (
            StatefulSignalSpecification::Integrator {
                cadence_nanos,
                time_unit_nanos,
                rounding,
                overflow,
                ..
            },
            EvaluatorNodeState::Integrator {
                accumulator,
                pending,
                previous_input,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let current_input = inputs[0].value()?.clone();
            if let Some(last) = *last_nanos {
                let delta = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let prior = previous_input
                    .as_ref()
                    .ok_or(SignalEvaluationError::InvalidState)?;
                if *cadence_nanos == 0 {
                    let contribution = scale_value_fraction(
                        prior,
                        u128::from(delta),
                        u128::from(*time_unit_nanos),
                        *rounding,
                        *overflow,
                    )?;
                    *accumulator = arithmetic_values(accumulator, &contribution, false, *overflow)?;
                } else if delta > 0 {
                    integrate_to_cadence(
                        accumulator,
                        pending,
                        prior,
                        last,
                        now,
                        *cadence_nanos,
                        *time_unit_nanos,
                        *rounding,
                        *overflow,
                    )?;
                }
            }
            *last_nanos = Some(now);
            *previous_input = Some(current_input);
        }
        (
            StatefulSignalSpecification::LeakyIntegrator {
                cadence_nanos,
                time_unit_nanos,
                decay_ratio,
                maximum_catch_up_steps,
                rounding,
                overflow,
                ..
            },
            EvaluatorNodeState::LeakyIntegrator {
                accumulator,
                previous_input,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let current_input = inputs[0].value()?.clone();
            if let Some(last) = *last_nanos {
                let elapsed = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let steps = elapsed / *cadence_nanos;
                if steps > u64::from(*maximum_catch_up_steps) {
                    return Err(SignalEvaluationError::CatchUpLimitExceeded {
                        requested: steps,
                        maximum: *maximum_catch_up_steps,
                    });
                }
                let prior = previous_input
                    .as_ref()
                    .ok_or(SignalEvaluationError::InvalidState)?;
                let contribution = scale_value_fraction(
                    prior,
                    u128::from(*cadence_nanos),
                    u128::from(*time_unit_nanos),
                    *rounding,
                    *overflow,
                )?;
                for _ in 0..steps {
                    let decayed = scale_value(
                        accumulator,
                        *decay_ratio,
                        ExactRatio::new(0, 1).map_err(SignalEvaluationError::Program)?,
                        *rounding,
                        *overflow,
                    )?;
                    *accumulator = arithmetic_values(&decayed, &contribution, false, *overflow)?;
                }
                *last_nanos = Some(
                    last.checked_add(
                        steps
                            .checked_mul(*cadence_nanos)
                            .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                    )
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                );
            } else {
                *last_nanos = Some(now);
            }
            *previous_input = Some(current_input);
        }
        (
            StatefulSignalSpecification::FiniteStateMachine {
                transitions,
                unmatched_event,
                ..
            },
            EvaluatorNodeState::FiniteStateMachine { state, timers },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            let expired = timers
                .iter()
                .find_map(|(timer, deadline)| (*deadline <= now).then_some(timer.clone()));
            let input_event = match inputs.first() {
                Some(EvaluatedSignal::Value(SignalValue::Event { schema, .. })) => {
                    Some(schema.clone())
                }
                Some(EvaluatedSignal::Inactive) | None => expired.clone(),
                _ => return Err(SignalEvaluationError::TypeMismatch),
            };
            if let Some(expired) = expired {
                timers.remove(&expired);
            }
            if let Some(event) = input_event {
                let transition = transitions.iter().find(|transition| {
                    transition.from == *state
                        && transition.event == event
                        && transition.guard.as_ref().is_none_or(|guard| {
                            node.inputs
                                .iter()
                                .position(|input| input == guard)
                                .and_then(|index| inputs.get(index))
                                .and_then(|value| value.value().ok())
                                .and_then(|value| bool_value(value).ok())
                                == Some(true)
                        })
                });
                if let Some(transition) = transition {
                    *state = transition.to.clone();
                    for operation in &transition.timer_operations {
                        match operation {
                            StateMachineTimerOperation::Start {
                                timer,
                                duration_nanos,
                            } => {
                                timers.insert(
                                    timer.clone(),
                                    now.checked_add(*duration_nanos)
                                        .ok_or(SignalEvaluationError::ArithmeticOverflow)?,
                                );
                            }
                            StateMachineTimerOperation::Cancel { timer } => {
                                timers.remove(timer);
                            }
                        }
                    }
                    if let Some(variant) = &transition.emit {
                        emitted_events.push(StatefulSignalEvent {
                            node: node.id.clone(),
                            variant: variant.clone(),
                            coordinate: request.coordinate.clone(),
                            same_coordinate_sequence: request.same_coordinate_sequence,
                        });
                    }
                } else if unmatched_event.as_str() != "ignore" {
                    return Err(SignalEvaluationError::UnmatchedStateMachineEvent {
                        state: state.clone(),
                        event,
                    });
                }
            }
        }
        (
            StatefulSignalSpecification::MarkovChain {
                states,
                opportunity,
                probability_rows,
                ..
            },
            EvaluatorNodeState::MarkovChain {
                state,
                transition_sequence,
            },
        ) => {
            let actual = request
                .choice
                .opportunity
                .as_ref()
                .ok_or(SignalEvaluationError::OpportunityIdentityRequired)?;
            if actual.operation().as_str() != opportunity.as_str() {
                return Err(SignalEvaluationError::OpportunityKindMismatch);
            }
            let row = states
                .iter()
                .position(|candidate| candidate == state)
                .and_then(|index| probability_rows.get(index))
                .ok_or(SignalEvaluationError::InvalidState)?;
            let draw = keyed_transition_u64(node, request, *transition_sequence) % 1_000_000;
            let mut cumulative = 0_u64;
            let selected = row
                .iter()
                .position(|probability| {
                    cumulative += u64::from(*probability);
                    draw < cumulative
                })
                .ok_or(SignalEvaluationError::InvalidProbabilityRow)?;
            *state = states[selected].clone();
            *transition_sequence = transition_sequence
                .checked_add(1)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        }
        (
            StatefulSignalSpecification::BurstProcess {
                good_to_bad_millionths,
                bad_to_good_millionths,
                opportunity,
                ..
            },
            EvaluatorNodeState::BurstProcess {
                bad,
                transition_sequence,
            },
        ) => {
            let actual = request
                .choice
                .opportunity
                .as_ref()
                .ok_or(SignalEvaluationError::OpportunityIdentityRequired)?;
            if actual.operation().as_str() != opportunity.as_str() {
                return Err(SignalEvaluationError::OpportunityKindMismatch);
            }
            let probability = if *bad {
                *bad_to_good_millionths
            } else {
                *good_to_bad_millionths
            };
            if keyed_transition_u64(node, request, *transition_sequence) % 1_000_000
                < u64::from(probability)
            {
                *bad = !*bad;
            }
            *transition_sequence = transition_sequence
                .checked_add(1)
                .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
        }
        (
            StatefulSignalSpecification::Counter {
                maximum,
                overflow,
                reset_event,
                ..
            },
            EvaluatorNodeState::Counter { count },
        ) => {
            if let EvaluatedSignal::Value(SignalValue::Event { schema, .. }) = &inputs[0] {
                if reset_event.as_ref() == Some(schema) {
                    *count = 0;
                } else if *count == *maximum {
                    if *overflow == SignalOverflow::Error {
                        return Err(SignalEvaluationError::ArithmeticOverflow);
                    }
                } else {
                    *count += 1;
                }
            }
        }
        (
            StatefulSignalSpecification::QueueModel {
                capacity, overflow, ..
            },
            EvaluatorNodeState::QueueModel {
                backlog,
                service_remainder,
                last_nanos,
            },
        ) => {
            let now = coordinate_nanos(&request.coordinate)?;
            if let Some(last) = *last_nanos {
                let elapsed = now
                    .checked_sub(last)
                    .ok_or(SignalEvaluationError::NonMonotoneEvaluation)?;
                let rate = match inputs[1].value()? {
                    SignalValue::RatePerSecond(value) | SignalValue::U64(value) => *value,
                    _ => return Err(SignalEvaluationError::TypeMismatch),
                };
                let service = u128::from(rate)
                    .checked_mul(u128::from(elapsed))
                    .and_then(|value| value.checked_add(u128::from(*service_remainder)))
                    .ok_or(SignalEvaluationError::ArithmeticOverflow)?;
                let completed = service / 1_000_000_000;
                *service_remainder = u64::try_from(service % 1_000_000_000)
                    .map_err(|_| SignalEvaluationError::ArithmeticOverflow)?;
                let completed = u32::try_from(completed).unwrap_or(u32::MAX);
                *backlog = backlog.saturating_sub(completed);
            }
            if matches!(inputs[0], EvaluatedSignal::Value(SignalValue::Event { .. })) {
                if *backlog < *capacity {
                    *backlog += 1;
                } else if overflow.as_str() == "error" {
                    return Err(SignalEvaluationError::QueueOverflow);
                } else if !matches!(overflow.as_str(), "drop-newest" | "drop-oldest") {
                    return Err(SignalEvaluationError::UnknownQueueOverflow(
                        overflow.clone(),
                    ));
                }
            }
            *last_nanos = Some(now);
        }
        _ => return Err(SignalEvaluationError::StateVariantMismatch),
    }
    state_output(node, state)
}
