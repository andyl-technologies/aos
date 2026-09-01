//! Focused deterministic binding runtime helpers.

use super::*;
pub(super) fn map_binding(
    binding: &FaultBinding,
    values: &[SignalValue],
    state: &mut BindingRuntimeState,
    now: u64,
    opportunity: Option<&FaultOpportunity>,
    scenario_seed: ContentHash,
) -> Result<MappingDecision, BindingRuntimeError> {
    match binding.mapping() {
        BindingMapping::ActiveWhenTrue { invert } => match &values[0] {
            SignalValue::Bool(value) => Ok(MappingDecision::Persistent(*value != *invert)),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::ActiveWhenEqual { value } => match &values[0] {
            SignalValue::Enum { variant, .. } => Ok(MappingDecision::Persistent(variant == value)),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::Threshold {
            comparison,
            threshold,
            clear_threshold,
            residence_nanos,
        } => {
            let desired = if state.active {
                if let Some(clear_threshold) = clear_threshold {
                    !threshold_matches(
                        &values[0],
                        clear_threshold,
                        reverse_comparison(*comparison),
                    )?
                } else {
                    threshold_matches(&values[0], threshold, *comparison)?
                }
            } else {
                threshold_matches(&values[0], threshold, *comparison)?
            };
            if desired == state.active {
                state.pending_activation = None;
                state.pending_since_nanos = None;
                return Ok(MappingDecision::NoAction);
            }
            if state.pending_activation != Some(desired) {
                state.pending_activation = Some(desired);
                state.pending_since_nanos = Some(now);
                if *residence_nanos > 0 {
                    return Ok(MappingDecision::NoAction);
                }
            }
            if now.saturating_sub(state.pending_since_nanos.unwrap_or(now)) < *residence_nanos {
                Ok(MappingDecision::NoAction)
            } else {
                Ok(MappingDecision::Persistent(desired))
            }
        }
        BindingMapping::MapParameter { .. }
        | BindingMapping::PiecewiseParameter { .. }
        | BindingMapping::ServiceProfile { .. } => {
            if binding.effect().lifetime() == EffectLifetime::Persistent {
                Ok(MappingDecision::Persistent(true))
            } else {
                Ok(MappingDecision::Apply)
            }
        }
        BindingMapping::Hazard => {
            let SignalValue::ProbabilityMillionths(probability) = values[0] else {
                return Err(BindingRuntimeError::MappingType);
            };
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            let draw = exact_hazard_draw(scenario_seed, binding.id(), opportunity.id())?;
            Ok(if draw < probability {
                MappingDecision::Apply
            } else {
                MappingDecision::NoAction
            })
        }
        BindingMapping::ImpulseOnEvent => Ok(if matches!(values[0], SignalValue::Event { .. }) {
            MappingDecision::Apply
        } else {
            MappingDecision::NoAction
        }),
        BindingMapping::StateTransition { .. } => Ok(
            if matches!(
                values[0],
                SignalValue::Event { .. } | SignalValue::Enum { .. }
            ) {
                MappingDecision::Apply
            } else {
                MappingDecision::NoAction
            },
        ),
    }
}

pub(super) fn exact_hazard_draw(
    scenario_seed: ContentHash,
    binding: &FaultObjectId,
    opportunity: ContentHash,
) -> Result<u32, BindingRuntimeError> {
    const WIDTH: u64 = 1_000_000;
    const MAX_ATTEMPTS: u64 = 64;
    let rejection = u64::MAX - u64::MAX % WIDTH;
    for counter in 0..MAX_ATTEMPTS {
        let material = format!(
            "seed={};binding={};opportunity={};counter={counter}",
            scenario_seed.to_hex(),
            binding.as_str(),
            opportunity.to_hex(),
        );
        let hash = ContentHash::from_canonical_material("crucible.binding-hazard.v1", &material);
        let draw = u64::from_be_bytes(
            hash.bytes[..8]
                .try_into()
                .map_err(|_| BindingRuntimeError::HazardKeyExhausted)?,
        );
        if draw < rejection {
            return u32::try_from(draw % WIDTH)
                .map_err(|_| BindingRuntimeError::HazardKeyExhausted);
        }
    }
    Err(BindingRuntimeError::HazardKeyExhausted)
}

pub(super) fn map_parameter_values(
    binding: &FaultBinding,
    sampled_values: Vec<SignalValue>,
) -> Result<Vec<SignalValue>, BindingRuntimeError> {
    let BindingMapping::PiecewiseParameter {
        points,
        rounding,
        overflow,
        ..
    } = binding.mapping()
    else {
        return Ok(sampled_values);
    };
    let input = sampled_values
        .first()
        .ok_or(BindingRuntimeError::MappingType)?;
    let transfer = points
        .iter()
        .map(|point| (point.input.clone(), point.output.clone()))
        .collect::<Vec<_>>();
    match evaluate_piecewise_linear(input, &transfer, *rounding, *overflow)
        .map_err(BindingRuntimeError::Evaluation)?
    {
        EvaluatedSignal::Value(value) => Ok(vec![value]),
        EvaluatedSignal::Inactive => Err(BindingRuntimeError::MappingType),
    }
}

pub(super) fn resolved_mapping_output(
    binding: &FaultBinding,
    values: &[SignalValue],
    activation_value: bool,
) -> Result<ResolvedMappingOutput, BindingRuntimeError> {
    match binding.mapping() {
        BindingMapping::ActiveWhenTrue { .. }
        | BindingMapping::ActiveWhenEqual { .. }
        | BindingMapping::Threshold { .. } => Ok(ResolvedMappingOutput::Activation {
            active: activation_value,
        }),
        BindingMapping::MapParameter { parameter }
        | BindingMapping::PiecewiseParameter { parameter, .. } => {
            Ok(ResolvedMappingOutput::Parameter {
                parameter: *parameter,
                value: values
                    .first()
                    .cloned()
                    .ok_or(BindingRuntimeError::MappingType)?,
            })
        }
        BindingMapping::Hazard => match values.first() {
            Some(SignalValue::ProbabilityMillionths(probability_millionths)) => {
                Ok(ResolvedMappingOutput::Hazard {
                    probability_millionths: *probability_millionths,
                })
            }
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::ImpulseOnEvent => match values.first() {
            Some(event @ SignalValue::Event { .. }) => Ok(ResolvedMappingOutput::Impulse {
                event: event.clone(),
            }),
            _ => Err(BindingRuntimeError::MappingType),
        },
        BindingMapping::StateTransition { transition_table } => {
            let request = values
                .first()
                .cloned()
                .ok_or(BindingRuntimeError::MappingType)?;
            let declaration = binding
                .transition_declaration()
                .ok_or(BindingRuntimeError::MappingDeclaration)?;
            let selected_transition = declaration
                .transitions
                .get(&request)
                .cloned()
                .unwrap_or_else(|| declaration.default_transition.clone());
            Ok(ResolvedMappingOutput::StateTransition {
                transition_table: transition_table.clone(),
                request,
                selected_transition,
            })
        }
        BindingMapping::ServiceProfile { service_profile } => {
            let declaration = binding
                .service_declaration()
                .ok_or(BindingRuntimeError::MappingDeclaration)?;
            Ok(ResolvedMappingOutput::ServiceProfile {
                service_profile: service_profile.clone(),
                input_contracts: declaration.inputs.clone(),
                inputs: values.to_vec(),
            })
        }
    }
}

pub(super) fn reverse_comparison(comparison: ThresholdComparison) -> ThresholdComparison {
    match comparison {
        ThresholdComparison::LessThan => ThresholdComparison::GreaterThanOrEqual,
        ThresholdComparison::LessThanOrEqual => ThresholdComparison::GreaterThan,
        ThresholdComparison::GreaterThan => ThresholdComparison::LessThanOrEqual,
        ThresholdComparison::GreaterThanOrEqual => ThresholdComparison::LessThan,
    }
}

pub(super) fn threshold_matches(
    value: &SignalValue,
    threshold: &SignalValue,
    comparison: ThresholdComparison,
) -> Result<bool, BindingRuntimeError> {
    let order = compare_numeric(value, threshold).map_err(BindingRuntimeError::Evaluation)?;
    Ok(match comparison {
        ThresholdComparison::LessThan => order.is_lt(),
        ThresholdComparison::LessThanOrEqual => !order.is_gt(),
        ThresholdComparison::GreaterThan => order.is_gt(),
        ThresholdComparison::GreaterThanOrEqual => !order.is_lt(),
    })
}

pub(super) fn sample_identity_digest(
    binding: &FaultBinding,
    values: &[SignalValue],
    mapped_digest: ContentHash,
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<&FaultOpportunity>,
) -> ContentHash {
    if !values
        .iter()
        .any(|value| matches!(value, SignalValue::Event { .. }))
    {
        return mapped_digest;
    }
    let mut material = format!(
        "binding={};mapped={};virtual_nanos={};retired_instructions={:?};same_coordinate_sequence={};opportunity=",
        binding.id().as_str(),
        mapped_digest.to_hex(),
        coordinate.virtual_nanos,
        coordinate.retired_instructions,
        same_coordinate_sequence,
    );
    material.push_str(
        &opportunity
            .map(FaultOpportunity::id)
            .map_or_else(|| String::from("none"), |identity| identity.to_hex()),
    );
    ContentHash::from_canonical_material("crucible.binding-sample-identity.v1", &material)
}

pub(super) fn search_decision_identity(
    binding: &FaultBinding,
    sample: ContentHash,
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    transition_sequence: u64,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.binding-search-decision.v1",
        &format!(
            "binding={};sample={};virtual_nanos={};retired={};same_coordinate_sequence={same_coordinate_sequence};transition_sequence={transition_sequence}",
            binding.id().as_str(),
            sample.to_hex(),
            coordinate.virtual_nanos,
            coordinate
                .retired_instructions
                .map_or_else(|| String::from("none"), |value| value.to_string()),
        ),
    )
}
