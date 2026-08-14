//! Focused deterministic binding runtime helpers.

use super::*;
pub(super) fn binding_due(
    binding: &FaultBinding,
    state: &BindingRuntimeState,
    now: u64,
    opportunity: Option<&FaultOpportunity>,
) -> bool {
    match binding.sampling() {
        BindingSampling::AtOpportunity => opportunity.is_some(),
        BindingSampling::AtBoundary | BindingSampling::AtChange => opportunity.is_none(),
        BindingSampling::CadenceNanos(cadence) => {
            opportunity.is_none()
                && now.is_multiple_of(cadence.get())
                && state.last_sample_nanos != Some(now)
        }
        BindingSampling::AtEvent(parent) => match parent {
            BindingEventParent::VirtualTime | BindingEventParent::NodeCounter { .. } => {
                opportunity.is_none()
            }
            BindingEventParent::OpportunityOperation | BindingEventParent::OpportunityState => {
                opportunity.is_some()
            }
        },
    }
}

pub(super) fn opportunity_matches(
    binding: &FaultBinding,
    opportunity: Option<&FaultOpportunity>,
) -> bool {
    if !control_opportunity_matches(binding.effect(), opportunity) {
        return false;
    }
    match (binding.opportunity_filter(), opportunity) {
        (Some(filter), Some(opportunity)) => filter.matches(opportunity),
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

pub(super) fn control_opportunity_matches(
    effect: &EffectRequest,
    opportunity: Option<&FaultOpportunity>,
) -> bool {
    let control_transform = match effect.specification() {
        EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
            technology,
            operations,
            ..
        }) => Some((technology, operations)),
        _ => None,
    };
    match opportunity.map(FaultOpportunity::payload) {
        Some(OpportunityPayload::NetworkControl { technology, .. }) => control_transform
            .is_some_and(|(expected_technology, operations)| {
                expected_technology == technology
                    && opportunity.is_some_and(|value| operations.contains(value.operation()))
            }),
        Some(_) => control_transform.is_none(),
        None => true,
    }
}

pub(super) fn binding_phases(binding: &FaultBinding) -> Vec<FaultPhase> {
    binding.phases().iter().copied().collect()
}

pub(super) fn membership_digest(path: &FaultObjectId, targets: &ResolvedTargetSet) -> ContentHash {
    let mut material = format!(
        "path={};allow_empty={};targets=",
        path.as_str(),
        targets.allow_empty()
    );
    for target in targets.targets() {
        target.append_canonical(&mut material);
        material.push(';');
    }
    ContentHash::from_canonical_material("crucible.dynamic-membership.v1", &material)
}

pub(super) fn reserve_usize_runtime(
    resource_limits: FaultResourceLimits,
    field: &'static str,
    current: usize,
    requested: usize,
) -> Result<(), BindingRuntimeError> {
    let current = u64::try_from(current).map_err(|_| BindingRuntimeError::CountOverflow(field))?;
    let requested =
        u64::try_from(requested).map_err(|_| BindingRuntimeError::CountOverflow(field))?;
    resource_limits
        .reserve(field, current, requested)
        .map_err(BindingRuntimeError::ResourceLimit)
}

pub(super) fn recorded_effect_count(
    work_items: &[ResolvedReplayWorkItem],
) -> Result<usize, BindingRuntimeError> {
    work_items.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.records.len())
            .ok_or(BindingRuntimeError::CountOverflow(
                "resolved_effect_records",
            ))
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_membership_actions(
    binding: &FaultBinding,
    target: &ResolvedFaultTarget,
    phases: &[FaultPhase],
    kind: BindingActionKind,
    effect: &Arc<EffectRequest>,
    mapping_output: &Arc<ResolvedMappingOutput>,
    mapped_digest: ContentHash,
    transition_sequence: u64,
    coordinate: FaultCoordinate,
    cause: &BindingActionCause,
    evaluation: &mut BindingEvaluation,
) {
    evaluation
        .actions
        .extend(phases.iter().map(|phase| ResolvedBindingAction {
            kind,
            binding: binding.id().clone(),
            target: target.clone(),
            phase: *phase,
            effect: effect.clone(),
            mapping_output: mapping_output.clone(),
            mapped_digest,
            transition_sequence,
            opportunity: None,
            coordinate,
            cause: cause.clone(),
            expected_precondition: None,
        }));
}

pub(super) fn binding_coordinate(
    domain: SignalDomain,
    coordinate: FaultCoordinate,
    opportunity: Option<&FaultOpportunity>,
    sampling: &BindingSampling,
    same_coordinate_sequence: u64,
) -> Result<SignalCoordinate, BindingRuntimeError> {
    match domain {
        SignalDomain::VirtualTime => Ok(SignalCoordinate::VirtualTime {
            nanos: coordinate.virtual_nanos,
        }),
        SignalDomain::NodeCounter => {
            let retired_instructions = coordinate
                .retired_instructions
                .ok_or(BindingRuntimeError::CounterCoordinateRequired)?;
            let node = opportunity
                .map(|opportunity| target_signal_id(opportunity.target()))
                .transpose()?
                .ok_or(BindingRuntimeError::OpportunityRequired)?;
            Ok(SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            })
        }
        SignalDomain::Operation => {
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            operation_signal_coordinate(opportunity)
        }
        SignalDomain::Event => {
            let BindingSampling::AtEvent(parent) = sampling else {
                return Err(BindingRuntimeError::EventParentRequired);
            };
            let parent = match parent {
                BindingEventParent::VirtualTime => SignalCoordinate::VirtualTime {
                    nanos: coordinate.virtual_nanos,
                },
                BindingEventParent::NodeCounter { node } => SignalCoordinate::NodeCounter {
                    node: node.clone(),
                    retired_instructions: coordinate
                        .retired_instructions
                        .ok_or(BindingRuntimeError::CounterCoordinateRequired)?,
                },
                BindingEventParent::OpportunityOperation => operation_signal_coordinate(
                    opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?,
                )?,
                BindingEventParent::OpportunityState => {
                    let opportunity =
                        opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
                    SignalCoordinate::State {
                        adapter: adapter_signal_id(opportunity.adapter())?,
                        target: target_signal_id(opportunity.target())?,
                        boundary_sequence: opportunity.sequence(),
                    }
                }
            };
            Ok(SignalCoordinate::Event {
                parent: Box::new(parent),
                sequence: same_coordinate_sequence,
            })
        }
        SignalDomain::State => {
            let opportunity = opportunity.ok_or(BindingRuntimeError::OpportunityRequired)?;
            Ok(SignalCoordinate::State {
                adapter: SignalId::parse(match opportunity.adapter() {
                    FaultAdapter::Network => "network",
                    FaultAdapter::Storage => "storage",
                    FaultAdapter::Node => "node",
                })
                .map_err(BindingRuntimeError::Program)?,
                target: target_signal_id(opportunity.target())?,
                boundary_sequence: opportunity.sequence(),
            })
        }
        SignalDomain::Spatial => Err(BindingRuntimeError::UnprojectedSpatialSignal),
    }
}

pub(super) fn operation_signal_coordinate(
    opportunity: &FaultOpportunity,
) -> Result<SignalCoordinate, BindingRuntimeError> {
    Ok(SignalCoordinate::Operation {
        adapter: adapter_signal_id(opportunity.adapter())?,
        target: target_signal_id(opportunity.target())?,
        operation: SignalId::parse(opportunity.operation().as_str().replace('_', "-"))
            .map_err(BindingRuntimeError::Program)?,
        producer_sequence: opportunity.sequence(),
        suboperation: 0,
    })
}

pub(super) fn adapter_signal_id(adapter: FaultAdapter) -> Result<SignalId, BindingRuntimeError> {
    SignalId::parse(match adapter {
        FaultAdapter::Network => "network",
        FaultAdapter::Storage => "storage",
        FaultAdapter::Node => "node",
    })
    .map_err(BindingRuntimeError::Program)
}

pub(super) fn target_signal_id(
    target: &ResolvedFaultTarget,
) -> Result<SignalId, BindingRuntimeError> {
    let mut material = String::new();
    target.append_canonical(&mut material);
    SignalId::parse(format!(
        "target-{}",
        ContentHash::from_canonical_material("crucible.binding-target.v1", &material).to_hex()
    ))
    .map_err(BindingRuntimeError::Program)
}
