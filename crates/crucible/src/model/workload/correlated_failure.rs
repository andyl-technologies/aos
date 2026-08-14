//! Correlated-failure workload campaign bindings.

use super::*;

pub(super) fn correlated_failure_binding(
    node: &str,
    event: &SignalId,
    program: &SignalProgram,
) -> Result<FaultBinding, EngineError> {
    let node = FaultObjectId::parse(node).map_err(workload_fault_model_error)?;
    let binding = FaultObjectId::parse(&format!("correlated-outage-{node}"))
        .map_err(workload_fault_model_error)?;
    let target = ResolvedTargetSet::new(vec![ResolvedFaultTarget::Node { node }], false)
        .map_err(workload_fault_model_error)?;
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Impulse,
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Crash,
            downtime_nanos: 1_000_000_000,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Clear,
        }),
    )
    .map_err(workload_fault_model_error)?;

    FaultBinding::new(
        binding,
        vec![event.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target),
        [FaultPhase::Boundary].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        program,
    )
    .map_err(workload_fault_model_error)
}

pub(super) fn workload_fault_model_error(error: impl std::fmt::Display) -> EngineError {
    scenario_serialization_error(format!(
        "workload fault campaign validation failed: {error}"
    ))
}
