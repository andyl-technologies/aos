//! One bounded QEMU node fault for the portable finding inspection flight.

use std::collections::BTreeSet;
use std::error::Error;

use crucible_core::model::{
    BindingMapping, BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy,
    CpuServiceDiscipline, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, ExactRatio, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
    FaultSignalPlan, NodeEffectSpecification, PositiveU64, ResolvedFaultTarget, ResolvedTargetSet,
    SampleObservation, SignalDomain, SignalNode, SignalNodeKind, SignalProgram,
    SignalResourceLimits, SignalShape, SignalUnit, SignalValue, SignalValueType, TargetSelector,
    World,
};

/// Binding identity required in the copied archive's effect trace.
pub(crate) const BINDING: &str = "finding-cpu-service-fault";

/// Authors a persistent QEMU CPU-service fault that still lets the guest reply.
pub(super) fn cpu_service_fault(world: &World) -> Result<FaultSignalPlan, Box<dyn Error>> {
    let node = world
        .vm_nodes()
        .first()
        .ok_or("signal-rich finding has no guest node")?;
    let output = crucible_core::model::SignalId::parse("finding-cpu-service-enabled")?;
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)?,
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(true),
            },
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )?;
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::Node {
            node: FaultObjectId::parse(&node.id.name)?,
        }],
        false,
    )?;
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Node(NodeEffectSpecification::CpuService {
            vcpus: vec![0],
            capacity: ExactRatio::new(3, 4)?,
            quantum_instructions: PositiveU64::new("quantum_instructions", 64)?,
            service_rule: CpuServiceDiscipline::StrictCap,
        }),
    )?;
    let binding = FaultBinding::new(
        FaultObjectId::parse(BINDING)?,
        vec![output],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target),
        BTreeSet::from([FaultPhase::Run]),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )?;
    Ok(FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits::default(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_core::model::{
        Icount, NodeId, Plan, ReadyPoint, VmArchitecture, WhiteBoxPolicy, WorldNode,
    };

    #[test]
    fn cpu_service_binding_is_admitted_for_the_packaged_guest() -> Result<(), Box<dyn Error>> {
        let world = World::from_nodes_and_links(
            vec![WorldNode {
                id: NodeId {
                    name: String::from("choice-node"),
                },
                arch: VmArchitecture::X86_64,
                memory_mib: 128,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 0 },
                },
                white_box: WhiteBoxPolicy::Enabled,
                smp_vcpus: 1,
                icount_shift: 0,
                kernel: None,
                root_image: None,
                initrd: None,
            }],
            Vec::new(),
        )?;
        let plan =
            Plan::empty().with_fault_signals_for_world(&world, cpu_service_fault(&world)?)?;
        assert_eq!(plan.fault_signals().bindings().len(), 1);
        Ok(())
    }
}
