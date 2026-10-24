//! Regression tests for parent-bound preemption reduction.

use super::*;

#[test]
fn bare_swap_cannot_detach_a_preemption_from_its_typed_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = crate::happy_path_scenario()?.scenario.scenario_def();
    let root = Configuration::genesis(scenario);
    let first_config = PreemptionBranchConfig {
        node: NodeId {
            name: String::from("node-a"),
        },
        deadline: SimInstant { ticks: 2 },
        horizon: SimInstant { ticks: 2 },
        step: 1,
        switch_from_vcpu: VcpuId { index: 0 },
        switch_to_vcpu: VcpuId { index: 0 },
        target_vcpu: VcpuId { index: 0 },
        irq: IrqVector { vector: 32 },
    };
    let second_config = PreemptionBranchConfig {
        node: NodeId {
            name: String::from("node-b"),
        },
        ..first_config.clone()
    };
    let first = preemption_branch_choices(&root, &first_config)?
        .1
        .into_iter()
        .next()
        .ok_or("first typed preemption branch")?;
    let second = preemption_branch_choices(&root, &second_config)?
        .1
        .into_iter()
        .next()
        .ok_or("second typed preemption branch")?;
    let (bound, left, right) = if first.decisions()[1].reduction_order_key()
        > second.decisions()[1].reduction_order_key()
    {
        (
            first.decisions()[0].clone(),
            first.decisions()[1].clone(),
            second.decisions()[1].clone(),
        )
    } else {
        (
            second.decisions()[0].clone(),
            second.decisions()[1].clone(),
            first.decisions()[1].clone(),
        )
    };
    let configuration = Configuration {
        def: root.def,
        schedule: Schedule::from_decisions([bound, left.clone(), right.clone()]),
    };
    let policy = PartialOrderReductionPolicy::new().with_independent_pair(&left, &right);

    validate_preemption_branch_schedule(&configuration)?;
    assert!(partial_order_canonical_representative(&configuration, &policy).is_none());
    Ok(())
}
