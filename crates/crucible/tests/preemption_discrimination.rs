//! Typed commanded-preemption discrimination proofs.

use crucible::{
    Configuration, Decision, DecisionRecorder, Icount, IrqVector, NodeId, PreemptionBranchConfig,
    PreemptionDecision, PreemptionKind, ScenarioDef, SearchFrontierChoice, SimInstant, VcpuId,
    preemption_branch_choices, try_step,
};

fn scenario_from_world_material(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.world", material)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn modeled_last_writer(choice: &SearchFrontierChoice) -> u32 {
    let Some(Decision::Preemption(preemption)) = choice.decisions().last() else {
        panic!("typed preemption choice must end in causal preemption evidence");
    };
    match preemption.kind {
        PreemptionKind::VcpuSwitch { to_vcpu, .. } => to_vcpu.index,
        PreemptionKind::InterruptAt { target_vcpu, .. } => target_vcpu.index,
    }
}

fn selected_configuration(parent: &Configuration, choice: &SearchFrontierChoice) -> Configuration {
    choice
        .decisions()
        .iter()
        .cloned()
        .try_fold(parent.clone(), |configuration, decision| {
            try_step(&configuration, decision)
        })
        .unwrap_or_else(|error| panic!("typed preemption branch should apply: {error}"))
}

fn choices(
    parent: &Configuration,
    node_name: &str,
    deadline: u64,
    horizon: u64,
) -> Vec<SearchFrontierChoice> {
    let (_, choices) = preemption_branch_choices(
        parent,
        &PreemptionBranchConfig {
            node: node(node_name),
            deadline: SimInstant { ticks: deadline },
            horizon: SimInstant { ticks: horizon },
            step: 1024,
            switch_from_vcpu: VcpuId { index: 1 },
            switch_to_vcpu: VcpuId { index: 0 },
            target_vcpu: VcpuId { index: 1 },
            irq: IrqVector { vector: 32 },
        },
    )
    .unwrap_or_else(|error| panic!("typed preemption choices should build: {error}"));
    choices
}

#[test]
fn commanded_preemption_discriminates_a_known_two_vcpu_race() {
    let parent = Configuration::genesis(scenario_from_world_material(
        "world.nodes=race-node\nseed=preemption-discrimination",
    ));
    let baseline = DecisionRecorder::new(parent.clone())
        .default_rr_preemption(node("race-node"), Icount { retired: 4096 }, 4096, 2)
        .unwrap_or_else(|error| panic!("baseline preemption should derive: {error}"));
    let branches = choices(&parent, "race-node", 4096, 4096);
    let [switch, interrupt] = branches.as_slice() else {
        panic!("one boundary must produce switch and interrupt alternatives");
    };

    assert_eq!(modeled_last_writer(switch), 0);
    assert_eq!(modeled_last_writer(interrupt), 1);
    assert_eq!(
        match baseline.kind {
            PreemptionKind::VcpuSwitch { to_vcpu, .. } => to_vcpu.index,
            PreemptionKind::InterruptAt { target_vcpu, .. } => target_vcpu.index,
        },
        1
    );
    assert_ne!(
        selected_configuration(&parent, switch).id(),
        selected_configuration(&parent, interrupt).id()
    );
}

#[test]
fn commanded_preemption_discrimination_is_reproducible() {
    let parent = Configuration::genesis(scenario_from_world_material(
        "world.nodes=race-node\nseed=preemption-repro",
    ));
    let first = choices(&parent, "race-node", 4096, 4096);
    let second = choices(&parent, "race-node", 4096, 4096);

    assert_eq!(first, second);
    assert_eq!(
        selected_configuration(&parent, &first[0]).id(),
        selected_configuration(&parent, &second[0]).id()
    );
}

#[test]
fn single_vcpu_interrupt_timing_variation_is_distinct() {
    let parent = Configuration::genesis(scenario_from_world_material(
        "world.nodes=single-vcpu-node\nseed=interrupt-timing",
    ));
    let branches = choices(&parent, "single-vcpu-node", 1024, 2048);
    let early = &branches[1];
    let late = &branches[3];

    assert!(matches!(
        early.decisions().last(),
        Some(Decision::Preemption(PreemptionDecision {
            at: SimInstant { ticks: 1024 },
            ..
        }))
    ));
    assert!(matches!(
        late.decisions().last(),
        Some(Decision::Preemption(PreemptionDecision {
            at: SimInstant { ticks: 2048 },
            ..
        }))
    ));
    assert_ne!(
        selected_configuration(&parent, early).id(),
        selected_configuration(&parent, late).id()
    );
}
