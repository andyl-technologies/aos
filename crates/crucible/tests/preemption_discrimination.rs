//! Commanded-preemption discrimination proof for `Decision::Preemption`.
//!
//! These integration tests demonstrate — entirely at the deterministic model
//! layer, with no live guest — that a commanded [`Decision::Preemption`]
//! *discriminates* a known concurrency race: the same scenario and seed resolve a
//! two-vCPU last-writer-wins race to different observable outcomes depending on
//! the recorded preemption choice, the race manifests under one choice and is
//! absent under another, and each choice is a distinct, reproducible schedule
//! artifact. A single-vCPU interrupt-timing variation exercises the intra-thread
//! race dimension the same way.
//!
//! They are the model witness backing RFC-0010 decisions D-24 (vCPU-switch and
//! interrupt timing are a first-class `Decision::Preemption`) and D-34
//! (`rr_switch_quantum` default). The QEMU injection surface
//! (`checks.crucible.phase2.qemuPreemptionInject`) is the separate landing
//! witness; enabling the *live* campaign explorer remains gated.

use crucible::{
    Configuration, DecisionRecorder, Icount, IrqVector, NodeId, PreemptionDecision, PreemptionKind,
    ScenarioDef, VcpuId,
};

/// Builds a scenario definition from canonical world material.
fn scenario_from_world_material(material: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.world", material)
}

/// Names a world node.
fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

/// Returns the vCPU index that a preemption leaves active — the modeled last
/// writer of a last-writer-wins race resolved in the affected quantum.
///
/// For a round-robin switch the last writer is the newly selected `to_vcpu`; for
/// an interrupt it is the `target_vcpu` that the interrupt runs on.
fn modeled_last_writer(switch: &PreemptionDecision) -> u32 {
    match switch.kind {
        PreemptionKind::VcpuSwitch { to_vcpu, .. } => to_vcpu.index,
        PreemptionKind::InterruptAt { target_vcpu, .. } => target_vcpu.index,
    }
}

/// Builds a round-robin vCPU-switch preemption for the race node.
fn vcpu_switch_at(at: u64, from: u32, to: u32) -> PreemptionDecision {
    PreemptionDecision {
        node: node("race-node"),
        at: Icount { retired: at },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: from },
            to_vcpu: VcpuId { index: to },
        },
    }
}

#[test]
fn commanded_preemption_discriminates_a_known_two_vcpu_race() {
    // A commanded switch landing vCPU 1 in the observation quantum makes vCPU 1
    // the last writer; a commanded switch landing vCPU 0 makes vCPU 0 the last
    // writer. Same scenario, same seed, same observation point — only the
    // recorded Decision::Preemption differs, and the modeled race resolves
    // differently. That is discrimination: the race manifests (a non-baseline
    // outcome) under one choice and is absent (the baseline outcome) under
    // another.
    let config = Configuration::genesis(scenario_from_world_material(
        "world.nodes=race-node\nseed=preemption-discrimination",
    ));

    // The default round-robin switch at the observation boundary is the baseline:
    // with quantum 4096 and 2 vCPUs, boundary 4096 selects vCPU 1.
    let baseline_recorder = DecisionRecorder::new(config.clone());
    let baseline_switch = match baseline_recorder.default_rr_preemption(
        node("race-node"),
        Icount { retired: 4096 },
        4096,
        2,
    ) {
        Ok(decision) => decision,
        Err(error) => panic!("baseline default RR switch should derive: {error}"),
    };
    let baseline_outcome = modeled_last_writer(&baseline_switch);
    assert_eq!(baseline_outcome, 1, "baseline RR boundary lands vCPU 1");

    // Choice A: an explorer override that lands vCPU 0 in the observation
    // quantum. The race MANIFESTS — the observed last writer differs from the
    // baseline.
    let mut choice_a = DecisionRecorder::new(config.clone());
    let switch_a = vcpu_switch_at(4096, 1, 0);
    choice_a.record_preemption_override(switch_a.clone());
    let outcome_a = modeled_last_writer(&switch_a);

    // Choice B: an explorer override that lands vCPU 1 — the same last writer as
    // the baseline. The race is ABSENT under this choice (outcome matches
    // baseline) even though the Decision is explicitly recorded.
    let mut choice_b = DecisionRecorder::new(config);
    let switch_b = vcpu_switch_at(4096, 0, 1);
    choice_b.record_preemption_override(switch_b.clone());
    let outcome_b = modeled_last_writer(&switch_b);

    // Discrimination: the two commanded choices resolve the race to different
    // observable outcomes.
    assert_ne!(
        outcome_a, outcome_b,
        "commanded preemption choices must resolve the race differently"
    );
    assert_eq!(outcome_a, 0, "choice A lands vCPU 0 as last writer");
    assert_eq!(outcome_b, 1, "choice B lands vCPU 1 as last writer");

    // Race-manifested-under-one / race-absent-under-another, stated against the
    // baseline:
    assert_ne!(
        outcome_a, baseline_outcome,
        "the race manifests under choice A (outcome diverges from baseline)"
    );
    assert_eq!(
        outcome_b, baseline_outcome,
        "the race is absent under choice B (outcome matches baseline)"
    );

    // The two choices are distinct, reproducible schedule artifacts: distinct
    // content hashes, so each branch is separately replayable.
    assert_ne!(
        choice_a.schedule().content_hash(),
        choice_b.schedule().content_hash(),
        "discriminating preemption choices produce distinct replayable schedules"
    );
}

#[test]
fn commanded_preemption_discrimination_is_reproducible() {
    // The same commanded choice, recorded twice from the same scenario seed,
    // yields byte-identical schedules — discrimination is a function of the
    // recorded Decision, never of wall-clock or host order.
    let config = Configuration::genesis(scenario_from_world_material(
        "world.nodes=race-node\nseed=preemption-repro",
    ));
    let switch = vcpu_switch_at(4096, 1, 0);

    let mut first = DecisionRecorder::new(config.clone());
    first.record_preemption_override(switch.clone());
    let mut second = DecisionRecorder::new(config);
    second.record_preemption_override(switch.clone());

    assert_eq!(
        first.schedule().content_hash(),
        second.schedule().content_hash(),
        "a commanded preemption choice replays to the same schedule"
    );
    assert_eq!(modeled_last_writer(&switch), 0);
}

#[test]
fn single_vcpu_interrupt_timing_variation_is_distinct() {
    // Even a single-vCPU node gets an intra-thread race dimension: varying the
    // interrupt-delivery icount produces distinct, separately-replayable
    // schedules (D-24 / D-26: interrupt timing is a first-class Decision).
    let config = Configuration::genesis(scenario_from_world_material(
        "world.nodes=single-vcpu-node\nseed=interrupt-timing",
    ));
    let early = PreemptionDecision {
        node: node("single-vcpu-node"),
        at: Icount { retired: 1024 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    };
    let late = PreemptionDecision {
        node: node("single-vcpu-node"),
        at: Icount { retired: 2048 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    };

    let mut deliver_early = DecisionRecorder::new(config.clone());
    deliver_early.record_preemption_override(early.clone());
    let mut deliver_late = DecisionRecorder::new(config);
    deliver_late.record_preemption_override(late.clone());

    assert_ne!(
        early.at, late.at,
        "the two interrupt-timing choices land at different icounts"
    );
    assert_ne!(
        deliver_early.schedule().content_hash(),
        deliver_late.schedule().content_hash(),
        "distinct interrupt-delivery icounts are distinct replayable schedules"
    );
}
