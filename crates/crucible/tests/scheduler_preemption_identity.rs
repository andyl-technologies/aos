//! Checks that scheduler preemption requests participate in scenario identity.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test fixture construction fails loudly.
#![allow(clippy::expect_used)]

use crucible::{
    ExactLocalEvent, Icount, IrqVector, NetworkLookahead, NodeCounter, NodeId, PreemptionDecision,
    PreemptionKind, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration, SimInstant, VcpuId,
};

#[test]
fn preemption_requests_participate_in_configuration_identity() {
    let base = SchedulerLivenessScenario::from_canonical_material(
        "preemption-resolve-identity",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(6),
        )],
        Vec::new(),
    );
    let first = base
        .clone()
        .with_preemption_request(interrupt_preemption("runner", 3, 37));
    let second = base.with_preemption_request(interrupt_preemption("runner", 4, 37));

    assert_ne!(first.configuration, second.configuration);
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn interrupt_preemption(node: &str, at: u64, irq: u32) -> PreemptionDecision {
    PreemptionDecision {
        node: NodeId {
            name: node.to_owned(),
        },
        at: Icount { retired: at },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: irq },
        },
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}
