//! Node-set scheduling regressions for native-VMSTOP guest selectables.

#![cfg(target_os = "linux")]

use crucible::{
    AdvanceOutcome, BackendPhysicalStop, Icount, NodeId, SimulationBackend, VirtualTime,
};
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPendingRequest, SelectablePlanPresence,
};
use crucible_protocol::{SelectableRegister, SelectionReply, SelectionRequest};

use super::super::test_support::hot_fork::{
    QemuTestHotForkOutcome, QemuTestQuantumBoundary, scripted_hot_fork_source_with_script_for_test,
};
use crate::{QemuNode, QemuNodeSet};

#[test]
fn selectable_pause_returns_before_reissue_and_reply_reaches_the_next_choice() {
    let (plan, requests) = scripted_selectable_plan_and_requests(&[2_050, 3_050]);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node.clone(),
        scripted_selectable_source(
            Some(plan),
            requests.clone(),
            [
                QemuTestQuantumBoundary::Paused {
                    at: 2_050,
                    next_deadline: Some(10_000),
                },
                QemuTestQuantumBoundary::Paused {
                    at: 3_050,
                    next_deadline: None,
                },
                QemuTestQuantumBoundary::Reached,
            ],
        ),
    );

    let first = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
        .expect("step to first selectable");
    assert_eq!(first.reached, VirtualTime { ticks: 2_050 });
    assert_eq!(first.physical_stop, BackendPhysicalStop::GuestSelectable);
    assert_eq!(
        first.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 2_050 }
        }
    );
    let parked = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
        .expect("parked selectable retains its physical stop without reissuing the guest quantum");
    assert_eq!(parked.reached, VirtualTime { ticks: 2_050 });
    assert_eq!(parked.physical_stop, BackendPhysicalStop::GuestSelectable);
    assert_eq!(
        parked.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 2_050 }
        }
    );
    assert_eq!(
        SimulationBackend::node_now(&nodes, &node).expect("physical node time"),
        VirtualTime { ticks: 2_050 }
    );
    let first_pending = nodes
        .drain_pending_selectable_requests()
        .expect("drain first selectable");
    assert_eq!(first_pending.len(), 1);
    assert_eq!(first_pending[0].pending(), &requests[0]);
    assert_eq!(first_pending[0].pending().raw_icount(), 40);

    let first_reply =
        SelectionReply::selected(7, [1; 32], [2; 32], vec![1]).expect("first selected reply");
    nodes
        .enqueue_selectable_reply(&first_pending[0], &first_reply)
        .expect("enqueue first reply");

    let second = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
        .expect("step to second selectable");
    assert_eq!(second.reached, VirtualTime { ticks: 3_050 });
    assert_eq!(second.physical_stop, BackendPhysicalStop::GuestSelectable);
    assert_eq!(
        second.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 3_050 }
        }
    );
    let second_pending = nodes
        .drain_pending_selectable_requests()
        .expect("drain second selectable");
    assert_eq!(second_pending.len(), 1);
    assert_eq!(second_pending[0].pending(), &requests[1]);

    let second_reply =
        SelectionReply::selected(8, [3; 32], [4; 32], vec![2]).expect("second selected reply");
    nodes
        .enqueue_selectable_reply(&second_pending[0], &second_reply)
        .expect("enqueue second reply");
    let completed =
        SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
            .expect("step after both replies");
    assert_eq!(completed.reached, VirtualTime { ticks: 5_000 });
    assert_eq!(completed.outcome, AdvanceOutcome::ReachedHorizon);

    shutdown_scripted_nodes(&mut nodes, &[node]);
}

#[test]
fn ordinary_idle_pause_still_reissues_to_the_requested_ceiling() {
    let node = NodeId {
        name: String::from("node-a"),
    };
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node.clone(),
        scripted_selectable_source(
            None,
            [],
            [
                QemuTestQuantumBoundary::Paused {
                    at: 41,
                    next_deadline: Some(60),
                },
                QemuTestQuantumBoundary::Reached,
            ],
        ),
    );

    let observation =
        SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 100 })
            .expect("reissue ordinary idle pause");
    assert_eq!(observation.reached, VirtualTime { ticks: 100 });
    assert_eq!(observation.outcome, AdvanceOutcome::ReachedHorizon);
    assert!(
        nodes
            .drain_pending_selectable_requests()
            .expect("ordinary idle has no selectable")
            .is_empty()
    );

    shutdown_scripted_nodes(&mut nodes, &[node]);
}

#[test]
fn selectable_projection_requires_the_exact_physical_pause_boundary() {
    let (plan, requests) = scripted_selectable_plan_and_requests(&[2_000]);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node.clone(),
        scripted_selectable_source(
            Some(plan),
            requests,
            [QemuTestQuantumBoundary::Paused {
                at: 2_050,
                next_deadline: None,
            }],
        ),
    );

    let error = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
        .expect_err("mismatched selectable boundary must fail closed");
    assert!(
        error
            .to_string()
            .contains("selectable boundary 2000 differs from physical pause 2050")
    );

    shutdown_scripted_nodes(&mut nodes, &[node]);
}

#[test]
fn selectable_at_the_exact_ceiling_is_retained_before_the_fast_path_returns() {
    let (plan, requests) = scripted_selectable_plan_and_requests(&[5_000]);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        node.clone(),
        scripted_selectable_source(
            Some(plan),
            requests.clone(),
            [QemuTestQuantumBoundary::Paused {
                at: 5_000,
                next_deadline: None,
            }],
        ),
    );

    let observation =
        SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_000 })
            .expect("step to exact-ceiling selectable");
    assert_eq!(observation.reached, VirtualTime { ticks: 5_000 });
    assert_eq!(
        observation.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 5_000 }
        }
    );

    let parked = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 5_001 })
        .expect("exact-ceiling selectable retains the original physical stop");
    assert_eq!(parked.reached, VirtualTime { ticks: 5_000 });
    assert_eq!(parked.physical_stop, BackendPhysicalStop::GuestSelectable);
    assert_eq!(
        parked.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 5_000 }
        }
    );
    assert_eq!(
        SimulationBackend::node_now(&nodes, &node).expect("physical node time"),
        VirtualTime { ticks: 5_000 }
    );
    let pending = nodes
        .drain_pending_selectable_requests()
        .expect("drain exact-ceiling selectable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pending(), &requests[0]);

    shutdown_scripted_nodes(&mut nodes, &[node]);
}

#[test]
fn one_nodes_choice_does_not_project_a_peer_step() {
    let first = NodeId {
        name: String::from("node-a"),
    };
    let second = NodeId {
        name: String::from("node-b"),
    };
    let (plan, requests) = scripted_selectable_plan_and_requests(&[2_050]);
    let mut nodes = QemuNodeSet::new();
    nodes.insert(
        first.clone(),
        scripted_selectable_source(
            Some(plan),
            requests,
            [QemuTestQuantumBoundary::Paused {
                at: 2_050,
                next_deadline: None,
            }],
        ),
    );
    nodes.insert(
        second.clone(),
        scripted_selectable_source(
            None,
            [],
            [
                QemuTestQuantumBoundary::Paused {
                    at: 51,
                    next_deadline: Some(60),
                },
                QemuTestQuantumBoundary::Reached,
            ],
        ),
    );

    let first_observation =
        SimulationBackend::step_node_to(&mut nodes, &first, VirtualTime { ticks: 5_000 })
            .expect("step first node to choice");
    assert_eq!(first_observation.reached, VirtualTime { ticks: 2_050 });
    assert_eq!(
        first_observation.physical_stop,
        BackendPhysicalStop::GuestSelectable
    );
    assert_eq!(
        first_observation.outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 2_050 }
        }
    );

    let second_observation =
        SimulationBackend::step_node_to(&mut nodes, &second, VirtualTime { ticks: 5_000 })
            .expect("reissue peer ordinary pause");
    assert_eq!(second_observation.reached, VirtualTime { ticks: 5_000 });
    assert_eq!(second_observation.outcome, AdvanceOutcome::ReachedHorizon);
    assert_eq!(
        SimulationBackend::node_now(&nodes, &first).expect("first node coordinate"),
        VirtualTime { ticks: 2_050 }
    );
    assert_eq!(
        SimulationBackend::node_now(&nodes, &second).expect("second node coordinate"),
        VirtualTime { ticks: 5_000 }
    );

    let pending = nodes
        .drain_pending_selectable_requests()
        .expect("drain selected node request");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].node(), &first);

    shutdown_scripted_nodes(&mut nodes, &[first, second]);
}

fn scripted_selectable_plan_and_requests(
    boundaries: &[u64],
) -> (SelectableCatalogPlan, Vec<SelectablePlanPendingRequest>) {
    let declaration = SelectablePlanDeclaration::new(
        "product.test.selectable",
        vec![1, 2],
        vec![1],
        vec![String::from("test")],
        SelectablePlanPresence::Required,
    )
    .expect("selectable declaration");
    let mut plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 8, 8).expect("selectable limits"),
        vec![declaration],
        SelectablePlanContinuation::cold(),
    )
    .expect("selectable plan");
    let registration = SelectableRegister::new(
        1,
        "product.test.selectable",
        vec![1, 2],
        vec![1],
        vec![String::from("test")],
    )
    .expect("selectable registration");
    plan.apply_registration(&registration)
        .expect("mirror selectable registration");
    plan.apply_freeze().expect("freeze selectable catalog");

    let requests = boundaries
        .iter()
        .enumerate()
        .map(|(index, boundary)| {
            let sequence = u64::try_from(index)
                .expect("test request index")
                .checked_add(7)
                .expect("test request sequence");
            let request = SelectionRequest::new(
                sequence,
                "product.test.selectable",
                format!("instance-{index}"),
                None,
                192,
            )
            .expect("selection request");
            assert_eq!(boundary % 50, 0);
            let trap_raw = boundary / 50 - 1;
            let trap_tick_ps = boundary - 50;
            SelectablePlanPendingRequest::new(request, trap_raw, trap_tick_ps, 0, 0x1000)
        })
        .collect();
    (plan, requests)
}

fn scripted_selectable_source(
    selectable_catalog_plan: Option<SelectableCatalogPlan>,
    deferred_selectable_requests: impl IntoIterator<Item = SelectablePlanPendingRequest>,
    quantum_boundaries: impl IntoIterator<Item = QemuTestQuantumBoundary>,
) -> QemuNode {
    scripted_hot_fork_source_with_script_for_test(
        QemuTestHotForkOutcome::Forked,
        Vec::new(),
        selectable_catalog_plan,
        deferred_selectable_requests.into_iter().collect(),
        quantum_boundaries.into_iter().collect(),
    )
    .expect("scripted selectable source")
}

fn shutdown_scripted_nodes(nodes: &mut QemuNodeSet, node_ids: &[NodeId]) {
    for node in node_ids {
        nodes
            .take(node)
            .expect("scripted node remains installed")
            .shutdown_child()
            .expect("shut down scripted node");
    }
}
