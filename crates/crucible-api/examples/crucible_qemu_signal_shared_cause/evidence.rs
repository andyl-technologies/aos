//! Exact shared-event resolved-effect evidence checks.

use super::*;

fn effect_count(snapshot: &ProductionFaultEvidenceSnapshot) -> usize {
    snapshot.resolved_effect_trace.as_ref().map_or(0, |trace| {
        trace.work_items.iter().map(|item| item.records.len()).sum()
    })
}

pub(super) fn reached_restarted_node(snapshot: &ProductionFaultEvidenceSnapshot) -> bool {
    snapshot.frontier.ticks >= EVENT_NANOS
        && snapshot
            .nodes
            .iter()
            .any(|node| node.node.name == "node-a" && node.generation > 1)
}

pub(super) fn exact_shared_event_effects(
    before: &ProductionFaultEvidenceSnapshot,
    after: &ProductionFaultEvidenceSnapshot,
) -> bool {
    const EXPECTED: [(&str, EffectKind); 3] = [
        (
            "shared-power-forwarder",
            EffectKind::NetworkForwarderLifecycle,
        ),
        ("shared-power-storage", EffectKind::StorageVolatileCacheLoss),
        ("shared-power-node", EffectKind::NodeLifecycle),
    ];
    let before_shared = before
        .resolved_effect_trace
        .as_ref()
        .into_iter()
        .flat_map(|trace| &trace.work_items)
        .flat_map(|item| &item.records)
        .filter(|record| {
            EXPECTED
                .iter()
                .any(|(binding, _effect)| record.binding.as_str() == *binding)
        })
        .count();
    let Some(trace) = after.resolved_effect_trace.as_ref() else {
        return false;
    };
    let mut matching_items = trace.work_items.iter().filter(|item| {
        item.records.iter().any(|record| {
            EXPECTED
                .iter()
                .any(|(binding, _effect)| record.binding.as_str() == *binding)
        })
    });
    let Some(item) = matching_items.next() else {
        return false;
    };
    if matching_items.next().is_some()
        || before_shared != 0
        || effect_count(after) != effect_count(before) + EXPECTED.len()
        || item.coordinate.virtual_nanos != EVENT_NANOS
        || item.coordinate.retired_instructions.is_some()
        || item.opportunity.is_some()
        || item.records.len() != EXPECTED.len()
    {
        return false;
    }
    EXPECTED.iter().all(|(binding, effect)| {
        item.records.iter().any(|record| {
            record.binding.as_str() == *binding
                && record.effect == *effect
                && record.action_kind == BindingActionKind::Apply
                && record.phase == FaultPhase::Boundary
                && record.lifetime == EffectLifetime::Impulse
                && record.coordinate.virtual_nanos == EVENT_NANOS
                && record.same_coordinate_sequence == item.same_coordinate_sequence
                && record.transition_sequence == 1
                && record.derivation_fingerprint == item.derivation_fingerprint
                && record.cause == BindingActionCause::Signal
                && if *effect == EffectKind::NodeLifecycle {
                    record.coordinate.retired_instructions.is_some()
                } else {
                    record.coordinate.retired_instructions.is_none()
                }
        })
    })
}

pub(super) fn exact_terminal_matrix(
    before: &ProductionFaultEvidenceSnapshot,
    after: &ProductionFaultEvidenceSnapshot,
) -> bool {
    let Some(before_power_off) = before.nodes.iter().find(|node| node.node.name == "node-a") else {
        return false;
    };
    let Some(before_permanent) = before.nodes.iter().find(|node| node.node.name == "node-b") else {
        return false;
    };
    let Some(power_off) = after.nodes.iter().find(|node| node.node.name == "node-a") else {
        return false;
    };
    let Some(permanent) = after.nodes.iter().find(|node| node.node.name == "node-b") else {
        return false;
    };
    if before_power_off.service_state != "running"
        || before_power_off.scheduler_activity != SchedulerNodeActivity::Runnable
        || !before_power_off.backend_owned
        || before_power_off.process_ownership != "exact"
        || before_permanent.service_state != "running"
        || before_permanent.scheduler_activity != SchedulerNodeActivity::Runnable
        || !before_permanent.backend_owned
        || before_permanent.process_ownership != "exact"
        || power_off.generation != before_power_off.generation + 1
        || power_off.service_state != "powered_off"
        || power_off.scheduler_activity != SchedulerNodeActivity::Halted
        || !power_off.backend_owned
        || power_off.process_ownership != "exact"
        || permanent.generation != before_permanent.generation
        || permanent.service_state != "permanently_failed"
        || permanent.scheduler_activity != SchedulerNodeActivity::Done
        || permanent.backend_owned
        || permanent.process_ownership != "absent"
    {
        return false;
    }

    const EXPECTED: [(&str, NodeLifecycleTransition); 2] = [
        (
            "terminal-matrix-power-off",
            NodeLifecycleTransition::PowerOff,
        ),
        (
            "terminal-matrix-permanent-failure",
            NodeLifecycleTransition::PermanentFailure,
        ),
    ];
    let before_terminal = before
        .resolved_effect_trace
        .as_ref()
        .into_iter()
        .flat_map(|trace| &trace.work_items)
        .flat_map(|item| &item.records)
        .filter(|record| {
            EXPECTED
                .iter()
                .any(|(binding, _)| record.binding.as_str() == *binding)
        })
        .count();
    let Some(trace) = after.resolved_effect_trace.as_ref() else {
        return false;
    };
    let mut matching_items = trace.work_items.iter().filter(|item| {
        item.records.iter().any(|record| {
            EXPECTED
                .iter()
                .any(|(binding, _)| record.binding.as_str() == *binding)
        })
    });
    let Some(item) = matching_items.next() else {
        return false;
    };
    if matching_items.next().is_some()
        || before_terminal != 0
        || effect_count(after) != effect_count(before) + EXPECTED.len()
        || item.coordinate.virtual_nanos != TERMINAL_MATRIX_EVENT_NANOS
        || item.coordinate.retired_instructions.is_some()
        || item.opportunity.is_some()
        || item.records.len() != EXPECTED.len()
    {
        return false;
    }
    EXPECTED.iter().all(|(binding, transition)| {
        item.records.iter().any(|record| {
            record.binding.as_str() == *binding
                && record.effect == EffectKind::NodeLifecycle
                && record.action_kind == BindingActionKind::Apply
                && record.phase == FaultPhase::Boundary
                && record.lifetime == EffectLifetime::Impulse
                && record.coordinate.virtual_nanos == TERMINAL_MATRIX_EVENT_NANOS
                && record.coordinate.retired_instructions.is_some()
                && record.same_coordinate_sequence == item.same_coordinate_sequence
                && record.transition_sequence == 1
                && record.derivation_fingerprint == item.derivation_fingerprint
                && record.cause == BindingActionCause::Signal
                && matches!(
                    record.request.specification(),
                    EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
                        transition: actual,
                        ..
                    }) if *actual == *transition
                )
        })
    })
}
