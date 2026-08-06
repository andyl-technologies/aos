//! Assertion divergence, evidence extraction, formal trace export, and guest markers.

use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CausalEventLogPrefixDivergence {
    pub(super) expected_last_matching_event_prefix_len: usize,
    pub(super) expected_first_different_event_prefix_len: usize,
    pub(super) reproduced_first_different_event_prefix_len: usize,
}

impl CausalEventLogPrefixDivergence {
    pub(super) fn terminal(
        expected_log: &RecordedAssertionLog,
        reproduced_log: &RecordedAssertionLog,
    ) -> Self {
        Self {
            expected_last_matching_event_prefix_len: expected_log.entries().len(),
            expected_first_different_event_prefix_len: expected_log.entries().len(),
            reproduced_first_different_event_prefix_len: reproduced_log.entries().len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProjectedCausalEventLogEntry<'log> {
    raw_index: usize,
    entry: &'log SchedulerEventLogEntry,
}

impl<'log> ProjectedCausalEventLogEntry<'log> {
    fn raw_prefix_len(self) -> usize {
        self.raw_index.saturating_add(1)
    }
}

pub(super) fn first_different_assertion_replay_prefix(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> CausalEventLogPrefixDivergence {
    let expected = event_log_causal_projection(expected_log.entries());
    let reproduced = event_log_causal_projection(reproduced_log.entries());
    let max_len = expected.len().max(reproduced.len());
    if max_len == 0 {
        return CausalEventLogPrefixDivergence::terminal(expected_log, reproduced_log);
    }
    let mut low = 0;
    let mut high = max_len;
    while low < high {
        let middle = low + (high - low) / 2;
        if event_log_causal_projection_prefixes_match(&expected, &reproduced, middle) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    CausalEventLogPrefixDivergence {
        expected_last_matching_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &expected,
            low.saturating_sub(1),
            expected_log.entries().len(),
        ),
        expected_first_different_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &expected,
            low,
            expected_log.entries().len(),
        ),
        reproduced_first_different_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &reproduced,
            low,
            reproduced_log.entries().len(),
        ),
    }
}

pub(super) fn event_log_causal_projection(
    entries: &[SchedulerEventLogEntry],
) -> Vec<ProjectedCausalEventLogEntry<'_>> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(raw_index, entry)| {
            (entry.class() == SchedulerEventLogClass::Causal)
                .then_some(ProjectedCausalEventLogEntry { raw_index, entry })
        })
        .collect()
}

pub(super) fn event_log_raw_prefix_for_causal_prefix(
    projection: &[ProjectedCausalEventLogEntry<'_>],
    causal_prefix_len: usize,
    total_entries: usize,
) -> usize {
    if causal_prefix_len == 0 {
        return 0;
    }
    projection
        .get(causal_prefix_len - 1)
        .map(|entry| entry.raw_prefix_len())
        .unwrap_or_else(|| total_entries.saturating_add(1))
}

pub(super) fn event_log_causal_projection_prefixes_match(
    expected: &[ProjectedCausalEventLogEntry<'_>],
    reproduced: &[ProjectedCausalEventLogEntry<'_>],
    causal_prefix_len: usize,
) -> bool {
    let Some(expected_entries) = expected.get(..causal_prefix_len) else {
        return false;
    };
    let Some(reproduced_entries) = reproduced.get(..causal_prefix_len) else {
        return false;
    };
    let expected_entries = expected_entries
        .iter()
        .map(|entry| entry.entry.clone())
        .collect::<Vec<_>>();
    let reproduced_entries = reproduced_entries
        .iter()
        .map(|entry| entry.entry.clone())
        .collect::<Vec<_>>();
    compare_event_log_determinism(&expected_entries, &reproduced_entries).passes()
}

pub(super) fn event_log_causal_projections_match(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) -> bool {
    compare_event_log_determinism(expected, reproduced).passes()
}

pub(super) fn assertion_replay_report_for_prefix(
    artifact: ContentHash,
    properties: &Properties,
    world: &World,
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
    let prefix_len = prefix_len.min(recorded_log.entries().len());
    let prefix_log =
        RecordedAssertionLog::from_entries(recorded_log.entries()[..prefix_len].to_vec());
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(world)
        .check_run(properties, prefix_log.entries())?;
    Ok(host_assertion_report_with_reproduction_artifact(
        report, artifact,
    ))
}

pub(super) fn first_differing_violation(
    expected: &[HostAssertionViolation],
    reproduced: &[HostAssertionViolation],
) -> Option<(
    Option<HostAssertionViolation>,
    Option<HostAssertionViolation>,
)> {
    let max_len = expected.len().max(reproduced.len());
    (0..max_len).find_map(|index| {
        let expected = expected.get(index).cloned();
        let reproduced = reproduced.get(index).cloned();
        (expected != reproduced).then_some((expected, reproduced))
    })
}

pub(super) fn first_different_decision_prefix_len(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> Option<usize> {
    let expected = scheduler_decisions(expected_log);
    let reproduced = scheduler_decisions(reproduced_log);
    let max_len = expected.len().max(reproduced.len());
    (0..max_len).find_map(|index| {
        let expected = expected.get(index);
        let reproduced = reproduced.get(index);
        (expected != reproduced).then_some(index + 1)
    })
}

pub(super) fn scheduler_decisions(recorded_log: &RecordedAssertionLog) -> Vec<Decision> {
    recorded_log
        .entries()
        .iter()
        .filter_map(|entry| match entry.payload() {
            SchedulerEventLogPayload::Decision(decision) => Some(decision.clone()),
            SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Observable(_)
            | SchedulerEventLogPayload::EvaluationBoundary(_)
            | SchedulerEventLogPayload::TriggerFired(_)
            | SchedulerEventLogPayload::TriggerActionApplied(_)
            | SchedulerEventLogPayload::FaultObservation(_)
            | SchedulerEventLogPayload::Diagnostic(_) => None,
        })
        .collect()
}

pub(super) fn engine_error_message(error: &EngineError) -> String {
    error.to_string()
}

pub(super) fn observable_event_violation_site(
    event: &ObservableEvent,
) -> Option<(Option<Icount>, Option<NodeId>)> {
    match event.payload() {
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        } => Some((Some(*execution_icount), Some(node.clone()))),
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => Some((Some(*sample_icount), Some(node.clone()))),
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            ..
        } => Some((Some(*retired_icount), Some(node.clone()))),
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => Some((None, Some(node.clone()))),
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => None,
    }
}

pub(super) fn observable_event_evidence(
    event: &ObservableEvent,
    observed: impl Into<String>,
) -> HostAssertionViolationEvidence {
    let (at_icount, node) = observable_event_violation_site(event).unwrap_or((None, None));
    HostAssertionViolationEvidence {
        at_icount: at_icount.or(Some(Icount {
            retired: event.at().ticks,
        })),
        node,
        observed: observed.into(),
    }
}

pub(super) fn evaluation_point_evidence(
    point: EventEvaluationPoint,
    observed: impl Into<String>,
) -> HostAssertionViolationEvidence {
    HostAssertionViolationEvidence {
        at_icount: Some(Icount {
            retired: point.at().ticks,
        }),
        node: None,
        observed: observed.into(),
    }
}

pub(super) fn outcome_point_evidence(
    prefix: &ConditionEventLogPrefix,
    outcome: &HostAssertionOutcome,
) -> HostAssertionViolationEvidence {
    evaluation_point_evidence(
        EventEvaluationPoint::assertion_deadline(outcome.at),
        format!(
            "assertion outcome reason=\"{}\" entries={}",
            outcome.reason,
            prefix.scheduler_entries.len()
        ),
    )
}

pub(super) fn violation_detail(
    outcome: &HostAssertionOutcome,
    evidence: &HostAssertionViolationEvidence,
) -> String {
    format!(
        "expected={}; observed={}; reason={}",
        violation_expectation(outcome),
        evidence.observed,
        outcome.reason
    )
}

pub(super) fn violation_expectation(outcome: &HostAssertionOutcome) -> &'static str {
    match (outcome.quantifier, outcome.kind) {
        (AssertionQuantifierKind::Always, _) => "always predicate remains true",
        (AssertionQuantifierKind::Sometimes, _) => "sometimes predicate becomes true",
        (AssertionQuantifierKind::Eventually, _) => "eventually property satisfies before deadline",
        (AssertionQuantifierKind::AfterQuiescence, _) => {
            "after-quiescence predicate is true at terminal quiescence"
        }
        (AssertionQuantifierKind::Reachable, HostAssertionOutcomeKind::NeverReachedFail) => {
            "reachable predicate is reached"
        }
        (AssertionQuantifierKind::Reachable, _) => "unreachable predicate remains unreached",
        (AssertionQuantifierKind::GuestAlways, _) => "guest always marker remains true",
        (AssertionQuantifierKind::GuestSometimes, _) => "guest sometimes marker becomes true",
        (AssertionQuantifierKind::GuestReachable, HostAssertionOutcomeKind::NeverReachedFail) => {
            "guest reachable marker is reached"
        }
        (AssertionQuantifierKind::GuestReachable, _) => "guest reachable marker remains consistent",
        (AssertionQuantifierKind::GuestUnreachable, _) => "guest unreachable marker remains false",
    }
}

pub(super) fn assertion_reproduction_artifact_from_prefix(
    prefix: &ConditionEventLogPrefix,
) -> ContentHash {
    ContentHash::from_bytes(&external_formal_trace_bytes(&prefix.scheduler_entries))
}

pub(super) fn condition_violation_evidence(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> HostAssertionViolationEvidence {
    condition_violation_evidence_at(
        prefix,
        prefix.point(),
        condition,
        actual,
        white_box_policies,
    )
}

pub(super) fn condition_violation_evidence_at(
    prefix: &ConditionEventLogPrefix,
    point: EventEvaluationPoint,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> HostAssertionViolationEvidence {
    let scoped_prefix = condition_prefix_for_evidence_at(prefix, point);
    condition_observed_evidence(&scoped_prefix, condition, actual, white_box_policies)
        .unwrap_or_else(|| {
            evaluation_point_evidence(
                point,
                format!(
                    "predicate {} at virtual_time={} entries={}",
                    bool_observed_label(actual),
                    point.at().ticks,
                    scoped_prefix.scheduler_entries.len()
                ),
            )
        })
}

pub(super) fn condition_prefix_for_evidence_at(
    prefix: &ConditionEventLogPrefix,
    point: EventEvaluationPoint,
) -> ConditionEventLogPrefix {
    let through = point.at().ticks;
    let entries = prefix
        .scheduler_entries
        .iter()
        .take_while(|entry| entry.at().ticks <= through)
        .cloned()
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return ConditionEventLogPrefix::genesis().with_point(point);
    }
    ConditionEventLogPrefix::from_scheduler_event_log_entries(entries)
        .map(|prefix| prefix.with_point(point))
        .unwrap_or_else(|_| prefix.clone().with_point(point))
}

pub(super) fn condition_observed_evidence(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Option<HostAssertionViolationEvidence> {
    match condition {
        Condition::Not { predicate } => {
            let mut evidence =
                condition_observed_evidence(prefix, predicate, !actual, white_box_policies)?;
            evidence.observed = format!("not predicate was {actual}; inner {}", evidence.observed);
            Some(evidence)
        }
        Condition::AllOf { predicates } => {
            let predicate = predicates.iter().find(|predicate| {
                logged_condition_truth(prefix, predicate, white_box_policies) == actual
            })?;
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::AnyOf { predicates } => {
            let predicate = predicates.iter().find(|predicate| {
                logged_condition_truth(prefix, predicate, white_box_policies) == actual
            })?;
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::Once { predicate } => {
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::NetworkMatch { link, predicate } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && network_event_matches(event.payload(), link.as_ref(), predicate)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "network frame matched link={} payload_event",
                        optional_link_label(link.as_ref())
                    ),
                )
            }),
        Condition::ConsoleMatch { node, regex } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && matches!(
                        event.payload(),
                        ObservableEventPayload::ConsoleOutput {
                            node: observed_node,
                            ..
                        } if observed_node == node
                    )
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "console output on node={} matched regex={}",
                        node.name, regex.pattern
                    ),
                )
            }),
        Condition::CoveragePoint { node, point } if actual => {
            let resolved = match point {
                CodePoint::GuestAddress { address } => {
                    Some(ResolvedCodePoint::guest_address(*address))
                }
                CodePoint::Symbol { .. } => None,
            }?;
            prefix
                .observable_events()
                .iter()
                .find(|event| {
                    event.at() == prefix.point().at()
                        && coverage_event_matches(event.payload(), node, resolved)
                })
                .map(|event| {
                    observable_event_evidence(
                        event,
                        format!(
                            "coverage point node={} address={}",
                            node.name,
                            resolved.address()
                        ),
                    )
                })
        }
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } if actual => {
            let resolved = resolved_mem_place_for_evidence(place)?;
            prefix
                .observable_events()
                .iter()
                .find(|event| {
                    event.at() == prefix.point().at()
                        && memory_event_matches(event.payload(), node, &resolved, *cmp, *value)
                })
                .map(|event| {
                    observable_event_evidence(
                        event,
                        format!(
                            "memory predicate node={} place={} cmp={} expected={}",
                            node.name,
                            resolved_mem_place_label(&resolved),
                            memory_cmp_label(*cmp),
                            value
                        ),
                    )
                })
        }
        Condition::IoPattern { node, kind } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at() && io_event_matches(event.payload(), node, *kind)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "io completion node={} kind={}",
                        node.name,
                        io_kind_label(*kind)
                    ),
                )
            }),
        Condition::NodeState { node, state } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && node_state_event_matches(event.payload(), node, *state)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "node state node={} state={}",
                        node.name,
                        external_node_lifecycle_label(*state)
                    ),
                )
            }),
        Condition::AssertionState { name, state } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && assertion_state_event_matches(event.payload(), name, *state)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "assertion state assertion={} state={}",
                        name.name,
                        external_assertion_phase_label(*state)
                    ),
                )
            }),
        Condition::GuestMarker { marker } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && guest_marker_event_matches_policies(
                        event.payload(),
                        marker,
                        white_box_policies,
                    )
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!("guest marker marker={} matched", marker.name),
                )
            }),
        Condition::Named { name, nodes } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "named predicate name={} nodes={} returned {}",
                name,
                nodes.len(),
                actual
            ),
        )),
        Condition::At { at } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "time predicate expected={} actual={} returned {}",
                at.ticks,
                prefix.point().at().ticks,
                actual
            ),
        )),
        Condition::After { duration, of } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "after predicate event={} duration={} returned {}",
                of.name, duration.nanos, actual
            ),
        )),
        Condition::Timer { name } => Some(evaluation_point_evidence(
            prefix.point(),
            format!("timer predicate name={} returned {}", name.name, actual),
        )),
        Condition::Quiescent => Some(evaluation_point_evidence(
            prefix.point(),
            format!("quiescence predicate returned {actual}"),
        )),
        Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::GuestMarker { .. } => Some(evaluation_point_evidence(
            prefix.point(),
            false_observed_condition_summary(condition, prefix.point().at()),
        )),
    }
}

pub(super) fn logged_condition_truth(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool {
    let mut evaluation = ConditionEvaluation::from_log_prefix(prefix.clone(), false_condition_leaf)
        .with_white_box_policies(white_box_policies.clone());
    evaluation.evaluate_condition(condition)
}

pub(super) fn false_condition_leaf(_leaf: ConditionLeaf<'_>) -> bool {
    false
}

pub(super) fn guest_marker_event_matches_policies(
    event: &ObservableEventPayload,
    expected_marker: &MarkerId,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool {
    match event {
        ObservableEventPayload::GuestMarker { node, marker, .. } => {
            marker == expected_marker
                && white_box_policies.get(node) == Some(&WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. }
        | ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => false,
    }
}

pub(super) fn resolved_mem_place_for_evidence(place: &MemPlace) -> Option<ResolvedMemPlace> {
    match place {
        MemPlace::PhysicalAddress { address, width } => {
            Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
        }
        MemPlace::Register { name, width } => {
            Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
        }
        MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => None,
    }
}

pub(super) fn false_observed_condition_summary(condition: &Condition, at: VirtualTime) -> String {
    match condition {
        Condition::NetworkMatch { .. } => {
            format!("no matching network frame at virtual_time={}", at.ticks)
        }
        Condition::ConsoleMatch { node, regex } => format!(
            "no console output match node={} regex={} at virtual_time={}",
            node.name, regex.pattern, at.ticks
        ),
        Condition::CoveragePoint { node, .. } => format!(
            "no matching coverage point node={} at virtual_time={}",
            node.name, at.ticks
        ),
        Condition::MemoryPredicate { node, .. } => format!(
            "no matching memory sample node={} at virtual_time={}",
            node.name, at.ticks
        ),
        Condition::IoPattern { node, kind } => format!(
            "no matching io completion node={} kind={} at virtual_time={}",
            node.name,
            io_kind_label(*kind),
            at.ticks
        ),
        Condition::NodeState { node, state } => format!(
            "no node state node={} state={} at virtual_time={}",
            node.name,
            external_node_lifecycle_label(*state),
            at.ticks
        ),
        Condition::AssertionState { name, state } => format!(
            "no assertion state assertion={} state={} at virtual_time={}",
            name.name,
            external_assertion_phase_label(*state),
            at.ticks
        ),
        Condition::GuestMarker { marker } => format!(
            "no guest marker marker={} at virtual_time={}",
            marker.name, at.ticks
        ),
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::AllOf { .. }
        | Condition::AnyOf { .. }
        | Condition::Once { .. }
        | Condition::Not { .. } => {
            format!("predicate was false at virtual_time={}", at.ticks)
        }
    }
}

pub(super) fn guest_assertion_marker_event_evidence(
    event: &ObservableEvent,
    marker: &GuestAssertionMarker,
) -> HostAssertionViolationEvidence {
    observable_event_evidence(
        event,
        format!(
            "guest assertion marker id={} kind={} condition={} location={} details={}",
            marker.id.name,
            external_guest_assertion_kind_label(marker.kind),
            marker.condition,
            marker.location,
            details_reason(&marker.details)
        ),
    )
}

pub(super) fn guest_assertion_state_evidence(
    state: &GuestMarkerAssertionState,
    at: VirtualTime,
) -> HostAssertionViolationEvidence {
    HostAssertionViolationEvidence {
        at_icount: state.last_icount.or(Some(Icount { retired: at.ticks })),
        node: state.last_node.clone(),
        observed: format!(
            "guest assertion marker id={} kind={} observed_true={} location={} details={}",
            state.id.name,
            external_guest_assertion_kind_label(state.kind),
            state.observed_true,
            state.location,
            details_reason(&state.details)
        ),
    }
}

pub(super) fn bool_observed_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub(super) fn optional_link_label(link: Option<&LinkId>) -> String {
    link.map(|link| link.name.clone())
        .unwrap_or_else(|| String::from("*"))
}

pub(super) fn resolved_mem_place_label(place: &ResolvedMemPlace) -> String {
    match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            format!("physical:{address}:{bytes}")
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            format!("virtual:{address}:{bytes}")
        }
        ResolvedMemPlace::Register { name, bytes } => format!("register:{name}:{bytes}"),
    }
}

pub(super) fn memory_cmp_label(cmp: MemoryCmp) -> &'static str {
    match cmp {
        MemoryCmp::Eq => "eq",
        MemoryCmp::Ne => "ne",
        MemoryCmp::Lt => "lt",
        MemoryCmp::Le => "le",
        MemoryCmp::Gt => "gt",
        MemoryCmp::Ge => "ge",
    }
}

pub(super) fn io_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "9p",
        IoEventKind::Network => "network",
    }
}

pub(super) fn eventually_deadline(triggered_at: VirtualTime, deadline: VirtualTime) -> VirtualTime {
    VirtualTime {
        ticks: triggered_at.ticks.saturating_add(deadline.ticks),
    }
}

pub(super) fn condition_prefix_from_recorded_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<ConditionEventLogPrefix, ConditionEvaluationError> {
    if entries.is_empty() {
        Ok(ConditionEventLogPrefix::genesis())
    } else {
        ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec())
    }
}

pub(super) fn validate_recorded_event_log_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<(), ConditionEvaluationError> {
    if entries.is_empty() {
        return Ok(());
    }
    ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec()).map(|_| ())
}

pub(super) fn external_formal_trace_bytes(entries: &[SchedulerEventLogEntry]) -> Vec<u8> {
    let previous_prefix = scheduler_event_log_empty_prefix();
    let mut lines = Vec::new();
    lines.push(String::from("format=crucible.external-formal-trace.v1"));
    lines.push(format!(
        "scheduler_event_log_previous_prefix={}",
        previous_prefix.to_hex()
    ));
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        lines.push(external_formal_trace_entry_material(entry));
    }
    lines.join("\n").into_bytes()
}

pub(super) fn external_formal_trace_entry_material(entry: &SchedulerEventLogEntry) -> String {
    let mut lines = Vec::new();
    lines.push(String::from("entry_begin"));
    lines.push(format!("entry.sequence={}", entry.sequence()));
    lines.push(format!("entry.at_ticks={}", entry.at().ticks));
    lines.push(format!(
        "entry.class={}",
        external_scheduler_event_log_class_label(entry.class())
    ));
    lines.push(format!("entry.hash={}", entry.content_hash().to_hex()));
    lines.push(String::from("entry.payload_begin"));
    lines.push(external_scheduler_event_log_payload_material(
        entry.payload(),
    ));
    lines.push(String::from("entry.payload_end"));
    lines.push(String::from("entry_end"));
    lines.join("\n")
}

pub(super) fn external_scheduler_event_log_class_label(
    class: SchedulerEventLogClass,
) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

pub(super) fn external_scheduler_event_log_payload_material(
    payload: &SchedulerEventLogPayload,
) -> String {
    let mut lines = Vec::new();
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(external_scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(external_decision_material(decision));
        }
        SchedulerEventLogPayload::Observable(observable) => {
            lines.push(String::from("payload=observable"));
            lines.push(external_observable_event_payload_material(observable));
        }
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            lines.push(String::from("payload=evaluation-boundary"));
            lines.push(format!(
                "boundary.kind={}",
                external_scheduler_evaluation_boundary_kind_label(*kind)
            ));
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            lines.push(String::from("payload=trigger-fired"));
            lines.push(external_event_firing_material(firing));
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            lines.push(String::from("payload=trigger-action-applied"));
            lines.push(external_trigger_action_application_material(application));
        }
        SchedulerEventLogPayload::FaultObservation(observation) => {
            lines.push(String::from("payload=fault-observation"));
            lines.push(observation.canonical_material());
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => {
            lines.push(String::from("payload=diagnostic"));
            lines.push(external_string_material(
                "diagnostic.name",
                &diagnostic.name,
            ));
            lines.push(format!(
                "diagnostic.level={}",
                external_event_level_label(diagnostic.level)
            ));
            lines.push(format!("diagnostic.details={}", diagnostic.details.len()));
            for (index, (name, value)) in diagnostic.details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("diagnostic.detail.{index}.name"),
                    name,
                ));
                lines.push(external_event_attribute_value_material(
                    &format!("diagnostic.detail.{index}.value"),
                    value,
                ));
            }
        }
    }
    lines.join("\n")
}

pub(super) fn external_event_attribute_value_material(
    prefix: &str,
    value: &EventAttributeValue,
) -> String {
    let mut lines = Vec::new();
    match value {
        EventAttributeValue::Bool(value) => {
            lines.push(format!("{prefix}.type=bool"));
            lines.push(format!("{prefix}.bool={value}"));
        }
        EventAttributeValue::U64(value) => {
            lines.push(format!("{prefix}.type=u64"));
            lines.push(format!("{prefix}.u64={value}"));
        }
        EventAttributeValue::U128(value) => {
            lines.push(format!("{prefix}.type=u128"));
            lines.push(format!("{prefix}.u128={value}"));
        }
        EventAttributeValue::String(value) => {
            lines.push(format!("{prefix}.type=string"));
            lines.push(external_string_material(&format!("{prefix}.string"), value));
        }
        EventAttributeValue::Bytes(value) => {
            lines.push(format!("{prefix}.type=bytes"));
            lines.push(format!("{prefix}.bytes_len={}", value.len()));
            lines.push(format!("{prefix}.bytes={}", external_hex_bytes(value)));
        }
        EventAttributeValue::Node(value) => {
            lines.push(format!("{prefix}.type=node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), value));
        }
        EventAttributeValue::Event(value) => {
            lines.push(format!("{prefix}.type=event"));
            lines.push(external_event_id_material(
                &format!("{prefix}.event"),
                value,
            ));
        }
        EventAttributeValue::Fault(value) => {
            lines.push(format!("{prefix}.type=fault"));
            lines.push(external_fault_id_material(
                &format!("{prefix}.fault"),
                value,
            ));
        }
        EventAttributeValue::VirtualTime(value) => {
            lines.push(format!("{prefix}.type=virtual-time"));
            lines.push(format!("{prefix}.ticks={}", value.ticks));
        }
        EventAttributeValue::Icount(value) => {
            lines.push(format!("{prefix}.type=icount"));
            lines.push(format!("{prefix}.retired={}", value.retired));
        }
        EventAttributeValue::Level(value) => {
            lines.push(format!("{prefix}.type=level"));
            lines.push(format!(
                "{prefix}.level={}",
                external_event_level_label(*value)
            ));
        }
    }
    lines.join("\n")
}

pub(super) fn external_scheduled_event_material(event: &ScheduledEvent) -> String {
    let mut lines = Vec::new();
    lines.push(external_scheduled_event_key_material(&event.key));
    lines.push(format!(
        "event.resolve_class={}",
        external_scheduled_event_resolve_class_label(scheduled_event_resolve_class(event))
    ));
    lines.push(external_scheduled_event_payload_material(&event.payload));
    lines.join("\n")
}

pub(super) fn external_scheduled_event_key_material(key: &ScheduledEventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("event.time_ticks={}", key.virtual_time().ticks));
    lines.push(external_scheduler_node_material(
        "event.consumer",
        key.consumer(),
    ));
    lines.push(external_scheduler_node_material(
        "event.producer",
        key.producer(),
    ));
    lines.push(format!("event.sequence={}", key.sequence()));
    lines.join("\n")
}

pub(super) fn external_scheduled_event_payload_material(payload: &ScheduledEventPayload) -> String {
    let mut lines = Vec::new();
    match payload {
        ScheduledEventPayload::BackendInput(input) => {
            lines.push(String::from("event.payload=backend-input"));
            lines.push(external_node_id_material("event.payload.node", &input.node));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&input.payload)
            ));
        }
        ScheduledEventPayload::IoCompletion(completion) => {
            lines.push(String::from("event.payload=io-completion"));
            lines.push(external_scheduler_node_material(
                "event.payload.sub_node",
                &completion.sub_node,
            ));
            lines.push(external_node_id_material(
                "event.payload.target",
                &completion.target,
            ));
            lines.push(format!(
                "event.payload.delivery_icount={}",
                completion.delivery_icount.retired
            ));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&completion.payload)
            ));
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            lines.push(String::from("event.payload=fault-activation"));
            lines.push(external_fault_id_material("event.payload.fault", fault));
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            lines.push(String::from("event.payload=probabilistic-fault"));
            lines.push(external_fault_id_material(
                "event.payload.fault",
                &choice.fault,
            ));
            lines.push(external_rng_stream_material(
                "event.payload.stream",
                &choice.stream,
            ));
            lines.push(format!(
                "event.payload.rate_basis_points={}",
                choice.rate.basis_points()
            ));
        }
        ScheduledEventPayload::Control(operation) => {
            lines.push(String::from("event.payload=control"));
            lines.push(format!(
                "event.payload.control.sequence={}",
                operation.sequence
            ));
            lines.push(external_control_operation_kind_material(
                "event.payload.control.kind",
                &operation.kind,
            ));
        }
    }
    lines.join("\n")
}

pub(super) fn external_decision_material(decision: &Decision) -> String {
    use Decision as D;

    let mut lines = Vec::new();
    match decision {
        D::DeliveryOrder(order) => {
            lines.push(String::from("decision=delivery-order"));
            lines.push(format!("decision.at_ticks={}", order.at.ticks));
            lines.push(format!("decision.events={}", order.order.len()));
            for (index, event) in order.order.iter().enumerate() {
                lines.push(external_event_key_material(
                    &format!("decision.event.{index}"),
                    event,
                ));
            }
        }
        D::FaultFires(fault) => {
            lines.push(String::from("decision=fault-fires"));
            lines.push(format!("decision.at_ticks={}", fault.at.ticks));
            lines.push(external_fault_id_material("decision.fault", &fault.fault));
            lines.push(format!("decision.fired={}", fault.fired));
        }
        D::RngDraw(draw) => {
            lines.push(String::from("decision=rng-draw"));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &draw.stream,
            ));
            lines.push(format!("decision.value={}", draw.value));
        }
        D::Override(override_decision) => {
            lines.push(String::from("decision=override"));
            lines.push(external_string_material(
                "decision.point",
                &override_decision.point.key,
            ));
            lines.push(external_string_material(
                "decision.choice",
                &override_decision.choice.name,
            ));
        }
        D::Preemption(preemption) => {
            lines.push(String::from("decision=preemption"));
            lines.push(external_node_id_material("decision.node", &preemption.node));
            lines.push(format!("decision.at_retired={}", preemption.at.retired));
            lines.push(external_preemption_kind_material(
                "decision.preemption",
                &preemption.kind,
            ));
        }
        D::AppRandom(random) => {
            lines.push(String::from("decision=app-random"));
            lines.push(external_node_id_material("decision.node", &random.node));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &random.stream,
            ));
            lines.push(format!("decision.request_id={}", random.request_id));
            lines.push(format!("decision.width={}", random.width));
            lines.push(format!("decision.value={}", random.value));
        }
    }
    lines.join("\n")
}

pub(super) fn external_observable_event_payload_material(
    observable: &ObservableEventPayload,
) -> String {
    let mut lines = Vec::new();
    match observable {
        ObservableEventPayload::NetworkDelivered { link, payload } => {
            lines.push(String::from("observable=network-delivered"));
            lines.push(external_optional_link_material("observable.link", link));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::ConsoleOutput { node, bytes } => {
            lines.push(String::from("observable=console-output"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.bytes={}", external_hex_bytes(bytes)));
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => {
            lines.push(String::from("observable=coverage-block"));
            lines.push(format!(
                "observable.execution_icount={}",
                execution_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.guest_pc={guest_pc}"));
            lines.push(format!("observable.block_len={block_len}"));
        }
        ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=coverage-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_marker_id_material("observable.marker", marker));
        }
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => {
            lines.push(String::from("observable=memory-sample"));
            lines.push(format!(
                "observable.sample_icount={}",
                sample_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_resolved_mem_place_material(
                "observable.place",
                place,
            ));
            lines.push(format!("observable.value={value}"));
        }
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => {
            lines.push(String::from("observable=io-completion"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.kind={}",
                external_io_event_kind_label(*kind)
            ));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::NodeState { node, state } => {
            lines.push(String::from("observable=node-state"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.state={}",
                external_node_lifecycle_label(*state)
            ));
        }
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            lines.push(String::from("observable=assertion-state-changed"));
            lines.push(external_assertion_id_material("observable.assertion", name));
            lines.push(format!(
                "observable.state={}",
                external_assertion_phase_label(*state)
            ));
        }
        ObservableEventPayload::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => {
            lines.push(String::from("observable=assertion-evaluated"));
            lines.push(external_assertion_id_material("observable.assertion", name));
            lines.push(format!(
                "observable.flavor={}",
                external_assertion_quantifier_label(*flavor)
            ));
            lines.push(format!("observable.condition={condition}"));
            lines.push(external_string_material("observable.message", message));
            lines.push(format!("observable.details={}", details.len()));
            for (index, detail) in details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("observable.detail.{index}.key"),
                    &detail.key,
                ));
                lines.push(external_string_material(
                    &format!("observable.detail.{index}.value"),
                    &detail.value,
                ));
            }
        }
        ObservableEventPayload::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => {
            lines.push(String::from("observable=assertion-proximity"));
            lines.push(external_assertion_id_material(
                "observable.assertion",
                assertion,
            ));
            lines.push(format!(
                "observable.quantifier={}",
                external_assertion_quantifier_label(*quantifier)
            ));
            lines.push(format!("observable.distance={distance}"));
            lines.push(external_optional_node_id_material("observable.node", node));
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_marker_id_material("observable.marker", marker));
        }
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-assertion-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_assertion_id_material(
                "observable.marker.id",
                &marker.id,
            ));
            lines.push(external_string_material(
                "observable.marker.message",
                &marker.message,
            ));
            lines.push(format!(
                "observable.marker.kind={}",
                external_guest_assertion_kind_label(marker.kind)
            ));
            lines.push(format!("observable.marker.condition={}", marker.condition));
            lines.push(format!("observable.marker.must_hit={}", marker.must_hit));
            lines.push(format!(
                "observable.marker.details={}",
                marker.details.len()
            ));
            for (index, detail) in marker.details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("observable.marker.detail.{index}.key"),
                    &detail.key,
                ));
                lines.push(external_string_material(
                    &format!("observable.marker.detail.{index}.value"),
                    &detail.value,
                ));
            }
            lines.push(external_string_material(
                "observable.marker.location",
                &marker.location,
            ));
        }
    }
    lines.join("\n")
}

pub(super) fn external_event_firing_material(firing: &EventFiring) -> String {
    let mut lines = Vec::new();
    lines.push(external_event_id_material("firing.event", firing.event()));
    lines.push(format!("firing.at_ticks={}", firing.at().ticks));
    lines.push(external_action_material("firing.action", firing.action()));
    lines.join("\n")
}

pub(super) fn external_trigger_action_application_material(
    application: &TriggerActionApplication,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("application.sequence={}", application.sequence));
    lines.push(external_event_id_material(
        "application.event",
        &application.event,
    ));
    lines.push(format!("application.at_ticks={}", application.at.ticks));
    lines.push(format!("application.path_len={}", application.path.len()));
    for (index, path) in application.path.iter().enumerate() {
        lines.push(format!("application.path.{index}={path}"));
    }
    lines.push(external_action_material(
        "application.action",
        &application.action,
    ));
    lines.join("\n")
}

pub(super) fn external_action_material(prefix: &str, action: &Action) -> String {
    let mut lines = Vec::new();
    match action {
        Action::ArmTimer { name, after } => {
            lines.push(format!("{prefix}=arm-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
            lines.push(format!("{prefix}.after_nanos={}", after.nanos));
        }
        Action::CancelTimer { name } => {
            lines.push(format!("{prefix}=cancel-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
        }
        Action::StartNode { node } => {
            lines.push(format!("{prefix}=start-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::StopNode { node } => {
            lines.push(format!("{prefix}=stop-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::CreateSavepoint { label } => {
            lines.push(format!("{prefix}=create-savepoint"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Fork { label } => {
            lines.push(format!("{prefix}=fork"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Pass => {
            lines.push(format!("{prefix}=pass"));
        }
        Action::Fail { reason } => {
            lines.push(format!("{prefix}=fail"));
            lines.push(external_string_material(
                &format!("{prefix}.reason"),
                reason,
            ));
        }
        Action::Log { level, message } => {
            lines.push(format!("{prefix}=log"));
            lines.push(format!(
                "{prefix}.level={}",
                external_log_level_label(*level)
            ));
            lines.push(external_string_material(
                &format!("{prefix}.message"),
                message,
            ));
        }
        Action::Group(actions) => {
            lines.push(format!("{prefix}=group"));
            lines.push(format!("{prefix}.actions={}", actions.len()));
            for (index, action) in actions.iter().enumerate() {
                lines.push(external_action_material(
                    &format!("{prefix}.action.{index}"),
                    action,
                ));
            }
        }
    }
    lines.join("\n")
}

pub(super) fn external_control_operation_kind_material(
    prefix: &str,
    kind: &ControlOperationKind,
) -> String {
    let mut lines = Vec::new();
    match kind {
        ControlOperationKind::Pause => lines.push(format!("{prefix}=pause")),
        ControlOperationKind::Resume => lines.push(format!("{prefix}=resume")),
        ControlOperationKind::Step => lines.push(format!("{prefix}=step")),
        ControlOperationKind::Snapshot => lines.push(format!("{prefix}=snapshot")),
        ControlOperationKind::Fork => lines.push(format!("{prefix}=fork")),
        ControlOperationKind::Inject => lines.push(format!("{prefix}=inject")),
        ControlOperationKind::Query => lines.push(format!("{prefix}=query")),
    }
    lines.join("\n")
}

pub(super) fn external_event_key_material(prefix: &str, key: &EventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{prefix}.time_ticks={}", key.virtual_time.ticks));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.consumer"),
        &key.consumer,
    ));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.producer"),
        &key.producer,
    ));
    lines.push(format!("{prefix}.sequence={}", key.sequence));
    lines.join("\n")
}

pub(super) fn external_scheduler_node_material(prefix: &str, node: &SchedulerNodeId) -> String {
    format!(
        "{}\n{prefix}.kind={}",
        external_node_id_material(&format!("{prefix}.node"), &node.node),
        external_scheduling_node_kind_label(node.kind)
    )
}

pub(super) fn external_node_id_material(prefix: &str, node: &NodeId) -> String {
    external_string_material(prefix, &node.name)
}

pub(super) fn external_event_id_material(prefix: &str, id: &EventId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_assertion_id_material(prefix: &str, id: &AssertionId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_marker_id_material(prefix: &str, id: &MarkerId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_fault_id_material(prefix: &str, id: &FaultId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_timer_id_material(prefix: &str, id: &TimerId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_rng_stream_material(prefix: &str, stream: &RngStreamId) -> String {
    format!(
        "{}\n{}",
        external_string_material(&format!("{prefix}.domain"), &stream.domain),
        external_string_material(&format!("{prefix}.name"), &stream.name)
    )
}

pub(super) fn external_optional_label_material(prefix: &str, label: &Option<String>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}.present=true\n{}",
            external_string_material(prefix, label)
        ),
        None => format!("{prefix}.present=false"),
    }
}

pub(super) fn external_optional_link_material(prefix: &str, link: &Option<LinkId>) -> String {
    match link {
        Some(link) => format!(
            "{prefix}.present=true\n{}",
            external_link_id_material(prefix, link)
        ),
        None => format!("{prefix}.present=false"),
    }
}

pub(super) fn external_optional_node_id_material(prefix: &str, node: &Option<NodeId>) -> String {
    match node {
        Some(node) => format!(
            "{prefix}.present=true\n{}",
            external_node_id_material(prefix, node)
        ),
        None => format!("{prefix}.present=false"),
    }
}

pub(super) fn external_link_id_material(prefix: &str, id: &LinkId) -> String {
    external_string_material(prefix, &id.name)
}

pub(super) fn external_resolved_mem_place_material(
    prefix: &str,
    place: &ResolvedMemPlace,
) -> String {
    match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            format!("{prefix}=physical-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            format!("{prefix}=virtual-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::Register { name, bytes } => format!(
            "{prefix}=register\n{}\n{prefix}.bytes={bytes}",
            external_string_material(&format!("{prefix}.name"), name)
        ),
    }
}

pub(super) fn external_string_material(prefix: &str, value: &str) -> String {
    format!(
        "{prefix}.bytes_len={}\n{prefix}.bytes={}",
        value.len(),
        external_hex_bytes(value.as_bytes())
    )
}

pub(super) fn external_preemption_kind_material(prefix: &str, kind: &PreemptionKind) -> String {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => format!(
            "{prefix}=vcpu-switch\n{prefix}.from_vcpu={}\n{prefix}.to_vcpu={}",
            from_vcpu.index, to_vcpu.index
        ),
        PreemptionKind::InterruptAt { target_vcpu, irq } => format!(
            "{prefix}=interrupt-at\n{prefix}.target_vcpu={}\n{prefix}.irq={}",
            target_vcpu.index, irq.vector
        ),
    }
}

pub(super) fn external_scheduler_evaluation_boundary_kind_label(
    kind: SchedulerEvaluationBoundaryKind,
) -> &'static str {
    match kind {
        SchedulerEvaluationBoundaryKind::Quantum => "quantum",
        SchedulerEvaluationBoundaryKind::Rendezvous => "rendezvous",
    }
}

pub(super) fn external_scheduled_event_resolve_class_label(
    class: ScheduledEventResolveClass,
) -> &'static str {
    match class {
        ScheduledEventResolveClass::FrameDelivery => "frame-delivery",
        ScheduledEventResolveClass::IoCompletion => "io-completion",
        ScheduledEventResolveClass::FaultActivation => "fault-activation",
        ScheduledEventResolveClass::ProbabilisticFault => "probabilistic-fault",
        ScheduledEventResolveClass::Control => "control",
    }
}

pub(super) fn external_scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "9p",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

pub(super) fn external_io_event_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "9p",
        IoEventKind::Network => "network",
    }
}

pub(super) fn external_node_lifecycle_label(state: NodeLifecycle) -> &'static str {
    match state {
        NodeLifecycle::Started => "started",
        NodeLifecycle::Crashed => "crashed",
        NodeLifecycle::Hung => "hung",
        NodeLifecycle::Exited => "exited",
    }
}

pub(super) fn external_assertion_phase_label(phase: AssertionPhase) -> &'static str {
    match phase {
        AssertionPhase::Satisfied => "satisfied",
        AssertionPhase::Violated => "violated",
    }
}

pub(super) fn external_assertion_quantifier_label(flavor: AssertionQuantifierKind) -> &'static str {
    match flavor {
        AssertionQuantifierKind::Always => "always",
        AssertionQuantifierKind::Sometimes => "sometimes",
        AssertionQuantifierKind::Eventually => "eventually",
        AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        AssertionQuantifierKind::Reachable => "reachable",
        AssertionQuantifierKind::GuestAlways => "guest-always",
        AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        AssertionQuantifierKind::GuestReachable => "guest-reachable",
        AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}

pub(super) fn external_guest_assertion_kind_label(kind: GuestAssertionKind) -> &'static str {
    match kind {
        GuestAssertionKind::Always => "always",
        GuestAssertionKind::Sometimes => "sometimes",
        GuestAssertionKind::Reachable => "reachable",
        GuestAssertionKind::Unreachable => "unreachable",
    }
}

pub(super) fn external_log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

pub(super) fn external_event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

pub(super) fn external_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn condition_prefix_from_recorded_log(
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
    require_recorded_offset: bool,
) -> Result<ConditionEventLogPrefix, OfflineAssertionCheckError> {
    let entries = &recorded_log.entries()[..prefix_len];
    let prefix = condition_prefix_from_recorded_entries(entries)?
        .with_prefix_offsets(recorded_log.prefix_offsets.clone());
    let prefix_len = u64::try_from(prefix_len)
        .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len })?;
    let Some(offset) = recorded_log.event_log_offset(prefix_len) else {
        return if require_recorded_offset {
            Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len })
        } else {
            Ok(prefix)
        };
    };
    if offset.events != prefix_len {
        return Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
            prefix_len,
            offset_events: offset.events,
        });
    }
    Ok(prefix.with_event_log_offset(offset))
}

pub(super) fn observe_guest_marker_assertions(
    states: &mut Vec<GuestMarkerAssertionState>,
    prefix: &ConditionEventLogPrefix,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Vec<HostAssertionOutcome> {
    let mut outcomes = Vec::new();
    let at = prefix.point().at();
    for event in prefix.observable_events() {
        let ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } = event.payload()
        else {
            continue;
        };
        if white_box_policies.get(node) != Some(&WhiteBoxPolicy::Enabled) {
            continue;
        }
        let state = guest_marker_assertion_state_for(states, marker);
        if state.terminal.is_some() {
            continue;
        }
        state.observe_payload(*retired_icount, node, marker);
        if let Some(outcome) = observe_guest_marker_assertion_state(state, at, event, marker) {
            outcomes.push(outcome);
        }
    }
    outcomes
}

pub(super) fn guest_marker_assertion_state_for<'a>(
    states: &'a mut Vec<GuestMarkerAssertionState>,
    marker: &GuestAssertionMarker,
) -> &'a mut GuestMarkerAssertionState {
    match states.binary_search_by(|state| state.id.cmp(&marker.id)) {
        Ok(index) => &mut states[index],
        Err(index) => {
            states.insert(index, GuestMarkerAssertionState::new(marker));
            &mut states[index]
        }
    }
}

pub(super) fn finalize_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    match state.kind {
        GuestAssertionKind::Always => state.terminal(
            HostAssertionOutcomeKind::Passed,
            at,
            guest_marker_reason(state, "guest always marker stayed true"),
        ),
        GuestAssertionKind::Sometimes => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_reason(state, "guest sometimes marker never became true"),
            Some(guest_assertion_state_evidence(state, at)),
        ),
        GuestAssertionKind::Reachable if state.observed_true => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_reason(state, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Reachable if state.must_hit => state.terminal_with_evidence(
            HostAssertionOutcomeKind::NeverReachedFail,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
            Some(guest_assertion_state_evidence(state, at)),
        ),
        GuestAssertionKind::Reachable => state.terminal(
            HostAssertionOutcomeKind::NeverReachedWarn,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
        ),
        GuestAssertionKind::Unreachable => state.terminal(
            HostAssertionOutcomeKind::Passed,
            at,
            guest_marker_reason(state, "guest unreachable marker stayed unreached"),
        ),
    }
}

pub(super) fn guest_marker_reason(state: &GuestMarkerAssertionState, summary: &str) -> String {
    let details = details_reason(&state.details);
    format!("{summary}; location={}; details={details}", state.location)
}

pub(super) fn guest_marker_payload_reason(marker: &GuestAssertionMarker, summary: &str) -> String {
    let details = details_reason(&marker.details);
    format!("{summary}; location={}; details={details}", marker.location)
}

pub(super) fn details_reason(details: &[GuestAssertionDetail]) -> String {
    details
        .iter()
        .map(|detail| format!("{}={}", detail.key, detail.value))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn sort_host_assertion_outcomes(outcomes: &mut [HostAssertionOutcome]) {
    outcomes.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.at.cmp(&right.at))
            .then_with(|| {
                host_assertion_outcome_kind_rank(left.kind)
                    .cmp(&host_assertion_outcome_kind_rank(right.kind))
            })
            .then_with(|| left.reason.cmp(&right.reason))
    });
}

pub(super) fn sort_host_assertion_proximities(proximities: &mut [HostAssertionProximity]) {
    proximities.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.quantifier.cmp(&right.quantifier))
            .then_with(|| left.distance.cmp(&right.distance))
            .then_with(|| left.at.cmp(&right.at))
            .then_with(|| {
                left.event_log_offset
                    .events
                    .cmp(&right.event_log_offset.events)
            })
            .then_with(|| {
                left.event_log_offset
                    .bytes
                    .cmp(&right.event_log_offset.bytes)
            })
    });
}

pub(super) fn lifecycle_for_outcome_kind(kind: HostAssertionOutcomeKind) -> PropertyLifecycleState {
    match kind {
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn => PropertyLifecycleState::Passing,
        HostAssertionOutcomeKind::Satisfied => PropertyLifecycleState::Satisfied,
        HostAssertionOutcomeKind::NeverEvaluated => PropertyLifecycleState::Declared,
        HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
            PropertyLifecycleState::Violated
        }
    }
}

pub(super) fn host_assertion_outcome_kind_rank(kind: HostAssertionOutcomeKind) -> u8 {
    match kind {
        HostAssertionOutcomeKind::Passed => 0,
        HostAssertionOutcomeKind::Satisfied => 1,
        HostAssertionOutcomeKind::Warning => 2,
        HostAssertionOutcomeKind::NeverEvaluated => 3,
        HostAssertionOutcomeKind::NeverTriggered => 4,
        HostAssertionOutcomeKind::NeverReachedWarn => 5,
        HostAssertionOutcomeKind::NeverReachedFail => 6,
        HostAssertionOutcomeKind::Violated => 7,
    }
}

pub(super) fn host_assertion_outcome_fails_run(kind: HostAssertionOutcomeKind) -> bool {
    matches!(
        kind,
        HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail
    )
}
