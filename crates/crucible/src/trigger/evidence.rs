//! Assertion divergence, evidence extraction, formal trace export, and guest markers.

use super::*;

mod condition_output;
pub(super) use condition_output::*;
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

pub(super) fn first_different_assertion_replay_prefix(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> CausalEventLogPrefixDivergence {
    let mut expected = causal_entries(expected_log.entries());
    let mut reproduced = causal_entries(reproduced_log.entries());
    let mut matching = 0usize;
    let first_different = loop {
        match (expected.next(), reproduced.next()) {
            (Some((_, left)), Some((_, right))) if causal_entry_material_matches(left, right) => {
                matching += 1;
            }
            (None, None) if matching == 0 => {
                return CausalEventLogPrefixDivergence::terminal(expected_log, reproduced_log);
            }
            (None, None) => break matching,
            _ => break matching + 1,
        }
    };
    CausalEventLogPrefixDivergence {
        expected_last_matching_event_prefix_len: causal_raw_prefix(
            expected_log.entries(),
            first_different.saturating_sub(1),
        ),
        expected_first_different_event_prefix_len: causal_raw_prefix(
            expected_log.entries(),
            first_different,
        ),
        reproduced_first_different_event_prefix_len: causal_raw_prefix(
            reproduced_log.entries(),
            first_different,
        ),
    }
}

fn causal_entries(
    entries: &[SchedulerEventLogEntry],
) -> impl Iterator<Item = (usize, &SchedulerEventLogEntry)> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.class() == SchedulerEventLogClass::Causal)
}

fn causal_raw_prefix(entries: &[SchedulerEventLogEntry], causal_count: usize) -> usize {
    if causal_count == 0 {
        return 0;
    }
    causal_entries(entries)
        .nth(causal_count - 1)
        .map(|(index, _)| index.saturating_add(1))
        .unwrap_or_else(|| entries.len().saturating_add(1))
}

pub(super) struct BorrowedCausalMismatch<'a> {
    pub(super) expected: Option<(usize, &'a SchedulerEventLogEntry)>,
    pub(super) reproduced: Option<(usize, &'a SchedulerEventLogEntry)>,
}

pub(super) fn first_causal_mismatch<'a>(
    expected: &'a [SchedulerEventLogEntry],
    reproduced: &'a [SchedulerEventLogEntry],
) -> Option<BorrowedCausalMismatch<'a>> {
    let mut expected = causal_entries(expected);
    let mut reproduced = causal_entries(reproduced);
    loop {
        match (expected.next(), reproduced.next()) {
            (Some((_, left)), Some((_, right))) if causal_entry_material_matches(left, right) => {}
            (None, None) => return None,
            (expected, reproduced) => {
                return Some(BorrowedCausalMismatch {
                    expected,
                    reproduced,
                });
            }
        }
    }
}

pub(super) fn event_log_causal_projections_match(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) -> bool {
    first_causal_mismatch(expected, reproduced).is_none()
}

pub(super) fn assertion_replay_report_for_prefix(
    artifact: ContentHash,
    properties: &Properties,
    world: &World,
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
    let prefix_len = prefix_len.min(recorded_log.entries().len());
    let checker = assertions::admitted_offline_checker(world)
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let report = checker.check_run(properties, &recorded_log.entries()[..prefix_len])?;
    Ok(host_assertion_report_with_reproduction_artifact(
        report, artifact,
    ))
}

pub(super) fn first_differing_violation<'a>(
    expected: &'a [HostAssertionViolation],
    reproduced: &'a [HostAssertionViolation],
) -> Option<(
    Option<&'a HostAssertionViolation>,
    Option<&'a HostAssertionViolation>,
)> {
    (0..expected.len().max(reproduced.len())).find_map(|index| {
        let left = expected.get(index);
        let right = reproduced.get(index);
        (left != right).then_some((left, right))
    })
}

pub(super) fn first_different_decision_prefix_len(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> Option<usize> {
    let mut expected = scheduler_decisions(expected_log);
    let mut reproduced = scheduler_decisions(reproduced_log);
    let mut index = 1;
    loop {
        match (expected.next(), reproduced.next()) {
            (Some(left), Some(right)) if left == right => index += 1,
            (None, None) => return None,
            _ => return Some(index),
        }
    }
}

fn scheduler_decisions(recorded_log: &RecordedAssertionLog) -> impl Iterator<Item = &Decision> {
    recorded_log
        .entries()
        .iter()
        .filter_map(|entry| match entry.payload() {
            SchedulerEventLogPayload::Decision(decision) => Some(decision),
            _ => None,
        })
}

/// Compares canonical entry fields after the causal sequence is renumbered.
/// Sequence and its derived content hash disappear in that projection; every
/// other field remains identical, including the typed and open payload views.
fn causal_entry_material_matches(
    left: &SchedulerEventLogEntry,
    right: &SchedulerEventLogEntry,
) -> bool {
    left.time() == right.time()
        && left.source() == right.source()
        && left.level() == right.level()
        && left.class() == right.class()
        && left.event_payload() == right.event_payload()
        && left.payload() == right.payload()
}

pub(super) fn observable_event_violation_site(
    event: &ObservableEvent,
) -> Option<(Option<Icount>, Option<&NodeId>)> {
    match event.payload() {
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        } => Some((Some(*execution_icount), Some(node))),
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => Some((Some(*sample_icount), Some(node))),
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestMeasurement {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestSemanticMarker {
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
        } => Some((Some(*retired_icount), Some(node))),
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => Some((None, Some(node))),
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => None,
    }
}

pub(super) fn observable_event_evidence(
    event: &ObservableEvent,
    observed: impl std::fmt::Display,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    let (at_icount, node) = observable_event_violation_site(event).unwrap_or((None, None));
    Ok(HostAssertionViolationEvidence {
        at_icount: at_icount.or(Some(Icount {
            retired: event.at().ticks,
        })),
        node: node.map(assertions::owned_storage::copy_node).transpose()?,
        observed: crate::owned_decode::display_string(&observed)
            .map_err(assertions::owned_storage::admission)?,
    })
}

pub(super) fn evaluation_point_evidence(
    point: EventEvaluationPoint,
    observed: impl std::fmt::Display,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    Ok(HostAssertionViolationEvidence {
        at_icount: Some(Icount {
            retired: point.at().ticks,
        }),
        node: None,
        observed: crate::owned_decode::display_string(&observed)
            .map_err(assertions::owned_storage::admission)?,
    })
}

pub(super) fn outcome_point_evidence(
    prefix: &ConditionEventLogPrefix,
    outcome: &HostAssertionOutcome,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    evaluation_point_evidence(
        EventEvaluationPoint::assertion_deadline(outcome.at),
        format_args!(
            "assertion outcome reason=\"{}\" entries={}",
            outcome.reason,
            prefix.scheduler_entries.len()
        ),
    )
}

pub(super) fn violation_detail(
    outcome: &HostAssertionOutcome,
    evidence: &HostAssertionViolationEvidence,
) -> Result<String, EngineError> {
    crate::owned_decode::display_string(&format_args!(
        "expected={}; observed={}; reason={}",
        violation_expectation(outcome),
        evidence.observed,
        outcome.reason
    ))
    .map_err(assertions::owned_storage::admission)
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
) -> Result<ContentHash, EngineError> {
    external_formal_trace_hash(&prefix.scheduler_entries)
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
        ObservableEventPayload::GuestSemanticMarker { node, marker, .. } => {
            marker == &expected_marker.name
                && white_box_policies.get(node) == Some(&WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. }
        | ObservableEventPayload::GuestMeasurement { .. }
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

pub(super) fn bool_observed_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
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
        let mut prefix = ConditionEventLogPrefix::genesis();
        prefix._decode_custody = crate::owned_decode::require_current_custody()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        Ok(prefix)
    } else {
        crate::owned_decode::require_current_custody()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        let owned = crate::scheduler::copy_entries_admitted(entries)
            .map_err(ConditionEvaluationError::from)?;
        ConditionEventLogPrefix::from_scheduler_event_log_entries(owned)
    }
}

pub(super) fn validate_recorded_event_log_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<(), ConditionEvaluationError> {
    if entries.is_empty() {
        return Ok(());
    }
    let point = entries
        .last()
        .map(|entry| entry.at())
        .ok_or(ConditionEvaluationError::EmptyEventLogPrefix)?;
    let mut previous_observation: Option<(u64, VirtualTime)> = None;
    for (index, entry) in entries.iter().enumerate() {
        let expected = u64::try_from(index).map_err(|_| {
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: entry.sequence(),
            }
        })?;
        if entry.sequence() != expected {
            return Err(ConditionEvaluationError::NonPrefixEventLogSequence {
                expected,
                actual: entry.sequence(),
            });
        }
        if !entry.has_valid_content_hash()? {
            return Err(ConditionEvaluationError::InvalidEventLogEntryHash {
                sequence: entry.sequence(),
            });
        }
        if let Some(kind) = scheduler_entry_black_box_observation_kind(entry) {
            if let Some((previous_sequence, previous_at)) = previous_observation
                && entry.at().ticks < previous_at.ticks
            {
                return Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
                    previous_sequence,
                    previous_at,
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            previous_observation = Some((entry.sequence(), entry.at()));
            if entry.at().ticks > point.ticks {
                return Err(ConditionEvaluationError::FutureEventLogEntry {
                    point,
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            if let SchedulerEventLogPayload::Observable(payload) = entry.payload() {
                validate_observation_stamp(entry, payload, kind)?;
            }
        } else if entry.at().ticks > point.ticks {
            return Err(ConditionEvaluationError::FutureEventLogEntry {
                point,
                sequence: entry.sequence(),
                event_at: entry.at(),
            });
        }
    }
    Ok(())
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

pub(super) fn condition_prefix_from_recorded_log(
    recorded_log: &assertions::RecordedAssertionLogRef<'_>,
    prefix_len: usize,
    require_recorded_offset: bool,
) -> Result<ConditionEventLogPrefix, OfflineAssertionCheckError> {
    let entries = &recorded_log.entries()[..prefix_len];
    let child = crate::owned_decode::require_current_child_budget().map_err(|source| {
        OfflineAssertionCheckError::Engine(Box::new(assertions::owned_storage::admission(source)))
    })?;
    let _scope = child.enter();
    let prefix = condition_prefix_from_recorded_entries(entries)?.with_prefix_offsets(
        conditions::copy_prefix_offsets(recorded_log.prefix_offsets)?,
    );
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
) -> Result<Vec<HostAssertionOutcome>, EngineError> {
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
        assertions::owned_storage::reserve_slot(&mut outcomes)?;
        let state = guest_marker_assertion_state_for(states, marker)?;
        if state.terminal.is_some() {
            continue;
        }
        state.observe_payload(*retired_icount, node, marker)?;
        if let Some(outcome) = observe_guest_marker_assertion_state(state, at, event, marker)? {
            outcomes.push(outcome);
        }
    }
    Ok(outcomes)
}

pub(super) fn guest_marker_assertion_state_for<'a>(
    states: &'a mut Vec<GuestMarkerAssertionState>,
    marker: &GuestAssertionMarker,
) -> Result<&'a mut GuestMarkerAssertionState, EngineError> {
    match states.binary_search_by(|state| state.id.cmp(&marker.id)) {
        Ok(index) => Ok(&mut states[index]),
        Err(index) => {
            assertions::owned_storage::reserve_slot(states)?;
            let state = GuestMarkerAssertionState::new(marker)?;
            states.insert(index, state);
            Ok(&mut states[index])
        }
    }
}

pub(super) fn finalize_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
) -> Result<Option<HostAssertionOutcome>, EngineError> {
    if state.terminal.is_some() {
        return Ok(None);
    }

    let (kind, summary, needs_evidence) = match state.kind {
        GuestAssertionKind::Always => (
            HostAssertionOutcomeKind::Passed,
            "guest always marker stayed true",
            false,
        ),
        GuestAssertionKind::Sometimes => (
            HostAssertionOutcomeKind::Violated,
            "guest sometimes marker never became true",
            true,
        ),
        GuestAssertionKind::Reachable if state.observed_true => (
            HostAssertionOutcomeKind::Satisfied,
            "guest reachable marker was reached",
            false,
        ),
        GuestAssertionKind::Reachable if state.must_hit => (
            HostAssertionOutcomeKind::NeverReachedFail,
            "guest reachable marker was never reached",
            true,
        ),
        GuestAssertionKind::Reachable => (
            HostAssertionOutcomeKind::NeverReachedWarn,
            "guest reachable marker was never reached",
            false,
        ),
        GuestAssertionKind::Unreachable => (
            HostAssertionOutcomeKind::Passed,
            "guest unreachable marker stayed unreached",
            false,
        ),
    };
    // Render the admitted diagnostic before the mutable terminal publication;
    // its borrowed fields belong to the state that publication will update.
    let reason = crate::owned_decode::display_string(&guest_marker_reason(state, summary))
        .map_err(assertions::owned_storage::admission)?;
    let evidence = if needs_evidence {
        Some(guest_assertion_state_evidence(state, at)?)
    } else {
        None
    };
    state.terminal_with_evidence(kind, at, reason, evidence)
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
