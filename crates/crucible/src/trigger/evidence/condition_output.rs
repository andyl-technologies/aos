//! Borrowed condition evidence and admitted diagnostic formatting.

use super::super::assertions::owned_storage::{admission, copy_node, copy_string};
use super::*;
use std::fmt;

#[cfg(test)]
mod tests;

pub(in crate::trigger) fn validate_observation_stamp(
    entry: &SchedulerEventLogEntry,
    payload: &ObservableEventPayload,
    kind: BlackBoxObservationKind,
) -> Result<(), ConditionEvaluationError> {
    if entry.class() != SchedulerEventLogClass::Observational {
        return Err(ConditionEvaluationError::InvalidBlackBoxObservationClass {
            sequence: entry.sequence(),
            kind,
            class: entry.class(),
        });
    }
    let (node, retired) = match payload {
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::NodeState { node, .. }
        | ObservableEventPayload::IoCompletion {
            node,
            kind:
                IoEventKind::BlockRead
                | IoEventKind::BlockWrite
                | IoEventKind::Fsync
                | IoEventKind::NineP
                | IoEventKind::Network,
            ..
        } => (Some(node), None),
        ObservableEventPayload::CoverageBlock {
            node,
            execution_icount,
            ..
        } => (Some(node), Some(*execution_icount)),
        ObservableEventPayload::MemorySample {
            node,
            sample_icount,
            ..
        } => (Some(node), Some(*sample_icount)),
        _ => (None, None),
    };
    let actual = &entry.time().stamp;
    if actual.node.as_ref() == node
        && actual.tick.ticks == entry.at().ticks
        && actual.retired == retired
    {
        return Ok(());
    }
    let budget = crate::owned_decode::require_current_child_budget()
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
    let _scope = budget.enter();
    let copy = |node: &NodeId| -> Result<NodeId, ConditionEvaluationError> {
        Ok(NodeId {
            name: crate::owned_decode::display_string(&node.name)
                .map_err(ConditionEvaluationError::OriginalAdmission)?,
        })
    };
    let expected = EventLogTickStamp {
        node: node.map(copy).transpose()?,
        tick: crate::SimInstant {
            ticks: entry.at().ticks,
        },
        retired,
    };
    let actual = EventLogTickStamp {
        node: actual.node.as_ref().map(copy).transpose()?,
        tick: actual.tick,
        retired: actual.retired,
    };
    budget
        .check()
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
    Err(ConditionEvaluationError::InvalidBlackBoxObservationStamp {
        sequence: entry.sequence(),
        kind,
        expected,
        actual,
        _decode_custody: budget.custody(),
    })
}

fn text(value: impl fmt::Display) -> Result<String, EngineError> {
    crate::owned_decode::display_string(&value).map_err(admission)
}

/// Borrows exactly the history that the previous scoped-prefix constructor used.
struct EvidencePrefix<'a> {
    point: EventEvaluationPoint,
    entries: &'a [SchedulerEventLogEntry],
    events: &'a [ObservableEvent],
}

impl<'a> EvidencePrefix<'a> {
    fn at(prefix: &'a ConditionEventLogPrefix, point: EventEvaluationPoint) -> Self {
        let count = prefix
            .scheduler_entries
            .iter()
            .take_while(|entry| entry.at() <= point.at())
            .count();
        let selected = &prefix.scheduler_entries[..count];
        // A segmented log or a regressing non-observational timestamp could not
        // be reconstructed as a zero-based prefix. Preserve its existing full
        // history fallback without copying or revalidating authenticated entries.
        let entries = if selected.first().is_some_and(|entry| entry.sequence() != 0)
            || selected
                .last()
                .is_some_and(|last| selected.iter().any(|entry| entry.at() > last.at()))
        {
            &prefix.scheduler_entries[..]
        } else {
            selected
        };
        let observations = entries
            .iter()
            .filter(|entry| matches!(entry.payload(), SchedulerEventLogPayload::Observable(_)))
            .count();
        Self {
            point,
            entries,
            events: &prefix.observable_events[..observations],
        }
    }
}

pub(in crate::trigger) fn condition_violation_evidence(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    actual: bool,
    policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    condition_violation_evidence_at(prefix, prefix.point(), condition, actual, policies)
}

pub(in crate::trigger) fn condition_violation_evidence_at(
    prefix: &ConditionEventLogPrefix,
    point: EventEvaluationPoint,
    condition: &Condition,
    actual: bool,
    policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    let view = EvidencePrefix::at(prefix, point);
    match observed(&view, condition, actual, policies)? {
        Some(evidence) => Ok(evidence),
        None => evaluation_point_evidence(
            point,
            format_args!(
                "predicate {} at virtual_time={} entries={}",
                bool_observed_label(actual),
                point.at().ticks,
                view.entries.len()
            ),
        ),
    }
}

fn matched(
    prefix: &EvidencePrefix<'_>,
    predicate: impl Fn(&ObservableEvent) -> bool,
    message: impl fmt::Display,
) -> Result<Option<HostAssertionViolationEvidence>, EngineError> {
    prefix
        .events
        .iter()
        .find(|event| event.at() == prefix.point.at() && predicate(event))
        .map(|event| observable_event_evidence(event, message))
        .transpose()
}

fn observed(
    prefix: &EvidencePrefix<'_>,
    condition: &Condition,
    actual: bool,
    policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Result<Option<HostAssertionViolationEvidence>, EngineError> {
    match condition {
        Condition::Not { predicate } => {
            let Some(mut evidence) = observed(prefix, predicate, !actual, policies)? else {
                return Ok(None);
            };
            evidence.observed = text(format_args!(
                "not predicate was {actual}; inner {}",
                evidence.observed
            ))?;
            Ok(Some(evidence))
        }
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            for predicate in predicates {
                if logged_truth(prefix, predicate, policies)? == actual {
                    return observed(prefix, predicate, actual, policies);
                }
            }
            Ok(None)
        }
        Condition::Once { predicate } => observed(prefix, predicate, actual, policies),
        Condition::NetworkMatch { link, predicate } if actual => matched(
            prefix,
            |event| network_event_matches(event.payload(), link.as_ref(), predicate),
            format_args!(
                "network frame matched link={} payload_event",
                link.as_ref().map_or("*", |link| &link.name)
            ),
        ),
        Condition::ConsoleMatch { node, regex } if actual => matched(
            prefix,
            |event| matches!(event.payload(), ObservableEventPayload::ConsoleOutput { node: observed, .. } if observed == node),
            format_args!(
                "console output on node={} matched regex={}",
                node.name,
                regex.pattern()
            ),
        ),
        Condition::CoveragePoint { node, point } if actual => {
            let CodePoint::GuestAddress { address } = point else {
                return Ok(None);
            };
            let resolved = ResolvedCodePoint::guest_address(*address);
            matched(
                prefix,
                |event| coverage_event_matches(event.payload(), node, resolved),
                format_args!(
                    "coverage point node={} address={}",
                    node.name,
                    resolved.address()
                ),
            )
        }
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } if actual => {
            let Some(resolved) = resolved_place(place)? else {
                return Ok(None);
            };
            matched(
                prefix,
                |event| memory_event_matches(event.payload(), node, &resolved, *cmp, *value),
                format_args!(
                    "memory predicate node={} place={} cmp={} expected={}",
                    node.name,
                    PlaceLabel(&resolved),
                    memory_cmp_label(*cmp),
                    value
                ),
            )
        }
        Condition::IoPattern { node, kind } if actual => matched(
            prefix,
            |event| io_event_matches(event.payload(), node, *kind),
            format_args!(
                "io completion node={} kind={}",
                node.name,
                io_kind_label(*kind)
            ),
        ),
        Condition::NodeState { node, state } if actual => matched(
            prefix,
            |event| node_state_event_matches(event.payload(), node, *state),
            format_args!(
                "node state node={} state={}",
                node.name,
                external_node_lifecycle_label(*state)
            ),
        ),
        Condition::AssertionState { name, state } if actual => matched(
            prefix,
            |event| assertion_state_event_matches(event.payload(), name, *state),
            format_args!(
                "assertion state assertion={} state={}",
                name.name,
                external_assertion_phase_label(*state)
            ),
        ),
        Condition::GuestMarker { marker } if actual => matched(
            prefix,
            |event| guest_marker_event_matches_policies(event.payload(), marker, policies),
            format_args!("guest marker marker={} matched", marker.name),
        ),
        Condition::Named { name, nodes } => Ok(Some(evaluation_point_evidence(
            prefix.point,
            format_args!(
                "named predicate name={} nodes={} returned {}",
                name,
                nodes.len(),
                actual
            ),
        )?)),
        Condition::At { at } => Ok(Some(evaluation_point_evidence(
            prefix.point,
            format_args!(
                "time predicate expected={} actual={} returned {}",
                at.ticks,
                prefix.point.at().ticks,
                actual
            ),
        )?)),
        Condition::After { duration, of } => Ok(Some(evaluation_point_evidence(
            prefix.point,
            format_args!(
                "after predicate event={} duration={} returned {}",
                of.name, duration.ticks, actual
            ),
        )?)),
        Condition::Timer { name } => Ok(Some(evaluation_point_evidence(
            prefix.point,
            format_args!("timer predicate name={} returned {}", name.name, actual),
        )?)),
        Condition::Quiescent => Ok(Some(evaluation_point_evidence(
            prefix.point,
            format_args!("quiescence predicate returned {actual}"),
        )?)),
        _ => Ok(Some(evaluation_point_evidence(
            prefix.point,
            FalseSummary(condition, prefix.point.at()),
        )?)),
    }
}

struct LoggedTruth<'a> {
    view: &'a EvidencePrefix<'a>,
    policies: &'a BTreeMap<NodeId, WhiteBoxPolicy>,
    failure: std::cell::Cell<Option<crate::owned_decode::DecodeAdmissionError>>,
}

impl condition_evaluator_sealed::Sealed for LoggedTruth<'_> {}

impl ConditionEvaluator for LoggedTruth<'_> {
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.view.point
    }
    fn event_log_offset(&self) -> EventLogOffset {
        EventLogOffset::default()
    }
    fn leaf_is_true(&mut self, _leaf: ConditionLeaf<'_>) -> bool {
        false
    }
    fn observable_events(&self) -> &[ObservableEvent] {
        self.view.events
    }
    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.policies.get(node).copied()
    }
    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.view
            .entries
            .iter()
            .rev()
            .find_map(|entry| match entry.payload() {
                SchedulerEventLogPayload::TriggerFired(firing) if firing.event() == event => {
                    Some(firing.at())
                }
                _ => None,
            })
    }
    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        for entry in self.view.entries.iter().rev() {
            let SchedulerEventLogPayload::TriggerActionApplied(application) = entry.payload()
            else {
                continue;
            };
            match &application.action {
                Action::CancelTimer { name } if name == timer => return None,
                Action::ArmTimer { name, after } if name == timer => {
                    if let Some(ticks) = application.at.ticks.checked_add(after.ticks) {
                        return Some(VirtualTime { ticks });
                    }
                }
                _ => {}
            }
        }
        None
    }
    // This evidence-only oracle is pure and has no retained Once state. Each
    // inner leaf observes the same immutable log and fixed false named oracle.
    fn once_condition_is_latched(&self, _: &Condition) -> bool {
        false
    }
    fn records_once_latches(&self) -> bool {
        false
    }
    fn prepare_once_latches(&mut self, _: usize) -> Result<(), EngineError> {
        Ok(())
    }
    fn latch_once_condition(&mut self, _: Condition) {}
    fn resolve_mem_place(&self, _: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => match crate::owned_decode::display_string(name) {
                Ok(name) => Some(ResolvedMemPlace::register(name, width.bytes())),
                Err(error) => {
                    self.failure.set(Some(error));
                    None
                }
            },
            _ => None,
        }
    }
}

fn logged_truth(
    view: &EvidencePrefix<'_>,
    condition: &Condition,
    policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Result<bool, EngineError> {
    let mut evaluator = LoggedTruth {
        view,
        policies,
        failure: std::cell::Cell::new(None),
    };
    let truth = try_evaluate_condition(&mut evaluator, condition)?;
    if let Some(error) = evaluator.failure.take() {
        return Err(admission(error));
    }
    Ok(truth)
}

fn resolved_place(place: &MemPlace) -> Result<Option<ResolvedMemPlace>, EngineError> {
    Ok(match place {
        MemPlace::PhysicalAddress { address, width } => {
            Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
        }
        MemPlace::Register { name, width } => Some(ResolvedMemPlace::register(
            copy_string(name)?,
            width.bytes(),
        )),
        _ => None,
    })
}

struct PlaceLabel<'a>(&'a ResolvedMemPlace);

impl fmt::Display for PlaceLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ResolvedMemPlace::PhysicalAddress { address, bytes } => {
                write!(f, "physical:{address}:{bytes}")
            }
            ResolvedMemPlace::VirtualAddress { address, bytes } => {
                write!(f, "virtual:{address}:{bytes}")
            }
            ResolvedMemPlace::Register { name, bytes } => write!(f, "register:{name}:{bytes}"),
        }
    }
}

struct FalseSummary<'a>(&'a Condition, VirtualTime);

impl fmt::Display for FalseSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let at = self.1.ticks;
        match self.0 {
            Condition::NetworkMatch { .. } => {
                write!(f, "no matching network frame at virtual_time={at}")
            }
            Condition::ConsoleMatch { node, regex } => write!(
                f,
                "no console output match node={} regex={} at virtual_time={at}",
                node.name,
                regex.pattern()
            ),
            Condition::CoveragePoint { node, .. } => write!(
                f,
                "no matching coverage point node={} at virtual_time={at}",
                node.name
            ),
            Condition::MemoryPredicate { node, .. } => write!(
                f,
                "no matching memory sample node={} at virtual_time={at}",
                node.name
            ),
            Condition::IoPattern { node, kind } => write!(
                f,
                "no matching io completion node={} kind={} at virtual_time={at}",
                node.name,
                io_kind_label(*kind)
            ),
            Condition::NodeState { node, state } => write!(
                f,
                "no node state node={} state={} at virtual_time={at}",
                node.name,
                external_node_lifecycle_label(*state)
            ),
            Condition::AssertionState { name, state } => write!(
                f,
                "no assertion state assertion={} state={} at virtual_time={at}",
                name.name,
                external_assertion_phase_label(*state)
            ),
            Condition::GuestMarker { marker } => write!(
                f,
                "no guest marker marker={} at virtual_time={at}",
                marker.name
            ),
            _ => write!(f, "predicate was false at virtual_time={at}"),
        }
    }
}

pub(in crate::trigger) fn guest_assertion_marker_event_evidence(
    event: &ObservableEvent,
    marker: &GuestAssertionMarker,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    observable_event_evidence(
        event,
        format_args!(
            "guest assertion marker id={} kind={} condition={} location={} details={}",
            marker.id.name,
            external_guest_assertion_kind_label(marker.kind),
            marker.condition,
            marker.location,
            details_reason(&marker.details)
        ),
    )
}

pub(in crate::trigger) fn guest_assertion_state_evidence(
    state: &GuestMarkerAssertionState,
    at: VirtualTime,
) -> Result<HostAssertionViolationEvidence, EngineError> {
    Ok(HostAssertionViolationEvidence {
        at_icount: state.last_icount.or(Some(Icount { retired: at.ticks })),
        node: state.last_node.as_ref().map(copy_node).transpose()?,
        observed: text(format_args!(
            "guest assertion marker id={} kind={} observed_true={} location={} details={}",
            state.id.name,
            external_guest_assertion_kind_label(state.kind),
            state.observed_true,
            state.location,
            details_reason(&state.details)
        ))?,
    })
}

pub(in crate::trigger) struct DetailsDisplay<'a>(&'a [GuestAssertionDetail]);

impl fmt::Display for DetailsDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, detail) in self.0.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            write!(f, "{}={}", detail.key, detail.value)?;
        }
        Ok(())
    }
}

pub(in crate::trigger) fn details_reason(details: &[GuestAssertionDetail]) -> DetailsDisplay<'_> {
    DetailsDisplay(details)
}

pub(in crate::trigger) struct GuestReason<'a, S> {
    summary: S,
    location: &'a str,
    details: DetailsDisplay<'a>,
}

impl<S: fmt::Display> fmt::Display for GuestReason<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; location={}; details={}",
            self.summary, self.location, self.details
        )
    }
}

pub(in crate::trigger) fn guest_marker_reason<S: fmt::Display>(
    state: &GuestMarkerAssertionState,
    summary: S,
) -> GuestReason<'_, S> {
    GuestReason {
        summary,
        location: &state.location,
        details: details_reason(&state.details),
    }
}

pub(in crate::trigger) fn guest_marker_payload_reason<S: fmt::Display>(
    marker: &GuestAssertionMarker,
    summary: S,
) -> GuestReason<'_, S> {
    GuestReason {
        summary,
        location: &marker.location,
        details: details_reason(&marker.details),
    }
}
