//! Shared condition evaluation, transactional Once latches, and concrete matchers.

use super::*;

/// Evaluates a condition through the shared assertion/trigger evaluator.
///
/// The recursive structure lives in this non-overridable function. Implementors
/// of [`ConditionEvaluator`] provide leaf truth, deterministic observation
/// sources, and `Once` latch storage at a deterministic evaluation point, so
/// assertion and trigger consumers cannot diverge on compound predicate
/// traversal.
pub(crate) fn evaluate_condition<E>(evaluator: &mut E, condition: &Condition) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match try_evaluate_condition(evaluator, condition) {
        Ok(matched) => matched,
        Err(error) => {
            if let Some(budget) = crate::owned_decode::current_budget() {
                let source = match error {
                    EngineError::ArtifactDecodeAdmission { source } => source,
                    source => crate::owned_decode::DecodeAdmissionError::new(source),
                };
                budget.record_failure(source);
            }
            false
        }
    }
}

pub(in crate::trigger) fn try_evaluate_condition<E>(
    evaluator: &mut E,
    condition: &Condition,
) -> Result<bool, EngineError>
where
    E: ConditionEvaluator + ?Sized,
{
    check_evaluation_admission()?;
    let count = count_once_conditions(condition)?;
    let budget = crate::owned_decode::current_budget();
    let scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_array::<&Condition>(count))
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(count)
        .map_err(|source| EngineError::ArtifactDecodeAdmission {
            source: crate::owned_decode::DecodeAdmissionError::new(source),
        })?;
    let matched = evaluate_condition_inner(evaluator, condition, &mut pending);
    check_evaluation_admission()?;
    if !evaluator.records_once_latches() {
        return Ok(matched);
    }

    // Every compound predicate finishes before any Once state changes.
    // Construct all owned copies and admit destination capacity first, so a
    // later refused regex or copy leaves the original latches unchanged.
    let mut prepared = Vec::new();
    let prepared_scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_array::<Condition>(pending.len()))
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    prepared
        .try_reserve_exact(pending.len())
        .map_err(|source| EngineError::ArtifactDecodeAdmission {
            source: crate::owned_decode::DecodeAdmissionError::new(source),
        })?;
    for predicate in pending {
        prepared.push(predicate.try_clone_admitted()?);
    }
    evaluator.prepare_once_latches(prepared.len())?;
    check_evaluation_admission()?;
    for predicate in prepared {
        evaluator.latch_once_condition(predicate);
    }
    drop(prepared_scratch);
    drop(scratch);
    Ok(matched)
}

fn count_once_conditions(condition: &Condition) -> Result<usize, EngineError> {
    let count = match condition {
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            let mut count = 0_usize;
            for predicate in predicates {
                count = count
                    .checked_add(count_once_conditions(predicate)?)
                    .ok_or_else(|| EngineError::ArtifactDecodeAdmission {
                        source: crate::owned_decode::DecodeAdmissionError::new(
                            std::io::Error::other(
                                "predicate latch count exceeds the addressable resource bound",
                            ),
                        ),
                    })?;
            }
            count
        }
        Condition::Once { predicate } => count_once_conditions(predicate)?
            .checked_add(1)
            .ok_or_else(|| EngineError::ArtifactDecodeAdmission {
                source: crate::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
                    "predicate latch count exceeds the addressable resource bound",
                )),
            })?,
        Condition::Not { predicate } => count_once_conditions(predicate)?,
        _ => 0,
    };
    Ok(count)
}

fn evaluate_condition_inner<'condition, E>(
    evaluator: &mut E,
    condition: &'condition Condition,
    pending: &mut Vec<&'condition Condition>,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match condition {
        Condition::At { at } => evaluator.evaluation_point().at() == *at,
        Condition::After { duration, of } => evaluator
            .last_event_firing(of)
            .and_then(|fired_at| fired_at.ticks.checked_add(duration.ticks))
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at().ticks),
        Condition::Timer { name } => evaluator
            .timer_fire_time(name)
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at()),
        Condition::NetworkMatch { link, predicate } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| network_event_matches(event, link.as_ref(), predicate),
        ),
        Condition::ConsoleMatch { node, regex } => console_stream_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            node,
            regex,
        ),
        Condition::CoveragePoint { node, point } => coverage_point_matches(evaluator, node, point),
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => memory_predicate_matches(evaluator, node, place, *cmp, *value),
        Condition::IoPattern { node, kind } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| io_event_matches(event, node, *kind),
        ),
        Condition::NodeState { node, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| node_state_event_matches(event, node, *state),
        ),
        Condition::AssertionState { name, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| assertion_state_event_matches(event, name, *state),
        ),
        Condition::Quiescent => evaluator
            .scheduler_quiescence()
            .is_some_and(SchedulerQuiescence::is_quiescent),
        Condition::Named { name, nodes } => evaluator.leaf_is_true(ConditionLeaf::Named {
            name: name.as_str(),
            nodes,
        }),
        Condition::GuestMarker { marker } => guest_marker_matches(evaluator, marker),
        Condition::AllOf { predicates } => {
            let mut all_true = true;
            for condition in predicates {
                all_true &= evaluate_condition_inner(evaluator, condition, pending);
            }
            all_true
        }
        Condition::AnyOf { predicates } => {
            let mut any_true = false;
            for condition in predicates {
                any_true |= evaluate_condition_inner(evaluator, condition, pending);
            }
            any_true
        }
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate)
                || pending.iter().any(|latched| *latched == predicate.as_ref())
            {
                true
            } else if evaluate_condition_inner(evaluator, predicate, pending)
                && check_evaluation_admission().is_ok()
            {
                pending.push(predicate);
                true
            } else {
                false
            }
        }
        Condition::Not { predicate } => !evaluate_condition_inner(evaluator, predicate, pending),
    }
}

pub(in crate::trigger) fn observable_event_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    matches_payload: impl Fn(&ObservableEventPayload) -> bool,
) -> bool {
    events
        .iter()
        .any(|event| event.at() == at && matches_payload(event.payload()))
}

pub(in crate::trigger) fn network_event_matches(
    event: &ObservableEventPayload,
    expected_link: Option<&LinkId>,
    predicate: &FramePredicate,
) -> bool {
    let ObservableEventPayload::NetworkDelivered { link, payload } = event else {
        return false;
    };
    let link_matches = expected_link.is_none_or(|expected| link.as_ref() == Some(expected));
    link_matches && frame_predicate_matches(predicate, payload)
}

pub(in crate::trigger) fn frame_predicate_matches(
    predicate: &FramePredicate,
    payload: &[u8],
) -> bool {
    match predicate {
        FramePredicate::Any => true,
        FramePredicate::Exact(expected) => payload == expected,
        FramePredicate::Contains(needle) => {
            needle.is_empty()
                || payload
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        }
        FramePredicate::Prefix(prefix) => payload.starts_with(prefix),
    }
}

pub(in crate::trigger) fn console_stream_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    expected_node: &NodeId,
    regex: &RegexProgram,
) -> bool {
    match try_console_stream_matches(at, events, expected_node, regex) {
        Ok(matched) => matched,
        Err(crate::predicate_regex::PredicateRegexError::Admission(source)) => {
            // A cache may belong to another retained original scope. Keep
            // its precise refusal in this evaluator's scope as well, so the
            // fallible firing/assertion boundary refuses before effects.
            if let Some(budget) = crate::owned_decode::current_budget() {
                budget.record_failure(source);
            }
            false
        }
        // Invalid component predicates retain their historic false result.
        // Admitted scenario validation compiles every pattern before release.
        Err(_) => false,
    }
}

fn try_console_stream_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    expected_node: &NodeId,
    regex: &RegexProgram,
) -> Result<bool, crate::predicate_regex::PredicateRegexError> {
    let mut length = 0_usize;
    let mut has_current = false;
    for event in events {
        let ObservableEventPayload::ConsoleOutput { node, bytes } = event.payload() else {
            continue;
        };
        if node != expected_node || event.at() > at {
            continue;
        }
        has_current |= event.at() == at;
        length = length.checked_add(bytes.len()).ok_or_else(|| {
            crate::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
                "console predicate stream length exceeds the addressable resource bound",
            ))
        })?;
    }
    if !has_current {
        return Ok(false);
    }

    let program = regex.compiled()?;
    let budget = crate::owned_decode::current_budget();
    let scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_array::<u8>(length))
        .transpose()?;
    let mut stream = Vec::new();
    stream
        .try_reserve_exact(length)
        .map_err(crate::owned_decode::DecodeAdmissionError::new)?;
    let mut current_start = None;
    for event in events {
        let ObservableEventPayload::ConsoleOutput { node, bytes } = event.payload() else {
            continue;
        };
        if node != expected_node {
            continue;
        }
        if event.at() < at {
            stream.extend_from_slice(bytes);
        } else if event.at() == at {
            current_start.get_or_insert(stream.len());
            stream.extend_from_slice(bytes);
        }
    }
    let matched = program.any_match_ending_after(&stream, current_start.unwrap_or(length));
    drop(stream);
    drop(scratch);
    matched
}

pub(in crate::trigger) fn check_evaluation_admission() -> Result<(), EngineError> {
    if let Some(budget) = crate::owned_decode::current_budget() {
        budget
            .check()
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    }
    Ok(())
}

pub(in crate::trigger) fn coverage_point_matches<E>(
    evaluator: &E,
    expected_node: &NodeId,
    point: &CodePoint,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_code_point(expected_node, point) else {
        return false;
    };
    let at = evaluator.evaluation_point().at();
    let events = evaluator.observable_events();
    let matches_current = events.iter().any(|event| {
        event.at() == at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    let seen_before = events.iter().any(|event| {
        event.at() < at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    matches_current && !seen_before
}

pub(in crate::trigger) fn coverage_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_point: ResolvedCodePoint,
) -> bool {
    let ObservableEventPayload::CoverageBlock {
        execution_icount: _,
        node,
        guest_pc,
        block_len,
    } = event
    else {
        return false;
    };
    node == expected_node && block_contains_address(*guest_pc, *block_len, expected_point.address())
}

pub(in crate::trigger) fn block_contains_address(
    guest_pc: u64,
    block_len: u32,
    address: u64,
) -> bool {
    let Some(end) = guest_pc.checked_add(u64::from(block_len)) else {
        return false;
    };
    guest_pc <= address && address < end
}

pub(in crate::trigger) fn memory_predicate_matches<E>(
    evaluator: &E,
    expected_node: &NodeId,
    place: &MemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_mem_place(expected_node, place) else {
        return false;
    };
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| memory_event_matches(event, expected_node, &resolved, cmp, expected_value),
    )
}

pub(in crate::trigger) fn memory_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_place: &ResolvedMemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool {
    let ObservableEventPayload::MemorySample {
        sample_icount: _,
        node,
        place,
        value,
    } = event
    else {
        return false;
    };
    node == expected_node
        && place == expected_place
        && memory_cmp_matches(cmp, *value, expected_value)
}

pub(in crate::trigger) fn memory_cmp_matches(cmp: MemoryCmp, actual: u64, expected: u64) -> bool {
    match cmp {
        MemoryCmp::Eq => actual == expected,
        MemoryCmp::Ne => actual != expected,
        MemoryCmp::Lt => actual < expected,
        MemoryCmp::Le => actual <= expected,
        MemoryCmp::Gt => actual > expected,
        MemoryCmp::Ge => actual >= expected,
    }
}

pub(in crate::trigger) fn io_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_kind: IoEventKind,
) -> bool {
    let ObservableEventPayload::IoCompletion { node, kind, .. } = event else {
        return false;
    };
    node == expected_node && (expected_kind == IoEventKind::Any || expected_kind == *kind)
}

pub(in crate::trigger) fn node_state_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_state: NodeLifecycle,
) -> bool {
    let ObservableEventPayload::NodeState { node, state } = event else {
        return false;
    };
    node == expected_node && *state == expected_state
}

pub(in crate::trigger) fn assertion_state_event_matches(
    event: &ObservableEventPayload,
    expected_name: &AssertionId,
    expected_state: AssertionPhase,
) -> bool {
    let ObservableEventPayload::AssertionStateChanged { name, state } = event else {
        return false;
    };
    name == expected_name && *state == expected_state
}

pub(in crate::trigger) fn guest_marker_matches<E>(evaluator: &E, expected_marker: &MarkerId) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| guest_marker_event_matches(evaluator, event, expected_marker),
    )
}

pub(in crate::trigger) fn guest_marker_event_matches<E>(
    evaluator: &E,
    event: &ObservableEventPayload,
    expected_marker: &MarkerId,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match event {
        ObservableEventPayload::GuestMarker {
            retired_icount: _,
            node,
            marker,
        } => {
            marker == expected_marker
                && evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestSemanticMarker { node, marker, .. } => {
            marker == &expected_marker.name
                && evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. } => false,
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::GuestMeasurement { .. }
        | ObservableEventPayload::AssertionProximity { .. } => false,
    }
}
