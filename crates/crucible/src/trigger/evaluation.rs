//! Cached condition evaluation, runtime fact projection, and predicate matching.

use super::*;
pub(super) struct HostConditionEvaluation<'prefix, 'state, O: ?Sized> {
    observed: ObservedState<'prefix>,
    oracle: &'state mut O,
    once_latches: &'state mut Vec<Condition>,
    leaf_cache: &'state mut HostConditionEvaluationCache,
    white_box_policies: &'state BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &'state BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &'state BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&'state SchedulerQuiescence>,
}

pub(super) type HostConditionEvaluationCache = BTreeMap<HostConditionLeafKey, bool>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HostConditionLeafKey {
    Named { name: String, nodes: Vec<NodeId> },
    GuestMarker { marker: MarkerId },
}

impl HostConditionLeafKey {
    fn from_leaf(leaf: ConditionLeaf<'_>) -> Self {
        match leaf {
            ConditionLeaf::Named { name, nodes } => Self::Named {
                name: name.to_owned(),
                nodes: nodes.to_vec(),
            },
            ConditionLeaf::GuestMarker { marker } => Self::GuestMarker {
                marker: marker.clone(),
            },
        }
    }
}

impl<O> condition_evaluator_sealed::Sealed for HostConditionEvaluation<'_, '_, O> where
    O: HostAssertionOracle + ?Sized
{
}

impl<O> ConditionEvaluator for HostConditionEvaluation<'_, '_, O>
where
    O: HostAssertionOracle + ?Sized,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.observed.point()
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.observed.event_log_offset()
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        let key = HostConditionLeafKey::from_leaf(leaf);
        if let Some(value) = self.leaf_cache.get(&key).copied() {
            return value;
        }
        let value = HostAssertionOracle::leaf_is_true(self.oracle, self.observed, leaf);
        self.leaf_cache.insert(key, value);
        value
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        self.observed.observable_events()
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.scheduler_quiescence
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => self
                .code_points
                .get(&(node.clone(), point.clone()))
                .copied(),
        }
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => {
                self.mem_places.get(&(node.clone(), place.clone())).cloned()
            }
        }
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn host_condition_is_true<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut leaf_cache = HostConditionEvaluationCache::new();
    host_condition_is_true_with_cache(
        prefix,
        condition,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    )
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn host_condition_is_true_with_cache<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches,
        leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    };
    evaluate_condition(&mut evaluator, condition)
}

pub(super) const ASSERTION_PROXIMITY_UNIT: u128 = 1;
pub(super) const ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC: u128 = u128::MAX;

pub(super) fn property_proximity_is_reportable(
    property: &Property,
    terminal_kind: HostAssertionOutcomeKind,
    eventually_triggered: bool,
) -> bool {
    match property {
        Property::Sometimes { .. } => terminal_kind == HostAssertionOutcomeKind::Violated,
        Property::Eventually { .. } => {
            eventually_triggered && terminal_kind == HostAssertionOutcomeKind::Violated
        }
        Property::Reachable {
            expectation: ReachabilityExpectation::Reachable { .. },
            ..
        } => matches!(
            terminal_kind,
            HostAssertionOutcomeKind::NeverReachedWarn | HostAssertionOutcomeKind::NeverReachedFail
        ),
        Property::Always { .. }
        | Property::AfterQuiescence { .. }
        | Property::Reachable {
            expectation: ReachabilityExpectation::Unreachable,
            ..
        } => false,
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn host_condition_distance_to_satisfaction<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &[Condition],
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> u128
where
    O: HostAssertionOracle + ?Sized,
{
    let mut local_once_latches = once_latches.to_vec();
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches: &mut local_once_latches,
        leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    };
    condition_distance_to_satisfaction(&mut evaluator, condition)
}

pub(super) fn condition_distance_to_satisfaction<E>(
    evaluator: &mut E,
    condition: &Condition,
) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    match condition {
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => memory_predicate_distance_to_satisfaction(evaluator, node, place, *cmp, *value),
        Condition::AllOf { predicates } => predicates.iter().fold(0_u128, |sum, predicate| {
            sum.saturating_add(condition_distance_to_satisfaction(evaluator, predicate))
        }),
        Condition::AnyOf { predicates } => predicates
            .iter()
            .map(|predicate| condition_distance_to_satisfaction(evaluator, predicate))
            .min()
            .unwrap_or(ASSERTION_PROXIMITY_UNIT),
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate) {
                0
            } else {
                condition_distance_to_satisfaction(evaluator, predicate)
            }
        }
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. }
        | Condition::Not { .. } => boolean_condition_distance(evaluator, condition),
    }
}

pub(super) fn boolean_condition_distance<E>(evaluator: &mut E, condition: &Condition) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    if evaluate_condition(evaluator, condition) {
        0
    } else {
        ASSERTION_PROXIMITY_UNIT
    }
}

pub(super) fn memory_predicate_distance_to_satisfaction<E>(
    evaluator: &mut E,
    expected_node: &NodeId,
    place: &MemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_mem_place(expected_node, place) else {
        return ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC;
    };
    evaluator
        .observable_events()
        .iter()
        .filter(|event| event.at() == evaluator.evaluation_point().at())
        .filter_map(|event| {
            let ObservableEventPayload::MemorySample {
                sample_icount: _,
                node,
                place,
                value,
            } = event.payload()
            else {
                return None;
            };
            (node == expected_node && place == &resolved)
                .then(|| memory_cmp_distance_to_satisfaction(cmp, *value, expected_value))
        })
        .min()
        .unwrap_or(ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC)
}

pub(super) fn memory_cmp_distance_to_satisfaction(
    cmp: MemoryCmp,
    actual: u64,
    expected: u64,
) -> u128 {
    match cmp {
        MemoryCmp::Eq => u128::from(actual.max(expected) - actual.min(expected)),
        MemoryCmp::Ne => {
            if actual != expected {
                0
            } else {
                ASSERTION_PROXIMITY_UNIT
            }
        }
        MemoryCmp::Lt => {
            if actual < expected {
                0
            } else {
                u128::from(actual) - u128::from(expected) + 1
            }
        }
        MemoryCmp::Le => {
            if actual <= expected {
                0
            } else {
                u128::from(actual) - u128::from(expected)
            }
        }
        MemoryCmp::Gt => {
            if actual > expected {
                0
            } else {
                u128::from(expected) - u128::from(actual) + 1
            }
        }
        MemoryCmp::Ge => {
            if actual >= expected {
                0
            } else {
                u128::from(expected) - u128::from(actual)
            }
        }
    }
}

pub(super) fn push_observed_state_facts(
    entry: &SchedulerEventLogEntry,
    observable_events: &mut Vec<ObservableEvent>,
    black_box_observation_kinds: &mut BTreeSet<BlackBoxObservationKind>,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
) -> Result<(), ConditionEvaluationError> {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(payload) => {
            let event = ObservableEvent {
                at: entry.at(),
                payload: payload.clone(),
            };
            if let Some(kind) = event.black_box_observation_kind() {
                validate_black_box_observation_entry(entry, &event, kind)?;
                black_box_observation_kinds.insert(kind);
            }
            observable_events.push(event);
        }
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            push_resolved_happening_observed_facts(
                entry.sequence(),
                entry.at(),
                event,
                ordering_facts,
            );
        }
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(order)) => {
            ordering_facts.push(ObservedOrderingFact::DeliveryOrder {
                sequence: entry.sequence(),
                at: entry.at(),
                order: order.order.clone(),
            });
        }
        SchedulerEventLogPayload::TriggerActionApplied(_) => {}
        SchedulerEventLogPayload::Decision(
            Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::AppRandom(_),
        )
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::FaultObservation(_)
        | SchedulerEventLogPayload::Diagnostic(_) => {}
    }
    Ok(())
}

pub(super) fn push_condition_runtime_facts(
    entry: &SchedulerEventLogEntry,
    event_firings: &mut BTreeMap<EventId, VirtualTime>,
    timer_fires: &mut BTreeMap<TimerId, VirtualTime>,
) {
    match entry.payload() {
        SchedulerEventLogPayload::TriggerFired(firing) => {
            event_firings.insert(firing.event().clone(), firing.at());
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => match &application.action {
            Action::ArmTimer { name, after } => {
                if let Some(ticks) = application.at.ticks.checked_add(after.nanos) {
                    timer_fires.insert(name.clone(), VirtualTime { ticks });
                }
            }
            Action::CancelTimer { name } => {
                timer_fires.remove(name);
            }
            Action::StartNode { .. }
            | Action::StopNode { .. }
            | Action::CreateSavepoint { .. }
            | Action::Fork { .. }
            | Action::Pass
            | Action::Fail { .. }
            | Action::Log { .. }
            | Action::Group(_) => {}
        },
        SchedulerEventLogPayload::ResolvedHappening(_)
        | SchedulerEventLogPayload::Decision(_)
        | SchedulerEventLogPayload::Observable(_)
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::FaultObservation(_)
        | SchedulerEventLogPayload::Diagnostic(_) => {}
    }
}

pub(super) fn scheduler_entry_black_box_observation_kind(
    entry: &SchedulerEventLogEntry,
) -> Option<BlackBoxObservationKind> {
    let SchedulerEventLogPayload::Observable(payload) = entry.payload() else {
        return None;
    };
    payload.black_box_observation_kind()
}

pub(super) fn validate_black_box_observation_entry(
    entry: &SchedulerEventLogEntry,
    event: &ObservableEvent,
    kind: BlackBoxObservationKind,
) -> Result<(), ConditionEvaluationError> {
    if entry.class() != SchedulerEventLogClass::Observational {
        return Err(ConditionEvaluationError::InvalidBlackBoxObservationClass {
            sequence: entry.sequence(),
            kind,
            class: entry.class(),
        });
    }
    let expected = black_box_observation_icount_stamp(event.at(), event.payload());
    if entry.time().icount != expected {
        return Err(ConditionEvaluationError::InvalidBlackBoxObservationStamp {
            sequence: entry.sequence(),
            kind,
            expected,
            actual: entry.time().icount.clone(),
        });
    }
    Ok(())
}

pub(super) fn black_box_observation_icount_stamp(
    at: VirtualTime,
    payload: &ObservableEventPayload,
) -> EventLogIcountStamp {
    match payload {
        ObservableEventPayload::NetworkDelivered { .. } => black_box_boundary_icount(at),
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion {
            kind:
                IoEventKind::BlockRead
                | IoEventKind::BlockWrite
                | IoEventKind::Fsync
                | IoEventKind::NineP
                | IoEventKind::Network,
            node,
            ..
        }
        | ObservableEventPayload::NodeState { node, .. } => {
            black_box_node_boundary_icount(at, node)
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *execution_icount,
        },
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *sample_icount,
        },
        ObservableEventPayload::IoCompletion {
            kind: IoEventKind::Any,
            ..
        }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::GuestMarker { .. }
        | ObservableEventPayload::GuestAssertionMarker { .. } => black_box_boundary_icount(at),
    }
}

pub(super) fn black_box_boundary_icount(at: VirtualTime) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: None,
        icount: Icount { retired: at.ticks },
    }
}

pub(super) fn black_box_node_boundary_icount(
    at: VirtualTime,
    node: &NodeId,
) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: Some(node.clone()),
        icount: Icount { retired: at.ticks },
    }
}

pub(super) fn push_resolved_happening_observed_facts(
    sequence: u64,
    at: VirtualTime,
    event: &ScheduledEvent,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
) {
    ordering_facts.push(ObservedOrderingFact::ResolvedHappening {
        sequence,
        at,
        key: event.key.clone(),
        class: scheduled_event_resolve_class(event),
    });
    match &event.payload {
        ScheduledEventPayload::BackendInput(_)
        | ScheduledEventPayload::IoCompletion(_)
        | ScheduledEventPayload::Control(_) => {}
    }
}

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
    match condition {
        Condition::At { at } => evaluator.evaluation_point().at() == *at,
        Condition::After { duration, of } => evaluator
            .last_event_firing(of)
            .and_then(|fired_at| fired_at.ticks.checked_add(duration.nanos))
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
                all_true &= evaluate_condition(evaluator, condition);
            }
            all_true
        }
        Condition::AnyOf { predicates } => {
            let mut any_true = false;
            for condition in predicates {
                any_true |= evaluate_condition(evaluator, condition);
            }
            any_true
        }
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate) {
                true
            } else if evaluate_condition(evaluator, predicate) {
                evaluator.latch_once_condition(predicate);
                true
            } else {
                false
            }
        }
        Condition::Not { predicate } => !evaluate_condition(evaluator, predicate),
    }
}

pub(super) fn observable_event_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    matches_payload: impl Fn(&ObservableEventPayload) -> bool,
) -> bool {
    events
        .iter()
        .any(|event| event.at() == at && matches_payload(event.payload()))
}

pub(super) fn network_event_matches(
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

pub(super) fn frame_predicate_matches(predicate: &FramePredicate, payload: &[u8]) -> bool {
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

pub(super) fn console_stream_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    expected_node: &NodeId,
    regex: &RegexProgram,
) -> bool {
    let Ok(program) = regex::bytes::Regex::new(&regex.pattern) else {
        return false;
    };
    let mut stream = Vec::new();
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
    let Some(current_start) = current_start else {
        return false;
    };
    program
        .find_iter(&stream)
        .any(|matched| matched.end() > current_start)
}

pub(super) fn coverage_point_matches<E>(
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

pub(super) fn coverage_event_matches(
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

pub(super) fn block_contains_address(guest_pc: u64, block_len: u32, address: u64) -> bool {
    let Some(end) = guest_pc.checked_add(u64::from(block_len)) else {
        return false;
    };
    guest_pc <= address && address < end
}

pub(super) fn memory_predicate_matches<E>(
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

pub(super) fn memory_event_matches(
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

pub(super) fn memory_cmp_matches(cmp: MemoryCmp, actual: u64, expected: u64) -> bool {
    match cmp {
        MemoryCmp::Eq => actual == expected,
        MemoryCmp::Ne => actual != expected,
        MemoryCmp::Lt => actual < expected,
        MemoryCmp::Le => actual <= expected,
        MemoryCmp::Gt => actual > expected,
        MemoryCmp::Ge => actual >= expected,
    }
}

pub(super) fn io_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_kind: IoEventKind,
) -> bool {
    let ObservableEventPayload::IoCompletion { node, kind, .. } = event else {
        return false;
    };
    node == expected_node && (expected_kind == IoEventKind::Any || expected_kind == *kind)
}

pub(super) fn node_state_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_state: NodeLifecycle,
) -> bool {
    let ObservableEventPayload::NodeState { node, state } = event else {
        return false;
    };
    node == expected_node && *state == expected_state
}

pub(super) fn assertion_state_event_matches(
    event: &ObservableEventPayload,
    expected_name: &AssertionId,
    expected_state: AssertionPhase,
) -> bool {
    let ObservableEventPayload::AssertionStateChanged { name, state } = event else {
        return false;
    };
    name == expected_name && *state == expected_state
}

pub(super) fn guest_marker_matches<E>(evaluator: &E, expected_marker: &MarkerId) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| guest_marker_event_matches(evaluator, event, expected_marker),
    )
}

pub(super) fn guest_marker_event_matches<E>(
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
        | ObservableEventPayload::AssertionProximity { .. } => false,
    }
}

/// Condition evaluator backed by a leaf oracle.
#[derive(Clone, Debug)]
pub struct ConditionEvaluation<O> {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    oracle: O,
    event_firings: BTreeMap<EventId, VirtualTime>,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    observable_events: Vec<ObservableEvent>,
    ordering_facts: Vec<ObservedOrderingFact>,
    scheduler_quiescence: Option<SchedulerQuiescence>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    once_latches: Vec<Condition>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl<O> ConditionEvaluation<O> {
    /// Builds a condition evaluator for one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            point: prefix.point,
            event_log_offset: prefix.event_log_offset,
            oracle,
            event_firings: prefix.event_firings,
            timer_fires: prefix.timer_fires,
            observable_events: prefix.observable_events,
            ordering_facts: prefix.ordering_facts,
            scheduler_quiescence: None,
            white_box_policies: BTreeMap::new(),
            once_latches: Vec::new(),
            code_points: BTreeMap::new(),
            mem_places: BTreeMap::new(),
        }
    }

    /// Returns the deterministic point where this evaluator observes the log.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity visible to this evaluator.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the read-only observed-state view for this evaluation pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        ObservedState {
            point: self.point,
            event_log_offset: self.event_log_offset,
            observable_events: &self.observable_events,
            ordering_facts: &self.ordering_facts,
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.event_firings = event_firings;
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.timer_fires = timer_fires;
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.scheduler_quiescence = Some(quiescence);
        self
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .vm_nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Evaluates a condition through the shared evaluator function.
    pub(crate) fn evaluate_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        evaluate_condition(self, condition)
    }
}

/// Shared assertion/trigger condition-evaluation pass for one log prefix.
#[derive(Clone, Debug)]
pub struct ConditionEvaluationPass<O> {
    evaluation: ConditionEvaluation<O>,
}

impl<O> ConditionEvaluationPass<O> {
    /// Builds a shared pass over one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            evaluation: ConditionEvaluation::from_log_prefix(prefix, oracle),
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_event_firings(event_firings);
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_timer_fires(timer_fires);
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.evaluation = self.evaluation.with_scheduler_quiescence(quiescence);
        self
    }

    /// Adds previously latched `Once` predicates visible to this pass.
    #[must_use]
    pub fn with_once_latches(mut self, once_latches: Vec<Condition>) -> Self {
        self.evaluation.once_latches = once_latches;
        self
    }

    /// Returns the `Once` predicates latched by this pass.
    #[must_use]
    pub fn once_latches(&self) -> &[Condition] {
        &self.evaluation.once_latches
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_white_box_policies(policies);
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(mut self, world: &World) -> Self {
        self.evaluation = self.evaluation.with_world_white_box_policies(world);
        self
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_code_points(code_points);
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_mem_places(mem_places);
        self
    }

    /// Returns the deterministic evaluation point for this pass.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.evaluation.point()
    }

    /// Returns the underlying condition evaluator.
    #[must_use]
    pub fn evaluator(&self) -> &ConditionEvaluation<O> {
        &self.evaluation
    }

    /// Returns the read-only observed-state view for this pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        self.evaluation.observed_state()
    }

    /// Evaluates an assertion predicate in this deterministic pass.
    pub fn evaluate_assertion_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        self.evaluation.evaluate_condition(condition)
    }

    /// Evaluates trigger conditions in this deterministic pass.
    pub fn evaluate_event_graph(
        &mut self,
        graph: &EventGraph,
        state: &mut EventGraphState,
    ) -> EventFirings
    where
        O: ConditionLeafOracle,
    {
        state.evaluate(graph, &mut self.evaluation)
    }
}

impl<O> condition_evaluator_sealed::Sealed for ConditionEvaluation<O> where O: ConditionLeafOracle {}

impl<O> ConditionEvaluator for ConditionEvaluation<O>
where
    O: ConditionLeafOracle,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.point
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.oracle.leaf_is_true(leaf)
    }

    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.event_firings.get(event).copied()
    }

    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.timer_fires.get(timer).copied()
    }

    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.timer_fires.clone()
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        &self.observable_events
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.scheduler_quiescence.as_ref()
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => self
                .code_points
                .get(&(node.clone(), point.clone()))
                .copied(),
        }
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => {
                self.mem_places.get(&(node.clone(), place.clone())).cloned()
            }
        }
    }
}
