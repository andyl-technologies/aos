//! Cached condition evaluation, runtime fact projection, and predicate matching.

mod predicates;
mod projection;

pub(crate) use predicates::evaluate_condition;
pub(super) use predicates::{
    assertion_state_event_matches, coverage_event_matches, io_event_matches, memory_event_matches,
    network_event_matches, node_state_event_matches, try_evaluate_condition,
};

use super::*;
pub(super) struct HostConditionEvaluation<'prefix, 'state, O: ?Sized> {
    observed: ObservedState<'prefix>,
    oracle: &'state mut O,
    once_latches: OnceLatches<'state>,
    leaf_cache: &'state mut HostConditionEvaluationCache,
    white_box_policies: &'state BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &'state BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &'state BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&'state SchedulerQuiescence>,
}

enum OnceLatches<'state> {
    Mutable(&'state mut Vec<Condition>),
    Borrowed(&'state [Condition]),
}

impl OnceLatches<'_> {
    fn values(&self) -> &[Condition] {
        match self {
            Self::Mutable(values) => values,
            Self::Borrowed(values) => values,
        }
    }
}

pub(super) type HostConditionEvaluationCache = BTreeMap<HostConditionLeafKey, bool>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HostConditionLeafKey {
    Named { name: String, nodes: Vec<NodeId> },
    GuestMarker { marker: MarkerId },
}

impl HostConditionLeafKey {
    fn matches_leaf(&self, leaf: &ConditionLeaf<'_>) -> bool {
        match (self, leaf) {
            (
                Self::Named { name, nodes },
                ConditionLeaf::Named {
                    name: candidate,
                    nodes: candidate_nodes,
                },
            ) => name == candidate && nodes == candidate_nodes,
            (Self::GuestMarker { marker }, ConditionLeaf::GuestMarker { marker: candidate }) => {
                marker == *candidate
            }
            _ => false,
        }
    }

    fn from_leaf(
        leaf: &ConditionLeaf<'_>,
    ) -> Result<Self, crate::owned_decode::DecodeAdmissionError> {
        Ok(match leaf {
            ConditionLeaf::Named { name, nodes } => {
                crate::owned_decode::charge_array::<NodeId>(nodes.len())?;
                let mut copied_nodes = Vec::new();
                copied_nodes
                    .try_reserve_exact(nodes.len())
                    .map_err(crate::owned_decode::DecodeAdmissionError::new)?;
                for node in *nodes {
                    copied_nodes.push(NodeId {
                        name: admitted_evaluation_string(&node.name)?,
                    });
                }
                Self::Named {
                    name: admitted_evaluation_string(name)?,
                    nodes: copied_nodes,
                }
            }
            ConditionLeaf::GuestMarker { marker } => Self::GuestMarker {
                marker: MarkerId {
                    name: admitted_evaluation_string(&marker.name)?,
                },
            },
        })
    }
}

fn admitted_evaluation_string(
    source: &str,
) -> Result<String, crate::owned_decode::DecodeAdmissionError> {
    crate::owned_decode::charge_array::<u8>(source.len())?;
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(crate::owned_decode::DecodeAdmissionError::new)?;
    value.push_str(source);
    Ok(value)
}

fn record_evaluation_refusal(source: crate::owned_decode::DecodeAdmissionError) {
    if let Some(budget) = crate::owned_decode::current_budget() {
        budget.record_failure(source);
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
        if let Some((_, value)) = self
            .leaf_cache
            .iter()
            .find(|(key, _)| key.matches_leaf(&leaf))
        {
            return *value;
        }
        let admission = crate::owned_decode::charge_btree_entry::<HostConditionLeafKey, bool>()
            .and_then(|()| HostConditionLeafKey::from_leaf(&leaf));
        let key = match admission {
            Ok(key) => key,
            Err(source) => {
                record_evaluation_refusal(source);
                return false;
            }
        };
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
        self.once_latches
            .values()
            .iter()
            .any(|latched| latched == condition)
    }

    fn prepare_once_latches(&mut self, additional: usize) -> Result<(), EngineError> {
        if let OnceLatches::Mutable(values) = &mut self.once_latches {
            crate::owned_decode::reserve_vec(values, additional)
                .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
        }
        Ok(())
    }

    fn records_once_latches(&self) -> bool {
        matches!(self.once_latches, OnceLatches::Mutable(_))
    }

    fn latch_once_condition(&mut self, condition: Condition) {
        if !self.once_condition_is_latched(&condition)
            && let OnceLatches::Mutable(values) = &mut self.once_latches
        {
            values.push(condition);
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
) -> Result<bool, EngineError>
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
    prefix: &impl HostObservedPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> Result<bool, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches: OnceLatches::Mutable(once_latches),
        leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    };
    try_evaluate_condition(&mut evaluator, condition)
}

/// Supplies a borrowed checked projection to host predicates.
pub(super) trait HostObservedPrefix {
    fn observed_state(&self) -> ObservedState<'_>;
}

impl HostObservedPrefix for ConditionEventLogPrefix {
    fn observed_state(&self) -> ObservedState<'_> {
        ConditionEventLogPrefix::observed_state(self)
    }
}

impl HostObservedPrefix for ObservedState<'_> {
    fn observed_state(&self) -> ObservedState<'_> {
        *self
    }
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
    prefix: &impl HostObservedPrefix,
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
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches: OnceLatches::Borrowed(once_latches),
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
    staging: &crate::owned_decode::DecodeBudget,
) -> Result<(), ConditionEvaluationError> {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(payload) => {
            let event = ObservableEvent {
                at: entry.at(),
                payload: crate::scheduler::copy_observable_admitted(payload)
                    .map_err(ConditionEvaluationError::from)?,
            };
            if let Some(kind) = event.black_box_observation_kind() {
                validate_black_box_observation_entry(entry, &event, kind)?;
                if !black_box_observation_kinds.contains(&kind) {
                    staging
                        .charge_btree_entry::<BlackBoxObservationKind, ()>()
                        .map_err(ConditionEvaluationError::OriginalAdmission)?;
                    black_box_observation_kinds.insert(kind);
                }
            }
            crate::owned_decode::reserve_vec(observable_events, 1)
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            observable_events.push(event);
        }
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            push_resolved_happening_observed_facts(
                entry.sequence(),
                entry.at(),
                event,
                ordering_facts,
            )?;
        }
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(order)) => {
            crate::owned_decode::reserve_vec(ordering_facts, 1)
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            ordering_facts.push(ObservedOrderingFact::DeliveryOrder {
                sequence: entry.sequence(),
                at: entry.at(),
                order: conditions::owned_prefix::copy(&order.order)?,
            });
        }
        SchedulerEventLogPayload::TriggerActionApplied(_) => {}
        SchedulerEventLogPayload::Decision(
            Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::Selection(_),
        )
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::FaultObservation(_)
        | SchedulerEventLogPayload::Diagnostic(_) => {}
    }
    Ok(())
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
    validate_observation_stamp(entry, event.payload(), kind)
}

pub(super) fn push_resolved_happening_observed_facts(
    sequence: u64,
    at: VirtualTime,
    event: &ScheduledEvent,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
) -> Result<(), ConditionEvaluationError> {
    crate::owned_decode::reserve_vec(ordering_facts, 1)
        .map_err(ConditionEvaluationError::OriginalAdmission)?;
    ordering_facts.push(ObservedOrderingFact::ResolvedHappening {
        sequence,
        at,
        key: conditions::owned_prefix::copy(&event.key)?,
        class: scheduled_event_resolve_class(event),
    });
    match &event.payload {
        ScheduledEventPayload::BackendInput(_)
        | ScheduledEventPayload::IoCompletion(_)
        | ScheduledEventPayload::Control(_) => {}
    }
    Ok(())
}

/// Condition evaluator backed by a leaf oracle.
#[derive(Debug)]
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
    _append_custodies: Vec<crate::owned_decode::DecodeCustody>,
    _array_custodies: [crate::owned_decode::DecodeCustody; 4],
    _decode_custody: crate::owned_decode::DecodeCustody,
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
            _append_custodies: prefix._append_custodies,
            _array_custodies: prefix._array_custodies,
            _decode_custody: prefix._decode_custody,
        }
    }

    /// Builds a condition evaluator from a borrowed deterministic prefix.
    ///
    /// Copies the observable state used by evaluation without copying the
    /// scheduler-entry history or its prefix-offset index. The evaluator owns
    /// its projected state and does not retain a borrow of `prefix`.
    /// # Errors
    /// Refuses a projected owned copy before allocation when its original
    /// prefix authority cannot admit an independent evaluation owner.
    pub fn from_log_prefix_ref(
        prefix: &ConditionEventLogPrefix,
        oracle: O,
    ) -> Result<Self, EngineError> {
        projection::copy_evaluation(prefix, oracle)
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
}

/// Shared assertion/trigger condition-evaluation pass for one log prefix.
#[derive(Debug)]
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

    /// Builds a shared pass by projecting a borrowed deterministic prefix.
    ///
    /// Copies only evaluation state, preserving the prefix's point and log
    /// identity without copying its scheduler-entry history or offset index.
    /// # Errors
    /// Refuses an owned projection that exceeds its prefix's original account.
    pub fn from_log_prefix_ref(
        prefix: &ConditionEventLogPrefix,
        oracle: O,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            evaluation: ConditionEvaluation::from_log_prefix_ref(prefix, oracle)?,
        })
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
    ///
    /// # Errors
    /// Returns the original allocation refusal before an assertion verdict
    /// can be accepted by the caller.
    pub fn evaluate_assertion_condition(
        &mut self,
        condition: &Condition,
    ) -> Result<bool, EngineError>
    where
        O: ConditionLeafOracle,
    {
        try_evaluate_condition(&mut self.evaluation, condition)
    }

    /// Evaluates trigger conditions in this deterministic pass.
    ///
    /// # Errors
    /// Returns the original allocation refusal before firing actions.
    pub fn evaluate_event_graph(
        &mut self,
        graph: &EventGraph,
        state: &mut EventGraphState,
    ) -> Result<EventFirings, EngineError>
    where
        O: ConditionLeafOracle,
    {
        state.evaluate(graph, &mut self.evaluation)
    }

    /// Evaluates triggers while deferring time predicates ahead of the shared frontier.
    ///
    /// A backend observation from one leading node may have a timestamp later
    /// than the shared scheduler frontier. Time-conditioned events retain their
    /// one-shot, edge, and latch state until the frontier reaches that prefix.
    /// Pure observational triggers keep their ordinary causal evaluation points.
    ///
    /// # Errors
    /// Returns the original allocation refusal before firing actions.
    pub fn evaluate_event_graph_at_frontier(
        &mut self,
        graph: &EventGraph,
        state: &mut EventGraphState,
        frontier: VirtualTime,
    ) -> Result<EventFirings, EngineError>
    where
        O: ConditionLeafOracle,
    {
        state.evaluate_with_frontier(graph, &mut self.evaluation, Some(frontier))
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
        let mut timers = BTreeMap::new();
        for (timer, at) in &self.timer_fires {
            let admission = crate::owned_decode::charge_btree_entry::<TimerId, VirtualTime>()
                .and_then(|()| admitted_evaluation_string(&timer.name));
            let name = match admission {
                Ok(name) => name,
                Err(source) => {
                    record_evaluation_refusal(source);
                    return BTreeMap::new();
                }
            };
            timers.insert(TimerId { name }, *at);
        }
        timers
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

    fn prepare_once_latches(&mut self, additional: usize) -> Result<(), EngineError> {
        crate::owned_decode::reserve_vec(&mut self.once_latches, additional)
            .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
    }

    fn latch_once_condition(&mut self, condition: Condition) {
        if !self.once_condition_is_latched(&condition) {
            self.once_latches.push(condition);
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
