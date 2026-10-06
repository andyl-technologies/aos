//! Canonical boundary and modeled-timeout replay state.

use super::*;

// Boundary replay is kept below the arithmetic layer so aggregation remains
// independently reusable by observation validators.

struct BoundaryProgress<'a> {
    selector: &'a BoundarySelector,
    satisfied: Option<MeasurementBoundaryEvidence>,
    children: Vec<BoundaryProgress<'a>>,
    event_count: u64,
    cohort_hits: BTreeMap<NodeId, (u64, ContentHash)>,
    last_network_activity: VirtualTime,
}

impl<'a> BoundaryProgress<'a> {
    fn new(
        selector: &'a BoundarySelector,
        scenario_ready_at: Option<VirtualTime>,
    ) -> Result<Self, MeasurementEvaluationError> {
        let mut children = Vec::new();
        if let BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } = selector
        {
            ownership::reserve(&mut children, selectors.len())?;
            for selector in selectors {
                children.push(Self::new(selector, scenario_ready_at)?);
            }
        }
        let satisfied = match selector {
            BoundarySelector::ScenarioGenesis => Some(MeasurementBoundaryEvidence {
                sequence: None,
                at: VirtualTime { ticks: 0 },
                events: Vec::new(),
                cohort: Vec::new(),
            }),
            BoundarySelector::ScenarioReady => {
                scenario_ready_at.map(|at| MeasurementBoundaryEvidence {
                    sequence: None,
                    at,
                    events: Vec::new(),
                    cohort: Vec::new(),
                })
            }
            _ => None,
        };
        Ok(Self {
            selector,
            satisfied,
            children,
            event_count: 0,
            cohort_hits: BTreeMap::new(),
            last_network_activity: VirtualTime { ticks: 0 },
        })
    }

    fn observe(
        &mut self,
        entry: &SchedulerEventLogEntry,
        cohort: &CohortPolicy,
    ) -> Result<bool, MeasurementEvaluationError> {
        if self.satisfied.is_some() {
            return Ok(true);
        }
        let satisfaction = match self.selector {
            BoundarySelector::ScenarioGenesis => None,
            BoundarySelector::ScenarioReady => (entry.event_payload().kind() == "scenario_ready")
                .then(|| evidence_for(entry))
                .transpose()?,
            BoundarySelector::PlanEvent { event } => entry_matches_plan_event(entry, event)
                .then(|| evidence_for(entry))
                .transpose()?,
            BoundarySelector::FaultOpportunity { binding } => {
                entry_matches_fault(entry, binding, &[FaultObservationKind::FaultOpportunity])
                    .then(|| evidence_for(entry))
                    .transpose()?
            }
            BoundarySelector::FaultTransition { binding } => entry_matches_fault(
                entry,
                binding,
                &[
                    FaultObservationKind::SignalTransition,
                    FaultObservationKind::SignalStateTransition,
                    FaultObservationKind::BindingActivation,
                    FaultObservationKind::BindingDeactivation,
                    FaultObservationKind::NetworkProfile,
                    FaultObservationKind::AssociationTransition,
                ],
            )
            .then(|| evidence_for(entry))
            .transpose()?,
            BoundarySelector::FaultApplied { binding } => {
                entry_matches_fault(entry, binding, &[FaultObservationKind::EffectApplied])
                    .then(|| evidence_for(entry))
                    .transpose()?
            }
            BoundarySelector::GuestMarker { marker, instance } => {
                self.observe_guest_marker(entry, cohort, marker, instance.as_ref())?
            }
            BoundarySelector::PropertyVerdict { property } => {
                entry_matches_property(entry, property)
                    .then(|| evidence_for(entry))
                    .transpose()?
            }
            BoundarySelector::VirtualTime { at } => (entry.at() >= *at)
                .then(|| evidence_for(entry))
                .transpose()?,
            BoundarySelector::NodeIcount { node, instructions } => {
                (entry.time().stamp.node.as_ref() == Some(node)
                    && entry
                        .time()
                        .stamp
                        .retired
                        .is_some_and(|count| count.retired >= *instructions))
                .then(|| evidence_for(entry))
                .transpose()?
            }
            BoundarySelector::EventCount { event, count } => {
                if entry_matches_plan_event(entry, event) {
                    self.event_count = self.event_count.saturating_add(1);
                }
                (self.event_count >= *count)
                    .then(|| evidence_for(entry))
                    .transpose()?
            }
            BoundarySelector::SchedulerQuiescence => None,
            BoundarySelector::NetworkIdle { link, window } => {
                if entry_is_network_activity(entry, link.as_ref()) {
                    self.last_network_activity = entry.at();
                }
                entry
                    .at()
                    .ticks
                    .checked_sub(self.last_network_activity.ticks)
                    .is_some_and(|idle| idle >= window.ticks)
                    .then(|| evidence_for(entry))
                    .transpose()?
            }
            BoundarySelector::All { .. } => {
                let mut all = true;
                for child in &mut self.children {
                    all &= child.observe(entry, cohort)?;
                }
                if all {
                    Some(merged_evidence_at(
                        Some(entry.sequence()),
                        entry.at(),
                        &self.children,
                    )?)
                } else {
                    None
                }
            }
            BoundarySelector::Any { .. } => {
                let mut selected = None;
                for child in &mut self.children {
                    if child.observe(entry, cohort)? {
                        selected = child.satisfied.take();
                        break;
                    }
                }
                selected
            }
        };
        self.satisfied = satisfaction;
        Ok(self.satisfied.is_some())
    }

    fn observe_terminal(
        &mut self,
        terminal: &MeasurementTerminalState,
    ) -> Result<bool, MeasurementEvaluationError> {
        if self.satisfied.is_some() {
            return Ok(true);
        }
        let satisfaction = match self.selector {
            BoundarySelector::VirtualTime { at } if terminal.at >= *at => {
                Some(terminal_evidence(terminal.at))
            }
            BoundarySelector::NodeIcount { node, instructions }
                if terminal
                    .node_icounts
                    .get(node)
                    .is_some_and(|icount| icount.retired >= *instructions) =>
            {
                Some(terminal_evidence(terminal.at))
            }
            BoundarySelector::SchedulerQuiescence if terminal.scheduler_quiescent => {
                Some(terminal_evidence(terminal.at))
            }
            BoundarySelector::NetworkIdle { window, .. }
                if terminal
                    .at
                    .ticks
                    .checked_sub(self.last_network_activity.ticks)
                    .is_some_and(|idle| idle >= window.ticks) =>
            {
                Some(terminal_evidence(terminal.at))
            }
            BoundarySelector::All { .. } => {
                let mut all = true;
                for child in &mut self.children {
                    all &= child.observe_terminal(terminal)?;
                }
                if all {
                    Some(merged_evidence_at(None, terminal.at, &self.children)?)
                } else {
                    None
                }
            }
            BoundarySelector::Any { .. } => {
                let mut selected = None;
                for child in &mut self.children {
                    if child.observe_terminal(terminal)? {
                        selected = child.satisfied.take();
                        break;
                    }
                }
                selected
            }
            _ => None,
        };
        self.satisfied = satisfaction;
        Ok(self.satisfied.is_some())
    }

    fn observe_guest_marker(
        &mut self,
        entry: &SchedulerEventLogEntry,
        cohort: &CohortPolicy,
        marker: &MarkerId,
        instance: Option<&MeasurementInstanceKey>,
    ) -> Result<Option<MeasurementBoundaryEvidence>, MeasurementEvaluationError> {
        let Some(node) = guest_marker_node(entry, marker, instance) else {
            return Ok(None);
        };
        let members = cohort_nodes(cohort);
        if members.binary_search(node).is_err() {
            return Ok(None);
        }
        if !self.cohort_hits.contains_key(node) {
            ownership::tree_entry::<NodeId, (u64, ContentHash)>()?;
            let node = ownership::copy_node(node)?;
            self.cohort_hits
                .insert(node, (entry.sequence(), entry.content_hash()));
        }
        let required = match cohort {
            CohortPolicy::All(nodes) => nodes.len(),
            CohortPolicy::Any(_) => 1,
            CohortPolicy::Quorum { required, .. } => usize::try_from(*required)
                .map_err(|_| MeasurementEvaluationError::ArithmeticOverflow)?,
        };
        if self.cohort_hits.len() < required {
            return Ok(None);
        }
        let mut selected = Vec::new();
        ownership::reserve(&mut selected, self.cohort_hits.len())?;
        selected.extend(
            self.cohort_hits
                .iter()
                .map(|(node, (sequence, hash))| (sequence, node, hash)),
        );
        selected.sort_unstable_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
        selected.truncate(required);
        let mut events = Vec::new();
        let mut cohort = Vec::new();
        ownership::reserve(&mut events, required)?;
        ownership::reserve(&mut cohort, required)?;
        for (sequence, node, hash) in selected {
            events.push(MeasurementBoundaryEvent {
                sequence: *sequence,
                content_hash: *hash,
            });
            cohort.push(ownership::copy_node(node)?);
        }
        Ok(Some(MeasurementBoundaryEvidence {
            sequence: Some(entry.sequence()),
            at: entry.at(),
            events,
            cohort,
        }))
    }

    fn activate(&mut self, at: VirtualTime) {
        if matches!(self.selector, BoundarySelector::NetworkIdle { .. }) {
            self.last_network_activity = at;
        }
        for child in &mut self.children {
            child.activate(at);
        }
    }
}

pub(super) fn evaluate_window(
    definition: &MeasurementDefinition,
    entries: &[SchedulerEventLogEntry],
    terminal: &MeasurementTerminalState,
) -> Result<MeasurementWindowOutcome, MeasurementEvaluationError> {
    let mut begin = BoundaryProgress::new(&definition.begin, terminal.scenario_ready_at)?;
    let mut end = BoundaryProgress::new(&definition.end, terminal.scenario_ready_at)?;
    let mut timeout = TimeoutProgress::new(definition.timeout.as_ref());
    let mut begin_evidence = begin.satisfied.take();
    if let Some(opened) = &begin_evidence {
        end.activate(opened.at);
        timeout.open(opened, entries.first());
    }

    for entry in entries {
        if begin_evidence.is_none() {
            begin.observe(entry, &definition.cohort)?;
            begin_evidence = begin.satisfied.take();
            if let Some(evidence) = &begin_evidence {
                end.activate(evidence.at);
                timeout.open(evidence, Some(entry));
            }
        }
        let Some(opened) = &begin_evidence else {
            continue;
        };
        if !entry_not_before_boundary(entry, opened) {
            continue;
        }
        end.observe(entry, &definition.cohort)?;
        if end
            .satisfied
            .as_ref()
            .is_some_and(|completed| event_boundary_not_before(opened, completed))
        {
            return Ok(MeasurementWindowOutcome::Completed {
                begin: begin_evidence
                    .take()
                    .ok_or(MeasurementEvaluationError::ReplayMismatch)?,
                end: end
                    .satisfied
                    .take()
                    .ok_or(MeasurementEvaluationError::ReplayMismatch)?,
            });
        }
        if let Some(expired) = timeout.observe(entry)? {
            return Ok(MeasurementWindowOutcome::TimedOut {
                begin: begin_evidence
                    .take()
                    .ok_or(MeasurementEvaluationError::ReplayMismatch)?,
                timeout: expired,
            });
        }
    }

    if begin_evidence.is_none() {
        begin.observe_terminal(terminal)?;
        begin_evidence = begin.satisfied.take();
        if let Some(opened) = &begin_evidence {
            end.activate(opened.at);
            timeout.open(opened, None);
        }
    }
    let Some(opened) = begin_evidence else {
        return Ok(MeasurementWindowOutcome::NotStarted);
    };
    end.observe_terminal(terminal)?;
    if let Some(completed) = end
        .satisfied
        .take()
        .filter(|completed| completed.at >= opened.at)
    {
        return Ok(MeasurementWindowOutcome::Completed {
            begin: opened,
            end: completed,
        });
    }
    if let Some(expired) = timeout.observe_terminal(terminal) {
        return Ok(MeasurementWindowOutcome::TimedOut {
            begin: opened,
            timeout: expired,
        });
    }
    Ok(MeasurementWindowOutcome::Open { begin: opened })
}

fn entry_not_before_boundary(
    entry: &SchedulerEventLogEntry,
    boundary: &MeasurementBoundaryEvidence,
) -> bool {
    entry.at() > boundary.at
        || (entry.at() == boundary.at
            && boundary
                .sequence
                .is_none_or(|sequence| entry.sequence() >= sequence))
}

fn event_boundary_not_before(
    begin: &MeasurementBoundaryEvidence,
    end: &MeasurementBoundaryEvidence,
) -> bool {
    match end.at.cmp(&begin.at) {
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => match (begin.sequence, end.sequence) {
            (None, _) => true,
            (Some(begin), Some(end)) => end >= begin,
            (Some(_), None) => false,
        },
    }
}

struct TimeoutProgress<'a> {
    timeout: Option<&'a ModeledMeasurementTimeout>,
    opened_at: Option<VirtualTime>,
    node_baseline: Option<u64>,
    event_count: u64,
}

impl<'a> TimeoutProgress<'a> {
    fn new(timeout: Option<&'a ModeledMeasurementTimeout>) -> Self {
        Self {
            timeout,
            opened_at: None,
            node_baseline: None,
            event_count: 0,
        }
    }

    fn open(
        &mut self,
        evidence: &MeasurementBoundaryEvidence,
        entry: Option<&SchedulerEventLogEntry>,
    ) {
        self.opened_at = Some(evidence.at);
        if let Some(ModeledMeasurementTimeout::NodeIcount { node, .. }) = self.timeout
            && entry.is_some_and(|entry| entry.time().stamp.node.as_ref() == Some(node))
        {
            self.node_baseline =
                entry.and_then(|entry| entry.time().stamp.retired.map(|count| count.retired));
        }
    }

    fn observe(
        &mut self,
        entry: &SchedulerEventLogEntry,
    ) -> Result<Option<MeasurementBoundaryEvidence>, MeasurementEvaluationError> {
        let selected = (|| match self.timeout {
            None => None,
            Some(ModeledMeasurementTimeout::VirtualTime { nanos }) => self
                .opened_at?
                .ticks
                .checked_add(nanos.checked_mul(SIM_TICKS_PER_NS)?)
                .is_some_and(|deadline| entry.at().ticks >= deadline)
                .then_some(entry),
            Some(ModeledMeasurementTimeout::NodeIcount { node, instructions }) => {
                if entry.time().stamp.node.as_ref() != Some(node) {
                    return None;
                }
                let current = entry.time().stamp.retired?.retired;
                let baseline = *self.node_baseline.get_or_insert(current);
                current
                    .checked_sub(baseline)
                    .is_some_and(|elapsed| elapsed >= *instructions)
                    .then_some(entry)
            }
            Some(ModeledMeasurementTimeout::EventCount { event, count }) => {
                if entry_matches_plan_event(entry, event) {
                    self.event_count = self.event_count.saturating_add(1);
                }
                (self.event_count >= *count).then_some(entry)
            }
        })();
        selected.map(evidence_for).transpose()
    }

    fn observe_terminal(
        &self,
        terminal: &MeasurementTerminalState,
    ) -> Option<MeasurementBoundaryEvidence> {
        match self.timeout {
            Some(ModeledMeasurementTimeout::VirtualTime { nanos }) => self
                .opened_at?
                .ticks
                .checked_add(nanos.checked_mul(SIM_TICKS_PER_NS)?)
                .is_some_and(|deadline| terminal.at.ticks >= deadline)
                .then(|| terminal_evidence(terminal.at)),
            Some(ModeledMeasurementTimeout::NodeIcount { node, instructions }) => self
                .node_baseline
                .zip(terminal.node_icounts.get(node).map(|value| value.retired))
                .and_then(|(baseline, current)| current.checked_sub(baseline))
                .is_some_and(|elapsed| elapsed >= *instructions)
                .then(|| terminal_evidence(terminal.at)),
            Some(ModeledMeasurementTimeout::EventCount { count, .. }) => {
                (self.event_count >= *count).then(|| terminal_evidence(terminal.at))
            }
            None => None,
        }
    }
}

fn evidence_for(
    entry: &SchedulerEventLogEntry,
) -> Result<MeasurementBoundaryEvidence, MeasurementEvaluationError> {
    let mut events = Vec::new();
    ownership::reserve(&mut events, 1)?;
    events.push(MeasurementBoundaryEvent {
        sequence: entry.sequence(),
        content_hash: entry.content_hash(),
    });
    Ok(MeasurementBoundaryEvidence {
        sequence: Some(entry.sequence()),
        at: entry.at(),
        events,
        cohort: Vec::new(),
    })
}

fn terminal_evidence(at: VirtualTime) -> MeasurementBoundaryEvidence {
    MeasurementBoundaryEvidence {
        sequence: None,
        at,
        events: Vec::new(),
        cohort: Vec::new(),
    }
}

fn merged_evidence_at(
    sequence: Option<u64>,
    at: VirtualTime,
    children: &[BoundaryProgress<'_>],
) -> Result<MeasurementBoundaryEvidence, MeasurementEvaluationError> {
    let mut events = Vec::new();
    let mut cohort = Vec::new();
    for child in children {
        let proof = child
            .satisfied
            .as_ref()
            .ok_or(MeasurementEvaluationError::ReplayMismatch)?;
        ownership::reserve(&mut events, proof.events.len())?;
        events.extend_from_slice(&proof.events);
        ownership::reserve(&mut cohort, proof.cohort.len())?;
        for node in &proof.cohort {
            cohort.push(ownership::copy_node(node)?);
        }
    }
    events.sort_unstable_by(|left, right| {
        (left.sequence, left.content_hash).cmp(&(right.sequence, right.content_hash))
    });
    events.dedup_by(|left, right| left.content_hash == right.content_hash);
    Ok(MeasurementBoundaryEvidence {
        sequence,
        at,
        events,
        cohort: canonical_nodes(cohort),
    })
}

fn canonical_nodes(mut values: Vec<NodeId>) -> Vec<NodeId> {
    values.sort_unstable();
    values.dedup();
    values
}

fn cohort_nodes(cohort: &CohortPolicy) -> &[NodeId] {
    match cohort {
        CohortPolicy::All(nodes)
        | CohortPolicy::Any(nodes)
        | CohortPolicy::Quorum { nodes, .. } => nodes,
    }
}

fn entry_matches_plan_event(entry: &SchedulerEventLogEntry, event: &EventId) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::TriggerFired(firing) if firing.event() == event
    )
}

fn entry_matches_fault(
    entry: &SchedulerEventLogEntry,
    binding: &FaultObjectId,
    kinds: &[FaultObservationKind],
) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::FaultObservation(observation)
            if observation.binding.as_ref() == Some(binding) && kinds.contains(&observation.kind)
    )
}

fn entry_matches_property(entry: &SchedulerEventLogEntry, property: &AssertionId) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::Observable(
            ObservableEventPayload::AssertionStateChanged { name, .. }
        ) if name == property
    )
}

fn guest_marker_node<'a>(
    entry: &'a SchedulerEventLogEntry,
    marker: &MarkerId,
    instance: Option<&MeasurementInstanceKey>,
) -> Option<&'a NodeId> {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            node,
            marker: observed,
            ..
        }) if instance.is_none() && observed == marker => Some(node),
        SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
            node,
            marker: observed,
            instance: observed_instance,
            ..
        }) if observed == &marker.name
            && instance.is_some_and(|expected| expected.as_str() == observed_instance) =>
        {
            Some(node)
        }
        _ => None,
    }
}

fn entry_is_network_activity(entry: &SchedulerEventLogEntry, link: Option<&LinkId>) -> bool {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::NetworkDelivered {
            link: observed,
            ..
        }) => link.is_none_or(|expected| observed.as_ref() == Some(expected)),
        SchedulerEventLogPayload::FaultObservation(observation) => {
            link.is_none()
                && matches!(
                    observation.kind,
                    FaultObservationKind::NetworkProfile
                        | FaultObservationKind::AssociationTransition
                )
        }
        _ => false,
    }
}
