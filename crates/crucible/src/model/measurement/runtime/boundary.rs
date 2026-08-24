//! Canonical boundary and modeled-timeout replay state.

use super::*;

// Boundary replay is kept below the arithmetic layer so aggregation remains
// independently reusable by observation validators.

#[derive(Clone)]
struct BoundaryProgress {
    selector: BoundarySelector,
    satisfied: Option<MeasurementBoundaryEvidence>,
    children: Vec<BoundaryProgress>,
    event_count: u64,
    cohort_hits: BTreeMap<NodeId, (u64, ContentHash)>,
    last_network_activity: VirtualTime,
}

impl BoundaryProgress {
    fn new(selector: &BoundarySelector, scenario_ready_at: Option<VirtualTime>) -> Self {
        let children = match selector {
            BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors
                .iter()
                .map(|selector| Self::new(selector, scenario_ready_at))
                .collect(),
            _ => Vec::new(),
        };
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
        Self {
            selector: selector.clone(),
            satisfied,
            children,
            event_count: 0,
            cohort_hits: BTreeMap::new(),
            last_network_activity: VirtualTime { ticks: 0 },
        }
    }

    fn observe(
        &mut self,
        entry: &SchedulerEventLogEntry,
        cohort: &CohortPolicy,
    ) -> Option<MeasurementBoundaryEvidence> {
        if let Some(satisfied) = &self.satisfied {
            return Some(satisfied.clone());
        }
        let selector = self.selector.clone();
        let satisfaction = match &selector {
            BoundarySelector::ScenarioGenesis => None,
            BoundarySelector::ScenarioReady => {
                (entry.event_payload().kind() == "scenario_ready").then(|| evidence_for(entry))
            }
            BoundarySelector::PlanEvent { event } => {
                entry_matches_plan_event(entry, event).then(|| evidence_for(entry))
            }
            BoundarySelector::FaultOpportunity { binding } => {
                entry_matches_fault(entry, binding, &[FaultObservationKind::FaultOpportunity])
                    .then(|| evidence_for(entry))
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
            .then(|| evidence_for(entry)),
            BoundarySelector::FaultApplied { binding } => {
                entry_matches_fault(entry, binding, &[FaultObservationKind::EffectApplied])
                    .then(|| evidence_for(entry))
            }
            BoundarySelector::GuestMarker { marker, instance } => {
                self.observe_guest_marker(entry, cohort, marker, instance.as_ref())
            }
            BoundarySelector::PropertyVerdict { property } => {
                entry_matches_property(entry, property).then(|| evidence_for(entry))
            }
            BoundarySelector::VirtualTime { at } => {
                (entry.at() >= *at).then(|| evidence_for(entry))
            }
            BoundarySelector::NodeIcount { node, instructions } => {
                (entry.time().icount.node.as_ref() == Some(node)
                    && entry.time().icount.icount.retired >= *instructions)
                    .then(|| evidence_for(entry))
            }
            BoundarySelector::EventCount { event, count } => {
                if entry_matches_plan_event(entry, event) {
                    self.event_count = self.event_count.saturating_add(1);
                }
                (self.event_count >= *count).then(|| evidence_for(entry))
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
                    .is_some_and(|idle| idle >= window.nanos)
                    .then(|| evidence_for(entry))
            }
            BoundarySelector::All { .. } => {
                let mut all = true;
                let mut evidence = Vec::new();
                for child in &mut self.children {
                    if let Some(child_evidence) = child.observe(entry, cohort) {
                        evidence.push(child_evidence);
                    } else {
                        all = false;
                    }
                }
                all.then(|| merged_evidence(entry, evidence))
            }
            BoundarySelector::Any { .. } => self
                .children
                .iter_mut()
                .find_map(|child| child.observe(entry, cohort)),
        };
        if satisfaction.is_some() {
            self.satisfied = satisfaction.clone();
        }
        satisfaction
    }

    fn observe_terminal(
        &mut self,
        terminal: &MeasurementTerminalState,
    ) -> Option<MeasurementBoundaryEvidence> {
        if let Some(satisfied) = &self.satisfied {
            return Some(satisfied.clone());
        }
        let selector = self.selector.clone();
        let satisfaction = match &selector {
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
                    .is_some_and(|idle| idle >= window.nanos) =>
            {
                Some(terminal_evidence(terminal.at))
            }
            BoundarySelector::All { .. } => {
                let mut evidence = Vec::new();
                for child in &mut self.children {
                    evidence.push(child.observe_terminal(terminal)?);
                }
                Some(merged_terminal_evidence(terminal.at, evidence))
            }
            BoundarySelector::Any { .. } => self
                .children
                .iter_mut()
                .find_map(|child| child.observe_terminal(terminal)),
            _ => None,
        };
        if satisfaction.is_some() {
            self.satisfied = satisfaction.clone();
        }
        satisfaction
    }

    fn observe_guest_marker(
        &mut self,
        entry: &SchedulerEventLogEntry,
        cohort: &CohortPolicy,
        marker: &MarkerId,
        instance: Option<&MeasurementInstanceKey>,
    ) -> Option<MeasurementBoundaryEvidence> {
        let node = guest_marker_node(entry, marker, instance)?;
        let members = cohort_nodes(cohort);
        if members.binary_search(&node).is_err() {
            return None;
        }
        self.cohort_hits
            .entry(node.clone())
            .or_insert((entry.sequence(), entry.content_hash()));
        let required = match cohort {
            CohortPolicy::All(nodes) => nodes.len(),
            CohortPolicy::Any(_) => 1,
            CohortPolicy::Quorum { required, .. } => usize::try_from(*required).ok()?,
        };
        if self.cohort_hits.len() < required {
            return None;
        }
        let mut selected = self
            .cohort_hits
            .iter()
            .map(|(node, (sequence, hash))| (sequence, node, hash))
            .collect::<Vec<_>>();
        selected.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
        selected.truncate(required);
        Some(MeasurementBoundaryEvidence {
            sequence: Some(entry.sequence()),
            at: entry.at(),
            events: selected
                .iter()
                .map(|(sequence, _, hash)| MeasurementBoundaryEvent {
                    sequence: **sequence,
                    content_hash: **hash,
                })
                .collect(),
            cohort: selected
                .iter()
                .map(|(_, node, _)| (*node).clone())
                .collect(),
        })
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
    let mut begin = BoundaryProgress::new(&definition.begin, terminal.scenario_ready_at);
    let mut end = BoundaryProgress::new(&definition.end, terminal.scenario_ready_at);
    let mut timeout = TimeoutProgress::new(definition.timeout.as_ref());
    let mut begin_evidence = begin.satisfied.clone();
    if let Some(opened) = &begin_evidence {
        end.activate(opened.at);
        timeout.open(opened, entries.first());
    }

    for entry in entries {
        if begin_evidence.is_none() {
            begin_evidence = begin.observe(entry, &definition.cohort);
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
        if let Some(completed) = end
            .observe(entry, &definition.cohort)
            .filter(|completed| event_boundary_not_before(opened, completed))
        {
            return Ok(MeasurementWindowOutcome::Completed {
                begin: opened.clone(),
                end: completed,
            });
        }
        if let Some(expired) = timeout.observe(entry) {
            return Ok(MeasurementWindowOutcome::TimedOut {
                begin: opened.clone(),
                timeout: expired,
            });
        }
    }

    if begin_evidence.is_none() {
        begin_evidence = begin.observe_terminal(terminal);
        if let Some(opened) = &begin_evidence {
            end.activate(opened.at);
            timeout.open(opened, None);
        }
    }
    let Some(opened) = begin_evidence else {
        return Ok(MeasurementWindowOutcome::NotStarted);
    };
    if let Some(completed) = end
        .observe_terminal(terminal)
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

struct TimeoutProgress {
    timeout: Option<ModeledMeasurementTimeout>,
    opened_at: Option<VirtualTime>,
    node_baseline: Option<u64>,
    event_count: u64,
}

impl TimeoutProgress {
    fn new(timeout: Option<&ModeledMeasurementTimeout>) -> Self {
        Self {
            timeout: timeout.cloned(),
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
        if let Some(ModeledMeasurementTimeout::NodeIcount { node, .. }) = &self.timeout
            && entry.is_some_and(|entry| entry.time().icount.node.as_ref() == Some(node))
        {
            self.node_baseline = entry.map(|entry| entry.time().icount.icount.retired);
        }
    }

    fn observe(&mut self, entry: &SchedulerEventLogEntry) -> Option<MeasurementBoundaryEvidence> {
        match &self.timeout {
            None => None,
            Some(ModeledMeasurementTimeout::VirtualTime { nanos }) => self
                .opened_at?
                .ticks
                .checked_add(*nanos)
                .is_some_and(|deadline| entry.at().ticks >= deadline)
                .then(|| evidence_for(entry)),
            Some(ModeledMeasurementTimeout::NodeIcount { node, instructions }) => {
                if entry.time().icount.node.as_ref() != Some(node) {
                    return None;
                }
                let current = entry.time().icount.icount.retired;
                let baseline = *self.node_baseline.get_or_insert(current);
                current
                    .checked_sub(baseline)
                    .is_some_and(|elapsed| elapsed >= *instructions)
                    .then(|| evidence_for(entry))
            }
            Some(ModeledMeasurementTimeout::EventCount { event, count }) => {
                if entry_matches_plan_event(entry, event) {
                    self.event_count = self.event_count.saturating_add(1);
                }
                (self.event_count >= *count).then(|| evidence_for(entry))
            }
        }
    }

    fn observe_terminal(
        &self,
        terminal: &MeasurementTerminalState,
    ) -> Option<MeasurementBoundaryEvidence> {
        match &self.timeout {
            Some(ModeledMeasurementTimeout::VirtualTime { nanos }) => self
                .opened_at?
                .ticks
                .checked_add(*nanos)
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

fn evidence_for(entry: &SchedulerEventLogEntry) -> MeasurementBoundaryEvidence {
    MeasurementBoundaryEvidence {
        sequence: Some(entry.sequence()),
        at: entry.at(),
        events: vec![MeasurementBoundaryEvent {
            sequence: entry.sequence(),
            content_hash: entry.content_hash(),
        }],
        cohort: Vec::new(),
    }
}

fn terminal_evidence(at: VirtualTime) -> MeasurementBoundaryEvidence {
    MeasurementBoundaryEvidence {
        sequence: None,
        at,
        events: Vec::new(),
        cohort: Vec::new(),
    }
}

fn merged_evidence(
    entry: &SchedulerEventLogEntry,
    evidence: Vec<MeasurementBoundaryEvidence>,
) -> MeasurementBoundaryEvidence {
    merged_evidence_at(Some(entry.sequence()), entry.at(), evidence)
}

fn merged_terminal_evidence(
    at: VirtualTime,
    evidence: Vec<MeasurementBoundaryEvidence>,
) -> MeasurementBoundaryEvidence {
    merged_evidence_at(None, at, evidence)
}

fn merged_evidence_at(
    sequence: Option<u64>,
    at: VirtualTime,
    evidence: Vec<MeasurementBoundaryEvidence>,
) -> MeasurementBoundaryEvidence {
    let mut events = Vec::new();
    let mut cohort = Vec::new();
    for child in evidence {
        events.extend(child.events);
        cohort.extend(child.cohort);
    }
    events.sort_by(|left, right| {
        (left.sequence, left.content_hash).cmp(&(right.sequence, right.content_hash))
    });
    events.dedup_by(|left, right| left.content_hash == right.content_hash);
    MeasurementBoundaryEvidence {
        sequence,
        at,
        events,
        cohort: canonical_nodes(cohort),
    }
}

fn canonical_nodes(mut values: Vec<NodeId>) -> Vec<NodeId> {
    values.sort();
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

fn guest_marker_node(
    entry: &SchedulerEventLogEntry,
    marker: &MarkerId,
    instance: Option<&MeasurementInstanceKey>,
) -> Option<NodeId> {
    if instance.is_some() {
        // Instance-carrying marker events arrive with T-CAM-3.2. Existing
        // marker payloads cannot be silently treated as a matching instance.
        return None;
    }
    match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
            node,
            marker: observed,
            ..
        }) if observed == marker => Some(node.clone()),
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
