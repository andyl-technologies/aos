//! Event-log canonical material, typed payload projection, and binary segment codec.

use super::*;
pub(crate) fn scheduler_event_log_empty_prefix() -> ContentHash {
    ContentHash::from_canonical_material("crucible.scheduler.event-log.prefix.v1", "empty=true")
}

pub(super) fn scheduler_event_log_prefix_for_resume(offset: EventLogOffset) -> ContentHash {
    match offset.appended_segment {
        Some(appended_segment) => scheduler_event_log_prefix_after_append(
            offset.prefix,
            appended_segment,
            offset.bytes,
            offset.events,
        ),
        None => offset.prefix,
    }
}

pub(super) fn scheduler_event_log_prefix_after_append(
    previous_prefix: ContentHash,
    appended_segment: ContentHash,
    bytes: u64,
    events: u64,
) -> ContentHash {
    let prefix_material = format!(
        "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
        previous_prefix.to_hex(),
        appended_segment.to_hex(),
    );
    ContentHash::from_canonical_material("crucible.scheduler.event-log.prefix.v1", &prefix_material)
}

pub(super) fn scheduler_event_log_sequence(
    base: u64,
    offset: usize,
) -> Result<u64, SchedulerError> {
    let offset = u64::try_from(offset).map_err(|_| SchedulerError::BoundaryViolation {
        message: String::from("scheduler event-log entry offset exceeds u64"),
    })?;
    base.checked_add(offset)
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("scheduler event-log sequence overflow"),
        })
}

/// Builds a retained assertion log from a search configuration schedule.
///
/// # Errors
///
/// Returns [`OfflineAssertionCheckError`] when the schedule length cannot be
/// represented as event-log sequence numbers.
pub(crate) fn recorded_assertion_log_from_schedule_for_search(
    schedule: &Schedule,
) -> Result<RecordedAssertionLog, OfflineAssertionCheckError> {
    let mut entries = Vec::with_capacity(schedule.len().saturating_add(1));
    let mut terminal_ticks = 0_u64;
    for (index, decision) in schedule.decisions().iter().enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len: index })?;
        let at = search_schedule_decision_event_time(decision, sequence);
        terminal_ticks = terminal_ticks.max(at.ticks);
        entries.push(scheduler_event_log_entry(
            sequence,
            at,
            SchedulerEventLogPayload::Decision(decision.clone()),
        ));
    }

    let boundary_index = entries.len();
    let boundary_sequence = u64::try_from(boundary_index).map_err(|_| {
        OfflineAssertionCheckError::PrefixLengthOverflow {
            prefix_len: boundary_index,
        }
    })?;
    let boundary_ticks = if entries.is_empty() {
        terminal_ticks
    } else {
        terminal_ticks.saturating_add(1)
    };
    entries.push(scheduler_event_log_entry(
        boundary_sequence,
        VirtualTime {
            ticks: boundary_ticks,
        },
        SchedulerEventLogPayload::EvaluationBoundary(SchedulerEvaluationBoundaryKind::Quantum),
    ));

    RecordedAssertionLog::from_segments(vec![entries])
}

pub(super) fn search_schedule_decision_event_time(
    decision: &Decision,
    fallback_sequence: u64,
) -> VirtualTime {
    match decision {
        Decision::DeliveryOrder(order) => order.at,
        Decision::EffectOutcome(fault) => fault.at,
        Decision::Preemption(preemption) => VirtualTime {
            ticks: preemption.at.retired,
        },
        Decision::RngDraw(_) | Decision::Override(_) | Decision::AppRandom(_) => VirtualTime {
            ticks: fallback_sequence,
        },
    }
}

pub(super) fn scheduler_event_log_entry(
    sequence: u64,
    at: VirtualTime,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let event_payload = event_payload_from_scheduler_payload(&payload);
    let class = event_kind_catalog_class_for_entry_construction(&event_payload);
    scheduler_event_log_entry_with_class(sequence, at, class, event_payload, payload)
}

pub(super) fn scheduler_event_log_entry_with_class(
    sequence: u64,
    at: VirtualTime,
    class: SchedulerEventLogClass,
    event_payload: EventPayload,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let time = scheduler_event_log_time(at, &payload);
    let source = scheduler_event_log_payload_source(&payload);
    let level = scheduler_event_log_payload_level(&payload);
    let content_hash = ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.entry.v1",
        &scheduler_event_log_entry_material(
            sequence,
            &time,
            &source,
            level,
            class,
            &event_payload,
            &payload,
        ),
    );
    SchedulerEventLogEntry {
        sequence,
        at: time,
        source,
        level,
        class,
        event_payload,
        payload,
        content_hash,
        provenance: SchedulerEventLogEntryProvenance,
    }
}

pub(super) fn scheduler_event_log_entry_with_material(
    sequence: u64,
    at: EventLogTime,
    source: EventSource,
    level: EventLevel,
    class: SchedulerEventLogClass,
    event_payload: EventPayload,
    payload: SchedulerEventLogPayload,
) -> SchedulerEventLogEntry {
    let content_hash = ContentHash::from_canonical_material(
        "crucible.scheduler.event-log.entry.v1",
        &scheduler_event_log_entry_material(
            sequence,
            &at,
            &source,
            level,
            class,
            &event_payload,
            &payload,
        ),
    );
    SchedulerEventLogEntry {
        sequence,
        at,
        source,
        level,
        class,
        event_payload,
        payload,
        content_hash,
        provenance: SchedulerEventLogEntryProvenance,
    }
}

pub(super) fn scheduler_event_log_entry_material(
    sequence: u64,
    at: &EventLogTime,
    source: &EventSource,
    level: EventLevel,
    class: SchedulerEventLogClass,
    event_payload: &EventPayload,
    payload: &SchedulerEventLogPayload,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("sequence={sequence}"));
    lines.push(format!("at_virtual_time_ticks={}", at.virtual_time.ticks));
    lines.push(format!("at_icount_retired={}", at.icount.icount.retired));
    match &at.icount.node {
        Some(node) => {
            lines.push(String::from("at_icount_node=some"));
            lines.push(format!("at_icount_node_len={}", node.name.len()));
            lines.push(format!("at_icount_node_name={}", node.name));
        }
        None => lines.push(String::from("at_icount_node=none")),
    }
    lines.push(scheduler_event_log_source_material("source", source));
    lines.push(format!("level={}", event_level_label(level)));
    lines.push(format!("class={}", event_class_label(class)));
    lines.push(event_payload_material("event_payload", event_payload));
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(scheduler_decision_material(decision));
        }
        SchedulerEventLogPayload::Observable(observable) => {
            lines.push(String::from("payload=observable"));
            lines.push(format!("observable={observable:?}"));
        }
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            lines.push(String::from("payload=evaluation-boundary"));
            lines.push(format!("kind={kind:?}"));
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            lines.push(String::from("payload=trigger_fired"));
            lines.push(trigger_firing_material(firing));
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            lines.push(String::from("payload=trigger_action_applied"));
            lines.push(trigger_action_application_material(application));
        }
        SchedulerEventLogPayload::FaultObservation(observation) => {
            lines.push(String::from("payload=fault_observation"));
            lines.push(fault_observation_material(observation));
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => {
            lines.push(String::from("payload=diagnostic"));
            lines.push(diagnostic_payload_material(diagnostic));
        }
    }
    lines.join("\n")
}

pub(super) fn event_payload_from_scheduler_payload(
    payload: &SchedulerEventLogPayload,
) -> EventPayload {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            resolved_happening_event_payload(event)
        }
        SchedulerEventLogPayload::Decision(decision) => decision_event_payload(decision),
        SchedulerEventLogPayload::Observable(observable) => observable_event_payload(observable),
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            let mut attributes = BTreeMap::new();
            attributes.insert(
                String::from("boundary"),
                EventAttributeValue::String(evaluation_boundary_kind_label(*kind).to_owned()),
            );
            EventPayload::new("evaluation_boundary", attributes)
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            let mut attributes = BTreeMap::new();
            attributes.insert(
                String::from("event"),
                EventAttributeValue::Event(firing.event().clone()),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::String(firing.condition_summary().to_owned()),
            );
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(firing.at()),
            );
            attributes.insert(
                String::from("action"),
                EventAttributeValue::String(trigger_action_kind_label(firing.action()).to_owned()),
            );
            EventPayload::new("trigger_fired", attributes)
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            trigger_action_application_event_payload(application)
        }
        SchedulerEventLogPayload::FaultObservation(observation) => {
            fault_observation_event_payload(observation)
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.event_payload(),
    }
}

pub(super) fn resolved_happening_event_payload(event: &ScheduledEvent) -> EventPayload {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("virtual_time"),
        EventAttributeValue::VirtualTime(event.key.virtual_time()),
    );
    attributes.insert(
        String::from("consumer"),
        EventAttributeValue::Node(event.key.consumer().node.clone()),
    );
    attributes.insert(
        String::from("producer"),
        EventAttributeValue::Node(event.key.producer().node.clone()),
    );
    attributes.insert(
        String::from("sequence"),
        EventAttributeValue::U64(event.key.sequence()),
    );
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(input.node.clone()),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(input.payload.clone()),
            );
            EventPayload::new("backend_input", attributes)
        }
        ScheduledEventPayload::IoCompletion(completion) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(completion.target.clone()),
            );
            attributes.insert(
                String::from("delivery_icount"),
                EventAttributeValue::Icount(completion.delivery_icount),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(completion.payload.clone()),
            );
            EventPayload::new("io_completion", attributes)
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(fault.clone()),
            );
            EventPayload::new("fault_activation", attributes)
        }
        ScheduledEventPayload::ProbabilisticEffect(choice) => {
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(choice.fault.clone()),
            );
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(choice.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(choice.stream.name.clone()),
            );
            attributes.insert(
                String::from("rate_basis_points"),
                EventAttributeValue::U64(u64::from(choice.rate.basis_points())),
            );
            EventPayload::new("probabilistic_effect", attributes)
        }
        ScheduledEventPayload::Control(operation) => {
            attributes.insert(
                String::from("command_id"),
                EventAttributeValue::U64(operation.sequence),
            );
            attributes.insert(
                String::from("command"),
                EventAttributeValue::String(
                    control_operation_kind_label(&operation.kind).to_owned(),
                ),
            );
            EventPayload::new("control", attributes)
        }
    }
}

pub(super) fn decision_event_payload(decision: &Decision) -> EventPayload {
    let mut attributes = BTreeMap::new();
    match decision {
        Decision::DeliveryOrder(order) => {
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(order.at),
            );
            attributes.insert(
                String::from("events"),
                EventAttributeValue::U64(order.order.len() as u64),
            );
            EventPayload::new("delivery_order", attributes)
        }
        Decision::EffectOutcome(fault) => {
            attributes.insert(
                String::from("at"),
                EventAttributeValue::VirtualTime(fault.at),
            );
            attributes.insert(
                String::from("fault"),
                EventAttributeValue::Fault(fault.fault.clone()),
            );
            attributes.insert(
                String::from("fired"),
                EventAttributeValue::Bool(fault.fired),
            );
            EventPayload::new("effect_outcome", attributes)
        }
        Decision::RngDraw(draw) => {
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(draw.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(draw.stream.name.clone()),
            );
            attributes.insert(String::from("value"), EventAttributeValue::U64(draw.value));
            EventPayload::new("rng_draw", attributes)
        }
        Decision::Override(override_decision) => {
            attributes.insert(
                String::from("point"),
                EventAttributeValue::String(override_decision.point.key.clone()),
            );
            attributes.insert(
                String::from("choice"),
                EventAttributeValue::String(override_decision.choice.name.clone()),
            );
            EventPayload::new("override", attributes)
        }
        Decision::Preemption(preemption) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(preemption.node.clone()),
            );
            attributes.insert(
                String::from("at"),
                EventAttributeValue::Icount(preemption.at),
            );
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(preemption_kind_label(&preemption.kind).to_owned()),
            );
            EventPayload::new("preemption", attributes)
        }
        Decision::AppRandom(random) => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(random.node.clone()),
            );
            attributes.insert(
                String::from("stream_domain"),
                EventAttributeValue::String(random.stream.domain.clone()),
            );
            attributes.insert(
                String::from("stream_name"),
                EventAttributeValue::String(random.stream.name.clone()),
            );
            attributes.insert(
                String::from("request_id"),
                EventAttributeValue::U64(random.request_id),
            );
            attributes.insert(
                String::from("width"),
                EventAttributeValue::U64(u64::from(random.width)),
            );
            attributes.insert(
                String::from("value"),
                EventAttributeValue::U64(random.value),
            );
            EventPayload::new("app_random", attributes)
        }
    }
}

pub(super) fn observable_event_payload(observable: &ObservableEventPayload) -> EventPayload {
    let mut attributes = BTreeMap::new();
    match observable {
        ObservableEventPayload::NetworkDelivered { link, payload } => {
            if let Some(link) = link {
                attributes.insert(
                    String::from("link"),
                    EventAttributeValue::String(link.name.clone()),
                );
            }
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(payload.clone()),
            );
            EventPayload::new("network_delivered", attributes)
        }
        ObservableEventPayload::ConsoleOutput { node, bytes } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("bytes"),
                EventAttributeValue::Bytes(bytes.clone()),
            );
            EventPayload::new("console_output", attributes)
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => {
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(String::from("basic_block")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("execution_icount"),
                EventAttributeValue::Icount(*execution_icount),
            );
            attributes.insert(
                String::from("guest_pc"),
                EventAttributeValue::U64(*guest_pc),
            );
            attributes.insert(
                String::from("block_len"),
                EventAttributeValue::U64(u64::from(*block_len)),
            );
            attributes.insert(
                String::from("block"),
                EventAttributeValue::String(format!("{guest_pc:#x}+{block_len:#x}")),
            );
            EventPayload::new("coverage", attributes)
        }
        ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(String::from("named")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(marker.name.clone()),
            );
            EventPayload::new("coverage", attributes)
        }
        ObservableEventPayload::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(assertion.name.clone()),
            );
            attributes.insert(
                String::from("quantifier"),
                EventAttributeValue::String(
                    assertion_quantifier_kind_label(*quantifier).to_owned(),
                ),
            );
            attributes.insert(
                String::from("distance"),
                EventAttributeValue::U128(*distance),
            );
            if let Some(node) = node {
                attributes.insert(
                    String::from("node"),
                    EventAttributeValue::Node(node.clone()),
                );
            }
            EventPayload::new("assertion_proximity", attributes)
        }
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("sample_icount"),
                EventAttributeValue::Icount(*sample_icount),
            );
            attributes.insert(
                String::from("place"),
                EventAttributeValue::String(format!("{place:?}")),
            );
            attributes.insert(String::from("value"), EventAttributeValue::U64(*value));
            EventPayload::new("memory_sample", attributes)
        }
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("kind"),
                EventAttributeValue::String(format!("{kind:?}")),
            );
            attributes.insert(
                String::from("payload"),
                EventAttributeValue::Bytes(payload.clone()),
            );
            EventPayload::new("observed_io_completion", attributes)
        }
        ObservableEventPayload::NodeState { node, state } => {
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("state"),
                EventAttributeValue::String(format!("{state:?}")),
            );
            EventPayload::new("node_state", attributes)
        }
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(name.name.clone()),
            );
            attributes.insert(
                String::from("new_state"),
                EventAttributeValue::String(format!("{state:?}")),
            );
            EventPayload::new("assertion_state_changed", attributes)
        }
        ObservableEventPayload::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => {
            attributes.insert(
                String::from("id"),
                EventAttributeValue::String(name.name.clone()),
            );
            attributes.insert(
                String::from("flavor"),
                EventAttributeValue::String(format!("{flavor:?}")),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::Bool(*condition),
            );
            attributes.insert(
                String::from("message"),
                EventAttributeValue::String(message.clone()),
            );
            insert_guest_assertion_details(&mut attributes, details);
            EventPayload::new("assertion_evaluated", attributes)
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("marker_kind"),
                EventAttributeValue::String(String::from("event")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("marker"),
                EventAttributeValue::String(marker.name.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            EventPayload::new("guest_marker", attributes)
        }
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            attributes.insert(
                String::from("marker_kind"),
                EventAttributeValue::String(String::from("assert")),
            );
            attributes.insert(
                String::from("node"),
                EventAttributeValue::Node(node.clone()),
            );
            attributes.insert(
                String::from("retired_icount"),
                EventAttributeValue::Icount(*retired_icount),
            );
            attributes.insert(
                String::from("assertion"),
                EventAttributeValue::String(marker.id.name.clone()),
            );
            attributes.insert(
                String::from("flavor"),
                EventAttributeValue::String(format!("{:?}", marker.kind)),
            );
            attributes.insert(
                String::from("condition"),
                EventAttributeValue::Bool(marker.condition),
            );
            attributes.insert(
                String::from("must_hit"),
                EventAttributeValue::Bool(marker.must_hit),
            );
            attributes.insert(
                String::from("message"),
                EventAttributeValue::String(marker.message.clone()),
            );
            attributes.insert(
                String::from("location"),
                EventAttributeValue::String(marker.location.clone()),
            );
            insert_guest_assertion_details(&mut attributes, &marker.details);
            EventPayload::new("guest_marker", attributes)
        }
    }
}

pub(super) fn insert_guest_assertion_details(
    attributes: &mut BTreeMap<String, EventAttributeValue>,
    details: &[crate::trigger::GuestAssertionDetail],
) {
    let details_len = u64::try_from(details.len()).unwrap_or(u64::MAX);
    attributes.insert(
        String::from("details_len"),
        EventAttributeValue::U64(details_len),
    );
    for (index, detail) in details.iter().enumerate() {
        attributes.insert(
            format!("detail.{index}.key"),
            EventAttributeValue::String(detail.key.clone()),
        );
        attributes.insert(
            format!("detail.{index}.value"),
            EventAttributeValue::String(detail.value.clone()),
        );
    }
}

pub(super) fn trigger_action_application_event_payload(
    application: &TriggerActionApplication,
) -> EventPayload {
    if let Action::Log { level, message } = &application.action {
        let mut details = BTreeMap::new();
        details.insert(
            String::from("event"),
            EventAttributeValue::Event(application.event.clone()),
        );
        details.insert(
            String::from("level"),
            EventAttributeValue::Level(event_level_from_trigger_log(*level)),
        );
        details.insert(
            String::from("message"),
            EventAttributeValue::String(message.clone()),
        );
        return EventPayload::diagnostic("trigger.log", details);
    }

    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("event"),
        EventAttributeValue::Event(application.event.clone()),
    );
    attributes.insert(
        String::from("at"),
        EventAttributeValue::VirtualTime(application.at),
    );
    attributes.insert(
        String::from("sequence"),
        EventAttributeValue::U64(application.sequence),
    );
    attributes.insert(
        String::from("action"),
        EventAttributeValue::String(trigger_action_kind_label(&application.action).to_owned()),
    );
    EventPayload::new("trigger_action_applied", attributes)
}

pub(super) fn scheduler_event_log_time(
    at: VirtualTime,
    payload: &SchedulerEventLogPayload,
) -> EventLogTime {
    EventLogTime {
        virtual_time: at,
        icount: scheduler_event_log_payload_icount(at, payload),
    }
}

pub(super) fn scheduler_event_log_payload_icount(
    at: VirtualTime,
    payload: &SchedulerEventLogPayload,
) -> EventLogIcountStamp {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            scheduled_event_payload_icount(at, &event.payload)
        }
        SchedulerEventLogPayload::Decision(decision) => decision_icount(at, decision),
        SchedulerEventLogPayload::Observable(observable) => {
            observable_payload_icount(at, observable)
        }
        SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_)
        | SchedulerEventLogPayload::FaultObservation(_)
        | SchedulerEventLogPayload::Diagnostic(_) => boundary_icount(at),
    }
}

pub(super) fn scheduled_event_payload_icount(
    at: VirtualTime,
    payload: &ScheduledEventPayload,
) -> EventLogIcountStamp {
    match payload {
        ScheduledEventPayload::BackendInput(input) => node_boundary_icount(at, &input.node),
        ScheduledEventPayload::IoCompletion(completion) => EventLogIcountStamp {
            node: Some(completion.target.clone()),
            icount: completion.delivery_icount,
        },
        ScheduledEventPayload::FaultActivation(_)
        | ScheduledEventPayload::ProbabilisticEffect(_)
        | ScheduledEventPayload::Control(_) => boundary_icount(at),
    }
}

pub(super) fn decision_icount(at: VirtualTime, decision: &Decision) -> EventLogIcountStamp {
    match decision {
        Decision::Preemption(preemption) => EventLogIcountStamp {
            node: Some(preemption.node.clone()),
            icount: preemption.at,
        },
        Decision::AppRandom(random) => node_boundary_icount(at, &random.node),
        Decision::DeliveryOrder(_)
        | Decision::EffectOutcome(_)
        | Decision::RngDraw(_)
        | Decision::Override(_) => boundary_icount(at),
    }
}

pub(super) fn observable_payload_icount(
    at: VirtualTime,
    observable: &ObservableEventPayload,
) -> EventLogIcountStamp {
    match observable {
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => node_boundary_icount(at, node),
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        }
        | ObservableEventPayload::CoverageMarker {
            retired_icount: execution_icount,
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
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *retired_icount,
        },
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. } => boundary_icount(at),
    }
}

pub(super) fn boundary_icount(at: VirtualTime) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: None,
        icount: Icount { retired: at.ticks },
    }
}

pub(super) fn node_boundary_icount(at: VirtualTime, node: &NodeId) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: Some(node.clone()),
        icount: Icount { retired: at.ticks },
    }
}

pub(super) fn scheduler_event_log_payload_source(
    payload: &SchedulerEventLogPayload,
) -> EventSource {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => scheduled_event_source(event),
        SchedulerEventLogPayload::Decision(decision) => decision_source(decision),
        SchedulerEventLogPayload::Observable(observable) => observable_payload_source(observable),
        SchedulerEventLogPayload::EvaluationBoundary(_) => EventSource::Engine,
        SchedulerEventLogPayload::TriggerFired(firing) => EventSource::Scenario {
            event: firing.event().clone(),
        },
        SchedulerEventLogPayload::TriggerActionApplied(application) => EventSource::Scenario {
            event: application.event.clone(),
        },
        SchedulerEventLogPayload::FaultObservation(_) => EventSource::Engine,
        SchedulerEventLogPayload::Diagnostic(_) => EventSource::Engine,
    }
}

pub(super) fn scheduled_event_source(event: &ScheduledEvent) -> EventSource {
    match &event.payload {
        ScheduledEventPayload::Control(operation) => EventSource::Command {
            command_id: operation.sequence,
        },
        payload => scheduled_event_payload_source(payload),
    }
}

pub(super) fn scheduled_event_payload_source(payload: &ScheduledEventPayload) -> EventSource {
    match payload {
        ScheduledEventPayload::BackendInput(input) => EventSource::Node {
            node: input.node.clone(),
        },
        ScheduledEventPayload::IoCompletion(completion) => EventSource::Node {
            node: completion.target.clone(),
        },
        ScheduledEventPayload::FaultActivation(fault) => EventSource::Scenario {
            event: EventId::from_name(fault.name.clone()),
        },
        ScheduledEventPayload::ProbabilisticEffect(choice) => EventSource::Scenario {
            event: EventId::from_name(choice.fault.name.clone()),
        },
        ScheduledEventPayload::Control(operation) => EventSource::Command {
            command_id: operation.sequence,
        },
    }
}

pub(super) fn decision_source(decision: &Decision) -> EventSource {
    match decision {
        Decision::Preemption(preemption) => EventSource::Node {
            node: preemption.node.clone(),
        },
        Decision::AppRandom(random) => EventSource::Guest {
            node: random.node.clone(),
        },
        Decision::DeliveryOrder(_)
        | Decision::EffectOutcome(_)
        | Decision::RngDraw(_)
        | Decision::Override(_) => EventSource::Engine,
    }
}

pub(super) fn observable_payload_source(observable: &ObservableEventPayload) -> EventSource {
    match observable {
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::MemorySample { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => {
            EventSource::Node { node: node.clone() }
        }
        ObservableEventPayload::GuestMarker { node, .. }
        | ObservableEventPayload::CoverageMarker { node, .. }
        | ObservableEventPayload::GuestAssertionMarker { node, .. } => {
            EventSource::Guest { node: node.clone() }
        }
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. } => EventSource::Engine,
    }
}

pub(super) fn scheduler_event_log_payload_level(payload: &SchedulerEventLogPayload) -> EventLevel {
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(_) => EventLevel::Info,
        SchedulerEventLogPayload::Decision(Decision::RngDraw(_)) => EventLevel::Trace,
        SchedulerEventLogPayload::Decision(_) => EventLevel::Debug,
        SchedulerEventLogPayload::Observable(observable) => observable_payload_level(observable),
        SchedulerEventLogPayload::EvaluationBoundary(_) => EventLevel::Trace,
        SchedulerEventLogPayload::TriggerFired(_) => EventLevel::Debug,
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            trigger_action_application_level(application)
        }
        SchedulerEventLogPayload::FaultObservation(observation) => {
            fault_observation_level(observation.kind)
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.level,
    }
}

pub(super) fn observable_payload_level(observable: &ObservableEventPayload) -> EventLevel {
    match observable {
        ObservableEventPayload::CoverageBlock { .. } => EventLevel::Trace,
        ObservableEventPayload::MemorySample { .. } => EventLevel::Debug,
        ObservableEventPayload::AssertionProximity { .. } => EventLevel::Debug,
        ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::GuestMarker { .. }
        | ObservableEventPayload::GuestAssertionMarker { .. } => EventLevel::Info,
    }
}

pub(super) fn trigger_action_application_level(
    application: &TriggerActionApplication,
) -> EventLevel {
    match &application.action {
        Action::Log { level, .. } => event_level_from_trigger_log(*level),
        Action::Fail { .. } => EventLevel::Error,
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Group(_) => EventLevel::Info,
    }
}

pub(super) fn event_level_from_trigger_log(level: LogLevel) -> EventLevel {
    match level {
        LogLevel::Debug => EventLevel::Debug,
        LogLevel::Info => EventLevel::Info,
        LogLevel::Warn => EventLevel::Warn,
        LogLevel::Error => EventLevel::Error,
    }
}

pub(super) fn scheduler_event_log_source_material(prefix: &str, source: &EventSource) -> String {
    match source {
        EventSource::Scenario { event } => format!(
            "{prefix}=scenario\n{prefix}.event_len={}\n{prefix}.event={}",
            event.name.len(),
            event.name
        ),
        EventSource::Engine => format!("{prefix}=engine"),
        EventSource::Node { node } => format!(
            "{prefix}=node\n{prefix}.node_len={}\n{prefix}.node={}",
            node.name.len(),
            node.name
        ),
        EventSource::Guest { node } => format!(
            "{prefix}=guest\n{prefix}.node_len={}\n{prefix}.node={}",
            node.name.len(),
            node.name
        ),
        EventSource::Command { command_id } => {
            format!("{prefix}=command\n{prefix}.command_id={command_id}")
        }
    }
}

pub(super) fn event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

pub(super) fn assertion_quantifier_kind_label(kind: AssertionQuantifierKind) -> &'static str {
    match kind {
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

pub(super) fn event_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

pub(super) fn event_payload_material(prefix: &str, payload: &EventPayload) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{prefix}.kind_len={}", payload.kind().len()));
    lines.push(format!("{prefix}.kind={}", payload.kind()));
    lines.push(format!(
        "{prefix}.attributes={}",
        payload.attributes().len()
    ));
    for (name, value) in payload.attributes() {
        lines.push(format!("{prefix}.attribute.{name}.name_len={}", name.len()));
        lines.push(format!("{prefix}.attribute.{name}.name={name}"));
        lines.push(event_attribute_value_material(
            &format!("{prefix}.attribute.{name}.value"),
            value,
        ));
    }
    lines.join("\n")
}

pub(super) fn event_attribute_value_material(prefix: &str, value: &EventAttributeValue) -> String {
    match value {
        EventAttributeValue::Bool(value) => format!("{prefix}.type=bool\n{prefix}.value={value}"),
        EventAttributeValue::U64(value) => format!("{prefix}.type=u64\n{prefix}.value={value}"),
        EventAttributeValue::U128(value) => format!("{prefix}.type=u128\n{prefix}.value={value}"),
        EventAttributeValue::String(value) => format!(
            "{prefix}.type=string\n{prefix}.len={}\n{prefix}.value={value}",
            value.len()
        ),
        EventAttributeValue::Bytes(value) => format!(
            "{prefix}.type=bytes\n{prefix}.len={}\n{prefix}.value={}",
            value.len(),
            hex_bytes(value)
        ),
        EventAttributeValue::Node(value) => format!(
            "{prefix}.type=node\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::Event(value) => format!(
            "{prefix}.type=event\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::Fault(value) => format!(
            "{prefix}.type=fault\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::VirtualTime(value) => {
            format!("{prefix}.type=virtual-time\n{prefix}.ticks={}", value.ticks)
        }
        EventAttributeValue::Icount(value) => {
            format!("{prefix}.type=icount\n{prefix}.retired={}", value.retired)
        }
        EventAttributeValue::Level(value) => {
            format!(
                "{prefix}.type=level\n{prefix}.value={}",
                event_level_label(*value)
            )
        }
    }
}

pub(super) fn diagnostic_payload_material(diagnostic: &EventDiagnosticPayload) -> String {
    let mut lines = Vec::new();
    lines.push(format!("diagnostic.name_len={}", diagnostic.name.len()));
    lines.push(format!("diagnostic.name={}", diagnostic.name));
    lines.push(format!(
        "diagnostic.level={}",
        event_level_label(diagnostic.level)
    ));
    lines.push(event_payload_material(
        "diagnostic.event_payload",
        &diagnostic.event_payload(),
    ));
    lines.join("\n")
}

pub(super) fn fault_observation_material(observation: &FaultObservation) -> String {
    observation.canonical_material()
}

pub(super) fn fault_observation_event_payload(observation: &FaultObservation) -> EventPayload {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("semantic_version"),
        EventAttributeValue::U64(u64::from(observation.semantic_version)),
    );
    attributes.insert(
        String::from("coordinate"),
        EventAttributeValue::VirtualTime(VirtualTime {
            ticks: observation.coordinate.virtual_nanos,
        }),
    );
    if let Some(retired) = observation.coordinate.retired_instructions {
        attributes.insert(
            String::from("retired_instructions"),
            EventAttributeValue::U64(retired),
        );
    }
    if let Some(binding) = &observation.binding {
        attributes.insert(
            String::from("binding"),
            EventAttributeValue::String(binding.as_str().to_owned()),
        );
    }
    if let Some(target) = &observation.target {
        attributes.insert(
            String::from("target_kind"),
            EventAttributeValue::String(target.kind().as_str().to_owned()),
        );
        attributes.insert(
            String::from("target"),
            EventAttributeValue::String(target.canonical_material()),
        );
    }
    if let Some(opportunity) = observation.opportunity {
        attributes.insert(
            String::from("opportunity"),
            EventAttributeValue::String(opportunity.to_hex()),
        );
    }
    attributes.insert(
        String::from("evidence"),
        EventAttributeValue::String(observation.evidence.to_hex()),
    );
    EventPayload::new(observation.kind.as_str(), attributes)
}

pub(super) const fn fault_observation_level(kind: FaultObservationKind) -> EventLevel {
    match kind {
        FaultObservationKind::SignalSample | FaultObservationKind::FaultOpportunity => {
            EventLevel::Trace
        }
        FaultObservationKind::EffectChoice | FaultObservationKind::EffectCombined => {
            EventLevel::Debug
        }
        FaultObservationKind::EffectRejected => EventLevel::Error,
        FaultObservationKind::SignalTransition
        | FaultObservationKind::SignalStateTransition
        | FaultObservationKind::BindingActivation
        | FaultObservationKind::BindingDeactivation
        | FaultObservationKind::EffectApplied
        | FaultObservationKind::NetworkProfile
        | FaultObservationKind::AssociationTransition
        | FaultObservationKind::TraceAlignment => EventLevel::Info,
    }
}

pub(super) fn evaluation_boundary_kind_label(
    kind: SchedulerEvaluationBoundaryKind,
) -> &'static str {
    match kind {
        SchedulerEvaluationBoundaryKind::Quantum => "quantum",
        SchedulerEvaluationBoundaryKind::Rendezvous => "rendezvous",
    }
}

pub(super) fn preemption_kind_label(kind: &PreemptionKind) -> &'static str {
    match kind {
        PreemptionKind::VcpuSwitch { .. } => "vcpu-switch",
        PreemptionKind::InterruptAt { .. } => "interrupt-at",
    }
}

pub(super) fn trigger_action_kind_label(action: &Action) -> &'static str {
    match action {
        Action::ArmTimer { .. } => "arm-timer",
        Action::CancelTimer { .. } => "cancel-timer",
        Action::StartNode { .. } => "start-node",
        Action::StopNode { .. } => "stop-node",
        Action::CreateSavepoint { .. } => "create-savepoint",
        Action::Fork { .. } => "fork",
        Action::Pass => "pass",
        Action::Fail { .. } => "fail",
        Action::Log { .. } => "log",
        Action::Group(_) => "group",
    }
}

pub(super) fn event_kind_catalog_class_for_entry_construction(
    payload: &EventPayload,
) -> SchedulerEventLogClass {
    match event_kind_catalog_class(payload) {
        Some(class) => class,
        None => SchedulerEventLogClass::Observational,
    }
}

pub(super) fn event_kind_catalog_class(payload: &EventPayload) -> Option<SchedulerEventLogClass> {
    crate::event_catalog::event_kind_catalog_class(payload.kind())
}

pub(super) fn trigger_action_application_material(
    application: &TriggerActionApplication,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("trigger_action_sequence={}", application.sequence));
    lines.push(format!("event_len={}", application.event.name.len()));
    lines.push(format!("event={}", application.event.name));
    lines.push(format!("applied_at_ticks={}", application.at.ticks));
    lines.push(format!("path_len={}", application.path.len()));
    for (depth, index) in application.path.iter().enumerate() {
        lines.push(format!("path.{depth}={index}"));
    }
    lines.push(trigger_action_material("action", &application.action));
    lines.join("\n")
}

pub(super) fn trigger_firing_material(firing: &EventFiring) -> String {
    let mut lines = Vec::new();
    lines.push(format!("event_len={}", firing.event().name.len()));
    lines.push(format!("event={}", firing.event().name));
    lines.push(format!("fired_at_ticks={}", firing.at().ticks));
    lines.push(format!(
        "condition_summary_len={}",
        firing.condition_summary().len()
    ));
    lines.push(format!("condition_summary={}", firing.condition_summary()));
    lines.push(trigger_action_material("action", firing.action()));
    lines.join("\n")
}

pub(super) fn trigger_action_material(prefix: &str, action: &Action) -> String {
    let mut lines = Vec::new();
    match action {
        Action::ArmTimer { name, after } => {
            lines.push(format!("{prefix}.kind=arm-timer"));
            lines.push(trigger_timer_material(&format!("{prefix}.timer"), name));
            lines.push(format!("{prefix}.after_nanos={}", after.nanos));
        }
        Action::CancelTimer { name } => {
            lines.push(format!("{prefix}.kind=cancel-timer"));
            lines.push(trigger_timer_material(&format!("{prefix}.timer"), name));
        }
        Action::StartNode { node } => {
            lines.push(format!("{prefix}.kind=start-node"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        Action::StopNode { node } => {
            lines.push(format!("{prefix}.kind=stop-node"));
            lines.push(trigger_node_material(&format!("{prefix}.node"), node));
        }
        Action::CreateSavepoint { label } => {
            lines.push(format!("{prefix}.kind=create-savepoint"));
            lines.push(trigger_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Fork { label } => {
            lines.push(format!("{prefix}.kind=fork"));
            lines.push(trigger_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Pass => {
            lines.push(format!("{prefix}.kind=pass"));
        }
        Action::Fail { reason } => {
            lines.push(format!("{prefix}.kind=fail"));
            lines.push(format!("{prefix}.reason_len={}", reason.len()));
            lines.push(format!("{prefix}.reason={reason}"));
        }
        Action::Log { level, message } => {
            lines.push(format!("{prefix}.kind=log"));
            lines.push(format!(
                "{prefix}.level={}",
                trigger_log_level_label(*level)
            ));
            lines.push(format!("{prefix}.message_len={}", message.len()));
            lines.push(format!("{prefix}.message={message}"));
        }
        Action::Group(actions) => {
            lines.push(format!("{prefix}.kind=group"));
            lines.push(format!("{prefix}.actions={}", actions.len()));
            for (index, action) in actions.iter().enumerate() {
                lines.push(trigger_action_material(
                    &format!("{prefix}.action.{index}"),
                    action,
                ));
            }
        }
    }
    lines.join("\n")
}

pub(super) fn trigger_node_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}.len={}\n{prefix}={}", node.name.len(), node.name)
}

pub(super) fn trigger_timer_material(prefix: &str, timer: &TimerId) -> String {
    format!("{prefix}.len={}\n{prefix}={}", timer.name.len(), timer.name)
}

pub(super) fn trigger_optional_label_material(prefix: &str, label: &Option<String>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}.present=true\n{prefix}.len={}\n{prefix}={label}",
            label.len()
        ),
        None => format!("{prefix}.present=false"),
    }
}

pub(super) fn trigger_log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

pub(super) fn scheduler_link_ids_for_nodes(left: &NodeId, right: &NodeId) -> [LinkId; 2] {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    [
        LinkId::from_name(format!(
            "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
            endpoint_a.name.len(),
            endpoint_a.name,
            endpoint_b.name.len(),
            endpoint_b.name
        )),
        LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name)),
    ]
}

pub(super) fn instantiate_world_network_links(
    world: &World,
    shift: Shift,
) -> Result<
    BTreeMap<(LinkId, NetworkLinkDirection), WorldNetworkLinkRuntime>,
    SchedulerWorldInstantiationError,
> {
    let mut links = BTreeMap::new();
    let mut legacy_counts = BTreeMap::new();
    for definition in world.links() {
        let legacy =
            scheduler_link_ids_for_nodes(definition.endpoints().0, definition.endpoints().1)[1]
                .clone();
        let count = legacy_counts.entry(legacy).or_insert(0_usize);
        *count = count.saturating_add(1);
    }
    for (index, definition) in world.links().iter().enumerate() {
        let [canonical_id, legacy_id] =
            scheduler_link_ids_for_nodes(definition.endpoints().0, definition.endpoints().1);
        let legacy_id = (legacy_counts.get(&legacy_id) == Some(&1)).then_some(legacy_id);
        for (direction_index, direction) in [
            NetworkLinkDirection::EndpointAToEndpointB,
            NetworkLinkDirection::EndpointBToEndpointA,
        ]
        .into_iter()
        .enumerate()
        {
            let physical_index = index
                .checked_mul(2)
                .and_then(|value| value.checked_add(direction_index))
                .ok_or(SchedulerWorldInstantiationError::TooManyNetworkLinks { count: index })?;
            let source_node = u32::try_from(physical_index).map_err(|_| {
                SchedulerWorldInstantiationError::TooManyNetworkLinks {
                    count: physical_index,
                }
            })?;
            let base_faults = world_link_base_faults(definition);
            let minimum_latency = definition
                .latency()
                .nanos
                .saturating_sub(definition.jitter().nanos);
            let link = crucible_device::NetLink::new(
                shift.bits,
                source_node,
                minimum_latency,
                MIN_LINK_LATENCY.nanos,
                base_faults.clone(),
            )
            .map_err(|source| SchedulerWorldInstantiationError::Network {
                link: canonical_id.clone(),
                direction,
                source,
            })?;
            links.insert(
                (canonical_id.clone(), direction),
                WorldNetworkLinkRuntime {
                    canonical_id: canonical_id.clone(),
                    legacy_id: legacy_id.clone(),
                    endpoint_a: definition.endpoints().0.clone(),
                    endpoint_b: definition.endpoints().1.clone(),
                    direction,
                    scheduler_node: definition.scheduler_node_id(),
                    rng_stream: RngStreamId::for_link(canonical_id.name.clone()),
                    fault_id: crate::DeviceId::from_name(format!(
                        "{}\nnetwork_direction={direction:?}",
                        canonical_id.name
                    )),
                    link,
                },
            );
        }
    }
    Ok(links)
}

pub(super) fn world_link_base_faults(link: &LinkDef) -> crucible_device::LinkFaults {
    let mut faults = crucible_device::LinkFaults::none();
    faults.jitter_window_ns = link.jitter().nanos.saturating_mul(2);
    if link.loss().millionths() != 0 {
        faults.loss =
            crucible_device::Probability::new(u64::from(link.loss().millionths()), 1_000_000);
    }
    if let Some(bits_per_second) = link.bandwidth_bps() {
        faults.bandwidth_bits_per_sec.push(bits_per_second);
    }
    faults
}

pub(super) fn apply_trigger_action(
    state: &mut TriggerActionState,
    static_topology: Option<&WorldStaticTopology>,
    firing: &EventFiring,
    action: &Action,
    path: &mut Vec<u64>,
    entries: &mut Vec<TriggerActionApplication>,
) -> Result<(), SchedulerError> {
    match action {
        Action::Group(actions) => {
            for (index, action) in actions.iter().enumerate() {
                let index =
                    u64::try_from(index).map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("trigger action group index exceeds u64"),
                    })?;
                path.push(index);
                apply_trigger_action(state, static_topology, firing, action, path, entries)?;
                path.pop();
            }
            Ok(())
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {
            let sequence = u64::try_from(state.applications.len()).map_err(|_| {
                SchedulerError::BoundaryViolation {
                    message: String::from("trigger action sequence exceeds u64"),
                }
            })?;
            let application = TriggerActionApplication {
                sequence,
                event: firing.event().clone(),
                at: firing.at(),
                path: path.clone(),
                action: action.clone(),
            };
            apply_trigger_effect(state, static_topology, &application)?;
            state.applications.push(application.clone());
            entries.push(application);
            Ok(())
        }
    }
}

pub(super) fn apply_trigger_effect(
    state: &mut TriggerActionState,
    static_topology: Option<&WorldStaticTopology>,
    application: &TriggerActionApplication,
) -> Result<(), SchedulerError> {
    match &application.action {
        Action::ArmTimer { name, after } => {
            let ticks = application
                .at
                .ticks
                .checked_add(after.nanos)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "trigger timer `{}` overflows virtual time at {} + {}",
                        name.name, application.at.ticks, after.nanos
                    ),
                })?;
            state
                .armed_timers
                .insert(name.clone(), VirtualTime { ticks });
        }
        Action::CancelTimer { name } => {
            state.armed_timers.remove(name);
        }
        Action::StartNode { node } => {
            validate_trigger_node_schedule_target(static_topology, node)?;
            state
                .node_states
                .insert(node.clone(), NodeLifecycle::Started);
        }
        Action::StopNode { node } => {
            validate_trigger_node_schedule_target(static_topology, node)?;
            state
                .node_states
                .insert(node.clone(), NodeLifecycle::Exited);
        }
        Action::CreateSavepoint { label } => {
            state.savepoints.push(TriggerLabelRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                label: label.clone(),
            });
        }
        Action::Fork { label } => {
            state.forks.push(TriggerLabelRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                label: label.clone(),
            });
        }
        Action::Pass => {
            apply_trigger_verdict_effect(state, application);
        }
        Action::Fail { .. } => {
            apply_trigger_verdict_effect(state, application);
        }
        Action::Log { level, message } => {
            state.diagnostics.push(TriggerDiagnosticRecord {
                sequence: application.sequence,
                event: application.event.clone(),
                at: application.at,
                level: *level,
                message: message.clone(),
            });
        }
        Action::Group(_) => {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("trigger group action must be flattened before application"),
            });
        }
    }
    Ok(())
}

pub(super) fn apply_trigger_verdict_effect(
    state: &mut TriggerActionState,
    application: &TriggerActionApplication,
) {
    match &application.action {
        Action::Pass => {
            state.termination_requested = true;
            if !matches!(
                state.verdict.as_ref(),
                Some(verdict) if verdict.failed_reason.is_some()
            ) {
                state.verdict = Some(TriggerVerdict {
                    sequence: application.sequence,
                    event: application.event.clone(),
                    at: application.at,
                    failed_reason: None,
                });
            }
        }
        Action::Fail { reason } => {
            state.termination_requested = true;
            if !matches!(
                state.verdict.as_ref(),
                Some(verdict) if verdict.failed_reason.is_some()
            ) {
                state.verdict = Some(TriggerVerdict {
                    sequence: application.sequence,
                    event: application.event.clone(),
                    at: application.at,
                    failed_reason: Some(reason.clone()),
                });
            }
        }
        _ => {}
    }
}

pub(super) fn validate_trigger_node_schedule_target(
    static_topology: Option<&WorldStaticTopology>,
    node: &NodeId,
) -> Result<(), SchedulerError> {
    let Some(static_topology) = static_topology else {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action for `{}` has no world static topology",
                node.name
            ),
        });
    };
    if !static_topology.participants.contains(node) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action references undeclared node `{}`",
                node.name
            ),
        });
    }
    if !static_topology.bake_nodes.contains(node) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger node scheduling action references unbaked node `{}`",
                node.name
            ),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SchedulerEventLogSegmentMaterial {
    previous_prefix: ContentHash,
    pub(super) entries: Vec<SchedulerEventLogSegmentEntryMaterial>,
}

impl SchedulerEventLogSegmentMaterial {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(EVENT_LOG_SEGMENT_BINARY_MAGIC);
        bytes.extend_from_slice(&EVENT_LOG_SEGMENT_BINARY_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.previous_prefix.bytes);
        write_u64_le(&mut bytes, self.entries.len() as u64);
        for entry in &self.entries {
            write_u64_le(&mut bytes, entry.sequence);
            write_u64_le(&mut bytes, entry.at_virtual_time_ticks);
            write_u64_le(&mut bytes, entry.at_icount_retired);
            write_optional_string(&mut bytes, entry.at_icount_node.as_deref());
            write_string(&mut bytes, &entry.source_material);
            bytes.push(event_level_code(entry.level));
            bytes.push(event_class_code(entry.class));
            write_string(&mut bytes, &entry.payload_kind);
            write_u64_le(&mut bytes, entry.payload_attribute_count);
            bytes.extend_from_slice(&entry.content_hash.bytes);
            write_string(&mut bytes, &entry.entry_material);
        }
        bytes
    }

    pub(super) fn text_view(&self) -> String {
        let mut lines = Vec::new();
        lines.push(String::from(
            "format=crucible.scheduler.event-log.segment-text.v1",
        ));
        lines.push(String::from(
            "canonical_format=crucible.scheduler.event-log.segment.v1",
        ));
        lines.push(format!("schema_version={EVENT_LOG_SEGMENT_BINARY_VERSION}"));
        lines.push(format!("previous_prefix={}", self.previous_prefix.to_hex()));
        lines.push(format!("entries={}", self.entries.len()));
        for entry in &self.entries {
            lines.push(format!("entry.sequence={}", entry.sequence));
            lines.push(format!(
                "entry.at_virtual_time_ticks={}",
                entry.at_virtual_time_ticks
            ));
            lines.push(format!(
                "entry.at_icount_retired={}",
                entry.at_icount_retired
            ));
            match &entry.at_icount_node {
                Some(node) => {
                    lines.push(String::from("entry.at_icount_node=some"));
                    lines.push(format!("entry.at_icount_node_name={node}"));
                }
                None => lines.push(String::from("entry.at_icount_node=none")),
            }
            lines.push(entry.source_material.clone());
            lines.push(format!("entry.level={}", event_level_label(entry.level)));
            lines.push(format!("entry.class={}", event_class_label(entry.class)));
            lines.push(format!("entry.payload.kind={}", entry.payload_kind));
            lines.push(format!(
                "entry.payload.attributes={}",
                entry.payload_attribute_count
            ));
            lines.push(format!("entry.hash={}", entry.content_hash.to_hex()));
            lines.push(format!("entry.bytes={}", entry.entry_material.len()));
            lines.push(String::from("entry.material_begin"));
            lines.push(entry.entry_material.clone());
            lines.push(String::from("entry.material_end"));
        }
        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SchedulerEventLogSegmentEntryMaterial {
    pub(super) sequence: u64,
    pub(super) at_virtual_time_ticks: u64,
    pub(super) at_icount_retired: u64,
    pub(super) at_icount_node: Option<String>,
    pub(super) source_material: String,
    pub(super) level: EventLevel,
    pub(super) class: SchedulerEventLogClass,
    pub(super) payload_kind: String,
    pub(super) payload_attribute_count: u64,
    pub(super) content_hash: ContentHash,
    pub(super) entry_material: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SchedulerEventLogSegmentDecodeError {
    InvalidMagic,
    UnsupportedVersion { version: u32 },
    Truncated { field: &'static str },
    InvalidUtf8 { field: &'static str },
    InvalidFlag { field: &'static str, value: u8 },
    InvalidLevel { value: u8 },
    InvalidClass { value: u8 },
    LengthTooLarge { field: &'static str, len: u64 },
    TrailingBytes { remaining: usize },
}

pub(super) struct SchedulerEventLogSegmentCursor<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> SchedulerEventLogSegmentCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], SchedulerEventLogSegmentDecodeError> {
        let end = self.offset.checked_add(len).ok_or(
            SchedulerEventLogSegmentDecodeError::LengthTooLarge {
                field,
                len: len as u64,
            },
        )?;
        let Some(slice) = self.bytes.get(self.offset..end) else {
            return Err(SchedulerEventLogSegmentDecodeError::Truncated { field });
        };
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, SchedulerEventLogSegmentDecodeError> {
        Ok(self.read_exact(field, 1)?[0])
    }

    fn read_u32_le(
        &mut self,
        field: &'static str,
    ) -> Result<u32, SchedulerEventLogSegmentDecodeError> {
        let mut word = [0; 4];
        word.copy_from_slice(self.read_exact(field, 4)?);
        Ok(u32::from_le_bytes(word))
    }

    fn read_u64_le(
        &mut self,
        field: &'static str,
    ) -> Result<u64, SchedulerEventLogSegmentDecodeError> {
        let mut word = [0; 8];
        word.copy_from_slice(self.read_exact(field, 8)?);
        Ok(u64::from_le_bytes(word))
    }

    fn read_string(
        &mut self,
        field: &'static str,
    ) -> Result<String, SchedulerEventLogSegmentDecodeError> {
        let len = self.read_u64_le(field)?;
        let len = usize::try_from(len)
            .map_err(|_| SchedulerEventLogSegmentDecodeError::LengthTooLarge { field, len })?;
        let bytes = self.read_exact(field, len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| SchedulerEventLogSegmentDecodeError::InvalidUtf8 { field })
    }

    fn read_optional_string(
        &mut self,
        field: &'static str,
    ) -> Result<Option<String>, SchedulerEventLogSegmentDecodeError> {
        match self.read_u8(field)? {
            EVENT_LOG_SEGMENT_NODE_ABSENT => Ok(None),
            EVENT_LOG_SEGMENT_NODE_PRESENT => Ok(Some(self.read_string(field)?)),
            value => Err(SchedulerEventLogSegmentDecodeError::InvalidFlag { field, value }),
        }
    }

    fn read_content_hash(
        &mut self,
        field: &'static str,
    ) -> Result<ContentHash, SchedulerEventLogSegmentDecodeError> {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.read_exact(field, 32)?);
        Ok(ContentHash { bytes })
    }

    fn finish(&self) -> Result<(), SchedulerEventLogSegmentDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SchedulerEventLogSegmentDecodeError::TrailingBytes {
                remaining: self.bytes.len() - self.offset,
            })
        }
    }
}

pub(crate) fn scheduler_event_log_segment_bytes(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> Vec<u8> {
    let bytes = scheduler_event_log_segment_material(previous_prefix, entries).encode();
    debug_assert!(
        decode_scheduler_event_log_segment(&bytes)
            .map(|decoded| decoded.encode() == bytes)
            .unwrap_or(false)
    );
    bytes
}

pub(super) fn scheduler_event_log_segment_material(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> SchedulerEventLogSegmentMaterial {
    let entries = entries
        .iter()
        .map(|entry| {
            let entry_material = scheduler_event_log_entry_material(
                entry.sequence,
                &entry.at,
                &entry.source,
                entry.level,
                entry.class,
                &entry.event_payload,
                &entry.payload,
            );
            SchedulerEventLogSegmentEntryMaterial {
                sequence: entry.sequence,
                at_virtual_time_ticks: entry.at.virtual_time.ticks,
                at_icount_retired: entry.at.icount.icount.retired,
                at_icount_node: entry.at.icount.node.as_ref().map(|node| node.name.clone()),
                source_material: scheduler_event_log_source_material("entry.source", &entry.source),
                level: entry.level,
                class: entry.class,
                payload_kind: entry.event_payload.kind().to_owned(),
                payload_attribute_count: entry.event_payload.attributes().len() as u64,
                content_hash: entry.content_hash,
                entry_material,
            }
        })
        .collect();
    SchedulerEventLogSegmentMaterial {
        previous_prefix,
        entries,
    }
}

pub(super) fn decode_scheduler_event_log_segment(
    bytes: &[u8],
) -> Result<SchedulerEventLogSegmentMaterial, SchedulerEventLogSegmentDecodeError> {
    let mut cursor = SchedulerEventLogSegmentCursor::new(bytes);
    if cursor.read_exact("magic", EVENT_LOG_SEGMENT_BINARY_MAGIC.len())?
        != EVENT_LOG_SEGMENT_BINARY_MAGIC
    {
        return Err(SchedulerEventLogSegmentDecodeError::InvalidMagic);
    }
    let version = cursor.read_u32_le("version")?;
    if version != EVENT_LOG_SEGMENT_BINARY_VERSION {
        return Err(SchedulerEventLogSegmentDecodeError::UnsupportedVersion { version });
    }
    let previous_prefix = cursor.read_content_hash("previous_prefix")?;
    let entry_count = cursor.read_u64_le("entries")?;
    let entry_count = usize::try_from(entry_count).map_err(|_| {
        SchedulerEventLogSegmentDecodeError::LengthTooLarge {
            field: "entries",
            len: entry_count,
        }
    })?;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(SchedulerEventLogSegmentEntryMaterial {
            sequence: cursor.read_u64_le("entry.sequence")?,
            at_virtual_time_ticks: cursor.read_u64_le("entry.at_virtual_time_ticks")?,
            at_icount_retired: cursor.read_u64_le("entry.at_icount_retired")?,
            at_icount_node: cursor.read_optional_string("entry.at_icount_node")?,
            source_material: cursor.read_string("entry.source")?,
            level: event_level_from_code(cursor.read_u8("entry.level")?)?,
            class: event_class_from_code(cursor.read_u8("entry.class")?)?,
            payload_kind: cursor.read_string("entry.payload.kind")?,
            payload_attribute_count: cursor.read_u64_le("entry.payload.attributes")?,
            content_hash: cursor.read_content_hash("entry.hash")?,
            entry_material: cursor.read_string("entry.material")?,
        });
    }
    cursor.finish()?;
    Ok(SchedulerEventLogSegmentMaterial {
        previous_prefix,
        entries,
    })
}

pub(super) fn write_u64_le(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u64_le(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

pub(super) fn write_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(EVENT_LOG_SEGMENT_NODE_PRESENT);
            write_string(bytes, value);
        }
        None => bytes.push(EVENT_LOG_SEGMENT_NODE_ABSENT),
    }
}

pub(super) fn event_level_code(level: EventLevel) -> u8 {
    match level {
        EventLevel::Trace => EVENT_LOG_LEVEL_TRACE,
        EventLevel::Debug => EVENT_LOG_LEVEL_DEBUG,
        EventLevel::Info => EVENT_LOG_LEVEL_INFO,
        EventLevel::Warn => EVENT_LOG_LEVEL_WARN,
        EventLevel::Error => EVENT_LOG_LEVEL_ERROR,
    }
}

pub(super) fn event_level_from_code(
    value: u8,
) -> Result<EventLevel, SchedulerEventLogSegmentDecodeError> {
    match value {
        EVENT_LOG_LEVEL_TRACE => Ok(EventLevel::Trace),
        EVENT_LOG_LEVEL_DEBUG => Ok(EventLevel::Debug),
        EVENT_LOG_LEVEL_INFO => Ok(EventLevel::Info),
        EVENT_LOG_LEVEL_WARN => Ok(EventLevel::Warn),
        EVENT_LOG_LEVEL_ERROR => Ok(EventLevel::Error),
        value => Err(SchedulerEventLogSegmentDecodeError::InvalidLevel { value }),
    }
}

pub(super) fn event_class_code(class: SchedulerEventLogClass) -> u8 {
    match class {
        SchedulerEventLogClass::Causal => EVENT_LOG_CLASS_CAUSAL,
        SchedulerEventLogClass::Observational => EVENT_LOG_CLASS_OBSERVATIONAL,
    }
}

pub(super) fn event_class_from_code(
    value: u8,
) -> Result<SchedulerEventLogClass, SchedulerEventLogSegmentDecodeError> {
    match value {
        EVENT_LOG_CLASS_CAUSAL => Ok(SchedulerEventLogClass::Causal),
        EVENT_LOG_CLASS_OBSERVATIONAL => Ok(SchedulerEventLogClass::Observational),
        value => Err(SchedulerEventLogSegmentDecodeError::InvalidClass { value }),
    }
}

pub(super) fn scheduler_ordered_decisions(
    decisions: Vec<Decision>,
    fallback: SimInstant,
    shift: Shift,
    preemption_times: &[(PreemptionDecision, SimInstant)],
) -> Result<Vec<Decision>, SchedulerError> {
    let mut keyed = Vec::with_capacity(decisions.len());
    for (index, decision) in decisions.into_iter().enumerate() {
        keyed.push((
            scheduler_decision_event_log_time(&decision, fallback, shift, preemption_times)?,
            index,
            decision,
        ));
    }
    keyed.sort_by(|left, right| {
        left.0
            .ticks
            .cmp(&right.0.ticks)
            .then_with(|| left.1.cmp(&right.1))
    });

    Ok(keyed.into_iter().map(|(_, _, decision)| decision).collect())
}

pub(super) fn scheduler_decision_event_log_time(
    decision: &Decision,
    fallback: SimInstant,
    shift: Shift,
    preemption_times: &[(PreemptionDecision, SimInstant)],
) -> Result<VirtualTime, SchedulerError> {
    match decision {
        Decision::DeliveryOrder(order) => Ok(order.at),
        Decision::EffectOutcome(fault) => Ok(fault.at),
        Decision::Preemption(preemption) => {
            if let Some((_, virtual_time)) = preemption_times
                .iter()
                .find(|(decision, _)| decision == preemption)
            {
                Ok(VirtualTime {
                    ticks: virtual_time.nanos,
                })
            } else {
                Ok(VirtualTime {
                    ticks: preemption.at.to_virtual(shift)?.nanos,
                })
            }
        }
        Decision::RngDraw(_) | Decision::Override(_) | Decision::AppRandom(_) => Ok(VirtualTime {
            ticks: fallback.nanos,
        }),
    }
}

pub(super) fn scheduler_decision_material(decision: &Decision) -> String {
    let mut lines = Vec::new();
    match decision {
        Decision::DeliveryOrder(order) => {
            lines.push(String::from("decision=delivery-order"));
            lines.push(format!("decision_at={}", order.at.ticks));
            lines.push(format!("decision_events={}", order.order.len()));
            for event in &order.order {
                lines.push(format!("event_time={}", event.virtual_time.ticks));
                lines.push(format!(
                    "event_consumer:\n{}",
                    scheduler_node_material(&event.consumer)
                ));
                lines.push(format!(
                    "event_producer:\n{}",
                    scheduler_node_material(&event.producer)
                ));
                lines.push(format!("event_sequence={}", event.sequence));
            }
        }
        Decision::EffectOutcome(fault) => {
            lines.push(String::from("decision=effect-outcome"));
            lines.push(format!("decision_at={}", fault.at.ticks));
            lines.push(format!("fault_name_len={}", fault.fault.name.len()));
            lines.push(format!("fault_name={}", fault.fault.name));
            lines.push(format!("fired={}", fault.fired));
        }
        Decision::RngDraw(draw) => {
            lines.push(String::from("decision=rng-draw"));
            lines.push(format!("stream_domain_len={}", draw.stream.domain.len()));
            lines.push(format!("stream_domain={}", draw.stream.domain));
            lines.push(format!("stream_name_len={}", draw.stream.name.len()));
            lines.push(format!("stream_name={}", draw.stream.name));
            lines.push(format!("value={}", draw.value));
        }
        Decision::Override(override_decision) => {
            lines.push(String::from("decision=override"));
            lines.push(format!("point_len={}", override_decision.point.key.len()));
            lines.push(format!("point={}", override_decision.point.key));
            lines.push(format!(
                "choice_len={}",
                override_decision.choice.name.len()
            ));
            lines.push(format!("choice={}", override_decision.choice.name));
        }
        Decision::Preemption(preemption) => {
            lines.push(String::from("decision=preemption"));
            lines.push(format!("node_len={}", preemption.node.name.len()));
            lines.push(format!("node={}", preemption.node.name));
            lines.push(format!("at_retired={}", preemption.at.retired));
            match &preemption.kind {
                PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                    lines.push(String::from("preemption_kind=vcpu-switch"));
                    lines.push(format!("from_vcpu={}", from_vcpu.index));
                    lines.push(format!("to_vcpu={}", to_vcpu.index));
                }
                PreemptionKind::InterruptAt { target_vcpu, irq } => {
                    lines.push(String::from("preemption_kind=interrupt-at"));
                    lines.push(format!("target_vcpu={}", target_vcpu.index));
                    lines.push(format!("irq={}", irq.vector));
                }
            }
        }
        Decision::AppRandom(random) => {
            lines.push(String::from("decision=app-random"));
            lines.push(format!("node_len={}", random.node.name.len()));
            lines.push(format!("node={}", random.node.name));
            lines.push(format!("stream_domain_len={}", random.stream.domain.len()));
            lines.push(format!("stream_domain={}", random.stream.domain));
            lines.push(format!("stream_name_len={}", random.stream.name.len()));
            lines.push(format!("stream_name={}", random.stream.name));
            lines.push(format!("request_id={}", random.request_id));
            lines.push(format!("width={}", random.width));
            lines.push(format!("value={}", random.value));
        }
    }
    lines.join("\n")
}
