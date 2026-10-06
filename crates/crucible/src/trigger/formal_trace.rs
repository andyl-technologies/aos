//! Borrowed canonical external trace projections and exact admitted output.
//!
//! Each projection writes directly into its caller. Nested prefixes, hexadecimal
//! bytes and recursive actions stay borrowed; no intermediate material is owned.

use super::*;
use std::fmt::{self, Display, Write};

mod observable;
use observable::external_observable_event_payload_material;

struct Render<F>(F);

impl<F: Fn(&mut dyn Write) -> fmt::Result> Display for Render<F> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(output)
    }
}

struct Lines<'a> {
    output: &'a mut dyn Write,
    first: bool,
}

impl<'a> Lines<'a> {
    fn new(output: &'a mut dyn Write) -> Self {
        Self {
            output,
            first: true,
        }
    }

    fn push(&mut self, value: impl Display) -> fmt::Result {
        if !self.first {
            self.output.write_char('\n')?;
        }
        self.first = false;
        write!(self.output, "{value}")
    }
}

struct Hex<'a>(&'a [u8]);

impl Display for Hex<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(super) fn external_formal_trace_bytes(
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<u8>, EngineError> {
    crate::owned_decode::display_string(&external_formal_trace_display(entries))
        .map(String::into_bytes)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

pub(super) fn external_formal_trace_hash(
    entries: &[SchedulerEventLogEntry],
) -> Result<ContentHash, EngineError> {
    struct HashOutput(blake3::Hasher);
    impl Write for HashOutput {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            self.0.update(value.as_bytes());
            Ok(())
        }
    }
    let budget = crate::owned_decode::current_budget();
    let _scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_bytes(std::mem::size_of::<HashOutput>() as u64))
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let mut output = HashOutput(blake3::Hasher::new());
    write!(&mut output, "{}", external_formal_trace_display(entries)).map_err(|source| {
        EngineError::ArtifactDecodeAdmission {
            source: crate::owned_decode::DecodeAdmissionError::new(source),
        }
    })?;
    Ok(ContentHash {
        bytes: *output.0.finalize().as_bytes(),
    })
}

pub(super) fn external_formal_trace_display<'a>(
    entries: &'a [SchedulerEventLogEntry],
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push("format=crucible.external-formal-trace.v1")?;
        lines.push(format_args!(
            "scheduler_event_log_previous_prefix={}",
            Hex(&scheduler_event_log_empty_prefix().bytes)
        ))?;
        lines.push(format_args!("entries={}", entries.len()))?;
        for entry in entries {
            lines.push(external_formal_trace_entry_material(entry))?;
        }
        Ok(())
    })
}

pub(super) fn external_formal_trace_entry_material<'a>(
    entry: &'a SchedulerEventLogEntry,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push("entry_begin")?;
        lines.push(format_args!("entry.sequence={}", entry.sequence()))?;
        lines.push(format_args!("entry.at_ticks={}", entry.at().ticks))?;
        lines.push(format_args!(
            "entry.class={}",
            external_scheduler_event_log_class_label(entry.class())
        ))?;
        lines.push(format_args!(
            "entry.hash={}",
            Hex(&entry.content_hash().bytes)
        ))?;
        lines.push("entry.payload_begin")?;
        lines.push(external_scheduler_event_log_payload_material(
            entry.payload(),
        ))?;
        lines.push("entry.payload_end")?;
        lines.push("entry_end")?;
        Ok(())
    })
}

pub(super) fn external_scheduler_event_log_class_label(
    class: SchedulerEventLogClass,
) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

pub(super) fn external_scheduler_event_log_payload_material<'a>(
    payload: &'a SchedulerEventLogPayload,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match payload {
            SchedulerEventLogPayload::ResolvedHappening(event) => {
                lines.push("payload=resolved-happening")?;
                lines.push(external_scheduled_event_material(event))?;
            }
            SchedulerEventLogPayload::Decision(decision) => {
                lines.push("payload=decision")?;
                lines.push(external_decision_material(decision))?;
            }
            SchedulerEventLogPayload::Observable(observable) => {
                lines.push("payload=observable")?;
                lines.push(external_observable_event_payload_material(observable))?;
            }
            SchedulerEventLogPayload::EvaluationBoundary(kind) => {
                lines.push("payload=evaluation-boundary")?;
                lines.push(format_args!(
                    "boundary.kind={}",
                    external_scheduler_evaluation_boundary_kind_label(*kind)
                ))?;
            }
            SchedulerEventLogPayload::TriggerFired(firing) => {
                lines.push("payload=trigger-fired")?;
                lines.push(external_event_firing_material(firing))?;
            }
            SchedulerEventLogPayload::TriggerActionApplied(application) => {
                lines.push("payload=trigger-action-applied")?;
                lines.push(external_trigger_action_application_material(application))?;
            }
            SchedulerEventLogPayload::FaultObservation(observation) => {
                lines.push("payload=fault-observation")?;
                lines.push(observation.canonical_display())?;
            }
            SchedulerEventLogPayload::Diagnostic(diagnostic) => {
                lines.push("payload=diagnostic")?;
                lines.push(external_string_material(
                    &"diagnostic.name",
                    &diagnostic.name,
                ))?;
                lines.push(format_args!(
                    "diagnostic.level={}",
                    external_event_level_label(diagnostic.level)
                ))?;
                lines.push(format_args!(
                    "diagnostic.details={}",
                    diagnostic.details.len()
                ))?;
                for (index, (name, value)) in diagnostic.details.iter().enumerate() {
                    lines.push(external_string_material(
                        &format_args!("diagnostic.detail.{index}.name"),
                        name,
                    ))?;
                    lines.push(external_event_attribute_value_material(
                        &format_args!("diagnostic.detail.{index}.value"),
                        value,
                    ))?;
                }
            }
        }
        Ok(())
    })
}

pub(super) fn external_event_attribute_value_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    value: &'a EventAttributeValue,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match value {
            EventAttributeValue::Bool(value) => {
                lines.push(format_args!("{prefix}.type=bool"))?;
                lines.push(format_args!("{prefix}.bool={value}"))?;
            }
            EventAttributeValue::U64(value) => {
                lines.push(format_args!("{prefix}.type=u64"))?;
                lines.push(format_args!("{prefix}.u64={value}"))?;
            }
            EventAttributeValue::U128(value) => {
                lines.push(format_args!("{prefix}.type=u128"))?;
                lines.push(format_args!("{prefix}.u128={value}"))?;
            }
            EventAttributeValue::String(value) => {
                lines.push(format_args!("{prefix}.type=string"))?;
                lines.push(external_string_material(
                    &format_args!("{prefix}.string"),
                    value,
                ))?;
            }
            EventAttributeValue::Bytes(value) => {
                lines.push(format_args!("{prefix}.type=bytes"))?;
                lines.push(format_args!("{prefix}.bytes_len={}", value.len()))?;
                lines.push(format_args!("{prefix}.bytes={}", Hex(value)))?;
            }
            EventAttributeValue::Node(value) => {
                lines.push(format_args!("{prefix}.type=node"))?;
                lines.push(external_node_id_material(
                    &format_args!("{prefix}.node"),
                    value,
                ))?;
            }
            EventAttributeValue::Event(value) => {
                lines.push(format_args!("{prefix}.type=event"))?;
                lines.push(external_event_id_material(
                    &format_args!("{prefix}.event"),
                    value,
                ))?;
            }
            EventAttributeValue::VirtualTime(value) => {
                lines.push(format_args!("{prefix}.type=virtual-time"))?;
                lines.push(format_args!("{prefix}.ticks={}", value.ticks))?;
            }
            EventAttributeValue::Icount(value) => {
                lines.push(format_args!("{prefix}.type=icount"))?;
                lines.push(format_args!("{prefix}.retired={}", value.retired))?;
            }
            EventAttributeValue::Level(value) => {
                lines.push(format_args!("{prefix}.type=level"))?;
                lines.push(format_args!(
                    "{prefix}.level={}",
                    external_event_level_label(*value)
                ))?;
            }
        }
        Ok(())
    })
}

pub(super) fn external_scheduled_event_material<'a>(
    event: &'a ScheduledEvent,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push(external_scheduled_event_key_material(&event.key))?;
        lines.push(format_args!(
            "event.resolve_class={}",
            external_scheduled_event_resolve_class_label(scheduled_event_resolve_class(event))
        ))?;
        lines.push(external_scheduled_event_payload_material(&event.payload))?;
        Ok(())
    })
}

pub(super) fn external_scheduled_event_key_material<'a>(
    key: &'a ScheduledEventKey,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!(
            "event.time_ticks={}",
            key.virtual_time().ticks
        ))?;
        lines.push(external_scheduler_node_material(
            &"event.consumer",
            key.consumer(),
        ))?;
        lines.push(external_scheduler_node_material(
            &"event.producer",
            key.producer(),
        ))?;
        lines.push(format_args!("event.sequence={}", key.sequence()))?;
        Ok(())
    })
}

pub(super) fn external_scheduled_event_payload_material<'a>(
    payload: &'a ScheduledEventPayload,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match payload {
            ScheduledEventPayload::BackendInput(input) => {
                lines.push("event.payload=backend-input")?;
                lines.push(external_node_id_material(
                    &"event.payload.node",
                    &input.node,
                ))?;
                lines.push(format_args!("event.payload.bytes={}", Hex(&input.payload)))?;
            }
            ScheduledEventPayload::IoCompletion(completion) => {
                lines.push("event.payload=io-completion")?;
                lines.push(external_scheduler_node_material(
                    &"event.payload.sub_node",
                    &completion.sub_node,
                ))?;
                lines.push(external_node_id_material(
                    &"event.payload.target",
                    &completion.target,
                ))?;
                lines.push(format_args!(
                    "event.payload.delivery_tick={}",
                    completion.delivery_tick.ticks
                ))?;
                lines.push(format_args!(
                    "event.payload.bytes={}",
                    Hex(&completion.payload)
                ))?;
            }
            ScheduledEventPayload::Control(operation) => {
                lines.push("event.payload=control")?;
                lines.push(format_args!(
                    "event.payload.control.sequence={}",
                    operation.sequence
                ))?;
                lines.push(external_control_operation_kind_material(
                    &"event.payload.control.kind",
                    &operation.kind,
                ))?;
            }
        }
        Ok(())
    })
}

pub(super) fn external_decision_material<'a>(
    decision: &'a Decision,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        use Decision as D;

        let mut lines = Lines::new(out);
        match decision {
            D::DeliveryOrder(order) => {
                lines.push("decision=delivery-order")?;
                lines.push(format_args!("decision.at_ticks={}", order.at.ticks))?;
                lines.push(format_args!("decision.events={}", order.order.len()))?;
                for (index, event) in order.order.iter().enumerate() {
                    lines.push(external_event_key_material(
                        &format_args!("decision.event.{index}"),
                        event,
                    ))?;
                }
            }
            D::RngDraw(draw) => {
                lines.push("decision=rng-draw")?;
                lines.push(external_rng_stream_material(
                    &"decision.stream",
                    &draw.stream,
                ))?;
                lines.push(format_args!("decision.value={}", draw.value))?;
            }
            D::Override(override_decision) => {
                lines.push("decision=override")?;
                lines.push(external_string_material(
                    &"decision.point",
                    &override_decision.point.key,
                ))?;
                lines.push(external_string_material(
                    &"decision.choice",
                    &override_decision.choice.name,
                ))?;
            }
            D::Preemption(preemption) => {
                lines.push("decision=preemption")?;
                lines.push(external_node_id_material(
                    &"decision.node",
                    &preemption.node,
                ))?;
                lines.push(format_args!("decision.at_tick={}", preemption.at.ticks))?;
                lines.push(external_preemption_kind_material(
                    &"decision.preemption",
                    &preemption.kind,
                ))?;
            }
            D::Selection(selection) => {
                lines.push("decision=campaign-selection")?;
                lines.push(format_args!(
                    "decision.canonical_selection={}",
                    Hex(selection.canonical_bytes())
                ))?;
            }
        }
        Ok(())
    })
}

pub(super) fn external_event_firing_material<'a>(
    firing: &'a EventFiring,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push(external_event_id_material(&"firing.event", firing.event()))?;
        lines.push(format_args!("firing.at_ticks={}", firing.at().ticks))?;
        lines.push(external_action_material(&"firing.action", firing.action()))?;
        Ok(())
    })
}

pub(super) fn external_trigger_action_application_material<'a>(
    application: &'a TriggerActionApplication,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!(
            "application.sequence={}",
            application.sequence
        ))?;
        lines.push(external_event_id_material(
            &"application.event",
            &application.event,
        ))?;
        lines.push(format_args!(
            "application.at_ticks={}",
            application.at.ticks
        ))?;
        lines.push(format_args!(
            "application.path_len={}",
            application.path.len()
        ))?;
        for (index, path) in application.path.iter().enumerate() {
            lines.push(format_args!("application.path.{index}={path}"))?;
        }
        lines.push(external_action_material(
            &"application.action",
            &application.action,
        ))?;
        Ok(())
    })
}

pub(super) fn external_action_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    action: &'a Action,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match action {
            Action::ArmTimer { name, after } => {
                lines.push(format_args!("{prefix}=arm-timer"))?;
                lines.push(external_timer_id_material(
                    &format_args!("{prefix}.timer"),
                    name,
                ))?;
                lines.push(format_args!("{prefix}.after_nanos={}", after.ticks))?;
            }
            Action::CancelTimer { name } => {
                lines.push(format_args!("{prefix}=cancel-timer"))?;
                lines.push(external_timer_id_material(
                    &format_args!("{prefix}.timer"),
                    name,
                ))?;
            }
            Action::StartNode { node } => {
                lines.push(format_args!("{prefix}=start-node"))?;
                lines.push(external_node_id_material(
                    &format_args!("{prefix}.node"),
                    node,
                ))?;
            }
            Action::StopNode { node } => {
                lines.push(format_args!("{prefix}=stop-node"))?;
                lines.push(external_node_id_material(
                    &format_args!("{prefix}.node"),
                    node,
                ))?;
            }
            Action::CreateSavepoint { label } => {
                lines.push(format_args!("{prefix}=create-savepoint"))?;
                lines.push(external_optional_label_material(
                    &format_args!("{prefix}.label"),
                    label,
                ))?;
            }
            Action::Fork { label } => {
                lines.push(format_args!("{prefix}=fork"))?;
                lines.push(external_optional_label_material(
                    &format_args!("{prefix}.label"),
                    label,
                ))?;
            }
            Action::Pass => {
                lines.push(format_args!("{prefix}=pass"))?;
            }
            Action::Fail { reason } => {
                lines.push(format_args!("{prefix}=fail"))?;
                lines.push(external_string_material(
                    &format_args!("{prefix}.reason"),
                    reason,
                ))?;
            }
            Action::Log { level, message } => {
                lines.push(format_args!("{prefix}=log"))?;
                lines.push(format_args!(
                    "{prefix}.level={}",
                    external_log_level_label(*level)
                ))?;
                lines.push(external_string_material(
                    &format_args!("{prefix}.message"),
                    message,
                ))?;
            }
            Action::Group(actions) => {
                lines.push(format_args!("{prefix}=group"))?;
                lines.push(format_args!("{prefix}.actions={}", actions.len()))?;
                for (index, action) in actions.iter().enumerate() {
                    lines.push(external_action_material(
                        &format_args!("{prefix}.action.{index}"),
                        action,
                    ))?;
                }
            }
        }
        Ok(())
    })
}

pub(super) fn external_control_operation_kind_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    kind: &'a ControlOperationKind,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match kind {
            ControlOperationKind::Pause => lines.push(format_args!("{prefix}=pause"))?,
            ControlOperationKind::Resume => lines.push(format_args!("{prefix}=resume"))?,
            ControlOperationKind::Step => lines.push(format_args!("{prefix}=step"))?,
            ControlOperationKind::Snapshot => lines.push(format_args!("{prefix}=snapshot"))?,
            ControlOperationKind::Fork => lines.push(format_args!("{prefix}=fork"))?,
            ControlOperationKind::Query => lines.push(format_args!("{prefix}=query"))?,
        }
        Ok(())
    })
}

pub(super) fn external_event_key_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    key: &'a EventKey,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!(
            "{prefix}.time_ticks={}",
            key.virtual_time.ticks
        ))?;
        lines.push(external_scheduler_node_material(
            &format_args!("{prefix}.consumer"),
            &key.consumer,
        ))?;
        lines.push(external_scheduler_node_material(
            &format_args!("{prefix}.producer"),
            &key.producer,
        ))?;
        lines.push(format_args!("{prefix}.sequence={}", key.sequence))?;
        Ok(())
    })
}

pub(super) fn external_scheduler_node_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    node: &'a SchedulerNodeId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(
            out,
            "{}",
            format_args!(
                "{}\n{prefix}.kind={}",
                external_node_id_material(&format_args!("{prefix}.node"), &node.node),
                external_scheduling_node_kind_label(node.kind)
            )
        )
    })
}

pub(super) fn external_node_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    node: &'a NodeId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &node.name))
    })
}

pub(super) fn external_event_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    id: &'a EventId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &id.name))
    })
}

pub(super) fn external_assertion_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    id: &'a AssertionId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &id.name))
    })
}

pub(super) fn external_marker_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    id: &'a MarkerId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &id.name))
    })
}

pub(super) fn external_timer_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    id: &'a TimerId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &id.name))
    })
}

pub(super) fn external_rng_stream_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    stream: &'a RngStreamId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(
            out,
            "{}",
            format_args!(
                "{}\n{}",
                external_string_material(&format_args!("{prefix}.domain"), &stream.domain),
                external_string_material(&format_args!("{prefix}.name"), &stream.name)
            )
        )
    })
}

pub(super) fn external_optional_label_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    label: &'a Option<String>,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| match label {
        Some(label) => write!(
            out,
            "{prefix}.present=true\n{}",
            external_string_material(prefix, label)
        ),
        None => write!(out, "{prefix}.present=false"),
    })
}

pub(super) fn external_optional_link_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    link: &'a Option<LinkId>,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| match link {
        Some(link) => write!(
            out,
            "{prefix}.present=true\n{}",
            external_link_id_material(prefix, link)
        ),
        None => write!(out, "{prefix}.present=false"),
    })
}

pub(super) fn external_optional_node_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    node: &'a Option<NodeId>,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| match node {
        Some(node) => write!(
            out,
            "{prefix}.present=true\n{}",
            external_node_id_material(prefix, node)
        ),
        None => write!(out, "{prefix}.present=false"),
    })
}

pub(super) fn external_link_id_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    id: &'a LinkId,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(out, "{}", external_string_material(prefix, &id.name))
    })
}

pub(super) fn external_resolved_mem_place_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    place: &'a ResolvedMemPlace,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            write!(
                out,
                "{prefix}=physical-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}"
            )
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            write!(
                out,
                "{prefix}=virtual-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}"
            )
        }
        ResolvedMemPlace::Register { name, bytes } => write!(
            out,
            "{prefix}=register\n{}\n{prefix}.bytes={bytes}",
            external_string_material(&format_args!("{prefix}.name"), name)
        ),
    })
}

pub(super) fn external_string_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    value: &'a str,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        write!(
            out,
            "{}",
            format_args!(
                "{prefix}.bytes_len={}\n{prefix}.bytes={}",
                value.len(),
                Hex(value.as_bytes())
            )
        )
    })
}

pub(super) fn external_preemption_kind_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    kind: &'a PreemptionKind,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => write!(
            out,
            "{prefix}=vcpu-switch\n{prefix}.from_vcpu={}\n{prefix}.to_vcpu={}",
            from_vcpu.index, to_vcpu.index
        ),
        PreemptionKind::InterruptAt { target_vcpu, irq } => write!(
            out,
            "{prefix}=interrupt-at\n{prefix}.target_vcpu={}\n{prefix}.irq={}",
            target_vcpu.index, irq.vector
        ),
    })
}

#[cfg(test)]
mod tests;
