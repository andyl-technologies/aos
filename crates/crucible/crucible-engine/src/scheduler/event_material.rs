//! Borrowed event identity projections with exact canonical line and byte ordering.
//!
//! Recursive actions, prefixed keys and hexadecimal payloads render directly into
//! the caller. Owning output and semantic hashing share these format definitions.

use super::*;
use std::fmt::{self, Display, Write};

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

pub(super) fn scheduler_event_log_entry_material<'a>(
    sequence: u64,
    at: &'a EventLogTime,
    source: &'a EventSource,
    level: EventLevel,
    class: SchedulerEventLogClass,
    event_payload: &'a EventPayload,
    payload: &'a SchedulerEventLogPayload,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!("sequence={sequence}"))?;
        lines.push(format_args!(
            "at_virtual_time_ticks={}",
            at.virtual_time.ticks
        ))?;
        lines.push(format_args!("at_tick={}", at.stamp.tick.ticks))?;
        match at.stamp.retired {
            Some(retired) => lines.push(format_args!("at_raw_retired={}", retired.retired))?,
            None => lines.push("at_raw_retired=none")?,
        }
        match &at.stamp.node {
            Some(node) => {
                lines.push("at_node=some")?;
                lines.push(format_args!("at_node_len={}", node.name.len()))?;
                lines.push(format_args!("at_node_name={}", node.name))?;
            }
            None => lines.push("at_node=none")?,
        }
        lines.push(scheduler_event_log_source_material("source", source))?;
        lines.push(format_args!("level={}", event_level_label(level)))?;
        lines.push(format_args!("class={}", event_class_label(class)))?;
        lines.push(event_payload_material("event_payload", event_payload))?;
        match payload {
            SchedulerEventLogPayload::ResolvedHappening(event) => {
                lines.push("payload=resolved-happening")?;
                lines.push(scheduled_event_material(event))?;
            }
            SchedulerEventLogPayload::Decision(decision) => {
                lines.push("payload=decision")?;
                lines.push(scheduler_decision_material(decision))?;
            }
            SchedulerEventLogPayload::Observable(observable) => {
                lines.push("payload=observable")?;
                lines.push(format_args!("observable={observable:?}"))?;
            }
            SchedulerEventLogPayload::EvaluationBoundary(kind) => {
                lines.push("payload=evaluation-boundary")?;
                lines.push(format_args!("kind={kind:?}"))?;
            }
            SchedulerEventLogPayload::TriggerFired(firing) => {
                lines.push("payload=trigger_fired")?;
                lines.push(trigger_firing_material(firing))?;
            }
            SchedulerEventLogPayload::TriggerActionApplied(application) => {
                lines.push("payload=trigger_action_applied")?;
                lines.push(trigger_action_application_material(application))?;
            }
            SchedulerEventLogPayload::FaultObservation(observation) => {
                lines.push("payload=fault_observation")?;
                lines.push(fault_observation_material(observation))?;
            }
            SchedulerEventLogPayload::Diagnostic(diagnostic) => {
                lines.push("payload=diagnostic")?;
                lines.push(diagnostic_payload_material(diagnostic))?;
            }
        }
        Ok(())
    })
}

pub(super) fn event_payload_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    payload: &'a EventPayload,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!("{prefix}.kind_len={}", payload.kind().len()))?;
        lines.push(format_args!("{prefix}.kind={}", payload.kind()))?;
        lines.push(format_args!(
            "{prefix}.attributes={}",
            payload.attributes().len()
        ))?;
        for (name, value) in payload.attributes() {
            lines.push(format_args!(
                "{prefix}.attribute.{name}.name_len={}",
                name.len()
            ))?;
            lines.push(format_args!("{prefix}.attribute.{name}.name={name}"))?;
            lines.push(event_attribute_value_material(
                &format_args!("{prefix}.attribute.{name}.value"),
                value,
            ))?;
        }
        Ok(())
    })
}

pub(super) fn diagnostic_payload_material<'a>(
    diagnostic: &'a EventDiagnosticPayload,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!(
            "diagnostic.name_len={}",
            diagnostic.name.len()
        ))?;
        lines.push(format_args!("diagnostic.name={}", diagnostic.name))?;
        lines.push(format_args!(
            "diagnostic.level={}",
            event_level_label(diagnostic.level)
        ))?;
        lines.push(diagnostic_event_payload_material(diagnostic))?;
        Ok(())
    })
}

pub(super) fn trigger_action_application_material<'a>(
    application: &'a TriggerActionApplication,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!(
            "trigger_action_sequence={}",
            application.sequence
        ))?;
        lines.push(format_args!("event_len={}", application.event.name.len()))?;
        lines.push(format_args!("event={}", application.event.name))?;
        lines.push(format_args!("applied_at_ticks={}", application.at.ticks))?;
        lines.push(format_args!("path_len={}", application.path.len()))?;
        for (depth, index) in application.path.iter().enumerate() {
            lines.push(format_args!("path.{depth}={index}"))?;
        }
        lines.push(trigger_action_material("action", &application.action))?;
        Ok(())
    })
}

pub(super) fn trigger_firing_material<'a>(firing: &'a EventFiring) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!("event_len={}", firing.event().name.len()))?;
        lines.push(format_args!("event={}", firing.event().name))?;
        lines.push(format_args!("fired_at_ticks={}", firing.at().ticks))?;
        lines.push(format_args!(
            "condition_summary_len={}",
            firing.condition_summary().len()
        ))?;
        lines.push(format_args!(
            "condition_summary={}",
            firing.condition_summary()
        ))?;
        lines.push(trigger_action_material("action", firing.action()))?;
        Ok(())
    })
}

pub(super) fn trigger_action_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    action: &'a Action,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        match action {
            Action::ArmTimer { name, after } => {
                lines.push(format_args!("{prefix}.kind=arm-timer"))?;
                lines.push(trigger_timer_material(
                    &format_args!("{prefix}.timer"),
                    name,
                ))?;
                lines.push(format_args!("{prefix}.after_ticks={}", after.ticks))?;
            }
            Action::CancelTimer { name } => {
                lines.push(format_args!("{prefix}.kind=cancel-timer"))?;
                lines.push(trigger_timer_material(
                    &format_args!("{prefix}.timer"),
                    name,
                ))?;
            }
            Action::StartNode { node } => {
                lines.push(format_args!("{prefix}.kind=start-node"))?;
                lines.push(trigger_node_material(&format_args!("{prefix}.node"), node))?;
            }
            Action::StopNode { node } => {
                lines.push(format_args!("{prefix}.kind=stop-node"))?;
                lines.push(trigger_node_material(&format_args!("{prefix}.node"), node))?;
            }
            Action::CreateSavepoint { label } => {
                lines.push(format_args!("{prefix}.kind=create-savepoint"))?;
                lines.push(trigger_optional_label_material(
                    &format_args!("{prefix}.label"),
                    label,
                ))?;
            }
            Action::Fork { label } => {
                lines.push(format_args!("{prefix}.kind=fork"))?;
                lines.push(trigger_optional_label_material(
                    &format_args!("{prefix}.label"),
                    label,
                ))?;
            }
            Action::Pass => {
                lines.push(format_args!("{prefix}.kind=pass"))?;
            }
            Action::Fail { reason } => {
                lines.push(format_args!("{prefix}.kind=fail"))?;
                lines.push(format_args!("{prefix}.reason_len={}", reason.len()))?;
                lines.push(format_args!("{prefix}.reason={reason}"))?;
            }
            Action::Log { level, message } => {
                lines.push(format_args!("{prefix}.kind=log"))?;
                lines.push(format_args!(
                    "{prefix}.level={}",
                    trigger_log_level_label(*level)
                ))?;
                lines.push(format_args!("{prefix}.message_len={}", message.len()))?;
                lines.push(format_args!("{prefix}.message={message}"))?;
            }
            Action::Group(actions) => {
                lines.push(format_args!("{prefix}.kind=group"))?;
                lines.push(format_args!("{prefix}.actions={}", actions.len()))?;
                for (index, action) in actions.iter().enumerate() {
                    lines.push(trigger_action_material(
                        &format_args!("{prefix}.action.{index}"),
                        action,
                    ))?;
                }
            }
        }
        Ok(())
    })
}

pub(super) fn scheduler_decision_material<'a>(decision: &'a Decision) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        match decision {
            Decision::DeliveryOrder(order) => {
                lines.push("decision=delivery-order")?;
                lines.push(format_args!("decision_at={}", order.at.ticks))?;
                lines.push(format_args!("decision_events={}", order.order.len()))?;
                for event in &order.order {
                    lines.push(format_args!("event_time={}", event.virtual_time.ticks))?;
                    lines.push(format_args!(
                        "event_consumer:\n{}",
                        scheduler_node_material(&event.consumer)
                    ))?;
                    lines.push(format_args!(
                        "event_producer:\n{}",
                        scheduler_node_material(&event.producer)
                    ))?;
                    lines.push(format_args!("event_sequence={}", event.sequence))?;
                }
            }
            Decision::RngDraw(draw) => {
                lines.push("decision=rng-draw")?;
                lines.push(format_args!(
                    "stream_domain_len={}",
                    draw.stream.domain.len()
                ))?;
                lines.push(format_args!("stream_domain={}", draw.stream.domain))?;
                lines.push(format_args!("stream_name_len={}", draw.stream.name.len()))?;
                lines.push(format_args!("stream_name={}", draw.stream.name))?;
                lines.push(format_args!("value={}", draw.value))?;
            }
            Decision::Override(override_decision) => {
                lines.push("decision=override")?;
                lines.push(format_args!(
                    "point_len={}",
                    override_decision.point.key.len()
                ))?;
                lines.push(format_args!("point={}", override_decision.point.key))?;
                lines.push(format_args!(
                    "choice_len={}",
                    override_decision.choice.name.len()
                ))?;
                lines.push(format_args!("choice={}", override_decision.choice.name))?;
            }
            Decision::Preemption(preemption) => {
                lines.push("decision=preemption")?;
                lines.push(format_args!("node_len={}", preemption.node.name.len()))?;
                lines.push(format_args!("node={}", preemption.node.name))?;
                lines.push(format_args!("at_tick={}", preemption.at.ticks))?;
                match &preemption.kind {
                    PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                        lines.push("preemption_kind=vcpu-switch")?;
                        lines.push(format_args!("from_vcpu={}", from_vcpu.index))?;
                        lines.push(format_args!("to_vcpu={}", to_vcpu.index))?;
                    }
                    PreemptionKind::InterruptAt { target_vcpu, irq } => {
                        lines.push("preemption_kind=interrupt-at")?;
                        lines.push(format_args!("target_vcpu={}", target_vcpu.index))?;
                        lines.push(format_args!("irq={}", irq.vector))?;
                    }
                }
            }
            Decision::Selection(selection) => {
                lines.push("decision=campaign-selection")?;
                lines.push(format_args!(
                    "canonical_selection={}",
                    Hex(selection.canonical_bytes())
                ))?;
            }
        }
        Ok(())
    })
}

pub(super) fn scheduler_event_log_source_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    source: &'a EventSource,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| match source {
        EventSource::Scenario { event } => write!(
            out,
            "{prefix}=scenario\n{prefix}.event_len={}\n{prefix}.event={}",
            event.name.len(),
            event.name
        ),
        EventSource::Engine => write!(out, "{prefix}=engine"),
        EventSource::Node { node } => write!(
            out,
            "{}",
            scheduler_event_log_node_source_material(prefix, &node.name)
        ),
        EventSource::Guest { node } => write!(
            out,
            "{prefix}=guest\n{prefix}.node_len={}\n{prefix}.node={}",
            node.name.len(),
            node.name
        ),
        EventSource::Command { command_id } => {
            write!(out, "{prefix}=command\n{prefix}.command_id={command_id}")
        }
    })
}

pub(super) fn event_attribute_value_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    value: &'a EventAttributeValue,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| match value {
        EventAttributeValue::Bool(value) => {
            write!(out, "{prefix}.type=bool\n{prefix}.value={value}")
        }
        EventAttributeValue::U64(value) => write!(out, "{prefix}.type=u64\n{prefix}.value={value}"),
        EventAttributeValue::U128(value) => {
            write!(out, "{prefix}.type=u128\n{prefix}.value={value}")
        }
        EventAttributeValue::String(value) => write!(
            out,
            "{prefix}.type=string\n{prefix}.len={}\n{prefix}.value={value}",
            value.len()
        ),
        EventAttributeValue::Bytes(value) => write!(
            out,
            "{prefix}.type=bytes\n{prefix}.len={}\n{prefix}.value={}",
            value.len(),
            Hex(value)
        ),
        EventAttributeValue::Node(value) => write!(
            out,
            "{prefix}.type=node\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::Event(value) => write!(
            out,
            "{prefix}.type=event\n{prefix}.name_len={}\n{prefix}.name={}",
            value.name.len(),
            value.name
        ),
        EventAttributeValue::VirtualTime(value) => {
            write!(
                out,
                "{prefix}.type=virtual-time\n{prefix}.ticks={}",
                value.ticks
            )
        }
        EventAttributeValue::Icount(value) => {
            write!(
                out,
                "{prefix}.type=icount\n{prefix}.retired={}",
                value.retired
            )
        }
        EventAttributeValue::Level(value) => {
            write!(
                out,
                "{prefix}.type=level\n{prefix}.value={}",
                event_level_label(*value)
            )
        }
    })
}

pub(super) fn trigger_node_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    node: &'a NodeId,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "{prefix}.len={}\n{prefix}={}",
            node.name.len(),
            node.name
        )
    })
}

pub(super) fn trigger_timer_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    timer: &'a TimerId,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "{prefix}.len={}\n{prefix}={}",
            timer.name.len(),
            timer.name
        )
    })
}

pub(super) fn trigger_optional_label_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    label: &'a Option<String>,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| match label {
        Some(label) => write!(
            out,
            "{prefix}.present=true\n{prefix}.len={}\n{prefix}={label}",
            label.len()
        ),
        None => write!(out, "{prefix}.present=false"),
    })
}

pub(super) fn scheduled_event_material<'a>(event: &'a ScheduledEvent) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "event:\n{}\n{}",
            scheduled_event_key_material(&event.key),
            scheduled_event_payload_material(&event.payload),
        )
    })
}

pub(super) fn scheduled_event_key_material<'a>(key: &'a ScheduledEventKey) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "event_time={}\nevent_consumer:\n{}\nevent_producer:\n{}\nevent_sequence={}",
            key.virtual_time().ticks,
            scheduler_node_material(key.consumer()),
            scheduler_node_material(key.producer()),
            key.sequence(),
        )
    })
}

pub(super) fn scheduled_event_payload_material<'a>(
    payload: &'a ScheduledEventPayload,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| match payload {
        ScheduledEventPayload::BackendInput(input) => write!(
            out,
            "payload=backend-input\npayload_node_len={}\npayload_node={}\npayload_bytes={}",
            input.node.name.len(),
            input.node.name,
            Hex(&input.payload),
        ),
        ScheduledEventPayload::IoCompletion(completion) => write!(
            out,
            "payload=io-completion\npayload_sub_node:\n{}\npayload_target_len={}\npayload_target={}\npayload_delivery_tick={}\npayload_bytes={}",
            scheduler_node_material(&completion.sub_node),
            completion.target.name.len(),
            completion.target.name,
            completion.delivery_tick.ticks,
            Hex(&completion.payload),
        ),
        ScheduledEventPayload::Control(operation) => {
            write!(
                out,
                "payload=control\n{}",
                control_operation_material(operation)
            )
        }
    })
}

pub(super) fn control_operation_material<'a>(operation: &'a ControlOperation) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push(format_args!("control_sequence={}", operation.sequence))?;
        lines.push(format_args!(
            "control_kind={}",
            control_operation_kind_label(&operation.kind)
        ))?;
        match &operation.kind {
            ControlOperationKind::Pause
            | ControlOperationKind::Resume
            | ControlOperationKind::Step
            | ControlOperationKind::Snapshot
            | ControlOperationKind::Fork
            | ControlOperationKind::Query => {}
        }
        Ok(())
    })
}

pub(super) fn scheduler_node_material<'a>(node: &'a SchedulerNodeId) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "node_name_len={}\nnode_name={}\nnode_kind={}",
            node.node.name.len(),
            node.node.name,
            scheduling_node_kind_label(node.kind),
        )
    })
}

pub(super) fn fault_observation_material(observation: &FaultObservation) -> impl Display + '_ {
    observation.canonical_display()
}

fn diagnostic_event_payload_material(diagnostic: &EventDiagnosticPayload) -> impl Display + '_ {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        let prefix = "diagnostic.event_payload";
        lines.push(format_args!("{prefix}.kind_len=10"))?;
        lines.push(format_args!("{prefix}.kind=diagnostic"))?;
        lines.push(format_args!(
            "{prefix}.attributes={}",
            diagnostic.details.len() + usize::from(!diagnostic.details.contains_key("name"))
        ))?;
        let mut name_written = false;
        for (name, value) in &diagnostic.details {
            if !name_written && name.as_str() >= "name" {
                lines.push(diagnostic_name_material(prefix, &diagnostic.name))?;
                name_written = true;
            }
            if name == "name" {
                continue;
            }
            lines.push(format_args!(
                "{prefix}.attribute.{name}.name_len={}",
                name.len()
            ))?;
            lines.push(format_args!("{prefix}.attribute.{name}.name={name}"))?;
            lines.push(event_attribute_value_material(
                &format_args!("{prefix}.attribute.{name}.value"),
                value,
            ))?;
        }
        if !name_written {
            lines.push(diagnostic_name_material(prefix, &diagnostic.name))?;
        }
        Ok(())
    })
}

fn diagnostic_name_material<'a>(prefix: &'a str, name: &'a str) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "{prefix}.attribute.name.name_len=4\n{prefix}.attribute.name.name=name\n{prefix}.attribute.name.value.type=string\n{prefix}.attribute.name.value.len={}\n{prefix}.attribute.name.value.value={name}",
            name.len()
        )
    })
}

/// Borrows node source identity directly from a checked wire name.
pub(super) fn scheduler_event_log_node_source_material<'a>(
    prefix: &'a (impl Display + ?Sized),
    name: &'a str,
) -> impl Display + 'a {
    Render(move |out: &mut dyn Write| {
        write!(
            out,
            "{prefix}=node\n{prefix}.node_len={}\n{prefix}.node={name}",
            name.len()
        )
    })
}

/// Compares trusted canonical text with a borrowed projection without a copy.
#[cfg(test)]
pub(super) fn canonical_text_matches(text: &str, material: &impl Display) -> bool {
    struct Comparison<'a> {
        remaining: &'a str,
    }
    impl Write for Comparison<'_> {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            self.remaining = self.remaining.strip_prefix(value).ok_or(fmt::Error)?;
            Ok(())
        }
    }
    let mut output = Comparison { remaining: text };
    write!(&mut output, "{material}").is_ok() && output.remaining.is_empty()
}

pub(super) fn scheduler_event_log_segment_text_material(
    segment: &super::event_codec::SchedulerEventLogSegmentMaterial,
) -> impl Display + '_ {
    Render(move |out: &mut dyn Write| {
        let mut lines = Lines::new(out);
        lines.push("format=crucible.scheduler.event-log.segment-text.v5")?;
        lines.push("canonical_format=crucible.scheduler.event-log.segment.v5")?;
        lines.push(format_args!(
            "schema_version={EVENT_LOG_SEGMENT_BINARY_VERSION}"
        ))?;
        lines.push(format_args!(
            "previous_prefix={}",
            Hex(&segment.previous_prefix.bytes)
        ))?;
        lines.push(format_args!("entries={}", segment.entries.len()))?;
        for entry in &segment.entries {
            lines.push(format_args!("entry.sequence={}", entry.sequence))?;
            lines.push(format_args!(
                "entry.at_virtual_time_ticks={}",
                entry.at_virtual_time_ticks
            ))?;
            lines.push(format_args!("entry.at_tick={}", entry.at_tick))?;
            match entry.at_raw_retired {
                Some(retired) => lines.push(format_args!("entry.at_raw_retired={retired}"))?,
                None => lines.push("entry.at_raw_retired=none")?,
            }
            match &entry.at_node {
                Some(node) => {
                    lines.push("entry.at_node=some")?;
                    lines.push(format_args!("entry.at_node_name={node}"))?;
                }
                None => lines.push("entry.at_node=none")?,
            }
            lines.push(&entry.source_material)?;
            lines.push(format_args!(
                "entry.level={}",
                event_level_label(entry.level)
            ))?;
            lines.push(format_args!(
                "entry.class={}",
                event_class_label(entry.class)
            ))?;
            lines.push(format_args!("entry.payload.kind={}", entry.payload_kind))?;
            lines.push(format_args!(
                "entry.payload.attributes={}",
                entry.payload_attribute_count
            ))?;
            lines.push(format_args!(
                "entry.hash={}",
                Hex(&entry.content_hash.bytes)
            ))?;
            lines.push(format_args!("entry.bytes={}", entry.entry_material.len()))?;
            lines.push("entry.material_begin")?;
            lines.push(&entry.entry_material)?;
            lines.push("entry.material_end")?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests;
