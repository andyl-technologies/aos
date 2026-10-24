//! Borrowed observable and guest measurement projections for external traces.

use super::*;

pub(super) fn external_observable_event_payload_material<'a>(
    observable: &'a ObservableEventPayload,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match observable {
            ObservableEventPayload::NetworkDelivered { link, payload } => {
                lines.push("observable=network-delivered")?;
                lines.push(external_optional_link_material(&"observable.link", link))?;
                lines.push(format_args!("observable.payload_bytes={}", Hex(payload)))?;
            }
            ObservableEventPayload::ConsoleOutput { node, bytes } => {
                lines.push("observable=console-output")?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(format_args!("observable.bytes={}", Hex(bytes)))?;
            }
            ObservableEventPayload::CoverageBlock {
                execution_icount,
                node,
                guest_pc,
                block_len,
            } => {
                lines.push("observable=coverage-block")?;
                lines.push(format_args!(
                    "observable.execution_icount={}",
                    execution_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(format_args!("observable.guest_pc={guest_pc}"))?;
                lines.push(format_args!("observable.block_len={block_len}"))?;
            }
            ObservableEventPayload::CoverageMarker {
                retired_icount,
                node,
                marker,
            } => {
                lines.push("observable=coverage-marker")?;
                lines.push(format_args!(
                    "observable.retired_icount={}",
                    retired_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(external_marker_id_material(&"observable.marker", marker))?;
            }
            ObservableEventPayload::MemorySample {
                sample_icount,
                node,
                place,
                value,
            } => {
                lines.push("observable=memory-sample")?;
                lines.push(format_args!(
                    "observable.sample_icount={}",
                    sample_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(external_resolved_mem_place_material(
                    &"observable.place",
                    place,
                ))?;
                lines.push(format_args!("observable.value={value}"))?;
            }
            ObservableEventPayload::IoCompletion {
                node,
                kind,
                payload,
            } => {
                lines.push("observable=io-completion")?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(format_args!(
                    "observable.kind={}",
                    external_io_event_kind_label(*kind)
                ))?;
                lines.push(format_args!("observable.payload_bytes={}", Hex(payload)))?;
            }
            ObservableEventPayload::NodeState { node, state } => {
                lines.push("observable=node-state")?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(format_args!(
                    "observable.state={}",
                    external_node_lifecycle_label(*state)
                ))?;
            }
            ObservableEventPayload::AssertionStateChanged { name, state } => {
                lines.push("observable=assertion-state-changed")?;
                lines.push(external_assertion_id_material(
                    &"observable.assertion",
                    name,
                ))?;
                lines.push(format_args!(
                    "observable.state={}",
                    external_assertion_phase_label(*state)
                ))?;
            }
            ObservableEventPayload::AssertionEvaluated {
                name,
                flavor,
                condition,
                message,
                details,
            } => {
                lines.push("observable=assertion-evaluated")?;
                lines.push(external_assertion_id_material(
                    &"observable.assertion",
                    name,
                ))?;
                lines.push(format_args!(
                    "observable.flavor={}",
                    external_assertion_quantifier_label(*flavor)
                ))?;
                lines.push(format_args!("observable.condition={condition}"))?;
                lines.push(external_string_material(&"observable.message", message))?;
                lines.push(format_args!("observable.details={}", details.len()))?;
                for (index, detail) in details.iter().enumerate() {
                    lines.push(external_string_material(
                        &format_args!("observable.detail.{index}.key"),
                        &detail.key,
                    ))?;
                    lines.push(external_string_material(
                        &format_args!("observable.detail.{index}.value"),
                        &detail.value,
                    ))?;
                }
            }
            ObservableEventPayload::AssertionProximity {
                assertion,
                quantifier,
                distance,
                node,
            } => {
                lines.push("observable=assertion-proximity")?;
                lines.push(external_assertion_id_material(
                    &"observable.assertion",
                    assertion,
                ))?;
                lines.push(format_args!(
                    "observable.quantifier={}",
                    external_assertion_quantifier_label(*quantifier)
                ))?;
                lines.push(format_args!("observable.distance={distance}"))?;
                lines.push(external_optional_node_id_material(&"observable.node", node))?;
            }
            ObservableEventPayload::GuestMarker {
                retired_icount,
                node,
                marker,
            } => {
                lines.push("observable=guest-marker")?;
                lines.push(format_args!(
                    "observable.retired_icount={}",
                    retired_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(external_marker_id_material(&"observable.marker", marker))?;
            }
            ObservableEventPayload::GuestMeasurement {
                retired_icount,
                node,
                event,
            } => {
                lines.push(format_args!(
                    "observable.retired_icount={}",
                    retired_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                match event {
                    GuestMeasurementEvent::Begin {
                        measurement,
                        instance,
                    } => {
                        lines.push("observable=guest-measurement-begin")?;
                        lines.push(external_string_material(
                            &"observable.measurement",
                            measurement,
                        ))?;
                        lines.push(external_string_material(&"observable.instance", instance))?;
                    }
                    GuestMeasurementEvent::Sample {
                        measurement,
                        instance,
                        metric,
                        value,
                    } => {
                        lines.push("observable=guest-metric-sample")?;
                        lines.push(external_string_material(
                            &"observable.measurement",
                            measurement,
                        ))?;
                        lines.push(external_string_material(&"observable.instance", instance))?;
                        lines.push(external_string_material(&"observable.metric", metric))?;
                        lines.push(external_guest_measurement_value_material(
                            &"observable.value",
                            value,
                        ))?;
                    }
                    GuestMeasurementEvent::End {
                        measurement,
                        instance,
                    } => {
                        lines.push("observable=guest-measurement-end")?;
                        lines.push(external_string_material(
                            &"observable.measurement",
                            measurement,
                        ))?;
                        lines.push(external_string_material(&"observable.instance", instance))?;
                    }
                }
            }
            ObservableEventPayload::GuestSemanticMarker {
                retired_icount,
                node,
                marker,
                instance,
                details,
            } => {
                lines.push("observable=guest-semantic-marker")?;
                lines.push(format_args!(
                    "observable.retired_icount={}",
                    retired_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(external_string_material(&"observable.marker", marker))?;
                lines.push(external_string_material(&"observable.instance", instance))?;
                lines.push(format_args!("observable.details={}", details.len()))?;
                for (index, detail) in details.iter().enumerate() {
                    lines.push(external_string_material(
                        &format_args!("observable.detail.{index}.key"),
                        &detail.key,
                    ))?;
                    lines.push(external_guest_measurement_value_material(
                        &format_args!("observable.detail.{index}.value"),
                        &detail.value,
                    ))?;
                }
            }
            ObservableEventPayload::GuestAssertionMarker {
                retired_icount,
                node,
                marker,
            } => {
                lines.push("observable=guest-assertion-marker")?;
                lines.push(format_args!(
                    "observable.retired_icount={}",
                    retired_icount.retired
                ))?;
                lines.push(external_node_id_material(&"observable.node", node))?;
                lines.push(external_assertion_id_material(
                    &"observable.marker.id",
                    &marker.id,
                ))?;
                lines.push(external_string_material(
                    &"observable.marker.message",
                    &marker.message,
                ))?;
                lines.push(format_args!(
                    "observable.marker.kind={}",
                    external_guest_assertion_kind_label(marker.kind)
                ))?;
                lines.push(format_args!(
                    "observable.marker.condition={}",
                    marker.condition
                ))?;
                lines.push(format_args!(
                    "observable.marker.must_hit={}",
                    marker.must_hit
                ))?;
                lines.push(format_args!(
                    "observable.marker.details={}",
                    marker.details.len()
                ))?;
                for (index, detail) in marker.details.iter().enumerate() {
                    lines.push(external_string_material(
                        &format_args!("observable.marker.detail.{index}.key"),
                        &detail.key,
                    ))?;
                    lines.push(external_string_material(
                        &format_args!("observable.marker.detail.{index}.value"),
                        &detail.value,
                    ))?;
                }
                lines.push(external_string_material(
                    &"observable.marker.location",
                    &marker.location,
                ))?;
            }
        }
        Ok(())
    })
}

fn external_guest_measurement_value_material<'a>(
    prefix: &'a dyn std::fmt::Display,
    value: &'a GuestMeasurementValue,
) -> impl std::fmt::Display + 'a {
    Render(move |out: &mut dyn std::fmt::Write| {
        let mut lines = Lines::new(out);
        match value {
            GuestMeasurementValue::Signed(value) => {
                lines.push(format_args!("{prefix}.kind=signed"))?;
                lines.push(format_args!("{prefix}.value={value}"))?;
            }
            GuestMeasurementValue::Unsigned(value) => {
                lines.push(format_args!("{prefix}.kind=unsigned"))?;
                lines.push(format_args!("{prefix}.value={value}"))?;
            }
            GuestMeasurementValue::Rational(value) => {
                lines.push(format_args!("{prefix}.kind=rational"))?;
                lines.push(format_args!("{prefix}.negative={}", value.negative))?;
                lines.push(format_args!("{prefix}.numerator={}", value.numerator))?;
                lines.push(format_args!("{prefix}.denominator={}", value.denominator))?;
            }
            GuestMeasurementValue::Boolean(value) => {
                lines.push(format_args!("{prefix}.kind=boolean"))?;
                lines.push(format_args!("{prefix}.value={value}"))?;
            }
            GuestMeasurementValue::Enumerated(value) => {
                lines.push(format_args!("{prefix}.kind=enumerated"))?;
                lines.push(external_string_material(
                    &format_args!("{prefix}.value"),
                    value,
                ))?;
            }
            GuestMeasurementValue::SignedVector(values) => {
                lines.push(format_args!("{prefix}.kind=signed-vector"))?;
                lines.push(format_args!("{prefix}.elements={}", values.len()))?;
                for (index, value) in values.iter().enumerate() {
                    lines.push(format_args!("{prefix}.element.{index}={value}"))?;
                }
            }
            GuestMeasurementValue::UnsignedVector(values) => {
                lines.push(format_args!("{prefix}.kind=unsigned-vector"))?;
                lines.push(format_args!("{prefix}.elements={}", values.len()))?;
                for (index, value) in values.iter().enumerate() {
                    lines.push(format_args!("{prefix}.element.{index}={value}"))?;
                }
            }
        }
        Ok(())
    })
}
