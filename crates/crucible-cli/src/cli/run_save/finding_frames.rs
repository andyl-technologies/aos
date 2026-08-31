//! Canonical streamed-event decoding for finding evidence.

use super::*;

pub(super) fn property_violation_from_frames(
    form: &crucible::ScenarioDefForm,
    frames: &[Vec<u8>],
    reproduction_artifact: crucible::ContentHash,
) -> Result<crucible_model::HostAssertionViolation, CliError> {
    let mut violations = Vec::new();
    for frame in frames {
        let text = std::str::from_utf8(frame)
            .map_err(|error| backend_error(format!("event frame is not UTF-8: {error}")))?;
        if canonical_frame_value(text, "kind") != Some("crucible.event.assertion_state_changed") {
            continue;
        }
        let Some(assertion_name) = canonical_frame_string_attribute(text, "id")? else {
            continue;
        };
        if canonical_frame_string_attribute(text, "new_state")?.as_deref() != Some("Violated") {
            continue;
        }
        let assertion = form
            .properties()
            .assertions()
            .iter()
            .find(|candidate| candidate.id.name == assertion_name)
            .ok_or_else(|| {
                backend_error(format!(
                    "violation referenced undeclared assertion `{assertion_name}`"
                ))
            })?;
        let at_virtual_time = canonical_frame_u64(text, "virtual-time-ticks")?;
        let at_icount = canonical_frame_u64(text, "icount-retired")?;
        let node = match canonical_frame_value(text, "icount-node") {
            Some("none") | None => None,
            Some(value) => Some(crucible::NodeId {
                name: canonical_frame_hex_string("icount-node", value)?,
            }),
        };
        violations.push(crucible_model::HostAssertionViolation {
            assertion: assertion.id.clone(),
            message: assertion.message.clone(),
            quantifier: assertion.quantifier_kind(),
            event_kind: String::from("assertion_state_changed"),
            at_icount: Some(crucible::Icount { retired: at_icount }),
            at_virtual_time: crucible::VirtualTime {
                ticks: at_virtual_time,
            },
            node,
            detail: String::from("assertion entered the Violated state"),
            reproduction_artifact,
        });
    }
    violations.sort_by(|left, right| {
        (
            left.assertion.name.as_str(),
            left.at_virtual_time.ticks,
            left.at_icount.map(|value| value.retired),
            left.node.as_ref().map(|node| node.name.as_str()),
        )
            .cmp(&(
                right.assertion.name.as_str(),
                right.at_virtual_time.ticks,
                right.at_icount.map(|value| value.retired),
                right.node.as_ref().map(|node| node.name.as_str()),
            ))
    });
    violations.into_iter().next().ok_or_else(|| {
        backend_error("failed iteration did not stream an assertion violation event")
    })
}

fn canonical_frame_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

fn canonical_frame_u64(text: &str, key: &'static str) -> Result<u64, CliError> {
    canonical_frame_value(text, key)
        .ok_or_else(|| backend_error(format!("event frame is missing `{key}`")))?
        .parse::<u64>()
        .map_err(|_| backend_error(format!("event frame has invalid `{key}`")))
}

fn canonical_frame_string_attribute(
    text: &str,
    requested_name: &str,
) -> Result<Option<String>, CliError> {
    for line in text
        .lines()
        .filter_map(|line| line.strip_prefix("attribute="))
    {
        let mut fields = line.split('|');
        let Some(name_hex) = fields.next() else {
            continue;
        };
        let Some(kind) = fields.next() else {
            continue;
        };
        let Some(value_hex) = fields.next() else {
            continue;
        };
        if canonical_frame_hex_string("attribute-name", name_hex)? == requested_name {
            if kind != "string" {
                return Err(backend_error(format!(
                    "event attribute `{requested_name}` is not a string"
                )));
            }
            return canonical_frame_hex_string(requested_name, value_hex).map(Some);
        }
    }
    Ok(None)
}

fn canonical_frame_hex_string(field: &str, value: &str) -> Result<String, CliError> {
    let bytes = parse_hex_bytes(0, field, value)?;
    String::from_utf8(bytes)
        .map_err(|error| backend_error(format!("event `{field}` is not UTF-8: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_evidence_reads_exact_stream_frame() -> Result<(), Box<dyn std::error::Error>> {
        use crucible_api::OpenSetAttributeValue::String as Text;

        let scenario = crucible::happy_path_scenario()?.scenario;
        let assertion = scenario
            .properties()
            .assertions()
            .first()
            .ok_or_else(|| std::io::Error::other("fixture has no assertion"))?;
        let frame = crucible_api::StreamingEventFrame {
            generation: 0,
            cursor: crucible_api::EventLogCursor::new(4),
            next_cursor: crucible_api::EventLogCursor::new(5),
            event: crucible_api::OpenSetEventEnvelope {
                sequence: 4,
                at: crucible_api::OpenSetEventTime {
                    virtual_time_ticks: 17,
                    icount_retired: 23,
                    icount_node: Some(String::from("fixture-node")),
                },
                source: crucible_api::OpenSetEventSource::Node {
                    node: String::from("fixture-node"),
                },
                level: crucible::EventLevel::Info,
                observational: false,
                payload: crucible_api::OpenSetPayload::new(
                    "crucible.event.assertion_state_changed",
                    [
                        (String::from("id"), Text(assertion.id.name.clone())),
                        (String::from("new_state"), Text(String::from("Violated"))),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        };
        let exact_frame = canonical_streaming_event_frame_bytes(&frame);
        let artifact = crucible::ContentHash::from_bytes(b"property-frame");
        let violation = property_violation_from_frames(&scenario, &[exact_frame], artifact)?;

        assert_eq!(violation.assertion, assertion.id);
        assert_eq!(violation.quantifier, assertion.quantifier_kind());
        assert_eq!(violation.at_virtual_time.ticks, 17);
        assert_eq!(violation.at_icount.map(|value| value.retired), Some(23));
        assert_eq!(
            violation.node.as_ref().map(|node| node.name.as_str()),
            Some("fixture-node")
        );
        assert_eq!(violation.reproduction_artifact, artifact);
        Ok(())
    }
}
