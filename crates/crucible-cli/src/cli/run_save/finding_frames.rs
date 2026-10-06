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
        if canonical_frame_value(text, "icount-retired").is_some()
            || canonical_frame_value(text, "icount-node").is_some()
        {
            return Err(backend_error(
                "event frame uses obsolete icount stamp fields",
            ));
        }
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
        let stamp_tick = canonical_frame_u64(text, "stamp-tick")?;
        if at_virtual_time != stamp_tick {
            return Err(backend_error(
                "event frame has mismatched virtual-time and stamp ticks",
            ));
        }
        let at_icount = match canonical_frame_value(text, "stamp-retired") {
            Some("none") => None,
            Some(value) => Some(crucible::Icount {
                retired: value
                    .parse()
                    .map_err(|_| backend_error("event frame has invalid `stamp-retired`"))?,
            }),
            None => return Err(backend_error("event frame is missing `stamp-retired`")),
        };
        let node = match canonical_frame_value(text, "stamp-node") {
            Some("none") => None,
            Some(value) => Some(crucible::NodeId {
                name: canonical_frame_hex_string("stamp-node", value)?,
            }),
            None => return Err(backend_error("event frame is missing `stamp-node`")),
        };
        let owned_bytes = assertion
            .id
            .name
            .len()
            .checked_add(assertion.message.len())
            .and_then(|bytes| bytes.checked_add("assertion_state_changed".len()))
            .and_then(|bytes| bytes.checked_add("assertion entered the Violated state".len()))
            .ok_or_else(|| backend_error("assertion evidence size overflow"))?;
        crucible_session::engine::owned_decode::charge_bytes(
            u64::try_from(owned_bytes)
                .map_err(|_| backend_error("assertion evidence size overflow"))?,
        )
        .map_err(|error| backend_error(format!("admit assertion evidence fields: {error}")))?;
        crucible_session::engine::owned_decode::reserve_vec(&mut violations, 1)
            .map_err(|error| backend_error(format!("admit assertion evidence storage: {error}")))?;
        violations.push(
            crucible_model::HostAssertionViolation::from_owned_fields(
                crucible_model::HostAssertionViolationFields {
                    assertion: assertion.id.clone(),
                    message: assertion.message.clone(),
                    quantifier: assertion.quantifier_kind(),
                    event_kind: String::from("assertion_state_changed"),
                    at_icount,
                    at_virtual_time: crucible::VirtualTime {
                        ticks: at_virtual_time,
                    },
                    node,
                    detail: String::from("assertion entered the Violated state"),
                    reproduction_artifact,
                },
            )
            .map_err(|error| backend_error(format!("admit assertion violation: {error}")))?,
        );
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
    crucible_session::engine::owned_decode::charge_bytes(value.len() as u64)
        .map_err(|error| backend_error(format!("admit event field: {error}")))?;
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
        let resources = crucible_daemon::component_ram_root_resources()?;
        let maximum = resources.decoded_metadata_limit()?;
        let budget = crucible_session::engine::owned_decode::DecodeBudget::for_store(resources)?;
        let _scope = budget.enter();

        let scenario = crucible::happy_path_scenario()?.scenario;
        let assertion = scenario
            .properties()
            .assertions()
            .first()
            .ok_or_else(|| std::io::Error::other("fixture has no assertion"))?;
        let frame_for_retired = |stamp_retired| {
            crucible_api::StreamingEventFrame::from_owned_fields(
                0,
                crucible_api::EventLogCursor::new(4),
                crucible_api::EventLogCursor::new(5),
                crucible_api::OpenSetEventEnvelope {
                    sequence: 4,
                    at: crucible_api::OpenSetEventTime {
                        virtual_time_ticks: 17,
                        stamp_tick: 17,
                        stamp_retired,
                        stamp_node: Some(String::from("fixture-node")),
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
            )
            .unwrap_or_else(|error| panic!("component event frame: {error}"))
        };
        let frame = frame_for_retired(Some(23));
        let exact_frame = canonical_streaming_event_frame_bytes(&frame);
        assert_eq!(
            admitted_streaming_event_frame_bytes(&frame, &budget)?,
            exact_frame
        );
        let artifact = crucible::ContentHash::from_bytes(b"property-frame");
        let violation = property_violation_from_frames(
            &scenario,
            std::slice::from_ref(&exact_frame),
            artifact,
        )?;

        assert_eq!(violation.assertion, assertion.id);
        assert_eq!(violation.quantifier, assertion.quantifier_kind());
        assert_eq!(violation.at_virtual_time.ticks, 17);
        assert_eq!(violation.at_icount.map(|value| value.retired), Some(23));
        assert_eq!(
            violation.node.as_ref().map(|node| node.name.as_str()),
            Some("fixture-node")
        );
        assert_eq!(violation.reproduction_artifact, artifact);

        let optional_frame = frame_for_retired(None);
        let optional_frame = canonical_streaming_event_frame_bytes(&optional_frame);
        let optional_violation =
            property_violation_from_frames(&scenario, &[optional_frame], artifact)?;
        assert_eq!(optional_violation.at_icount, None);

        let obsolete_frame = std::str::from_utf8(&exact_frame)?
            .replace("stamp-retired=23", "icount-retired=23")
            .into_bytes();
        assert!(property_violation_from_frames(&scenario, &[obsolete_frame], artifact).is_err());

        // A prior exhaustion remains authoritative before the renderer reserves
        // its output, even when the same immutable frame was rendered earlier.
        assert!(budget.charge_bytes(maximum).is_err());
        assert!(admitted_streaming_event_frame_bytes(&frame, &budget).is_err());
        Ok(())
    }
}
