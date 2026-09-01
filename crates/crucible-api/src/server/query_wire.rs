//! Query-kind decoding and query-result response encoding.

use super::*;

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn attribute_wire(value: &OpenSetAttributeValue) -> String {
    match value {
        OpenSetAttributeValue::Bool(value) => {
            format!("bool|{}", if *value { "true" } else { "false" })
        }
        OpenSetAttributeValue::Int(value) => format!("int|{value}"),
        OpenSetAttributeValue::Uint(value) => format!("uint|{value}"),
        OpenSetAttributeValue::Uint128(value) => format!("uint128|{value}"),
        OpenSetAttributeValue::Float64Bits(value) => format!("float64bits|{value}"),
        OpenSetAttributeValue::String(value) => format!("string|{}", hex_encode(value.as_bytes())),
        OpenSetAttributeValue::Bytes(value) => format!("bytes|{}", hex_encode(value)),
    }
}

pub(super) fn state_wire_name(state: LiveStateKind) -> &'static str {
    match state {
        LiveStateKind::Loaded => "loaded",
        LiveStateKind::Paused => "paused",
        LiveStateKind::Running => "running",
        LiveStateKind::Stopped => "stopped",
    }
}

pub(super) fn lifecycle_state_wire_name(state: LifecycleStateKind) -> &'static str {
    match state {
        LifecycleStateKind::Loaded => "loaded",
        LifecycleStateKind::Paused => "paused",
        LifecycleStateKind::Running => "running",
        LifecycleStateKind::Stopped => "stopped",
    }
}

pub(super) fn outcome_wire_name(outcome: Option<OutcomeKind>) -> &'static str {
    match outcome {
        Some(OutcomeKind::Passed) => "passed",
        Some(OutcomeKind::Failed) => "failed",
        Some(OutcomeKind::Timeout) => "timeout",
        Some(OutcomeKind::Crashed) => "crashed",
        Some(OutcomeKind::Stopped) => "stopped",
        None => "none",
    }
}

pub(super) fn content_hash_option_wire(hash: Option<ContentHash>) -> String {
    match hash {
        Some(hash) => hash.to_hex(),
        None => String::from("none"),
    }
}

pub(super) fn command_name(command: SessionCommandKind) -> String {
    open_set_command_kind(command).unwrap_or_else(|| {
        let command_name = API_COMMAND_MAPPINGS
            .iter()
            .find(|mapping| mapping.command_kind == command)
            .map(|mapping| mapping.command_name)
            .unwrap_or("unknown");
        format!("crucible.cmd.{command_name}")
    })
}

pub(super) fn push_session_ref(output: &mut String, session: SessionRef) {
    push_wire_line(output, "session-id", &session.id.value.to_string());
    push_wire_line(output, "epoch", &session.epoch.to_string());
    push_wire_line(output, "seed", &session.seed.to_hex());
}

pub(super) fn push_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

pub(super) fn parse_query_kind_line(line: Option<&str>) -> Result<QueryKind, String> {
    let value = parse_wire_line(line, "query=")?;
    let mut fields = value.split('|');
    match fields
        .next()
        .ok_or_else(|| String::from("missing query kind"))?
    {
        "snapshot" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::Snapshot)
        }
        "breakpoint-firings" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::BreakpointFirings)
        }
        "state" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::State)
        }
        "event-log-length" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::EventLogLength)
        }
        "search-frontier" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::SearchFrontier)
        }
        "resolved-effect-trace" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::ResolvedEffectTrace)
        }
        "execution-fingerprint" => {
            let node = parse_hex_string_field(fields.next(), "query fingerprint node")?;
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::ExecutionFingerprint {
                node: NodeId { name: node },
            })
        }
        "debug-operator-endpoint" => {
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::DebugOperatorEndpoint)
        }
        kind => Err(format!("unknown query kind `{kind}`")),
    }
}

pub(super) fn query_result_wire(result: Option<&QueryResult>) -> String {
    match result {
        Some(QueryResult::State(state)) => {
            format!("state|{}", lifecycle_state_wire_name(*state))
        }
        Some(QueryResult::EventLogLength(len)) => {
            format!("event-log-length|{len}")
        }
        Some(QueryResult::SearchFrontier {
            frontiers,
            pending_branch_choices,
        }) => {
            let mut output = format!(
                "search-frontier|{pending_branch_choices}|{}",
                frontiers.len()
            );
            for frontier in frontiers {
                output.push('|');
                output.push_str(&frontier.at.ticks.to_string());
                output.push('|');
                output.push_str(&frontier.configuration.def.id().to_hex());
                output.push('|');
                output.push_str(&frontier.configuration.def.seed().to_hex());
                output.push('|');
                output.push_str(&frontier.configuration.def.app_random_draw_cap().to_string());
                output.push('|');
                output.push_str(&hex_encode(
                    &frontier.configuration.schedule.to_compact_binary(),
                ));
                output.push('|');
                output.push_str(&frontier.choices.choices().len().to_string());
                for choice in frontier.choices.choices() {
                    let schedule = Schedule::from_decisions(choice.decisions().iter().cloned());
                    output.push('|');
                    output.push_str(&hex_encode(&schedule.to_compact_binary()));
                }
            }
            output
        }
        Some(QueryResult::ResolvedEffectTrace(Some(trace))) => {
            format!("resolved-effect-trace|{}", hex_encode(trace))
        }
        Some(QueryResult::ResolvedEffectTrace(None)) => String::from("resolved-effect-trace|none"),
        Some(QueryResult::ExecutionFingerprint(sample)) => format!(
            "execution-fingerprint|{}|{}|{}",
            hex_encode(sample.node.name.as_bytes()),
            sample.at.ticks,
            sample.fingerprint.hash.to_hex()
        ),
        Some(QueryResult::DebugOperatorEndpoint(Some((node, endpoint)))) => format!(
            "debug-operator-endpoint|{}|{}",
            hex_encode(node.name.as_bytes()),
            hex_encode(endpoint.as_str().as_bytes())
        ),
        Some(QueryResult::DebugOperatorEndpoint(None)) => {
            String::from("debug-operator-endpoint|none")
        }
        Some(QueryResult::Snapshot(snapshot)) => {
            let terminal = snapshot
                .terminal_savepoint
                .as_ref()
                .map(|checkpoint| hex_encode(&checkpoint.to_compact_binary()))
                .unwrap_or_else(|| String::from("none"));
            format!(
                "snapshot|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                snapshot_engine_state_wire(&snapshot.state),
                snapshot.frontier.ticks,
                snapshot.event_log_len,
                snapshot.quanta,
                snapshot.configuration.def.id().to_hex(),
                snapshot.configuration.def.seed().to_hex(),
                snapshot.configuration.def.app_random_draw_cap(),
                hex_encode(&snapshot.configuration.schedule.to_compact_binary()),
                terminal
            )
        }
        Some(QueryResult::BreakpointFirings(firings)) => breakpoint_firings_wire(firings),
        None => String::from("none"),
    }
}
