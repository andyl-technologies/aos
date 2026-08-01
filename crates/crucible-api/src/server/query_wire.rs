//! Query-kind decoding and query-result response encoding.

use super::*;

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
        "execution-fingerprint" => {
            let node = parse_hex_string_field(fields.next(), "query fingerprint node")?;
            reject_extra_query_field(fields.next())?;
            Ok(QueryKind::ExecutionFingerprint {
                node: NodeId { name: node },
            })
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
        Some(QueryResult::ExecutionFingerprint(sample)) => format!(
            "execution-fingerprint|{}|{}|{}",
            hex_encode(sample.node.name.as_bytes()),
            sample.at.ticks,
            sample.fingerprint.hash.to_hex()
        ),
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
