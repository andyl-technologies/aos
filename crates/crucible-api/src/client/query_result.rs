//! Typed query-result wire decoding for the control client.

use super::*;

pub(super) fn parse_query_result_line(
    line: Option<&str>,
) -> Result<Option<QueryResult>, ControlClientError> {
    let value = parse_prefixed_line(line, "query-result=")?;
    if value == "none" {
        return Ok(None);
    }
    let mut fields = value.split('|');
    match fields
        .next()
        .ok_or_else(|| rpc_decode("missing query result kind"))?
    {
        "state" => {
            let state = parse_lifecycle_state_field(fields.next(), "query result state")?;
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::State(state)))
        }
        "event-log-length" => {
            let len = parse_usize_field(fields.next(), "query result event log length")?;
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::EventLogLength(len)))
        }
        "search-frontier" => {
            let pending_branch_choices = parse_usize_field(
                fields.next(),
                "query result pending search branch choice count",
            )?;
            let frontier_count =
                parse_usize_field(fields.next(), "query result search frontier count")?;
            let mut frontiers = Vec::with_capacity(frontier_count);
            for _ in 0..frontier_count {
                let at = VirtualTime {
                    ticks: parse_u64_field(fields.next(), "query result search frontier time")?,
                };
                let scenario_id = parse_required_content_hash_field(
                    fields.next(),
                    "query result search frontier scenario id",
                )?;
                let seed = parse_seed_field(fields.next(), "query result search frontier seed")?;
                let app_random_draw_cap = parse_u64_field(
                    fields.next(),
                    "query result search frontier app-random draw cap",
                )?;
                let configuration_schedule = parse_hex_bytes_field(
                    fields.next(),
                    "query result search frontier configuration schedule",
                )?;
                let configuration_schedule = Schedule::from_compact_binary(&configuration_schedule)
                    .map_err(|error| {
                        rpc_decode(format!(
                            "invalid query result search frontier configuration schedule: {error}"
                        ))
                    })?;
                let choice_count =
                    parse_usize_field(fields.next(), "query result search frontier choice count")?;
                let mut choices = Vec::with_capacity(choice_count);
                for _ in 0..choice_count {
                    let bytes = parse_hex_bytes_field(
                        fields.next(),
                        "query result search frontier choice",
                    )?;
                    let schedule = Schedule::from_compact_binary(&bytes).map_err(|error| {
                        rpc_decode(format!(
                            "invalid query result search frontier choice: {error}"
                        ))
                    })?;
                    choices.push(schedule.decisions().to_vec());
                }
                frontiers.push(crucible::SearchRuntimeFrontier {
                    configuration: Configuration {
                        def: crucible::ScenarioDef::from_trusted_identity(
                            scenario_id,
                            seed,
                            app_random_draw_cap,
                        ),
                        schedule: configuration_schedule,
                    },
                    at,
                    choices: crucible::SearchFrontierChoices::from_decision_sequences(choices),
                });
            }
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::SearchFrontier {
                frontiers,
                pending_branch_choices,
            }))
        }
        "breakpoint-firings" => {
            let firings = parse_breakpoint_firings_fields(&mut fields)?;
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::BreakpointFirings(firings)))
        }
        "execution-fingerprint" => {
            let node = NodeId {
                name: parse_hex_string_field(fields.next(), "query result fingerprint node")?,
            };
            let at = VirtualTime {
                ticks: parse_u64_field(fields.next(), "query result fingerprint time")?,
            };
            let hash =
                parse_required_content_hash_field(fields.next(), "query result fingerprint hash")?;
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::ExecutionFingerprint(FingerprintSample {
                node,
                at,
                fingerprint: ExecutionFingerprint { hash },
            })))
        }
        "debug-operator-endpoint" => {
            let value = fields
                .next()
                .ok_or_else(|| rpc_decode("missing debug operator endpoint"))?;
            let target = if value == "none" {
                None
            } else {
                let node = NodeId {
                    name: parse_hex_string(value)?,
                };
                let endpoint = DebugGdbEndpoint::new(
                    "debug_operator_endpoint",
                    parse_hex_string_field(fields.next(), "debug operator endpoint")?,
                )
                .map_err(|error| rpc_decode(format!("invalid debug operator endpoint: {error}")))?;
                Some((node, endpoint))
            };
            reject_extra_query_result_fields(fields.next())?;
            Ok(Some(QueryResult::DebugOperatorEndpoint(target)))
        }
        "snapshot" => {
            let state = parse_engine_state_field(fields.next(), "query result snapshot state")?;
            let frontier = VirtualTime {
                ticks: parse_u64_field(fields.next(), "query result snapshot frontier")?,
            };
            let event_log_len =
                parse_usize_field(fields.next(), "query result snapshot event log length")?;
            let quanta = parse_u64_field(fields.next(), "query result snapshot quanta")?;
            let scenario_id = parse_required_content_hash_field(
                fields.next(),
                "query result snapshot scenario id",
            )?;
            let seed = parse_seed_field(fields.next(), "query result snapshot seed")?;
            let app_random_draw_cap =
                parse_u64_field(fields.next(), "query result snapshot app-random draw cap")?;
            let schedule_bytes =
                parse_hex_bytes_field(fields.next(), "query result snapshot schedule payload")?;
            let terminal_savepoint = fields
                .next()
                .ok_or_else(|| rpc_decode("missing query result snapshot terminal savepoint"))?;
            let terminal_savepoint = parse_optional_checkpoint_field(
                terminal_savepoint,
                "query result snapshot terminal savepoint",
            )?;
            reject_extra_query_result_fields(fields.next())?;
            let schedule = Schedule::from_compact_binary(&schedule_bytes).map_err(|error| {
                rpc_decode(format!("invalid query result snapshot schedule: {error}"))
            })?;
            let configuration = Configuration {
                def: crucible::ScenarioDef::from_trusted_identity(
                    scenario_id,
                    seed,
                    app_random_draw_cap,
                ),
                schedule,
            };
            Ok(Some(QueryResult::Snapshot(Box::new(EngineSnapshot {
                state,
                configuration,
                terminal_savepoint,
                frontier,
                event_log_len,
                quanta,
            }))))
        }
        kind => Err(rpc_decode(format!("unknown query result kind `{kind}`"))),
    }
}
