//! Savepoint reference and handle decoding.

use super::*;

/// Resolves a command's savepoint argument as a hash or exported handle.
///
/// # Errors
///
/// Returns [`CliError`] when the argument is absent, malformed, unreadable, or
/// cannot be decoded as a savepoint handle.
pub(crate) fn resolve_savepoint_ref(
    command_name: &'static str,
    savepoint: Option<&str>,
) -> Result<ResumeSavepointRef, CliError> {
    let Some(raw) = savepoint else {
        return Err(usage_error(format!(
            "{command_name} requires a SAVEPOINT argument"
        )));
    };
    let value = raw.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Err(artifact_error(
            "savepoint reference must not be empty or multiline",
        ));
    }
    if value.starts_with("blake3:") {
        return parse_blake3_content_hash("savepoint", value)
            .map(ResumeSavepointRef::CheckpointHash);
    }

    let path = Path::new(value);
    let bytes = fs::read(path).map_err(|error| {
        artifact_error(format!(
            "savepoint handle `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let handle = decode_savepoint_handle(&bytes)?;
    Ok(ResumeSavepointRef::Handle {
        path: path.to_path_buf(),
        handle,
    })
}

/// Decodes and validates the canonical line-oriented savepoint-handle format.
///
/// # Errors
///
/// Returns [`CliError`] when fields are missing, duplicated, malformed, or
/// internally inconsistent, or when embedded payloads fail validation.
pub(crate) fn decode_savepoint_handle(bytes: &[u8]) -> Result<SavepointHandle, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("savepoint handle is not UTF-8: {error}")))?;
    let mut schema = None;
    let mut label = None;
    let mut checkpoint = None;
    let mut scenario = None;
    let mut scenario_payload = None;
    let mut schedule_payload = None;
    let mut frontier_ticks = None;
    let mut at = None;
    let mut selector = None;
    let mut boundary_proof = None;
    let mut boundary_predicate = None;
    let mut terminal_condition = None;
    let mut materialization = None;
    let mut oracle_status = None;
    let mut canonical_log_digest = None;

    for (line_index, line_text) in text.lines().enumerate() {
        let fields = parse_artifact_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "schema" => {
                require_field_count(line_index, tag, &fields, 2)?;
                set_once(&mut schema, line_index, tag, fields[1].clone())?;
            }
            "label" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_required_field("savepoint label", &fields[1])?;
                set_once(&mut label, line_index, tag, fields[1].clone())?;
            }
            "checkpoint" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_blake3_content_hash("checkpoint", &fields[1])?;
                set_once(&mut checkpoint, line_index, tag, parsed)?;
            }
            "scenario" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_content_hash_hex_line(line_index, tag, &fields[1])?;
                validate_required_field("scenario label", &fields[2])?;
                set_once(
                    &mut scenario,
                    line_index,
                    tag,
                    (fields[1].clone(), fields[2].clone()),
                )?;
            }
            "scenario-payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = parse_hex_payload_line(line_index, tag, &fields[1], &fields[2])?;
                set_once(&mut scenario_payload, line_index, tag, payload)?;
            }
            "schedule-payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = parse_hex_payload_line(line_index, tag, &fields[1], &fields[2])?;
                set_once(&mut schedule_payload, line_index, tag, payload)?;
            }
            "frontier" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_u64(line_index, tag, &fields[1])?;
                set_once(&mut frontier_ticks, line_index, tag, parsed)?;
            }
            "at" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_save_at_label(line_index, tag, &fields[1])?;
                set_once(&mut at, line_index, tag, parsed)?;
            }
            "selector" => {
                let parsed = match fields.get(1).map(String::as_str) {
                    Some("none") => {
                        require_field_count(line_index, tag, &fields, 2)?;
                        None
                    }
                    Some("property-violation") => {
                        require_field_count(line_index, tag, &fields, 3)?;
                        validate_required_field("property selector", &fields[2])?;
                        Some(SaveAtSelector::PropertyViolation {
                            assertion: fields[2].clone(),
                        })
                    }
                    Some("guest-marker") => {
                        require_field_count(line_index, tag, &fields, 3)?;
                        validate_required_field("marker selector", &fields[2])?;
                        Some(SaveAtSelector::Marker {
                            name: fields[2].clone(),
                        })
                    }
                    Some(kind) => {
                        return Err(artifact_line_error(
                            line_index,
                            tag,
                            &format!("unknown selector kind `{kind}`"),
                        ));
                    }
                    None => {
                        return Err(artifact_line_error(
                            line_index,
                            tag,
                            "missing selector kind",
                        ));
                    }
                };
                set_once(&mut selector, line_index, tag, parsed)?;
            }
            "boundary-proof" => {
                let parsed = match fields.get(1).map(String::as_str) {
                    Some("coordinate") => {
                        require_field_count(line_index, tag, &fields, 4)?;
                        SavepointBoundaryProof::Coordinate {
                            frontier_ticks: parse_u64(line_index, tag, &fields[2])?,
                            quanta: parse_u64(line_index, tag, &fields[3])?,
                        }
                    }
                    Some("breakpoint") => {
                        require_field_count(line_index, tag, &fields, 6)?;
                        if fields[3] != "suspend" {
                            return Err(artifact_line_error(
                                line_index,
                                tag,
                                "save boundary breakpoint disposition must be `suspend`",
                            ));
                        }
                        SavepointBoundaryProof::Breakpoint {
                            breakpoint_id: parse_u64(line_index, tag, &fields[2])?,
                            frontier_ticks: parse_u64(line_index, tag, &fields[4])?,
                            quanta: parse_u64(line_index, tag, &fields[5])?,
                        }
                    }
                    Some(kind) => {
                        return Err(artifact_line_error(
                            line_index,
                            tag,
                            &format!("unknown boundary proof kind `{kind}`"),
                        ));
                    }
                    None => {
                        return Err(artifact_line_error(
                            line_index,
                            tag,
                            "missing boundary proof kind",
                        ));
                    }
                };
                set_once(&mut boundary_proof, line_index, tag, parsed)?;
            }
            "boundary-predicate" => {
                let parsed = if fields.get(1).is_some_and(|field| field == "none") {
                    require_field_count(line_index, tag, &fields, 2)?;
                    None
                } else {
                    require_field_count(line_index, tag, &fields, 3)?;
                    let payload = parse_hex_payload_line(line_index, tag, &fields[1], &fields[2])?;
                    let predicate =
                        crucible::Predicate::from_compact_binary(&payload).map_err(|error| {
                            artifact_line_error(
                                line_index,
                                tag,
                                &format!("predicate payload is malformed: {error}"),
                            )
                        })?;
                    Some(predicate)
                };
                set_once(&mut boundary_predicate, line_index, tag, parsed)?;
            }
            "terminal-condition" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_run_terminal_condition_label(line_index, tag, &fields[1])?;
                set_once(&mut terminal_condition, line_index, tag, parsed)?;
            }
            "materialization" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_required_field("materialization kind", &fields[1])?;
                validate_required_field("materialization source", &fields[2])?;
                set_once(
                    &mut materialization,
                    line_index,
                    tag,
                    format!("{}:{}", fields[1], fields[2]),
                )?;
            }
            "oracle" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_required_field("oracle status", &fields[1])?;
                set_once(&mut oracle_status, line_index, tag, fields[1].clone())?;
            }
            "canonical-log" => {
                require_field_count(line_index, tag, &fields, 2)?;
                validate_digest("canonical-log", &fields[1])?;
                set_once(
                    &mut canonical_log_digest,
                    line_index,
                    tag,
                    fields[1].clone(),
                )?;
            }
            _ => return Err(artifact_line_error(line_index, tag, "unknown line tag")),
        }
    }

    let schema = schema.ok_or_else(|| missing_line("schema"))?;
    if schema != SAVEPOINT_HANDLE_SCHEMA {
        return Err(artifact_error(format!(
            "unsupported savepoint handle schema `{schema}`"
        )));
    }
    let (scenario_id_hex, scenario_label) = scenario.ok_or_else(|| missing_line("scenario"))?;
    let frontier_ticks = frontier_ticks.ok_or_else(|| missing_line("frontier"))?;
    let at = at.ok_or_else(|| missing_line("at"))?;
    let terminal_condition =
        terminal_condition.ok_or_else(|| missing_line("terminal-condition"))?;
    let selector = selector.ok_or_else(|| missing_line("selector"))?;
    let boundary_proof = boundary_proof.ok_or_else(|| missing_line("boundary-proof"))?;
    let boundary_predicate =
        boundary_predicate.ok_or_else(|| missing_line("boundary-predicate"))?;
    validate_savepoint_boundary_proof(
        at,
        selector.as_ref(),
        &boundary_proof,
        boundary_predicate.as_ref(),
        frontier_ticks,
        terminal_condition,
    )?;
    Ok(SavepointHandle {
        label: label.ok_or_else(|| missing_line("label"))?,
        checkpoint: checkpoint.ok_or_else(|| missing_line("checkpoint"))?,
        scenario_id_hex,
        scenario_label,
        scenario_payload: scenario_payload.ok_or_else(|| missing_line("scenario-payload"))?,
        schedule_payload: schedule_payload.ok_or_else(|| missing_line("schedule-payload"))?,
        frontier_ticks,
        at,
        selector,
        boundary_proof: Some(boundary_proof),
        boundary_predicate,
        terminal_condition,
        materialization: materialization.ok_or_else(|| missing_line("materialization"))?,
        oracle_status: oracle_status.ok_or_else(|| missing_line("oracle"))?,
        canonical_log_digest: canonical_log_digest.ok_or_else(|| missing_line("canonical-log"))?,
    })
}

fn validate_savepoint_boundary_proof(
    at: SaveAtArg,
    selector: Option<&SaveAtSelector>,
    proof: &SavepointBoundaryProof,
    predicate: Option<&crucible::Predicate>,
    frontier_ticks: u64,
    terminal_condition: RunTerminalCondition,
) -> Result<(), CliError> {
    let proof_frontier = match proof {
        SavepointBoundaryProof::Coordinate { frontier_ticks, .. }
        | SavepointBoundaryProof::Breakpoint { frontier_ticks, .. } => *frontier_ticks,
    };
    if proof_frontier != frontier_ticks {
        return Err(artifact_error(format!(
            "savepoint boundary proof frontier {proof_frontier} did not match handle frontier {frontier_ticks}"
        )));
    }

    let expected_terminal_condition = match at {
        SaveAtArg::Quiescence | SaveAtArg::Marker => RunTerminalCondition::Quiescence,
        SaveAtArg::VirtualTime => RunTerminalCondition::VirtualTime,
        SaveAtArg::Property => RunTerminalCondition::Property,
    };
    if terminal_condition != expected_terminal_condition {
        return Err(artifact_error(format!(
            "savepoint terminal condition {} does not match --at {}",
            terminal_condition.label(),
            at.label()
        )));
    }

    let expected_predicate = match (at, selector) {
        (SaveAtArg::VirtualTime, None) => None,
        (SaveAtArg::Quiescence, None) => Some(crucible::Predicate::quiescent()),
        (SaveAtArg::Property, Some(SaveAtSelector::PropertyViolation { assertion })) => {
            Some(crucible::Predicate::assertion_state(
                crucible::AssertionId::from_name(assertion),
                crucible::AssertionPhase::Violated,
            ))
        }
        (SaveAtArg::Marker, Some(SaveAtSelector::Marker { name })) => Some(
            crucible::Predicate::guest_marker(crucible::MarkerId::from_name(name)),
        ),
        _ => {
            return Err(artifact_error(format!(
                "savepoint selector does not match --at {}",
                at.label()
            )));
        }
    };
    if predicate != expected_predicate.as_ref() {
        return Err(artifact_error(format!(
            "savepoint boundary predicate does not match --at {} selector",
            at.label()
        )));
    }

    let shape_is_valid = matches!(
        (at, proof),
        (
            SaveAtArg::VirtualTime,
            SavepointBoundaryProof::Coordinate { .. }
        ) | (
            SaveAtArg::Quiescence,
            SavepointBoundaryProof::Breakpoint { .. }
        ) | (
            SaveAtArg::Property,
            SavepointBoundaryProof::Breakpoint { .. }
        ) | (SaveAtArg::Marker, SavepointBoundaryProof::Breakpoint { .. })
    );
    if !shape_is_valid {
        return Err(artifact_error(format!(
            "savepoint boundary proof and selector do not match --at {}",
            at.label()
        )));
    }
    Ok(())
}
