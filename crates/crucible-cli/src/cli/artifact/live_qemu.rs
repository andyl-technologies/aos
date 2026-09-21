//! Canonical live-QEMU replay contracts embedded in reproduction artifacts.
//!
//! The contract records the complete initial scenario and schedule, terminal
//! snapshot, and execution controls that cannot be recovered from a terminal
//! model configuration alone. Replay also requires the paired model component
//! to carry identical scenario and final-schedule material.

use super::*;

const LIVE_QEMU_REPLAY_CONTRACT_SCHEMA: &str = "crucible.live-qemu-replay-contract.v4";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuReplayContract {
    pub(crate) producer: String,
    pub(crate) execution_owner: RunExecutionOwner,
    pub(crate) execution_mode: RunExecutionMode,
    pub(crate) initial_configuration: String,
    pub(crate) initial_scenario: Vec<u8>,
    pub(crate) initial_schedule: Vec<u8>,
    pub(crate) terminal_condition: String,
    pub(crate) terminal_status: String,
    pub(crate) terminal_outcome: String,
    pub(crate) terminal_configuration: String,
    pub(crate) final_frontier_ticks: u64,
    pub(crate) final_quanta: u64,
    pub(crate) final_event_log_len: u64,
    pub(crate) final_schedule: Vec<u8>,
    pub(crate) terminal_savepoint: Option<Vec<u8>>,
    pub(crate) budget_timed_out: bool,
    pub(crate) max_virtual_time_ticks: Option<u64>,
    pub(crate) max_quanta: Option<u64>,
    pub(crate) run_ceiling_icount: Option<u64>,
    pub(crate) lifecycle_quantum_budget: Option<u64>,
    pub(crate) coverage: bool,
    pub(crate) fingerprint_scope: LiveQemuFingerprintScope,
    pub(crate) branch: LiveQemuReplayBranch,
    pub(crate) network_choice_indices: Vec<u64>,
    pub(crate) startup_controls: Vec<LiveQemuReplayControl>,
    pub(crate) initial_controls: Vec<LiveQemuReplayControl>,
    pub(crate) controls: Vec<LiveQemuReplayControl>,
    pub(crate) reproduction_commands: Vec<crucible_api::ReproductionCommandRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveQemuReplayBranch {
    None,
    Resume {
        base_decisions: u64,
        frontier_ticks: u64,
    },
    Reseed {
        base_decisions: u64,
        frontier_ticks: u64,
        seed: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveQemuFingerprintScope {
    FullExecution,
    TerminalAllNodes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuReplayControl {
    pub(crate) sequence: u64,
    pub(crate) command: String,
}

impl LiveQemuReplayContract {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut text = String::new();
        artifact_line(&mut text, &["schema", LIVE_QEMU_REPLAY_CONTRACT_SCHEMA]);
        artifact_line(&mut text, &["producer", &self.producer]);
        artifact_line(
            &mut text,
            &[
                "execution",
                match self.execution_owner {
                    RunExecutionOwner::Session => "session",
                    RunExecutionOwner::Campaign => "campaign",
                },
                match self.execution_mode {
                    RunExecutionMode::Interactive => "interactive",
                    RunExecutionMode::ToCompletion => "to-completion",
                },
            ],
        );
        artifact_line(
            &mut text,
            &[
                "initial",
                &self.initial_configuration,
                &hex_bytes(&self.initial_scenario),
                &hex_bytes(&self.initial_schedule),
            ],
        );
        artifact_line(
            &mut text,
            &[
                "terminal",
                &self.terminal_condition,
                &self.terminal_status,
                &self.terminal_outcome,
                &self.terminal_configuration,
                &self.final_frontier_ticks.to_string(),
                &self.final_quanta.to_string(),
                bool_label(self.budget_timed_out),
            ],
        );
        artifact_line(
            &mut text,
            &[
                "snapshot",
                &self.final_event_log_len.to_string(),
                &hex_bytes(&self.final_schedule),
                &self
                    .terminal_savepoint
                    .as_deref()
                    .map(hex_bytes)
                    .unwrap_or_else(|| String::from("none")),
            ],
        );
        artifact_line(
            &mut text,
            &[
                "bounds",
                &optional_u64_label(self.max_virtual_time_ticks),
                &optional_u64_label(self.max_quanta),
                bool_label(self.coverage),
            ],
        );
        artifact_line(
            &mut text,
            &[
                "lifecycle",
                &optional_u64_label(self.run_ceiling_icount),
                &optional_u64_label(self.lifecycle_quantum_budget),
            ],
        );
        artifact_line(
            &mut text,
            &[
                "fingerprints",
                match self.fingerprint_scope {
                    LiveQemuFingerprintScope::FullExecution => "full-execution",
                    LiveQemuFingerprintScope::TerminalAllNodes => "terminal-all-nodes",
                },
            ],
        );
        match self.branch {
            LiveQemuReplayBranch::None => {
                artifact_line(&mut text, &["branch", "none"]);
            }
            LiveQemuReplayBranch::Resume {
                base_decisions,
                frontier_ticks,
            } => artifact_line(
                &mut text,
                &[
                    "branch",
                    "resume",
                    &base_decisions.to_string(),
                    &frontier_ticks.to_string(),
                ],
            ),
            LiveQemuReplayBranch::Reseed {
                base_decisions,
                frontier_ticks,
                seed,
            } => artifact_line(
                &mut text,
                &[
                    "branch",
                    "reseed",
                    &base_decisions.to_string(),
                    &frontier_ticks.to_string(),
                    &seed.to_string(),
                ],
            ),
        }
        for index in &self.network_choice_indices {
            artifact_line(&mut text, &["choice", "network", &index.to_string()]);
        }
        encode_controls(&mut text, "startup-control", &self.startup_controls);
        encode_controls(&mut text, "initial-control", &self.initial_controls);
        for control in &self.controls {
            artifact_line(
                &mut text,
                &["control", &control.sequence.to_string(), &control.command],
            );
        }
        for record in &self.reproduction_commands {
            artifact_line(
                &mut text,
                &[
                    "record",
                    &record.sequence.to_string(),
                    session_command_name(record.payload.command),
                    &hex_bytes(record.payload.command_payload.as_bytes()),
                    &record.payload.scheduler_batch.to_string(),
                    &record
                        .payload
                        .scheduler_control
                        .as_deref()
                        .map(|value| hex_bytes(value.as_bytes()))
                        .unwrap_or_else(|| String::from("none")),
                    &record.virtual_time.ticks.to_string(),
                    &record.quanta.to_string(),
                    &record.at_sequence.to_string(),
                    "accepted",
                    &record.observational_order.to_string(),
                ],
            );
        }
        text.into_bytes()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            artifact_error(format!("live-QEMU replay contract is not UTF-8: {error}"))
        })?;
        let mut schema = None;
        let mut producer = None;
        let mut execution = None;
        let mut initial = None;
        let mut terminal = None;
        let mut snapshot = None;
        let mut bounds = None;
        let mut lifecycle = None;
        let mut fingerprint_scope = None;
        let mut branch = None;
        let mut network_choice_indices = Vec::new();
        let mut startup_controls = Vec::new();
        let mut initial_controls = Vec::new();
        let mut controls = Vec::new();
        let mut reproduction_commands = Vec::new();
        for (line_index, line) in text.lines().enumerate() {
            let fields = parse_artifact_fields(line)?;
            let Some(tag) = fields.first().map(String::as_str) else {
                continue;
            };
            match tag {
                "schema" => {
                    require_field_count(line_index, tag, &fields, 2)?;
                    set_once(&mut schema, line_index, tag, fields[1].clone())?;
                }
                "producer" => {
                    require_field_count(line_index, tag, &fields, 2)?;
                    validate_required_field("live replay producer", &fields[1])?;
                    set_once(&mut producer, line_index, tag, fields[1].clone())?;
                }
                "execution" => {
                    require_field_count(line_index, tag, &fields, 3)?;
                    let owner = match fields[1].as_str() {
                        "session" => RunExecutionOwner::Session,
                        "campaign" => RunExecutionOwner::Campaign,
                        other => {
                            return Err(artifact_line_error(
                                line_index,
                                tag,
                                &format!("unknown execution owner `{other}`"),
                            ));
                        }
                    };
                    let mode = match fields[2].as_str() {
                        "interactive" => RunExecutionMode::Interactive,
                        "to-completion" => RunExecutionMode::ToCompletion,
                        other => {
                            return Err(artifact_line_error(
                                line_index,
                                tag,
                                &format!("unknown execution mode `{other}`"),
                            ));
                        }
                    };
                    set_once(&mut execution, line_index, tag, (owner, mode))?;
                }
                "initial" => {
                    require_field_count(line_index, tag, &fields, 4)?;
                    set_once(
                        &mut initial,
                        line_index,
                        tag,
                        (
                            fields[1].clone(),
                            parse_hex_bytes(line_index, tag, &fields[2])?,
                            parse_hex_bytes(line_index, tag, &fields[3])?,
                        ),
                    )?;
                }
                "terminal" => {
                    require_field_count(line_index, tag, &fields, 8)?;
                    set_once(
                        &mut terminal,
                        line_index,
                        tag,
                        (
                            fields[1].clone(),
                            fields[2].clone(),
                            fields[3].clone(),
                            fields[4].clone(),
                            parse_u64(line_index, tag, &fields[5])?,
                            parse_u64(line_index, tag, &fields[6])?,
                            parse_bool(line_index, tag, &fields[7])?,
                        ),
                    )?;
                }
                "bounds" => {
                    require_field_count(line_index, tag, &fields, 4)?;
                    set_once(
                        &mut bounds,
                        line_index,
                        tag,
                        (
                            parse_optional_u64(line_index, tag, &fields[1])?,
                            parse_optional_u64(line_index, tag, &fields[2])?,
                            parse_bool(line_index, tag, &fields[3])?,
                        ),
                    )?;
                }
                "snapshot" => {
                    require_field_count(line_index, tag, &fields, 4)?;
                    let savepoint = if fields[3] == "none" {
                        None
                    } else {
                        Some(parse_hex_bytes(line_index, tag, &fields[3])?)
                    };
                    set_once(
                        &mut snapshot,
                        line_index,
                        tag,
                        (
                            parse_u64(line_index, tag, &fields[1])?,
                            parse_hex_bytes(line_index, tag, &fields[2])?,
                            savepoint,
                        ),
                    )?;
                }
                "lifecycle" => {
                    require_field_count(line_index, tag, &fields, 3)?;
                    set_once(
                        &mut lifecycle,
                        line_index,
                        tag,
                        (
                            parse_optional_u64(line_index, tag, &fields[1])?,
                            parse_optional_u64(line_index, tag, &fields[2])?,
                        ),
                    )?;
                }
                "fingerprints" => {
                    require_field_count(line_index, tag, &fields, 2)?;
                    let parsed = match fields[1].as_str() {
                        "full-execution" => LiveQemuFingerprintScope::FullExecution,
                        "terminal-all-nodes" => LiveQemuFingerprintScope::TerminalAllNodes,
                        other => {
                            return Err(artifact_line_error(
                                line_index,
                                tag,
                                &format!("unknown fingerprint scope `{other}`"),
                            ));
                        }
                    };
                    set_once(&mut fingerprint_scope, line_index, tag, parsed)?;
                }
                "branch" => {
                    let parsed = parse_branch(line_index, tag, &fields)?;
                    set_once(&mut branch, line_index, tag, parsed)?;
                }
                "choice" => {
                    require_field_count(line_index, tag, &fields, 3)?;
                    let index = parse_u64(line_index, tag, &fields[2])?;
                    match fields[1].as_str() {
                        "network" => network_choice_indices.push(index),
                        other => {
                            return Err(artifact_line_error(
                                line_index,
                                tag,
                                &format!("unknown replay choice kind `{other}`"),
                            ));
                        }
                    }
                }
                "startup-control" | "initial-control" | "control" => {
                    require_field_count(line_index, tag, &fields, 3)?;
                    let control = LiveQemuReplayControl {
                        sequence: parse_u64(line_index, tag, &fields[1])?,
                        command: fields[2].clone(),
                    };
                    match tag {
                        "startup-control" => startup_controls.push(control),
                        "initial-control" => initial_controls.push(control),
                        _ => controls.push(control),
                    }
                }
                "record" => {
                    require_field_count(line_index, tag, &fields, 11)?;
                    reproduction_commands.push(parse_reproduction_record(line_index, &fields)?);
                }
                other => {
                    return Err(artifact_line_error(
                        line_index,
                        other,
                        "unknown live-QEMU replay contract line",
                    ));
                }
            }
        }
        if schema.as_deref() != Some(LIVE_QEMU_REPLAY_CONTRACT_SCHEMA) {
            return Err(artifact_error(
                "unsupported live-QEMU replay contract schema",
            ));
        }
        let (
            terminal_condition,
            terminal_status,
            terminal_outcome,
            terminal_configuration,
            final_frontier_ticks,
            final_quanta,
            budget_timed_out,
        ) = terminal
            .ok_or_else(|| artifact_error("live-QEMU replay contract has no terminal target"))?;
        let (max_virtual_time_ticks, max_quanta, coverage) =
            bounds.ok_or_else(|| artifact_error("live-QEMU replay contract has no bounds"))?;
        let (run_ceiling_icount, lifecycle_quantum_budget) = lifecycle
            .ok_or_else(|| artifact_error("live-QEMU replay contract has no lifecycle limits"))?;
        let producer =
            producer.ok_or_else(|| artifact_error("live-QEMU replay contract has no producer"))?;
        let (execution_owner, execution_mode) = execution
            .ok_or_else(|| artifact_error("live-QEMU replay contract has no execution route"))?;
        let (initial_configuration, initial_scenario, initial_schedule) =
            initial.ok_or_else(|| {
                artifact_error("live-QEMU replay contract has no initial configuration")
            })?;
        let (final_event_log_len, final_schedule, terminal_savepoint) = snapshot
            .ok_or_else(|| artifact_error("live-QEMU replay contract has no final snapshot"))?;
        if !matches!(
            producer.as_str(),
            "run" | "campaign-run" | "campaign-search" | "verify" | "search" | "fuzz"
        ) {
            return Err(artifact_error(format!(
                "live-QEMU replay contract has unsupported producer `{producer}`"
            )));
        }
        let contract = Self {
            producer,
            execution_owner,
            execution_mode,
            initial_configuration,
            initial_scenario,
            initial_schedule,
            terminal_condition,
            terminal_status,
            terminal_outcome,
            terminal_configuration,
            final_frontier_ticks,
            final_quanta,
            final_event_log_len,
            final_schedule,
            terminal_savepoint,
            budget_timed_out,
            max_virtual_time_ticks,
            max_quanta,
            run_ceiling_icount,
            lifecycle_quantum_budget,
            coverage,
            fingerprint_scope: fingerprint_scope.ok_or_else(|| {
                artifact_error("live-QEMU replay contract has no fingerprint scope")
            })?,
            branch: branch
                .ok_or_else(|| artifact_error("live-QEMU replay contract has no branch"))?,
            network_choice_indices,
            startup_controls,
            initial_controls,
            controls,
            reproduction_commands,
        };
        contract.validate_semantics()?;
        if contract.encode() != bytes {
            return Err(artifact_error(
                "non-canonical live-QEMU replay contract encoding",
            ));
        }
        Ok(contract)
    }

    fn validate_semantics(&self) -> Result<(), CliError> {
        if self.execution_mode == RunExecutionMode::Interactive
            && self.execution_owner != RunExecutionOwner::Session
        {
            return Err(artifact_error(
                "interactive live-QEMU artifacts require the session execution owner",
            ));
        }
        if self.execution_mode == RunExecutionMode::ToCompletion
            && self.execution_owner != RunExecutionOwner::Campaign
        {
            return Err(artifact_error(
                "to-completion live-QEMU artifacts require the campaign execution owner",
            ));
        }
        let initial_scenario =
            crucible::ScenarioDefForm::from_compact_binary(&self.initial_scenario)
                .map_err(|error| artifact_error(format!("decode initial scenario: {error}")))?;
        if initial_scenario.to_compact_binary() != self.initial_scenario {
            return Err(artifact_error("initial scenario encoding is not canonical"));
        }
        let initial_schedule = crucible::Schedule::from_compact_binary(&self.initial_schedule)
            .map_err(|error| artifact_error(format!("decode initial schedule: {error}")))?;
        if initial_schedule.to_compact_binary() != self.initial_schedule {
            return Err(artifact_error("initial schedule encoding is not canonical"));
        }
        let initial_configuration = crucible::Configuration {
            def: initial_scenario.scenario_def(),
            schedule: initial_schedule,
        };
        if format_content_hash_ref(initial_configuration.id()) != self.initial_configuration {
            return Err(artifact_error(
                "initial configuration identity does not match its scenario and schedule",
            ));
        }
        let final_schedule = crucible::Schedule::from_compact_binary(&self.final_schedule)
            .map_err(|error| artifact_error(format!("decode final schedule: {error}")))?;
        if final_schedule.to_compact_binary() != self.final_schedule {
            return Err(artifact_error("final schedule encoding is not canonical"));
        }
        if let Some(bytes) = &self.terminal_savepoint {
            let checkpoint = crucible::Checkpoint::from_compact_binary(bytes)
                .map_err(|error| artifact_error(format!("decode terminal savepoint: {error}")))?;
            if checkpoint.to_compact_binary() != *bytes {
                return Err(artifact_error(
                    "terminal savepoint encoding is not canonical",
                ));
            }
        }
        for (index, record) in self.reproduction_commands.iter().enumerate() {
            let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
            if record.sequence != expected {
                return Err(artifact_error(
                    "reproduction record sequences must be contiguous from one",
                ));
            }
            let _ = crucible_session::SessionControlLogEntry::try_from(record.clone())
                .map_err(|error| artifact_error(error.to_string()))?;
        }
        if self
            .network_choice_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(artifact_error(
                "live-QEMU replay network choice indices must be unique and increasing",
            ));
        }
        let fork_branch = !matches!(self.branch, LiveQemuReplayBranch::None);
        if fork_branch && self.producer != "campaign-run" {
            return Err(artifact_error(
                "live-QEMU replay branches require the campaign-run producer",
            ));
        }
        let branch_start = match &self.branch {
            LiveQemuReplayBranch::None => 0,
            LiveQemuReplayBranch::Resume { base_decisions, .. }
            | LiveQemuReplayBranch::Reseed { base_decisions, .. } => *base_decisions,
        };
        if self
            .network_choice_indices
            .iter()
            .any(|index| *index < branch_start)
        {
            return Err(artifact_error(
                "branch replay choices must belong to the post-branch suffix",
            ));
        }
        let terminal_scope = self.fingerprint_scope == LiveQemuFingerprintScope::TerminalAllNodes;
        let requires_terminal_scope = self.execution_mode == RunExecutionMode::Interactive
            || self.producer == "campaign-search"
            || fork_branch;
        if requires_terminal_scope != terminal_scope {
            return Err(artifact_error(
                "live-QEMU replay fingerprint scope is incompatible with its producer",
            ));
        }
        if matches!(self.producer.as_str(), "search" | "campaign-search")
            && (self.run_ceiling_icount.is_none() || self.lifecycle_quantum_budget.is_none())
        {
            return Err(artifact_error(
                "search replay contracts require explicit lifecycle ceilings",
            ));
        }
        validate_controls("startup", &self.startup_controls, |command| {
            matches!(command, "start" | "continue" | "step-quantum")
        })?;
        validate_controls("initial", &self.initial_controls, |command| {
            command == "query"
        })?;
        if fork_branch
            && (control_commands(&self.startup_controls) != ["start", "continue"]
                || control_commands(&self.initial_controls) != ["query"])
        {
            return Err(artifact_error(
                "live-QEMU branch replay requires startup controls `start,continue` and one initial `query`",
            ));
        }
        validate_controls("acknowledged", &self.controls, known_control_command)?;
        Ok(())
    }
}

fn parse_reproduction_record(
    line_index: usize,
    fields: &[String],
) -> Result<crucible_api::ReproductionCommandRecord, CliError> {
    let command = parse_session_command_kind(line_index, &fields[2])?;
    let command_payload = String::from_utf8(parse_hex_bytes(line_index, "record", &fields[3])?)
        .map_err(|error| {
            artifact_line_error(
                line_index,
                "record",
                &format!("command payload is not UTF-8: {error}"),
            )
        })?;
    let scheduler_control = if fields[5] == "none" {
        None
    } else {
        Some(
            String::from_utf8(parse_hex_bytes(line_index, "record", &fields[5])?).map_err(
                |error| {
                    artifact_line_error(
                        line_index,
                        "record",
                        &format!("scheduler control is not UTF-8: {error}"),
                    )
                },
            )?,
        )
    };
    if fields[9] != "accepted" {
        return Err(artifact_line_error(
            line_index,
            "record",
            "unknown reproduction command result",
        ));
    }
    Ok(crucible_api::ReproductionCommandRecord {
        sequence: parse_u64(line_index, "record", &fields[1])?,
        payload: crucible_api::ReproductionCommandPayload {
            command,
            command_payload,
            scheduler_batch: parse_u64(line_index, "record", &fields[4])?,
            scheduler_control,
        },
        virtual_time: crucible::VirtualTime {
            ticks: parse_u64(line_index, "record", &fields[6])?,
        },
        quanta: parse_u64(line_index, "record", &fields[7])?,
        at_sequence: parse_u64(line_index, "record", &fields[8])?,
        result: crucible_api::ReproductionCommandResult::Accepted,
        observational_order: parse_u64(line_index, "record", &fields[10])?,
    })
}

fn parse_session_command_kind(
    line_index: usize,
    command: &str,
) -> Result<SessionCommandKind, CliError> {
    SessionCommandKind::ALL
        .into_iter()
        .find(|candidate| session_command_name(*candidate) == command)
        .ok_or_else(|| {
            artifact_line_error(
                line_index,
                "record",
                &format!("unknown reproduction command `{command}`"),
            )
        })
}

fn control_commands(controls: &[LiveQemuReplayControl]) -> Vec<&str> {
    controls
        .iter()
        .map(|control| control.command.as_str())
        .collect()
}

fn encode_controls(text: &mut String, tag: &str, controls: &[LiveQemuReplayControl]) {
    for control in controls {
        artifact_line(
            text,
            &[tag, &control.sequence.to_string(), &control.command],
        );
    }
}

fn validate_controls(
    label: &str,
    controls: &[LiveQemuReplayControl],
    admitted: impl Fn(&str) -> bool,
) -> Result<(), CliError> {
    for (index, control) in controls.iter().enumerate() {
        if control.sequence != index as u64 {
            return Err(artifact_error(format!(
                "live-QEMU replay {label} control sequences must be contiguous from zero"
            )));
        }
        if !admitted(&control.command) {
            return Err(artifact_error(format!(
                "live-QEMU replay contract has unsupported {label} control command `{}`",
                control.command
            )));
        }
    }
    Ok(())
}

fn known_control_command(command: &str) -> bool {
    matches!(
        command,
        "start"
            | "continue"
            | "pause"
            | "step-quantum"
            | "step-event"
            | "step-assertion"
            | "step-timer"
            | "step-duration"
            | "set-breakpoint"
            | "remove-breakpoint"
            | "create-savepoint"
            | "query"
            | "stop"
            | "exhaust-budget"
            | "attach-gdb"
            | "debug-goto"
            | "debug-reverse-step"
            | "debug-reverse-continue"
            | "debug-fork-non-canonical"
    )
}

fn parse_branch(
    line_index: usize,
    tag: &str,
    fields: &[String],
) -> Result<LiveQemuReplayBranch, CliError> {
    match fields.get(1).map(String::as_str) {
        Some("none") => {
            require_field_count(line_index, tag, fields, 2)?;
            Ok(LiveQemuReplayBranch::None)
        }
        Some("resume") => {
            require_field_count(line_index, tag, fields, 4)?;
            Ok(LiveQemuReplayBranch::Resume {
                base_decisions: parse_u64(line_index, tag, &fields[2])?,
                frontier_ticks: parse_u64(line_index, tag, &fields[3])?,
            })
        }
        Some("reseed") => {
            require_field_count(line_index, tag, fields, 5)?;
            Ok(LiveQemuReplayBranch::Reseed {
                base_decisions: parse_u64(line_index, tag, &fields[2])?,
                frontier_ticks: parse_u64(line_index, tag, &fields[3])?,
                seed: parse_u64(line_index, tag, &fields[4])?,
            })
        }
        Some(other) => Err(artifact_line_error(
            line_index,
            tag,
            &format!("unknown replay branch kind `{other}`"),
        )),
        None => Err(artifact_line_error(
            line_index,
            tag,
            "missing replay branch kind",
        )),
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn optional_u64_label(value: Option<u64>) -> String {
    value.map_or_else(|| String::from("none"), |value| value.to_string())
}

fn parse_bool(line_index: usize, tag: &str, value: &str) -> Result<bool, CliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(artifact_line_error(
            line_index,
            tag,
            "expected `true` or `false`",
        )),
    }
}

fn parse_optional_u64(line_index: usize, tag: &str, value: &str) -> Result<Option<u64>, CliError> {
    if value == "none" {
        Ok(None)
    } else {
        parse_u64(line_index, tag, value).map(Some)
    }
}

#[cfg(test)]
#[path = "live_qemu/tests.rs"]
mod tests;
