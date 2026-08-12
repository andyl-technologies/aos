//! Canonical live-QEMU replay contracts embedded in v3 artifacts.
//!
//! The contract records execution controls that cannot be recovered from a
//! terminal model configuration alone. The scenario and typed schedule remain
//! authoritative in the paired model-reproduction component.

use super::*;

const LIVE_QEMU_REPLAY_CONTRACT_SCHEMA: &str = "crucible.live-qemu-replay-contract.v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuReplayContract {
    pub(crate) producer: String,
    pub(crate) terminal_condition: String,
    pub(crate) terminal_status: String,
    pub(crate) terminal_outcome: String,
    pub(crate) terminal_configuration: String,
    pub(crate) final_frontier_ticks: u64,
    pub(crate) final_quanta: u64,
    pub(crate) budget_timed_out: bool,
    pub(crate) max_virtual_time_ticks: Option<u64>,
    pub(crate) max_quanta: Option<u64>,
    pub(crate) run_ceiling_icount: Option<u64>,
    pub(crate) lifecycle_quantum_budget: Option<u64>,
    pub(crate) coverage: bool,
    pub(crate) fingerprint_scope: LiveQemuFingerprintScope,
    pub(crate) branch: LiveQemuReplayBranch,
    pub(crate) fault_choice_indices: Vec<u64>,
    pub(crate) network_choice_indices: Vec<u64>,
    pub(crate) startup_controls: Vec<LiveQemuReplayControl>,
    pub(crate) initial_controls: Vec<LiveQemuReplayControl>,
    pub(crate) controls: Vec<LiveQemuReplayControl>,
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
    PrefixOverrides {
        base_decisions: u64,
        frontier_ticks: u64,
        decision_start: u64,
        decision_end: u64,
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
            LiveQemuReplayBranch::PrefixOverrides {
                base_decisions,
                frontier_ticks,
                decision_start,
                decision_end,
            } => artifact_line(
                &mut text,
                &[
                    "branch",
                    "prefix-overrides",
                    &base_decisions.to_string(),
                    &frontier_ticks.to_string(),
                    &decision_start.to_string(),
                    &decision_end.to_string(),
                ],
            ),
        }
        for index in &self.fault_choice_indices {
            artifact_line(&mut text, &["choice", "fault", &index.to_string()]);
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
        text.into_bytes()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            artifact_error(format!("live-QEMU replay contract is not UTF-8: {error}"))
        })?;
        let mut schema = None;
        let mut producer = None;
        let mut terminal = None;
        let mut bounds = None;
        let mut lifecycle = None;
        let mut fingerprint_scope = None;
        let mut branch = None;
        let mut fault_choice_indices = Vec::new();
        let mut network_choice_indices = Vec::new();
        let mut startup_controls = Vec::new();
        let mut initial_controls = Vec::new();
        let mut controls = Vec::new();
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
                        "fault" => fault_choice_indices.push(index),
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
        if !matches!(
            producer.as_str(),
            "run" | "verify" | "search" | "fuzz" | "fork"
        ) {
            return Err(artifact_error(format!(
                "live-QEMU replay contract has unsupported producer `{producer}`"
            )));
        }
        let contract = Self {
            producer,
            terminal_condition,
            terminal_status,
            terminal_outcome,
            terminal_configuration,
            final_frontier_ticks,
            final_quanta,
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
            fault_choice_indices,
            network_choice_indices,
            startup_controls,
            initial_controls,
            controls,
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
        for (label, indices) in [
            ("fault", self.fault_choice_indices.as_slice()),
            ("network", self.network_choice_indices.as_slice()),
        ] {
            if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(artifact_error(format!(
                    "live-QEMU replay {label} choice indices must be unique and increasing"
                )));
            }
        }
        let fork_branch = !matches!(self.branch, LiveQemuReplayBranch::None);
        if (self.producer == "fork") != fork_branch {
            return Err(artifact_error(
                "live-QEMU replay branch recipes are required only for fork artifacts",
            ));
        }
        let branch_start = match &self.branch {
            LiveQemuReplayBranch::None => 0,
            LiveQemuReplayBranch::Resume { base_decisions, .. }
            | LiveQemuReplayBranch::Reseed { base_decisions, .. }
            | LiveQemuReplayBranch::PrefixOverrides { base_decisions, .. } => *base_decisions,
        };
        if self
            .fault_choice_indices
            .iter()
            .chain(&self.network_choice_indices)
            .any(|index| *index < branch_start)
        {
            return Err(artifact_error(
                "fork replay choices must belong to the post-branch suffix",
            ));
        }
        if let LiveQemuReplayBranch::PrefixOverrides {
            base_decisions,
            decision_start,
            decision_end,
            ..
        } = &self.branch
            && (decision_start != base_decisions || decision_end < decision_start)
        {
            return Err(artifact_error(
                "fork prefix-override coordinates are not a contiguous branch suffix",
            ));
        }
        let terminal_scope = self.fingerprint_scope == LiveQemuFingerprintScope::TerminalAllNodes;
        if matches!(self.producer.as_str(), "search" | "fork") != terminal_scope {
            return Err(artifact_error(
                "live-QEMU replay fingerprint scope is incompatible with its producer",
            ));
        }
        if self.producer == "search"
            && (self.run_ceiling_icount.is_none() || self.lifecycle_quantum_budget.is_none())
        {
            return Err(artifact_error(
                "search replay contracts require explicit lifecycle ceilings",
            ));
        }
        validate_controls("startup", &self.startup_controls, |command| {
            matches!(command, "start" | "continue" | "step-quantum")
                || self.producer == "fork" && command == "fork"
        })?;
        validate_controls("initial", &self.initial_controls, |command| {
            command == "query"
        })?;
        if self.producer == "fork"
            && (control_commands(&self.startup_controls) != ["fork", "continue"]
                || control_commands(&self.initial_controls) != ["query"])
        {
            return Err(artifact_error(
                "live-QEMU fork replay requires startup controls `fork,continue` and one initial `query`",
            ));
        }
        validate_controls("acknowledged", &self.controls, known_control_command)?;
        Ok(())
    }
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
            | "inject"
            | "set-breakpoint"
            | "remove-breakpoint"
            | "create-savepoint"
            | "fork"
            | "query"
            | "stop"
            | "exhaust-budget"
            | "snapshot"
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
        Some("prefix-overrides") => {
            require_field_count(line_index, tag, fields, 6)?;
            Ok(LiveQemuReplayBranch::PrefixOverrides {
                base_decisions: parse_u64(line_index, tag, &fields[2])?,
                frontier_ticks: parse_u64(line_index, tag, &fields[3])?,
                decision_start: parse_u64(line_index, tag, &fields[4])?,
                decision_end: parse_u64(line_index, tag, &fields[5])?,
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
