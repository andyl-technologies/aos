//! Canonical live-QEMU replay contracts embedded in v3 artifacts.
//!
//! The contract records execution controls that cannot be recovered from a
//! terminal model configuration alone. The scenario and typed schedule remain
//! authoritative in the paired model-reproduction component.

use super::*;

const LIVE_QEMU_REPLAY_CONTRACT_SCHEMA: &str = "crucible.live-qemu-replay-contract.v1";

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
    pub(crate) coverage: bool,
    pub(crate) branch: LiveQemuReplayBranch,
    pub(crate) fault_choice_indices: Vec<u64>,
    pub(crate) network_choice_indices: Vec<u64>,
    pub(crate) controls: Vec<LiveQemuReplayControl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveQemuReplayBranch {
    None,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuReplayControl {
    pub(crate) sequence: u64,
    pub(crate) configuration_decisions: u64,
    pub(crate) frontier_ticks: u64,
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
        match self.branch {
            LiveQemuReplayBranch::None => {
                artifact_line(&mut text, &["branch", "none"]);
            }
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
        for control in &self.controls {
            artifact_line(
                &mut text,
                &[
                    "control",
                    &control.sequence.to_string(),
                    &control.configuration_decisions.to_string(),
                    &control.frontier_ticks.to_string(),
                    &control.command,
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
        let mut terminal = None;
        let mut bounds = None;
        let mut branch = None;
        let mut fault_choice_indices = Vec::new();
        let mut network_choice_indices = Vec::new();
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
                "control" => {
                    require_field_count(line_index, tag, &fields, 5)?;
                    controls.push(LiveQemuReplayControl {
                        sequence: parse_u64(line_index, tag, &fields[1])?,
                        configuration_decisions: parse_u64(line_index, tag, &fields[2])?,
                        frontier_ticks: parse_u64(line_index, tag, &fields[3])?,
                        command: fields[4].clone(),
                    });
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
        for (expected, control) in controls.iter().enumerate() {
            if control.sequence != expected as u64 {
                return Err(artifact_error(format!(
                    "live-QEMU replay control sequence out of order: expected {expected}, got {}",
                    control.sequence
                )));
            }
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
        let contract = Self {
            producer: producer
                .ok_or_else(|| artifact_error("live-QEMU replay contract has no producer"))?,
            terminal_condition,
            terminal_status,
            terminal_outcome,
            terminal_configuration,
            final_frontier_ticks,
            final_quanta,
            budget_timed_out,
            max_virtual_time_ticks,
            max_quanta,
            coverage,
            branch: branch
                .ok_or_else(|| artifact_error("live-QEMU replay contract has no branch"))?,
            fault_choice_indices,
            network_choice_indices,
            controls,
        };
        if contract.encode() != bytes {
            return Err(artifact_error(
                "non-canonical live-QEMU replay contract encoding",
            ));
        }
        Ok(contract)
    }
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
mod tests {
    use super::*;

    #[test]
    fn live_qemu_replay_contract_round_trips_canonically() -> Result<(), CliError> {
        let contract = LiveQemuReplayContract {
            producer: String::from("fork"),
            terminal_condition: String::from("quiescence"),
            terminal_status: String::from("failed"),
            terminal_outcome: String::from("failed"),
            terminal_configuration: String::from("blake3:terminal"),
            final_frontier_ticks: 42,
            final_quanta: 7,
            budget_timed_out: false,
            max_virtual_time_ticks: None,
            max_quanta: Some(8),
            coverage: true,
            branch: LiveQemuReplayBranch::Reseed {
                base_decisions: 3,
                frontier_ticks: 11,
                seed: 99,
            },
            fault_choice_indices: vec![4],
            network_choice_indices: vec![5],
            controls: vec![LiveQemuReplayControl {
                sequence: 0,
                configuration_decisions: 3,
                frontier_ticks: 11,
                command: String::from("continue"),
            }],
        };
        let encoded = contract.encode();
        assert_eq!(LiveQemuReplayContract::decode(&encoded)?, contract);
        Ok(())
    }
}
