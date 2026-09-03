//! Renderer-independent maintenance results, diagnostics, actions, and views.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::MAINTENANCE_CLI_V1;
use crate::identity::RunId;
use crate::workflow::{DiscoveryDecision, GateOutcome, RunState, TaskStatus};

/// Classifies the outcome of the requested command independently of run state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandDisposition {
    /// The requested operation completed successfully.
    Success,
    /// A deterministic operation ran but did not satisfy its contract.
    OperationFailed,
    /// The arguments or requested combination are invalid.
    InvalidInvocation,
    /// Required local execution capability is unavailable.
    InfrastructureUnavailable,
    /// Discovery proved that no acceptable update exists.
    NoChange,
    /// A human decision or explicit authorization is required.
    ActionRequired,
    /// Fresh complete upstream evidence is unavailable.
    UpstreamUnknown,
    /// Conflicting source or identity evidence requires investigation.
    Quarantined,
    /// Immutable plan inputs no longer match current state.
    Stale,
    /// The invocation stopped after checkpointing its durable boundary.
    Interrupted,
}

impl CommandDisposition {
    /// Returns the stable process exit code for the disposition.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::NoChange => 10,
            Self::ActionRequired => 11,
            Self::OperationFailed => 12,
            Self::UpstreamUnknown => 13,
            Self::Quarantined => 14,
            Self::Stale => 15,
            Self::InfrastructureUnavailable => 16,
            Self::Interrupted => 17,
            Self::InvalidInvocation => 2,
        }
    }
}

/// Classifies supplemental diagnostic importance without replacing outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    /// Supplies important context while retaining the primary outcome.
    Warning,
    /// Explains a condition that prevents the requested operation.
    Error,
}

/// Identifies a bounded source range for a structured diagnostic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceSpan {
    /// Normalized repository-relative path or contract object label.
    pub source: String,
    /// Zero-based byte offset within the bounded source.
    pub offset: u64,
    /// Byte length of the highlighted range.
    pub length: u64,
}

/// Carries one stable, structured warning or error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Diagnostic {
    /// Stable machine-readable diagnostic code.
    pub code: String,
    /// Diagnostic importance, separate from gate and command outcomes.
    pub severity: DiagnosticSeverity,
    /// Concise one-line explanation.
    pub summary: String,
    /// Optional bounded supporting detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Optional exact source range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    /// Optional actionable remediation text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Classifies the side effect represented by a next action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectClass {
    /// Reads durable or repository state without mutation.
    ReadOnly,
    /// Changes protected local run state or a worktree.
    LocalMutation,
    /// Requires one operation-specific human decision.
    HumanDecision,
    /// Pushes or changes explicitly scoped remote Git or PR state.
    RemoteMutation,
}

/// Defines one exact command available from the current verified state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NextAction {
    /// Short human label rendered on an action card.
    pub label: String,
    /// Exact argument vector without shell interpolation.
    pub argv: Vec<String>,
    /// Reason this action is relevant now.
    pub reason: String,
    /// Machine-verifiable prerequisites summarized for the maintainer.
    #[serde(default)]
    pub prerequisites: Vec<String>,
    /// Side-effect class used by renderers and automation policy.
    pub effect_class: EffectClass,
    /// Immutable object digest or identifier bound by the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_context: Option<String>,
}

impl NextAction {
    fn validate(&self) -> Result<()> {
        if self.label.is_empty() || self.label.len() > 160 {
            bail!("next action label is empty or oversized");
        }
        if self.argv.len() < 2 || self.argv.len() > 32 {
            bail!("next action argv must contain between 2 and 32 values");
        }
        if self.argv.first().map(String::as_str) != Some("aos")
            || self.argv.get(1).map(String::as_str) != Some("maintain")
        {
            bail!("next action must invoke the aos maintain command family");
        }
        if self.argv.iter().any(|value| {
            value.is_empty()
                || value.len() > 4096
                || value
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
        }) {
            bail!("next action argv contains an invalid value");
        }
        Ok(())
    }
}

/// Carries one requested primary value with an explicit semantic name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrimaryValue {
    /// Stable field name interpreted by the command schema.
    pub name: String,
    /// Exact scalar value written to standard output in human modes.
    pub value: String,
}

/// Contains the single terminal result returned by a maintenance command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaintainCommandResult {
    /// Selects the exact closed CLI-result schema.
    pub schema_version: String,
    /// Stable maintenance subcommand name.
    pub command: String,
    /// Command outcome independent of durable run state.
    pub disposition: CommandDisposition,
    /// Stable process exit code derived from the disposition.
    pub exit_code: u8,
    /// Durable run associated with this result, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// Typed scalar command data for machine and human renderers.
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    /// Requested primary values owned by standard output.
    #[serde(default)]
    pub primary_values: Vec<PrimaryValue>,
    /// Structured supplemental diagnostics.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// One to three exact recommended commands at a stopped boundary.
    #[serde(default)]
    pub next_actions: Vec<NextAction>,
}

impl MaintainCommandResult {
    /// Validates the result's schema, exit code, bounds, and exact actions.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, mismatched exit code,
    /// oversized fields, too many actions, or unsafe action argument vectors.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != MAINTENANCE_CLI_V1 {
            bail!(
                "unsupported maintenance CLI schema: {}",
                self.schema_version
            );
        }
        if self.exit_code != self.disposition.exit_code() {
            bail!("maintenance result exit code does not match its disposition");
        }
        if self.command.is_empty() || self.command.len() > 96 {
            bail!("maintenance result command is empty or oversized");
        }
        if self.data.len() > 128
            || self.primary_values.len() > 32
            || self.diagnostics.len() > 128
            || self.next_actions.len() > 3
        {
            bail!("maintenance result exceeds collection limits");
        }
        for action in &self.next_actions {
            action.validate()?;
        }
        Ok(())
    }
}

/// Couples a typed result to the one process exit selected by dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCompletion {
    /// Complete renderer-independent result.
    pub result: MaintainCommandResult,
}

impl CommandCompletion {
    /// Constructs a completion only from a valid terminal result.
    ///
    /// # Errors
    ///
    /// Returns an error under the conditions described by
    /// [`MaintainCommandResult::validate`].
    pub fn new(result: MaintainCommandResult) -> Result<Self> {
        result.validate()?;
        Ok(Self { result })
    }

    /// Returns the stable process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.result.exit_code
    }
}

/// Holds one presentation-neutral task in the active operation DAG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskView {
    /// Stable task identity.
    pub id: String,
    /// Concise human label.
    pub label: String,
    /// Ephemeral task status.
    pub status: TaskStatus,
    /// Child tasks in deterministic display order.
    #[serde(default)]
    pub children: Vec<TaskView>,
}

/// Reduces durable and transient state into one renderer-neutral view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaintenanceView {
    /// Human title for the current durable object.
    pub title: String,
    /// Upstream-evidence axis, when the view concerns discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryDecision>,
    /// Durable run-state axis, when a run exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_state: Option<RunState>,
    /// Gate-outcome axis, when a gate is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<GateOutcome>,
    /// Controller-owned task tree.
    #[serde(default)]
    pub tasks: Vec<TaskView>,
    /// Structured warnings and errors.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// Exact actions available from the verified state.
    #[serde(default)]
    pub actions: Vec<NextAction>,
}

/// Escapes untrusted text before terminal measurement, styling, or layout.
///
/// The returned text visibly represents C0/C1 controls, ESC, line separators,
/// and bidirectional formatting controls. Input beyond `max_input_bytes` is
/// truncated at a UTF-8 boundary and marked visibly.
#[must_use]
pub fn escape_terminal(text: &str, max_input_bytes: usize) -> String {
    let mut output = String::new();
    let mut consumed = 0_usize;
    for character in text.chars() {
        let width = character.len_utf8();
        if consumed.saturating_add(width) > max_input_bytes {
            output.push_str("...[truncated]");
            break;
        }
        consumed += width;

        if must_escape(character) {
            use std::fmt::Write as _;
            let _ = write!(output, "\\u{{{:04X}}}", u32::from(character));
        } else {
            output.push(character);
        }
    }
    output
}

fn must_escape(character: char) -> bool {
    character.is_control()
        || matches!(
            u32::from(character),
            0x2028 | 0x2029 | 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> NextAction {
        NextAction {
            label: "Inspect the blocked run".to_string(),
            argv: vec![
                "aos".to_string(),
                "maintain".to_string(),
                "inspect".to_string(),
                "run-1".to_string(),
            ],
            reason: "source identity disagrees".to_string(),
            prerequisites: Vec::new(),
            effect_class: EffectClass::ReadOnly,
            bound_context: Some("sha256:context".to_string()),
        }
    }

    #[test]
    fn disposition_exit_codes_are_stable_and_distinct() {
        assert_eq!(CommandDisposition::Success.exit_code(), 0);
        assert_eq!(CommandDisposition::InvalidInvocation.exit_code(), 2);
        assert_eq!(CommandDisposition::ActionRequired.exit_code(), 11);
        assert_ne!(
            CommandDisposition::UpstreamUnknown.exit_code(),
            CommandDisposition::Quarantined.exit_code()
        );
    }

    #[test]
    fn completion_rejects_mismatched_exit_and_shell_actions() -> Result<()> {
        let mut result = MaintainCommandResult {
            schema_version: MAINTENANCE_CLI_V1.to_string(),
            command: "status".to_string(),
            disposition: CommandDisposition::ActionRequired,
            exit_code: 0,
            run_id: None,
            data: BTreeMap::new(),
            primary_values: Vec::new(),
            diagnostics: Vec::new(),
            next_actions: vec![action()],
        };
        assert!(CommandCompletion::new(result.clone()).is_err());

        result.exit_code = CommandDisposition::ActionRequired.exit_code();
        result.next_actions[0].argv = vec!["sh".to_string(), "-c".to_string()];
        assert!(CommandCompletion::new(result).is_err());
        Ok(())
    }

    #[test]
    fn terminal_escaping_is_visible_bounded_and_utf8_safe() {
        assert_eq!(
            escape_terminal("ok\n\u{1b}[31m\u{202e}x", 64),
            "ok\\u{000A}\\u{001B}[31m\\u{202E}x"
        );
        assert_eq!(escape_terminal("éé", 3), "é...[truncated]");
    }
}
