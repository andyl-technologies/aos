//! Reproduction artifact parsing error constructors.

use super::*;

pub(crate) fn artifact_line_error(line_index: usize, tag: &str, reason: &str) -> CliError {
    artifact_error(format!("line {} `{tag}`: {reason}", line_index + 1))
}

pub(crate) fn missing_line(tag: &str) -> CliError {
    artifact_error(format!("missing `{tag}` line"))
}

pub(crate) fn artifact_error(reason: impl Into<String>) -> CliError {
    CliError::Artifact(reason.into())
}

pub(crate) fn invalid_scenario(reason: impl Into<String>) -> CliError {
    CliError::InvalidScenario(reason.into())
}
