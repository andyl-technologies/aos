//! CLI unit tests grouped by user-facing workflow.

use super::*;

use std::error::Error;

use crucible_harness::reproduction::{ReproductionArtifact, mock_e2e_reproduction_artifact};
use tempfile::TempDir;

#[path = "tests/actual_failure.rs"]
mod actual_failure;
#[path = "tests/graph_support.rs"]
mod graph_support;
#[path = "tests/replay_artifact.rs"]
mod replay_artifact;
#[path = "tests/state_workflows.rs"]
mod state_workflows;
#[path = "tests/surface.rs"]
mod surface;
#[path = "tests/verify_dispatch.rs"]
mod verify_dispatch;

use graph_support::*;
use surface::*;

fn assert_qemu_workflow_unwired(error: &CliError, command: &str) {
    assert!(matches!(error, CliError::Backend(_)));
    assert_eq!(error.exit_code(), 4);
    let message = error.to_string();
    assert!(message.contains(&format!("local QEMU {command} execution is unavailable")));
    assert!(message.contains("no in-process double fallback was executed"));
    assert!(message.contains("select `--backend double` explicitly"));
}
