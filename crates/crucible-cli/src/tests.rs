//! CLI unit tests grouped by user-facing workflow.

use super::*;

use std::error::Error;

use crucible_harness::reproduction::{ReproductionArtifact, mock_e2e_reproduction_artifact};
use tempfile::TempDir;

#[path = "tests/replay_artifact.rs"]
mod replay_artifact;
#[path = "tests/state_workflows.rs"]
mod state_workflows;
#[path = "tests/surface.rs"]
mod surface;
#[path = "tests/verify_dispatch.rs"]
mod verify_dispatch;

use surface::*;
