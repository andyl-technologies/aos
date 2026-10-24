//! Final trusted collection revision reads at actual native callback boundaries.
//!
//! Ordinary runtimes retain None and their existing behavior. Collecting owners
//! retain the same opaque graph capsule; native preflight getters cannot erase
//! its purpose or outlive the original final source/owner revision check.

use crate::{node_admission::ConformanceGraph, node_contract::RuntimeError};

pub(super) fn final_collection_scope(
    collecting: Option<&ConformanceGraph>,
) -> Result<(), RuntimeError> {
    if let Some(graph) = collecting {
        graph
            .authenticate_current_scope()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
    }
    Ok(())
}
