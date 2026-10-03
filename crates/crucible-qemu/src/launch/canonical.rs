//! Canonical per-node launch identity rendering.

use super::{LaunchProfileError, validate_fixed_text};
use crucible::{NodeId, SIM_TICKS_PER_NS};

pub(super) fn canonical_node_tick_scale_lines(
    node_ids: &[NodeId],
) -> Result<Vec<String>, LaunchProfileError> {
    let mut ordered = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        validate_fixed_text("node_id", &node_id.name)?;
        ordered.push(node_id.name.clone());
    }

    ordered.sort();
    for adjacent in ordered.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(LaunchProfileError::DuplicateNodeId {
                node_id: adjacent[0].clone(),
            });
        }
    }

    Ok(ordered
        .into_iter()
        .map(|node_id| format!("node_sim_ticks_per_ns[{node_id}]={SIM_TICKS_PER_NS}"))
        .collect())
}
