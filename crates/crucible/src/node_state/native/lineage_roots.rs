//! Reserves selected graph and installed model roots before typed closure traversal.
//!
//! Roots identify known original bodies; their full byte and dependency closure
//! still requires the independently installed evidence reader. No root is a leaf
//! by default, and this data helper issues no native continuation authority.

use crucible_node_contract::{ContentRef, Validate};

use super::{StateError, StateLimits, refused};

pub(super) fn combine(
    mut graph: Vec<ContentRef>,
    installed: Vec<ContentRef>,
    limits: StateLimits,
) -> Result<Vec<ContentRef>, StateError> {
    let occurrences = graph
        .len()
        .checked_add(installed.len())
        .filter(|count| *count <= limits.maximum_content_objects)
        .ok_or_else(|| refused("lineage immutable root occurrence credit exhausted"))?;
    for reference in graph.iter().chain(&installed) {
        reference.validate().map_err(super::super::schema)?;
        let length = usize::try_from(reference.length.get())
            .map_err(|_| refused("lineage immutable root extent overflow"))?;
        if length > limits.maximum_content_bytes {
            return Err(refused("lineage immutable root object credit exhausted"));
        }
    }
    graph
        .try_reserve_exact(occurrences - graph.len())
        .map_err(|_| refused("lineage immutable root reservation failed"))?;
    graph.extend(installed);
    graph.sort();
    graph.dedup();
    Ok(graph)
}

#[cfg(test)]
#[path = "lineage_roots_models.rs"]
mod models;
