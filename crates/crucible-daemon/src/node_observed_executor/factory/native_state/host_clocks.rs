//! Bounds the source-selected independent portless Host Clock roster.
//!
//! This list is part of the complete regenerated graph. It supplies no native
//! certificate or readiness; each actual model is enrolled before admission.

use super::super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused};

/// Bounds the independently owned source-selected Clock additions.
pub(super) const MAXIMUM_ADDITIONAL_CLOCKS: usize = 4;

pub(in crate::node_observed_executor::factory) fn validate(
    selections: &[InstalledNodeSelection],
) -> Result<(), NodeObservedError> {
    if selections.len() > MAXIMUM_ADDITIONAL_CLOCKS {
        return Err(refused(
            "additional mixed Host Clock roster exceeds its source ceiling",
        ));
    }
    let mut previous = "cpu";
    for selected in selections {
        if !matches!(selected.kind, InstalledNodeKind::HostClock)
            || selected.node.as_str() <= previous
            || matches!(selected.owner.as_str(), "owner/clock" | "owner/cpu")
            || selections
                .iter()
                .filter(|other| other.owner == selected.owner)
                .count()
                != 1
        {
            return Err(refused(
                "additional mixed Host owner is unsupported, unsorted or duplicated",
            ));
        }
        previous = selected.node.as_str();
    }
    Ok(())
}

#[cfg(test)]
mod tests;
