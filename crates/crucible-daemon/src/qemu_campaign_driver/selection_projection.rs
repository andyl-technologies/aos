//! Attributes produced selections to the fresh portion of an attempt schedule.

use std::collections::BTreeSet;

use crucible::{Configuration, Decision};
use crucible_campaign::{ChoiceOpportunityId, Selection};

use super::QemuFreshModeledDriverError;

pub(super) fn produced_selections_after_start(
    start: &Configuration,
    child: &Configuration,
    discovered_ids: &BTreeSet<ChoiceOpportunityId>,
) -> Result<Vec<Selection>, QemuFreshModeledDriverError> {
    let start_decisions = start.schedule.decisions();
    let child_decisions = child.schedule.decisions();
    if !child_decisions.starts_with(start_decisions) {
        return Err(QemuFreshModeledDriverError::StartSchedulePrefixMismatch);
    }

    // A branch start already owns its selected prefix. Only decisions made by
    // this attempt can be published as selections produced by its observation.
    let selections = child_decisions[start_decisions.len()..]
        .iter()
        .filter_map(|decision| match decision {
            Decision::Selection(selection) => Some(selection),
            _ => None,
        })
        .map(|decision| Selection::from_canonical_bytes(decision.canonical_bytes()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|selection| discovered_ids.contains(&selection.opportunity()))
        .collect();
    Ok(selections)
}
