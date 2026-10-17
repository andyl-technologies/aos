//! Projects choices and produced selections without native lifecycle custody.

use std::collections::BTreeSet;

use crucible::{Configuration, Decision};
use crucible_campaign::{ChoiceDiscovery, ChoiceOpportunityId, Selection, SelectionOrigin};

use super::ModeledCampaignError;

pub(crate) fn produced_selections_after_start(
    start: &Configuration,
    child: &Configuration,
    discovered_ids: &BTreeSet<ChoiceOpportunityId>,
) -> Result<Vec<Selection>, ModeledCampaignError> {
    let start_decisions = start.schedule.decisions();
    let child_decisions = child.schedule.decisions();
    if !child_decisions.starts_with(start_decisions) {
        return Err(ModeledCampaignError::StartSchedulePrefixMismatch);
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
        // Campaign branches are authenticated repository inputs, including
        // when start replay applies one after the decoded semantic boundary.
        .filter(|selection| !matches!(selection.origin(), SelectionOrigin::CampaignBranch { .. }))
        .filter(|selection| discovered_ids.contains(&selection.opportunity()))
        .collect();
    Ok(selections)
}

pub(crate) fn has_unselected_discovery<'a>(
    configuration: &Configuration,
    discoveries: impl IntoIterator<Item = &'a ChoiceDiscovery>,
) -> Result<bool, ModeledCampaignError> {
    let selected = configuration
        .schedule
        .decisions()
        .iter()
        .filter_map(|decision| match decision {
            Decision::Selection(selection) => Some(selection),
            _ => None,
        })
        .map(|decision| {
            decision
                .selection()
                .map(|selection| selection.opportunity())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    for discovery in discoveries {
        let opportunity = discovery.opportunity().id()?;
        if !selected.contains(&opportunity) {
            return Ok(true);
        }
    }
    Ok(false)
}
