//! Attributes produced selections to the fresh portion of an attempt schedule.

use std::collections::BTreeSet;

use crucible::{Configuration, Decision};
use crucible_campaign::{ChoiceDiscovery, ChoiceOpportunityId, Selection, SelectionOrigin};

use super::{ModeledStop, QemuFreshModeledDriverError, QemuFreshPendingObservation};

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
        // Campaign branches are authenticated repository inputs, including
        // when start replay applies one after the decoded semantic boundary.
        .filter(|selection| !matches!(selection.origin(), SelectionOrigin::CampaignBranch { .. }))
        .filter(|selection| discovered_ids.contains(&selection.opportunity()))
        .collect();
    Ok(selections)
}

pub(super) fn has_unselected_discovery<'a>(
    configuration: &Configuration,
    discoveries: impl IntoIterator<Item = &'a ChoiceDiscovery>,
) -> Result<bool, QemuFreshModeledDriverError> {
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

pub(super) fn validate_live_network_preselection(
    pending: &QemuFreshPendingObservation,
) -> Result<(), QemuFreshModeledDriverError> {
    let Some(choice) = &pending.preselection else {
        return Ok(());
    };
    let reached_choice = is_next_choice_stop(&pending.stop);
    let opportunity = choice.discovery.opportunity().id()?;
    let retained = pending.discoveries.get(&opportunity) == Some(&choice.discovery);
    let unselected = has_unselected_discovery(&pending.configuration, [&choice.discovery])?;
    if !reached_choice || !retained || !unselected || pending.configuration != choice.parent {
        return Err(QemuFreshModeledDriverError::Scheduler(
            crucible::SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network choice observation lost its exact unselected parent",
                ),
            },
        ));
    }
    Ok(())
}

pub(super) fn is_next_choice_stop(stop: &ModeledStop) -> bool {
    match stop {
        ModeledStop::Reached(stop) => stop.accepts_next_choice(),
        ModeledStop::BoundedPrimaryReached { stop, .. } => stop.primary().accepts_next_choice(),
        _ => false,
    }
}
