//! Attributes produced selections to the fresh portion of an attempt schedule.

use std::collections::BTreeSet;

use crucible::Configuration;
use crucible_campaign::{ChoiceDiscovery, ChoiceOpportunityId, Selection};

use super::{ModeledStop, QemuFreshModeledDriverError, QemuFreshPendingObservation};

pub(super) fn produced_selections_after_start(
    start: &Configuration,
    child: &Configuration,
    discovered_ids: &BTreeSet<ChoiceOpportunityId>,
) -> Result<Vec<Selection>, QemuFreshModeledDriverError> {
    crate::modeled_campaign_driver::selection_projection::produced_selections_after_start(
        start,
        child,
        discovered_ids,
    )
    .map_err(Into::into)
}

pub(super) fn has_unselected_discovery<'a>(
    configuration: &Configuration,
    discoveries: impl IntoIterator<Item = &'a ChoiceDiscovery>,
) -> Result<bool, QemuFreshModeledDriverError> {
    crate::modeled_campaign_driver::selection_projection::has_unselected_discovery(
        configuration,
        discoveries,
    )
    .map_err(Into::into)
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
