//! Bounded event-log and choice-discovery retention for modeled attempts.

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    Configuration, QuantumOutcome, SchedulerEventLogEntry, SchedulerQuiescence, VirtualTime,
};
use crucible_campaign::{
    ChoiceDiscovery, ChoiceDomainId, ChoiceOpportunityId, MAX_OBSERVATION_CHOICE_DISCOVERIES,
    MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES, SelectableId,
};
use crucible_cas::content_store::ContentId;

use super::ModeledCampaignError;
use crate::attempt_evidence::{MAX_ATTEMPT_EVENT_LOG_BYTES, MAX_ATTEMPT_EVENT_LOG_ENTRIES};

pub(crate) fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_environment_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<Configuration, ModeledCampaignError> {
    let QuantumOutcome {
        configuration,
        discovered_choices,
        event_log_entries,
        scheduler_quiescence,
        frontier,
        ..
    } = outcome;
    append_event_entries(event_log, event_log_bytes, event_log_entries)?;
    for discovery in discovered_choices {
        if is_environment_fault_discovery(&discovery) && !retain_environment_fault_discoveries {
            continue;
        }
        discoveries.insert(discovery)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn is_environment_fault_discovery(discovery: &ChoiceDiscovery) -> bool {
    matches!(
        discovery.opportunity().source(),
        crucible_campaign::ChoiceSource::Environment { adapter, .. }
            if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                || adapter == crucible::NETWORK_FAULT_CAMPAIGN_ADAPTER
    )
}

pub(crate) fn append_event_entries(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    retained_bytes: &mut usize,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<(), ModeledCampaignError> {
    let total =
        event_log
            .len()
            .checked_add(entries.len())
            .ok_or(ModeledCampaignError::LimitExceeded {
                limit: "fresh-campaign-event-log-entry-count",
            })?;
    if total > MAX_ATTEMPT_EVENT_LOG_ENTRIES {
        return Err(ModeledCampaignError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        });
    }
    let added_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry.canonical_material_len()).ok_or(
            ModeledCampaignError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            },
        )
    })?;
    let total_bytes =
        retained_bytes
            .checked_add(added_bytes)
            .ok_or(ModeledCampaignError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            })?;
    if total_bytes > MAX_ATTEMPT_EVENT_LOG_BYTES {
        return Err(ModeledCampaignError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        });
    }
    event_log.extend(entries);
    *retained_bytes = total_bytes;
    Ok(())
}

#[derive(Default)]
pub(crate) struct RetainedChoiceDiscoveries {
    pub(crate) discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    pub(crate) representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    pub(crate) charged_records: BTreeSet<ContentId>,
    pub(crate) charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    pub(crate) fn from_replayed(
        replayed: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, ModeledCampaignError> {
        let mut discoveries = Self::default();
        for discovery in replayed.into_values() {
            discoveries.insert(discovery)?;
        }
        Ok(discoveries)
    }

    pub(crate) fn insert(
        &mut self,
        mut discovery: ChoiceDiscovery,
    ) -> Result<(), ModeledCampaignError> {
        let declaration = discovery.opportunity().declaration();
        let domain = discovery.opportunity().domain();
        let opportunity = discovery.opportunity().id()?;
        let contract = (declaration, domain);
        if let Some(validated) = self.representatives.get(&contract) {
            discovery.share_dependencies_from(validated)?;
        } else {
            self.charge(
                declaration.content_id(),
                discovery.declaration().canonical_bytes().len(),
            )?;
            self.charge(
                domain.content_id(),
                discovery.domain().canonical_bytes().len(),
            )?;
            self.representatives.insert(contract, discovery.clone());
        }

        if let Some(existing) = self.discoveries.get(&opportunity) {
            if existing.opportunity() != discovery.opportunity() {
                return Err(ModeledCampaignError::ConflictingChoice(opportunity));
            }
            return Ok(());
        }
        if self.discoveries.len() == MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(ModeledCampaignError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-count",
            });
        }
        self.charge(
            opportunity.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        )?;
        self.discoveries.insert(opportunity, discovery);
        Ok(())
    }

    fn charge(&mut self, id: ContentId, bytes: usize) -> Result<(), ModeledCampaignError> {
        if !self.charged_records.insert(id) {
            return Ok(());
        }
        let total =
            self.charged_bytes
                .checked_add(bytes)
                .ok_or(ModeledCampaignError::LimitExceeded {
                    limit: "fresh-campaign-discovered-choice-bytes",
                })?;
        if total > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
            return Err(ModeledCampaignError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            });
        }
        self.charged_bytes = total;
        Ok(())
    }
}
