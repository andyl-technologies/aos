//! Quantum retention into the attempt log, and bounded choice discoveries.

use super::*;

pub(super) fn append_quantum(
    event_log: &mut RetainedAttemptLog,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_environment_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<crucible_engine::Configuration, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let QuantumOutcome {
        configuration,
        discovered_choices,
        event_log_entries,
        scheduler_quiescence,
        frontier,
        ..
    } = outcome;
    event_log
        .append(event_log_entries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    for discovery in discovered_choices {
        if is_environment_fault_discovery(&discovery) && !retain_environment_fault_discoveries {
            continue;
        }
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn is_environment_fault_discovery(discovery: &ChoiceDiscovery) -> bool {
    matches!(
        discovery.opportunity().source(),
        crucible_campaign::ChoiceSource::Environment { adapter, .. }
            if adapter == crucible_engine::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                || adapter == crucible_engine::NETWORK_FAULT_CAMPAIGN_ADAPTER
    )
}

#[derive(Default)]
pub(super) struct RetainedChoiceDiscoveries {
    pub(super) discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    pub(super) representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    pub(super) charged_records: BTreeSet<ContentId>,
    pub(super) charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    pub(super) fn from_replayed(
        replayed: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let mut discoveries = Self::default();
        for discovery in replayed.into_values() {
            discoveries.insert(discovery)?;
        }
        Ok(discoveries)
    }

    pub(super) fn insert(
        &mut self,
        mut discovery: ChoiceDiscovery,
    ) -> Result<(), QemuFreshModeledDriverError> {
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
                return Err(QemuFreshModeledDriverError::ConflictingChoice(opportunity));
            }
            return Ok(());
        }
        self.charge(
            opportunity.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        )?;
        self.discoveries.insert(opportunity, discovery);
        Ok(())
    }

    fn charge(&mut self, id: ContentId, bytes: usize) -> Result<(), QemuFreshModeledDriverError> {
        if !self.charged_records.insert(id) {
            return Ok(());
        }
        let total = self.charged_bytes.checked_add(bytes).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            },
        )?;
        if total > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            });
        }
        self.charged_bytes = total;
        Ok(())
    }
}
